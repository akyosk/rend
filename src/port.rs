use std::error::Error;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use futures::future::join_all;
use tokio::sync::{Mutex, Semaphore};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::task;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::engine::Engine as _;
use reqwest::Client;
use serde_json::Value;
use reqwest::header::HeaderMap;
use std::collections::HashSet;
use crate::tofile::other_save_to_file;
use crate::outprint::Print;

// 定义常量
const TIMEOUT_DURATION: Duration = Duration::from_millis(500);
const MAX_CONCURRENT_TASKS: usize = 1000;
const MAX_PORTS_THRESHOLD: usize = 100;

#[derive(Clone)]
pub struct ApiKeys {
    pub fofa: String,
    pub shodan: String,
    pub zoomeye: String,
}

struct InfoIPRes {
    ips: InfoPortRes,
}

impl InfoIPRes {
    fn new() -> InfoIPRes {
        InfoIPRes {
            ips: InfoPortRes::new(),
        }
    }
}

struct InfoPortRes {
    ports: Vec<String>,
}

impl InfoPortRes {
    fn new() -> InfoPortRes {
        InfoPortRes {
            ports: Vec::new(),
        }
    }
    fn push(&mut self, port: String) {
        self.ports.push(port);
    }
    fn extend(&mut self, ports: Vec<String>) {
        self.ports.extend(ports);
    }
    fn rt(&self) -> Vec<String> {
        self.ports.clone()
    }
    fn res(&self) -> Vec<String> {
        let mut ports = self.ports.clone();
        ports.sort();
        ports.dedup();
        ports
    }
}

#[async_trait]
trait InfoPort {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>>;
}

struct ShodanIp;
struct FofaIp;
struct ZoomeyeIp;

#[async_trait]
impl InfoPort for ZoomeyeIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let base64_str = STANDARD.encode(format!("ip=\"{}\" && after=\"2024-05-07\"", ip));
        let url = "https://api.zoomeye.ai/v2/search";
        let mut headers = HeaderMap::new();
        headers.insert("api-key", api_keys.zoomeye.parse()?);
        let payload = serde_json::json!({
            "page": 1,
            "qbase64": base64_str,
            "pagesize": 100,
        });
        let response = client.post(url).headers(headers).json(&payload).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok(results);
        }
        let json_response = response.json::<Value>().await?;
        let data = match json_response.get("data") {
            Some(data) => data,
            None => {
                return Ok(InfoPortRes::new());
            }
        };
        let ports: Vec<i64> = data
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|item| item.get("port").and_then(|port| port.as_i64()))
            .collect();
        let unique_ports: Vec<i64> = ports.into_iter().collect::<HashSet<i64>>().into_iter().collect();
        let mut unique_ports = unique_ports;
        unique_ports.sort();
        for port in unique_ports {
            results.push(format!("{}:{}", ip, port.to_string()));
        }
        if results.ports.len() > MAX_PORTS_THRESHOLD {
            Print::passprint(format!("The ip {} may be CDN, excluding collection results", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok(results)
    }
}

#[async_trait]
impl InfoPort for ShodanIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_keys.shodan);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok(results);
        }
        let json_response = response.json::<Value>().await?;
        if let Some(ports) = json_response.get("ports").and_then(|p| p.as_array()) {
            ports.into_iter().for_each(|port| {
                results.push(format!("{}:{}", ip, port));
            });
        }
        if results.ports.len() > MAX_PORTS_THRESHOLD {
            Print::passprint(format!("The ip {} may be CDN, excluding collection results", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok(results)
    }
}

#[async_trait]
impl InfoPort for FofaIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let base64_str = STANDARD.encode(format!("ip={}", ip));
        let url = format!(
            "https://fofa.info/api/v1/search/all?key={}&qbase64={}&size=100&full=true",
            api_keys.fofa, base64_str
        );
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok(results);
        }
        let json_response = response.json::<Value>().await?;
        let empty_vec = vec![];
        let data_array = json_response.get("results").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
        data_array.iter().for_each(|data| {
            if let Some(ports) = data.get(2) {
                if let Some(p) = ports.as_str() {
                    results.push(format!("{}:{}", ip, p));
                }
            }
        });
        if results.ports.len() > MAX_PORTS_THRESHOLD {
            Print::passprint(format!("The ip {} may be CDN, excluding collection results", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok(results)
    }
}

async fn scan_port(
    ip: IpAddr,
    port: u16,
    semaphore: Arc<Semaphore>,
    open_ports: Arc<Mutex<HashSet<u16>>>,
    should_stop: Arc<Mutex<bool>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let _permit = semaphore.acquire().await?;
    let socket_addr = SocketAddr::new(ip, port);

    // 检查是否需要停止扫描
    {
        let should_stop_guard = should_stop.lock().await;
        if *should_stop_guard {
            return Ok(());
        }
    }

    let result = timeout(TIMEOUT_DURATION, TcpStream::connect(&socket_addr)).await;

    match result {
        Ok(Ok(_stream)) => {
            let mut open_ports_guard = open_ports.lock().await;
            open_ports_guard.insert(port);
            // 检查端口数量是否超过阈值
            if open_ports_guard.len() > MAX_PORTS_THRESHOLD {
                let mut should_stop_guard = should_stop.lock().await;
                *should_stop_guard = true;
            }
        }
        Ok(Err(_)) => {}
        Err(_) => {}
    }
    Ok(())
}

async fn scan_ports(ip: IpAddr, start_port: u16, end_port: u16) -> Result<HashSet<u16>, Box<dyn Error + Send + Sync>> {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS));
    let open_ports: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
    let should_stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let mut tasks = Vec::new();

    for port in start_port..=end_port {
        let semaphore_clone = Arc::clone(&semaphore);
        let open_ports_clone = Arc::clone(&open_ports);
        let should_stop_clone = Arc::clone(&should_stop);
        tasks.push(tokio::spawn(scan_port(
            ip,
            port,
            semaphore_clone,
            open_ports_clone,
            should_stop_clone,
        )));
    }

    for task in tasks {
        if let Err(_e) = task.await {}
    }

    let open_ports_guard = open_ports.lock().await;
    let should_stop_guard = should_stop.lock().await;

    if *should_stop_guard {
        Print::passprint(format!("IP {} may be CDN, too many open ports (>{}), excluding scan results", ip, MAX_PORTS_THRESHOLD).as_str());
        Ok(HashSet::new())
    } else {
        Ok(open_ports_guard.clone())
    }
}

async fn filter_cdn_ips(ips: &Vec<String>) -> Vec<String> {
    let semaphore = Arc::new(Semaphore::new(10));
    let non_cdn_ips = Arc::new(Mutex::new(Vec::new()));

    Print::infoprint(format!("Checking whether {} IPs are CDNs", ips.len()).as_str());

    let mut tasks = vec![];
    for ip in ips {
        let permit = semaphore.clone();
        let ip_clone = ip.clone();
        let non_cdn_ips_clone = Arc::clone(&non_cdn_ips);

        let task = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            let clean_ip = if ip_clone.contains(":") {
                ip_clone.split(":").next().unwrap_or(&ip_clone).to_string()
            } else {
                ip_clone.clone()
            };
            match is_cdn_ip(&clean_ip).await {
                (false, _) => {
                    let mut ips = non_cdn_ips_clone.lock().await;
                    ips.push(ip_clone);
                }
                (true, reason) => {
                    Print::passprint(format!("Skip CDN IP {}: {}", clean_ip, reason).as_str());
                }
            }
        });
        tasks.push(task);
    }

    join_all(tasks).await;

    let result = non_cdn_ips.lock().await.clone();
    Print::bannerprint(format!("CDN detection completed: {} IPs in total, {} non-CDN IPs initially screened out", ips.len(), result.len()).as_str());
    result
}

async fn is_cdn_ip(ip: &str) -> (bool, String) {
    match check_known_cdn_ranges(ip) {
        Some((is_cdn, reason)) if is_cdn => return (true, reason),
        _ => {}
    }
    (false, String::new())
}

fn check_known_cdn_ranges(ip: &str) -> Option<(bool, String)> {
    let cdn_ranges = [
        // cf
        ("103.21.244.0/22", "Cloudflare"),
        ("103.22.200.0/22", "Cloudflare"),
        ("103.31.4.0/22", "Cloudflare"),
        ("104.16.0.0/13", "Cloudflare"),
        ("104.24.0.0/14", "Cloudflare"),
        ("108.162.192.0/18", "Cloudflare"),
        ("131.0.72.0/22", "Cloudflare"),
        ("141.101.64.0/18", "Cloudflare"),
        ("162.158.0.0/15", "Cloudflare"),
        ("172.64.0.0/13", "Cloudflare"),
        ("173.245.48.0/20", "Cloudflare"),
        ("188.114.96.0/20", "Cloudflare"),
        ("190.93.240.0/20", "Cloudflare"),
        ("197.234.240.0/22", "Cloudflare"),
        ("198.41.128.0/17", "Cloudflare"),
        ("2400:cb00::/32", "Cloudflare"),
        ("2606:4700::/32", "Cloudflare"),
        ("2803:f800::/32", "Cloudflare"),
        ("2405:b500::/32", "Cloudflare"),
        ("2405:8100::/32", "Cloudflare"),
        ("2a06:98c0::/29", "Cloudflare"),
        ("2c0f:f248::/32", "Cloudflare"),
        // aws
        ("13.32.0.0/15", "AWS CloudFront"),
        ("13.35.0.0/16", "AWS CloudFront"),
        ("13.249.0.0/16", "AWS CloudFront"),
        ("52.46.0.0/18", "AWS CloudFront"),
        ("52.84.0.0/15", "AWS CloudFront"),
        ("52.222.0.0/17", "AWS CloudFront"),
        ("54.182.0.0/16", "AWS CloudFront"),
        ("54.192.0.0/16", "AWS CloudFront"),
        ("54.230.0.0/16", "AWS CloudFront"),
        ("54.239.0.0/17", "AWS CloudFront"),
        ("70.132.0.0/18", "AWS CloudFront"),
        ("99.84.0.0/16", "AWS CloudFront"),
        ("204.246.168.0/22", "AWS CloudFront"),
        ("205.251.192.0/21", "AWS CloudFront"),
        ("216.137.32.0/19", "AWS CloudFront"),
        ("2600:9000::/28", "AWS CloudFront"),
        ("2600:9000:1000::/36", "AWS CloudFront"),
        ("2600:9000:2000::/36", "AWS CloudFront"),
        ("2600:9000:3000::/36", "AWS CloudFront"),
        ("2600:9000:4000::/36", "AWS CloudFront"),
    ];

    if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
        for (range, provider) in &cdn_ranges {
            if is_ip_in_cidr(&ip_addr, range) {
                return Some((
                    true,
                    format!("The IP is in the network segment {}", provider),
                ));
            }
        }
    }

    None
}

fn is_ip_in_cidr(ip: &std::net::IpAddr, cidr: &str) -> bool {
    if let Ok(network) = cidr.parse::<ipnet::IpNet>() {
        return network.contains(ip);
    }
    false
}

async fn identify_service(ip: IpAddr, port: u16, timeout_duration: Duration, filename: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let skip_ports = [22, 21, 153, 445, 3306, 1521, 5432, 1433, 6379, 27017, 9200, 53, 23];
    if skip_ports.contains(&port) {
        return Ok(());
    }

    let socket_addr = SocketAddr::new(ip, port);

    if let Ok(is_jdwp) = check_jdwp(socket_addr, timeout_duration).await {
        if is_jdwp {
            Print::vulnportprint(format!("IP {}:{} Jdwp service detected", ip, port).as_str());
            let _ = other_save_to_file(filename, format!("IP {}:{} Jdwp service detected", ip, port).as_str());
            return Ok(());
        }
    }

    if let Ok(is_activemq) = check_activemq(socket_addr, timeout_duration).await {
        if is_activemq {
            Print::vulnportprint(format!("IP {}:{} ActiveMQ service detected", ip, port).as_str());
            let _ = other_save_to_file(filename, format!("IP {}:{} ActiveMQ service detected", ip, port).as_str());
            return Ok(());
        }
    }

    if let Ok(is_rmi) = check_rmi(socket_addr, timeout_duration).await {
        if is_rmi {
            Print::vulnportprint(format!("IP {}:{} RMI service detected", ip, port).as_str());
            let _ = other_save_to_file(filename, format!("IP {}:{} RMI service detected", ip, port).as_str());
            return Ok(());
        }
    }

    Ok(())
}

async fn check_jdwp(socket_addr: SocketAddr, timeout_duration: Duration) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let stream = timeout(timeout_duration, TcpStream::connect(socket_addr)).await??;
    let mut stream = stream;
    stream.write_all(b"JDWP-Handshake").await?;
    stream.flush().await?;

    let mut buffer = [0; 14];
    let result = timeout(timeout_duration, stream.read_exact(&mut buffer)).await;

    match result {
        Ok(Ok(_)) => {
            if buffer == b"JDWP-Handshake"[..] {
                return Ok(true);
            }
        }
        _ => {}
    }
    Ok(false)
}

async fn check_activemq(socket_addr: SocketAddr, timeout_duration: Duration) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let stream = timeout(timeout_duration, TcpStream::connect(socket_addr)).await??;
    let mut stream = stream;

    let openwire_frame = b"\x00\x00\x00\x0f\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    stream.write_all(openwire_frame).await?;
    stream.flush().await?;

    let mut buffer = vec![0; 1024];
    let result = timeout(timeout_duration, stream.read(&mut buffer)).await;

    match result {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            if response.contains("ActiveMQ") {
                return Ok(true);
            }
        }
        _ => {}
    }
    Ok(false)
}

async fn check_rmi(socket_addr: SocketAddr, timeout_duration: Duration) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let stream = timeout(timeout_duration, TcpStream::connect(socket_addr)).await??;
    let mut stream = stream;

    // JRMP 协议初始请求（简单的 "JRMI" 标识）
    let jrmp_request = b"JRMI\x00\x02\x4b";
    stream.write_all(jrmp_request).await?;
    stream.flush().await?;

    let mut buffer = vec![0; 256];
    let result = timeout(timeout_duration, stream.read(&mut buffer)).await;

    match result {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            // 检查响应是否包含 JRMP 或 RMI 相关标识
            if response.contains("JRMI") || response.contains("rmi") {
                return Ok(true);
            }
        }
        _ => {}
    }
    Ok(false)
}

pub async fn portmain(
    ips: &Vec<String>,
    filename: &str,
    client: Client,
    api_keys: ApiKeys,
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    Print::infoprint(format!("Received {} IP addresses in total", ips.len()).as_str());

    let non_cdn_ips = filter_cdn_ips(ips).await;

    if non_cdn_ips.is_empty() {
        Print::infoprint("Non-CDN IP addresses not detected, API queries and port scans skipped");
        return Ok(Vec::new());
    }

    Print::infoprint(format!("{} non-CDN IPs detected, starting API queries and port scanning", non_cdn_ips.len()).as_str());

    let ips_res = Arc::new(Mutex::new(InfoIPRes::new()));
    let semaphore = Arc::new(Semaphore::new(4));
    let open_ports_map = Arc::new(Mutex::new(Vec::<(String, Vec<u16>)>::new()));

    let shodan_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
    let fofa_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
    let zoomeye_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));

    Print::infoprint("Starting API-based port discovery");
    let fetchers: Vec<(Arc<dyn InfoPort + Send + Sync>, &str, Arc<Mutex<Vec<(String, usize)>>>)> = vec![
        (Arc::new(FofaIp), "Fofa", fofa_port_counts.clone()),
        (Arc::new(ShodanIp), "Shodan", shodan_port_counts.clone()),
        (Arc::new(ZoomeyeIp), "Zoomeye", zoomeye_port_counts.clone()),
    ];

    let mut api_tasks = vec![];
    for ip in non_cdn_ips.iter() {
        for (fetcher, _fetcher_name, port_counts) in &fetchers {
            let permit = semaphore.clone();
            let fetch = Arc::clone(fetcher);
            let client = client.clone();
            let api_keys = api_keys.clone();
            let ips_res_clone = Arc::clone(&ips_res);
            let ip_clone = ip.clone();
            let port_counts = Arc::clone(port_counts);
            let open_ports_map_clone = Arc::clone(&open_ports_map);

            let task = tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                match fetch.fetch(&ip_clone, api_keys, &client).await {
                    Ok(res) => {
                        let port_count = res.ports.len();
                        let mut ips_res = ips_res_clone.lock().await;
                        ips_res.ips.extend(res.rt());

                        let mut open_ports_map = open_ports_map_clone.lock().await;
                        let ports: Vec<u16> = res.rt().iter().filter_map(|s| {
                            let parts: Vec<&str> = s.split(':').collect();
                            if parts.len() == 2 {
                                parts[1].parse::<u16>().ok()
                            } else {
                                None
                            }
                        }).collect();
                        open_ports_map.push((ip_clone.clone(), ports));

                        let mut port_counts = port_counts.lock().await;
                        port_counts.push((ip_clone, port_count));
                    }
                    Err(_e) => {}
                }
            });
            api_tasks.push(task);
        }
    }
    join_all(api_tasks).await;

    for (fetcher_name, port_counts) in &[("Shodan", shodan_port_counts), ("Fofa", fofa_port_counts), ("Zoomeye", zoomeye_port_counts)] {
        let port_counts = port_counts.lock().await;
        let total_ports: usize = port_counts.iter().map(|(_, count)| count).sum();
        let ip_count = port_counts.len();
        if ip_count > 0 {
            Print::infoprint(format!("{} queried {} IPs, found {} total ports", fetcher_name, ip_count, total_ports).as_str());
        } else {
            Print::infoprint(format!("{} queried no IPs or found no ports", fetcher_name).as_str());
        }
    }
    Print::infoprint("API-based port discovery completed");

    if non_cdn_ips.len() <= 30 {
        Print::infoprint("Starting full port scan for non-CDN IPs");
        let ips_res_clone = Arc::clone(&ips_res);
        let open_ports_map_clone = Arc::clone(&open_ports_map);
        let total_ips = non_cdn_ips.len();

        for (index, ip_str) in non_cdn_ips.iter().enumerate() {
            Print::infoprint(format!("Scanning IP {}/{}: {}", index + 1, total_ips, ip_str).as_str());
            let ip = IpAddr::from_str(ip_str)?;
            let ip_clone_string = ip_str.clone();
            let ips_res_clone_local = Arc::clone(&ips_res_clone);
            let open_ports_map_clone_local = Arc::clone(&open_ports_map_clone);

            // 检查是否为 IPv6 地址
            if ip.is_ipv6() {
                Print::passprint(format!("IP {} is IPv6, skipping full port scan", ip_str).as_str());
                continue;
            }

            match scan_ports(ip, 1, 65535).await {
                Ok(open_ports) => {
                    let mut ips_res = ips_res_clone_local.lock().await;
                    let ports_string: Vec<String> = open_ports.iter().map(|&p| format!("{}:{}", ip_clone_string, p)).collect();
                    ips_res.ips.extend(ports_string);

                    let mut open_ports_map = open_ports_map_clone_local.lock().await;
                    let ports_vec: Vec<u16> = open_ports.into_iter().collect();
                    Print::infoprint(format!("IP {} Found Ports {}", ip_clone_string.clone(), ports_vec.len()).as_str());
                    open_ports_map.push((ip_clone_string, ports_vec));
                }
                Err(_e) => {
                    Print::passprint(format!("Port scanning failed for {}", ip_str).as_str());
                }
            }
        }
        Print::infoprint("Full port scan completed");
    }


    let final_res = ips_res.lock().await;
    let unique_ports = final_res.ips.res();

    if !unique_ports.is_empty() {
        Print::infoprint("Starting banner identification for all open ports");
        let mut banner_tasks = vec![];
        let open_ports_map = open_ports_map.lock().await;

        for (ip, ports) in open_ports_map.iter() {
            let ip_addr = match IpAddr::from_str(ip) {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            for &port in ports {
                let filename_clone = filename.to_string();
                let task = task::spawn(async move {
                    let _ = identify_service(ip_addr, port, Duration::from_secs(3), &filename_clone).await;
                });
                banner_tasks.push(task);
            }
        }

        join_all(banner_tasks).await;
        Print::infoprint("Port banner identification completed");
    }

    Ok(unique_ports)
}