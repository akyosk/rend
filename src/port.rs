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
use std::hash::RandomState;
use crate::infoscan::OtherSets;
use crate::tofile::other_save_to_file;
use crate::tofile::realip_to_file;
use crate::outprint::Print;
use serde_json::json;


// 定义常量
const TIMEOUT_DURATION: Duration = Duration::from_millis(500);
const MAX_CONCURRENT_TASKS: usize = 1000;
const MAX_PORTS_THRESHOLD: usize = 100; // API查询结果端口阈值
const QUAKE_CDN_THRESHOLD: i32 = 200; // Quake CDN 判断阈值

#[derive(Clone)]
pub struct ApiKeys {
    pub fofa: String,
    pub shodan: String,
    pub zoomeye: String,
    pub quake: String,
    pub yt: String,
}

struct CdnNum {
    cnd_num: i32,
}

impl CdnNum {
    fn new() -> CdnNum { CdnNum { cnd_num: 0 } }
    fn add_cnd_num(&mut self, cnd_num: i32) { self.cnd_num = cnd_num; }
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

struct InfoLinkRes {
    links: Vec<String>,
    ports: Vec<String>,
}

impl InfoLinkRes {
    fn new() -> InfoLinkRes {
        InfoLinkRes {
            links: Vec::new(),
            ports: Vec::new(),
        }
    }
    // fn push_link(&mut self, link: String) {
    //     self.links.push(link);
    // }
    // fn push_port(&mut self, port: String) {
    //     self.ports.push(port);
    // }
    fn extend_links(&mut self, links: Vec<String>) {
        self.links.extend(links);
    }
    // fn extend_ports(&mut self, ports: Vec<String>) {
    //     self.ports.extend(ports);
    // }
    fn rt_links(&self) -> Vec<String> {
        self.links.clone()
    }
    fn rt_ports(&self) -> Vec<String> {
        self.ports.clone()
    }
    fn res_links(&self) -> Vec<String> {
        let mut links = self.links.clone();
        links.sort();
        links.dedup();
        links
    }
    // fn res_ports(&self) -> Vec<String> {
    //     let mut ports = self.ports.clone();
    //     ports.sort();
    //     ports.dedup();
    //     ports
    // }
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
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client, scan_port_max: u64) -> Result<(InfoPortRes, bool), Box<dyn Error + Send + Sync>>;
}

#[async_trait]
trait InfoLinkIP {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoLinkRes, Box<dyn Error + Send + Sync>>;
}

struct ShodanIp;
struct FofaIp;
struct ZoomeyeIp;
struct QuakeIp;
struct QuakeIpCDN;
struct YtIp;

#[async_trait]
impl InfoLinkIP for YtIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoLinkRes, Box<dyn Error + Send + Sync>> {
        let query = STANDARD.encode(format!("ip=\"{}\"", ip));
        let url = format!("https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page=1&page_size=100&is_web=3&start_time=2024-01-01&end_time=2025-12-28", api_keys.yt, query);
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "127.0.0.1".parse()?);
        let response = client.get(&url).headers(headers).send().await?;
        if !response.status().is_success() {
            return Ok(InfoLinkRes::new());
        }
        let json_response = response.json::<Value>().await?;
            let mut results = InfoLinkRes::new();
            if let Some(data) = json_response.get("data").and_then(|d| d.get("arr")).and_then(|d| d.as_array()) {
                data.iter().for_each(|data| {
                    if let Some(domain) = data.get("domain").and_then(|o| o.as_str()) {
                        // let d = format!("123456{}", domain);
                        // results.links.push(d);
                        results.links.push(String::from(domain));
                    }
                    let port = data.get("port").map(|o| match o {
                        Value::String(s) => s.to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => "".to_string(),
                    });
                    if let Some(port) = port {
                        if !port.is_empty() {
                            results.ports.push(format!("{}:{}",ip, port));
                        }
                    }
                });
            }
            Ok(results)
        }
    }

#[async_trait]
impl InfoLinkIP for QuakeIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoLinkRes, Box<dyn Error + Send + Sync>> {
        let url = "https://quake.360.net/api/v3/search/quake_service";
        let mut headers = HeaderMap::new();
        headers.insert("x-quaketoken", api_keys.quake.parse()?);
        let query = json!({
            "query": format!("ip: \"{}\"", ip),
            "start": 0,
            "size": 100,
        });
        let response = client.post(url).json(&query).headers(headers).send().await?;
        if !response.status().is_success() {
            return Ok(InfoLinkRes::new());
        }
        let json_response = response.json::<Value>().await?;
        if json_response.get("code").and_then(|code| code.as_u64()) != Some(0) {
            return Ok(InfoLinkRes::new());
        }

        let empty_vec = vec![];
        let mut results = InfoLinkRes::new();
        let data_array = json_response.get("data").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
        data_array.iter().for_each(|data| {
            // 处理 port，可能为字符串或数字
            let port = data.get("port").map(|p| match p {
                Value::String(s) => s.to_string(),
                Value::Number(n) => n.to_string(),
                _ => "".to_string(),
            });
            // 处理 domain，可能为字符串或缺失
            let domain = data.get("domain").map(|d| match d {
                Value::String(s) => s.to_string(),
                _ => "".to_string(),
            });

            if let Some(port) = port {
                if !port.is_empty() {
                    results.ports.push(format!("{}:{}", ip, port));
                    if let Some(domain) = domain {
                        if !domain.is_empty() {
                            // let d = format!("123456{}", domain);
                            // results.links.push(d);
                            results.links.push(domain);
                        }
                    }
                }
            }
        });
        Ok(results)
    }
}

#[async_trait]
impl InfoPort for ZoomeyeIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client, _scan_port_max: u64) -> Result<(InfoPortRes, bool), Box<dyn Error + Send + Sync>> {
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
            return Ok((results, false));
        }
        let json_response = response.json::<Value>().await?;
        let data = match json_response.get("data") {
            Some(data) => data,
            None => {
                return Ok((InfoPortRes::new(), false));
            }
        };
        let ports: Vec<String> = data
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|item| {
                item.get("port").map(|port| match port {
                    Value::String(s) => s.to_string(),
                    Value::Number(n) => n.to_string(),
                    _ => "".to_string(),
                })
            })
            .filter(|port| !port.is_empty())
            .collect::<HashSet<String>>()
            .into_iter()
            .collect();
        let mut unique_ports = ports;
        unique_ports.sort();
        for port in unique_ports {
            results.push(format!("{}:{}", ip, port));
        }
        if results.ports.len() > MAX_PORTS_THRESHOLD {
            Print::passprint(format!("The ip {} may be CDN", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok((results, false))
    }
}

#[async_trait]
impl InfoPort for ShodanIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client, _scan_port_max: u64) -> Result<(InfoPortRes, bool), Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_keys.shodan);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok((results, false));
        }
        let json_response = response.json::<Value>().await?;
        if let Some(ports) = json_response.get("ports").and_then(|p| p.as_array()) {
            ports.into_iter().for_each(|port| {
                results.push(format!("{}:{}", ip, port));
            });
        }
        if results.ports.len() > MAX_PORTS_THRESHOLD {
            Print::passprint(format!("The ip {} may be CDN", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok((results, false))
    }
}

#[async_trait]
trait QuakeCdnChecker {
    async fn fetch_cdn_status(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<CdnNum, Box<dyn Error + Send + Sync>>;
}

#[async_trait]
impl QuakeCdnChecker for QuakeIpCDN {
    async fn fetch_cdn_status(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<CdnNum, Box<dyn Error + Send + Sync>> {
        let url = "https://quake.360.net/api/v3/search/quake_service";
        let mut headers = HeaderMap::new();
        headers.insert("x-quaketoken", api_keys.quake.parse()?);
        let query = json!({
        "query": format!("ip: {}", ip), "start": 0, "size": 1,
    });
        let mut results = CdnNum::new();
        let response = client.post(url).json(&query).headers(headers).send().await?;
        if !response.status().is_success() {
            return Ok(results)
        }

        let json_response = response.json::<Value>().await?;
        if json_response.get("code").and_then(|code| code.as_u64()) != Some(0) {
            Ok(results)
        } else {
            if let Some(total) = json_response
                .get("links")
                .and_then(|meta| meta.get("pagination"))
                .and_then(|pagination| pagination.get("total"))
                .and_then(|total| total.as_i64())
            {
                results.add_cnd_num(total as i32);
            }
            Ok(results)
        }
    }
}

#[async_trait]
impl InfoPort for FofaIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client, scan_port_max: u64) -> Result<(InfoPortRes, bool), Box<dyn Error + Send + Sync>> {
        let base64_str = STANDARD.encode(format!("ip={}", ip));
        let url = format!(
            "https://fofa.info/api/v1/search/all?key={}&qbase64={}&size=100&full=true",
            api_keys.fofa, base64_str
        );
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok((results, false));
        }
        let json_response = response.json::<Value>().await?;
        let empty_vec = vec![];
        let size_number = json_response.get("size").and_then(|data| data.as_u64()).unwrap_or(500);
        if size_number >= scan_port_max {
            Print::passprint(format!("The ip {} may be CDN", ip).as_str());
            return Ok((results, true));
        }
        let data_array = json_response.get("results").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
        data_array.iter().for_each(|data| {
            if let Some(ports) = data.get(2) {
                if let Some(p) = ports.as_str() {
                    results.push(format!("{}:{}", ip, p));
                }
            }
        });
        if results.ports.len() > MAX_PORTS_THRESHOLD {
            Print::passprint(format!("The ip {} may be CDN", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok((results, false))
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
        Print::passprint(format!("IP {} may be CDN, Ports (>{})", ip, MAX_PORTS_THRESHOLD).as_str());
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
                    Print::passprint(format!("IP {}: {}", clean_ip, reason).as_str());
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
        ("13.32.0.0/15", "AWS"),
        ("13.35.0.0/16", "AWS"),
        ("13.249.0.0/16", "AWS"),
        ("52.46.0.0/18", "AWS"),
        ("52.84.0.0/15", "AWS"),
        ("52.222.0.0/17", "AWS"),
        ("54.182.0.0/16", "AWS"),
        ("54.192.0.0/16", "AWS"),
        ("54.230.0.0/16", "AWS"),
        ("54.239.0.0/17", "AWS"),
        ("70.132.0.0/18", "AWS"),
        ("99.84.0.0/16", "AWS"),
        ("204.246.168.0/22", "AWS"),
        ("205.251.192.0/21", "AWS"),
        ("216.137.32.0/19", "AWS"),
        ("2600:9000::/28", "AWS"),
        ("2600:9000:1000::/36", "AWS"),
        ("2600:9000:2000::/36", "AWS"),
        ("2600:9000:3000::/36", "AWS"),
        ("2600:9000:4000::/36", "AWS"),
    ];

    if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
        for (range, provider) in &cdn_ranges {
            if is_ip_in_cidr(&ip_addr, range) {
                return Some((true, format!("is {}", provider)));
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

    let jrmp_request = b"JRMI\x00\x02\x4b";
    stream.write_all(jrmp_request).await?;
    stream.flush().await?;

    let mut buffer = vec![0; 256];
    let result = timeout(timeout_duration, stream.read(&mut buffer)).await;

    match result {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
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
    otherset: &OtherSets
) -> Result<(Vec<String>, Vec<String>), Box<dyn Error + Send + Sync>> {
    Print::infoprint(format!("Received {} IP addresses in total", ips.len()).as_str());

    let non_cdn_ips_initial = filter_cdn_ips(ips).await;
    let mut non_cdn_ips_initial: Vec<_> = non_cdn_ips_initial.into_iter()
        .filter(|ip| !ip.is_empty())
        .collect();

    if non_cdn_ips_initial.is_empty() {
        Print::infoprint("Non-CDN IP addresses not detected, API queries and port scans skipped");
        return Ok((Vec::new(), Vec::new()));
    }

    Print::infoprint(format!("{} non-CDN IPs initially screened out, starting Quake CDN check and then API queries and port scanning", non_cdn_ips_initial.len()).as_str());

    let ips_res = Arc::new(Mutex::new(InfoIPRes::new()));
    let links_res = Arc::new(Mutex::new(InfoLinkRes::new()));
    let semaphore = Arc::new(Semaphore::new(4));
    let open_ports_map = Arc::new(Mutex::new(Vec::<(String, Vec<u16>)>::new()));
    let fofa_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
    let shodan_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
    let zoomeye_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
    let yt_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
    let quake_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));

    // Quake CDN 判断
    Print::infoprint("Starting Quake API-based CDN check for initial non-CDN IPs");
    let quake_cdn_checker = Arc::new(QuakeIpCDN);
    let mut cdn_check_tasks = vec![];
    let quake_filtered_ips = Arc::new(Mutex::new(HashSet::new()));

    for ip in non_cdn_ips_initial.iter() {
        let permit = semaphore.clone();
        let checker = Arc::clone(&quake_cdn_checker);
        let client_clone = client.clone();
        let api_keys_clone = api_keys.clone();
        let ip_clone = ip.clone();
        let quake_filtered_ips_clone = Arc::clone(&quake_filtered_ips);

        let task = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            match checker.fetch_cdn_status(&ip_clone, api_keys_clone, &client_clone).await {
                Ok(cdn_num) => {
                    if cdn_num.cnd_num > QUAKE_CDN_THRESHOLD {
                        Print::passprint(format!("The ip {} may be CDN", ip_clone).as_str());
                    } else {
                        let mut filtered_ips = quake_filtered_ips_clone.lock().await;
                        filtered_ips.insert(ip_clone);
                    }
                },
                Err(e) => {
                    Print::errprint(format!("Quake CDN check failed for {}: {}", ip_clone, e).as_str());
                    let mut filtered_ips = quake_filtered_ips_clone.lock().await;
                    filtered_ips.insert(ip_clone);
                }
            }
        });
        cdn_check_tasks.push(task);
    }
    join_all(cdn_check_tasks).await;

    non_cdn_ips_initial = quake_filtered_ips.lock().await.iter().cloned().collect();
    non_cdn_ips_initial.sort();

    Print::bannerprint(format!("Quake CDN filtering completed: {} non-CDN IPs remain", non_cdn_ips_initial.len()).as_str());

    if non_cdn_ips_initial.is_empty() {
        Print::infoprint("All IPs identified as CDN or no valid IPs remain after Quake check. API queries and port scans skipped");
        return Ok((Vec::new(), Vec::new()));
    }

    // Fofa 查询
    Print::infoprint("Starting Fofa API-based port discovery");
    let fofa_fetcher = Arc::new(FofaIp);
    let mut api_tasks = vec![];
    let fofa_non_cdn_ips = Arc::new(Mutex::new(HashSet::<String, RandomState>::from_iter(non_cdn_ips_initial.clone())));

    for ip in non_cdn_ips_initial.iter() {
        let scan_port_max = otherset.scan_port_max.clone();
        let permit = semaphore.clone();
        let fetch = Arc::clone(&fofa_fetcher);
        let client_clone = client.clone();
        let api_keys_clone = api_keys.clone();
        let ips_res_clone = Arc::clone(&ips_res);
        let ip_clone = ip.clone();
        let port_counts = Arc::clone(&fofa_port_counts);
        let open_ports_map_clone = Arc::clone(&open_ports_map);
        let fofa_non_cdn_ips_clone = Arc::clone(&fofa_non_cdn_ips);

        let task = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            match fetch.fetch(&ip_clone, api_keys_clone, &client_clone, scan_port_max).await {
                Ok((res, is_cdn)) => {
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
                    port_counts.push((ip_clone.clone(), port_count));

                    if is_cdn {
                        let mut fofa_non_cdn_ips = fofa_non_cdn_ips_clone.lock().await;
                        fofa_non_cdn_ips.remove(&ip_clone);
                    }
                }
                Err(_e) => {
                    let mut fofa_non_cdn_ips = fofa_non_cdn_ips_clone.lock().await;
                    fofa_non_cdn_ips.insert(ip_clone);
                }
            }
        });
        api_tasks.push(task);
    }
    join_all(api_tasks).await;

    let port_counts = fofa_port_counts.lock().await;
    let total_ports: usize = port_counts.iter().map(|(_, count)| count).sum();
    let ip_count = port_counts.len();
    if ip_count > 0 {
        Print::infoprint(format!("Fofa queried {} IPs, found {} total ports", ip_count, total_ports).as_str());
    } else {
        Print::infoprint("Fofa queried no IPs or found no ports".to_string().as_str());
    }

    let filtered_non_cdn_ips_after_fofa: Vec<String> = fofa_non_cdn_ips.lock().await.iter().cloned().collect();
    Print::bannerprint(format!("After Fofa CDN filtering, {} non-CDN IPs remain", filtered_non_cdn_ips_after_fofa.len()).as_str());

    // YtIp 和 QuakeIp 查询
    Print::infoprint("Starting YtIp and QuakeIp API-based link and port discovery");
    let link_fetchers: Vec<(Arc<dyn InfoLinkIP + Send + Sync>, String, Arc<Mutex<Vec<(String, usize)>>>)> = vec![
        (Arc::new(YtIp), "YtIp".to_string(), yt_port_counts.clone()),
        (Arc::new(QuakeIp), "QuakeIp".to_string(), quake_port_counts.clone()),
    ];

    let mut link_api_tasks = vec![];
    for ip in filtered_non_cdn_ips_after_fofa.iter() {
        for (fetcher, fetcher_name, port_counts) in link_fetchers.iter().cloned() {
            let permit = semaphore.clone();
            let fetch = Arc::clone(&fetcher);
            let fetcher_name = fetcher_name.clone();
            let client_clone = client.clone();
            let api_keys_clone = api_keys.clone();
            let _ips_res_clone = Arc::clone(&ips_res);
            let links_res_clone = Arc::clone(&links_res);
            let ip_clone = ip.clone();
            let port_counts = Arc::clone(&port_counts);
            let open_ports_map_clone = Arc::clone(&open_ports_map);

            let task = tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                match fetch.fetch(&ip_clone, api_keys_clone, &client_clone).await {
                    Ok(res) => {
                        let mut links_res = links_res_clone.lock().await;
                        links_res.extend_links(res.rt_links());

                        // 处理端口信息
                        let ports = res.rt_ports(); // 直接使用 ports 字段
                        let mut ips_res = _ips_res_clone.lock().await;
                        ips_res.ips.extend(ports.clone());

                        let mut port_counts = port_counts.lock().await;
                        port_counts.push((ip_clone.clone(), res.links.len()));

                        let mut open_ports_map = open_ports_map_clone.lock().await;
                        let ports_u16: Vec<u16> = ports.iter().filter_map(|s| {
                            let parts: Vec<&str> = s.split(':').collect();
                            if parts.len() == 2 {
                                parts[1].parse::<u16>().map_err(|e| {
                                    Print::errprint(format!("Failed to parse port for {}: {}", s, e).as_str());
                                    None::<u16>
                                }).ok()
                            } else {
                                None::<u16>
                            }
                        }).collect();
                        open_ports_map.push((ip_clone.clone(), ports_u16));
                    }
                    Err(e) => {
                        Print::errprint(format!("{} query failed for {}: {}", fetcher_name, ip_clone, e).as_str());
                    }
                }
            });
            link_api_tasks.push(task);
        }
    }
    join_all(link_api_tasks).await;

    for (fetcher_name, port_counts) in &[("YtIp", yt_port_counts), ("QuakeIp", quake_port_counts)] {
        let port_counts = port_counts.lock().await;
        let total_links: usize = port_counts.iter().map(|(_, count)| count).sum();
        let ip_count = port_counts.len();
        if ip_count > 0 {
            Print::infoprint(format!("{} queried {} IPs, found {} total links", fetcher_name, ip_count, total_links).as_str());
        } else {
            Print::infoprint(format!("{} queried no IPs or found no links", fetcher_name).as_str());
        }
    }

    // Shodan 和 Zoomeye 查询
    Print::infoprint("Starting Shodan and Zoomeye API-based port discovery");
    let fetchers: Vec<(Arc<dyn InfoPort + Send + Sync>, &str, Arc<Mutex<Vec<(String, usize)>>>)> = vec![
        (Arc::new(ShodanIp), "Shodan", shodan_port_counts.clone()),
        (Arc::new(ZoomeyeIp), "Zoomeye", zoomeye_port_counts.clone()),
    ];

    let mut api_tasks = vec![];
    for ip in filtered_non_cdn_ips_after_fofa.iter() {
        for (fetcher, _fetcher_name, port_counts) in &fetchers {
            let scan_port_max = otherset.scan_port_max.clone();
            let permit = semaphore.clone();
            let fetch = Arc::clone(fetcher);
            let client_clone = client.clone();
            let api_keys_clone = api_keys.clone();
            let ips_res_clone = Arc::clone(&ips_res);
            let ip_clone = ip.clone();
            let port_counts = Arc::clone(port_counts);
            let open_ports_map_clone = Arc::clone(&open_ports_map);
            let task = tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                match fetch.fetch(&ip_clone, api_keys_clone, &client_clone, scan_port_max).await {
                    Ok((res, _)) => {
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

    for (fetcher_name, port_counts) in &[("Shodan", shodan_port_counts), ("Zoomeye", zoomeye_port_counts)] {
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

    // 端口扫描
    if filtered_non_cdn_ips_after_fofa.len() <= otherset.attack_port_number {
        Print::infoprint("Starting full port scan for non-CDN IPs");
        let ips_res_clone = Arc::clone(&ips_res);
        let open_ports_map_clone = Arc::clone(&open_ports_map);
        let total_ips = filtered_non_cdn_ips_after_fofa.len();

        for (index, ip_str) in filtered_non_cdn_ips_after_fofa.iter().enumerate() {
            Print::infoprint(format!("Scanning IP {}/{}: {}", index + 1, total_ips, ip_str).as_str());
            let ip = IpAddr::from_str(ip_str)?;
            let ip_clone_string = ip_str.clone();
            let ips_res_clone_local = Arc::clone(&ips_res_clone);
            let open_ports_map_clone_local = Arc::clone(&open_ports_map_clone);

            if ip.is_ipv6() {
                Print::passprint(format!("IP {} is IPv6, skipping full port scan", ip_str).as_str());
                continue;
            }

            match scan_ports(ip, otherset.port_random_min, otherset.port_random_max).await {
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
    let final_links = links_res.lock().await;
    let unique_links = final_links.res_links();

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

    let _ = realip_to_file(filename, &*filtered_non_cdn_ips_after_fofa);
    Ok((unique_ports, unique_links))
}