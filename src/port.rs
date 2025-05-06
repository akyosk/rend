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
use num_cpus;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::engine::Engine as _;
use reqwest::Client;
use serde_json::Value;
// use serde_json::json;
use reqwest::header::{HeaderMap, HeaderValue};
use crossbeam_channel::{bounded, Sender, Receiver};
use std::thread;
use std::io;
use std::collections::HashSet;
use crate::tofile::other_save_to_file;
use crate::outprint::Print;
#[derive(Clone)]
pub struct ApiKeys {
    pub fofa: String,
    pub yt: String,
    pub shodan: String,
    pub zoomeye: String,
    // pub quake: String,
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
struct YtIp;
// struct QuakeIp;
struct ZoomeyeIp;

// #[async_trait]
// impl InfoPort for QuakeIp {
//     async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
//         let url = "https://quake.360.net/api/v3/search/quake_service";
//         let mut headers = HeaderMap::new();
//         headers.insert("x-quaketoken", api_keys.quake.parse()?);
//         let query = json!({
//             "query": format!("ip: {}", ip), "start": 0, "size": 100,
//         });
//         let mut results = InfoPortRes::new();
//         let response = client.post(url).json(&query).headers(headers).send().await?;
//         if !response.status().is_success() {
//             return Ok(results);
//         }
//
//         let json_response = response.json::<Value>().await?;
//         if json_response.get("code").and_then(|code| code.as_u64()) != Some(0) {
//             Ok(results)
//         } else {
//             let empty_vec = vec![];
//             let data_array = json_response.get("data").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
//             data_array.iter().for_each(|data| {
//                 if let Some(port) = data.get("port") {
//                     if let Some(n) = port.as_u64() {
//                         results.push(format!("{}:{}", ip, n.to_string()));
//                     }
//                 }
//             });
//             if results.ports.len() > 100 {
//                 Print::passprint(format!("The ip {} may be CDN, excluding collection results", ip).as_str());
//                 results = InfoPortRes::new();
//             }
//             Ok(results)
//         }
//     }
// }
#[async_trait]
impl InfoPort for ZoomeyeIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let base64_str = STANDARD.encode(format!("ip=\"{}\" && after=\"2024-05-07\"", ip));
        let url = "https://api.zoomeye.ai/v2/search";
        let mut headers = HeaderMap::new();
        headers.insert(
            "api-key",
            api_keys.zoomeye.parse()?
        );
        let payload = serde_json::json!({
        "page": 1,
        "qbase64": base64_str,
        "pagesize":100,
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
        let ports: Vec<i64> = data.as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|item| item.get("port").and_then(|port| port.as_i64()))
            .collect();
        let unique_ports: Vec<i64> = ports.into_iter()
            .collect::<HashSet<i64>>()
            .into_iter()
            .collect();
        let mut unique_ports = unique_ports;
        unique_ports.sort();
        for port in unique_ports {
            results.push(format!("{}:{}", ip, port.to_string()));
        }
        if results.ports.len() > 100 {
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
        if results.ports.len() > 100 {
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
        let url = format!("https://fofa.info/api/v1/search/all?key={}&qbase64={}&size=100&full=true", api_keys.fofa, base64_str);
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
        if results.ports.len() > 100 {
            Print::passprint(format!("The ip {} may be CDN, excluding collection results", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok(results)
    }
}

#[async_trait]
impl InfoPort for YtIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let query = STANDARD.encode(format!("ip=\"{}\"", ip));
        let url = format!("https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page=1&page_size=100&is_web=3&start_time=2024-01-01&end_time=2025-12-28", api_keys.yt, query);
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", HeaderValue::from_static("127.0.0.1"));
        let response = client.get(&url).headers(headers).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok(results);
        }
        let json_response = response.json::<Value>().await?;
        if let Some(data) = json_response.get("data").and_then(|d| d.get("arr")).and_then(|d| d.as_array()) {
            data.iter().for_each(|data| {
                if let Some(port) = data.get("port") {
                    if let Some(n) = port.as_u64() {
                        results.push(format!("{}:{}", ip, n.to_string()));
                    }
                }
            });
        }
        if results.ports.len() > 100 {
            Print::passprint(format!("The ip {} may be CDN, excluding collection results", ip).as_str());
            results = InfoPortRes::new();
        }
        Ok(results)
    }
}


pub async fn portmain(
    ips: &Vec<String>,
    filename: &str,
    client: Client,
    api_keys: ApiKeys,

) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    Print::infoprint(format!("Received {} IP addresses in total", ips.len()).as_str());

    // 先进行CDN检测
    let non_cdn_ips = filter_cdn_ips(ips).await;

    if non_cdn_ips.is_empty() {
        Print::infoprint("Non-CDN IP addresses not detected, API queries and port scans skipped");
        return Ok(Vec::new());
    }

    Print::infoprint(format!("{} non-CDN IPs detected, starting API queries and port scanning", non_cdn_ips.len()).as_str());

    let ips_res = Arc::new(Mutex::new(InfoIPRes::new()));
    let semaphore = Arc::new(Semaphore::new(4));
    let open_ports_map = Arc::new(Mutex::new(Vec::<(String, Vec<u16>)>::new()));
    if non_cdn_ips.len() > 15 {
        // 用于统计每个API的端口数量
        let shodan_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
        let fofa_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
        let yt_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
        let zoomeye_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));
        // let quake_port_counts = Arc::new(Mutex::new(Vec::<(String, usize)>::new()));

        // 1. 通过API查找开放端口
        Print::infoprint("Starting API-based port discovery");
        let fetchers: Vec<(Arc<dyn InfoPort + Send + Sync>, &str, Arc<Mutex<Vec<(String, usize)>>>)> = vec![
            (Arc::new(FofaIp), "Fofa", fofa_port_counts.clone()),
            (Arc::new(YtIp), "Yt", yt_port_counts.clone()),
            (Arc::new(ShodanIp), "Shodan", shodan_port_counts.clone()),
            (Arc::new(ZoomeyeIp), "Zoomeye", zoomeye_port_counts.clone()),
            // (Arc::new(QuakeIp), "Quake", quake_port_counts.clone()),
        ];

        let mut api_tasks = vec![];
        for ip in non_cdn_ips.iter() {
            for (fetcher, _fetcher_name, port_counts) in &fetchers {
                let permit = semaphore.clone();
                let fetch = Arc::clone(fetcher);
                let client = client.clone();
                let api_keys = api_keys.clone();
                let ips_res = Arc::clone(&ips_res);
                let ip = ip.clone();
                let port_counts = Arc::clone(port_counts);

                let task = tokio::spawn(async move {
                    let _permit = permit.acquire().await.unwrap();
                    match fetch.fetch(&ip, api_keys, &client).await {
                        Ok(res) => {
                            let port_count = res.ports.len();
                            let mut ips_res = ips_res.lock().await;
                            ips_res.ips.extend(res.rt());
                            let mut port_counts = port_counts.lock().await;
                            port_counts.push((ip.clone(), port_count));
                        }
                        Err(_e) => {}
                    }
                });
                api_tasks.push(task);
            }
        }
        join_all(api_tasks).await;

        // 输出每个API的端口统计
        // for (fetcher_name, port_counts) in &[("Shodan", shodan_port_counts), ("Fofa", fofa_port_counts), ("Yt", yt_port_counts), ("Quake", quake_port_counts)] {
        for (fetcher_name, port_counts) in &[("Shodan", shodan_port_counts), ("Fofa", fofa_port_counts), ("Yt", yt_port_counts),("Zoomeye", zoomeye_port_counts)] {
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
    } else {
        // 2. 如果非CDN IP数量不超过100，进行全端口扫描

        Print::infoprint("Non-CDN IPs <= 20, starting full port scan");
        let mut scan_tasks = vec![];
        for ip in non_cdn_ips.iter() {
            let ip = ip.clone();
            let open_ports_map = Arc::clone(&open_ports_map);
            let ips_res = Arc::clone(&ips_res);
            let task = tokio::spawn(async move {
                match scan_all_ports(&ip).await {
                    Ok(ports) => {
                        let mut open_ports_map = open_ports_map.lock().await;
                        open_ports_map.push((ip.clone(), ports.clone()));
                        let mut ips_res = ips_res.lock().await;
                        for port in ports {
                            ips_res.ips.push(format!("{}:{}", ip, port));
                        }
                    }
                    Err(_e) => {
                        // println!("Error scanning {}: {}", ip, e);
                    }
                }
            });
            scan_tasks.push(task);
        }
        join_all(scan_tasks).await;
        Print::infoprint("Full port scan completed");

    }



    // 3. 对结果去重并进行banner检查
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
                let filename = filename.to_string();
                let task = task::spawn(async move {
                    let _ = identify_service(ip_addr, port, Duration::from_secs(3), &filename).await;
                });
                banner_tasks.push(task);
            }
        }

        join_all(banner_tasks).await;
        Print::infoprint("Port banner identification completed");
    }

    Ok(unique_ports)
}

async fn filter_cdn_ips(ips: &Vec<String>) -> Vec<String> {
    let semaphore = Arc::new(Semaphore::new(10));
    let non_cdn_ips = Arc::new(Mutex::new(Vec::new()));

    Print::infoprint(format!("Checking whether {} IPs are CDNs", ips.len()).as_str());

    let mut tasks = vec![];
    for ip in ips {
        let permit = semaphore.clone();
        let ip = ip.clone();
        let non_cdn_ips = Arc::clone(&non_cdn_ips);

        let task = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            let clean_ip = if ip.contains(":") {
                ip.split(":").next().unwrap_or(&ip).to_string()
            } else {
                ip.clone()
            };

            match is_cdn_ip(&clean_ip).await {
                (false, _) => {
                    let mut ips = non_cdn_ips.lock().await;
                    ips.push(ip);
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

async fn scan_all_ports(ip: &str) -> io::Result<Vec<u16>> {
    let target_ip: IpAddr = ip.parse().expect("Invalid IP address");
    let max_concurrent_scans = 200; // 最大并发连接数
    let ports: Vec<u16> = (1..=65535).collect();
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let num_cores = num_cpus::get().max(1);
    let semaphore = Arc::new(Semaphore::new(max_concurrent_scans)); // 在函数顶部定义

    Print::infoprint(format!("Start scanning {}, port range 1-65535, using {} processes", target_ip, num_cores).as_str());

    let (tx, rx): (Sender<u16>, Receiver<u16>) = bounded(1000);

    let chunk_size = (ports.len() / num_cores).max(1);
    let port_chunks: Vec<Vec<u16>> = ports
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    let mut handles = vec![];
    for chunk in port_chunks {
        let tx = tx.clone();
        let open_ports = Arc::clone(&open_ports);
        let semaphore = Arc::clone(&semaphore); // 克隆信号量
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let sub_chunk_size = (chunk.len() / max_concurrent_scans).max(1);
                let sub_chunks: Vec<Vec<u16>> = chunk
                    .chunks(sub_chunk_size)
                    .map(|sub_chunk| sub_chunk.to_vec())
                    .collect();

                let mut task_handles = vec![];

                for sub_chunk in sub_chunks {
                    let open_ports = Arc::clone(&open_ports);
                    let tx = tx.clone();
                    let semaphore = Arc::clone(&semaphore); // 再次克隆到异步任务
                    let task = tokio::spawn(async move {
                        for port in sub_chunk {
                            let _permit = semaphore.acquire().await.unwrap(); // 获取信号量许可
                            if scan_port(target_ip, port).await {
                                let mut ports = open_ports.lock().await;
                                if ports.len() >= 200 {
                                    return;
                                }
                                ports.push(port);
                                tx.send(port).unwrap();
                            }
                        }
                    });
                    task_handles.push(task);
                }

                for task in task_handles {
                    task.await.unwrap();
                }
            });
        });
        handles.push(handle);
    }

    drop(tx);

    let mut received_ports = vec![];
    while let Ok(port) = rx.recv() {
        received_ports.push(port);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let ports = open_ports.lock().await;
    if ports.len() >= 200 {
        Print::infoprint(format!("IP {} excluded due to excessive open ports (CDN)", target_ip).as_str());
        return Ok(vec![]);
    }

    Ok(ports.clone())
}

// 扫描单个端口
async fn scan_port(ip: IpAddr, port: u16) -> bool {
    let address = format!("{}:{}", ip, port);
    let duration = Duration::from_millis(500); // 超时时间 500ms

    match timeout(duration, tokio::net::TcpStream::connect(&address)).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) => false,
        Err(_) => false,
    }
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
