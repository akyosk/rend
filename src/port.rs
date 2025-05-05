use std::error::Error;
use std::sync::Arc;
use futures::future::join_all;
use tokio::sync::{Mutex, Semaphore};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use futures::stream::{self, StreamExt};
use tokio::task;
use num_cpus;
use crate::outprint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::tofile::other_save_to_file;

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
    fn extend(&mut self, ports: Vec<String>) {
        self.ports.extend(ports);
    }
    fn res(&self) -> Vec<String> {
        let mut ports = self.ports.clone();
        ports.sort();
        ports.dedup();
        ports
    }
}

pub async fn portmain(
    ips: &Vec<String>,
    filename:&str

) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let str_ip = format!("Received {} IP addresses in total", ips.len());
    outprint::Print::infoprint(str_ip.as_str());

    // 先进行CDN检测
    let non_cdn_ips = filter_cdn_ips(ips).await;

    if non_cdn_ips.is_empty() {
        outprint::Print::infoprint("Non-CDN IP addresses not detected, API queries and port scans skipped");
        return Ok(Vec::new());
    }

    outprint::Print::infoprint(
        format!(
            "{} non-CDN IPs detected, further IP CDN detection and port scanning started",
            non_cdn_ips.len()
        )
            .as_str(),
    );
    outprint::Print::infoprint("Scan multiple IP full ports, please wait patiently...");
    let ips_res = Arc::new(Mutex::new(InfoIPRes::new()));
    let semaphore = Arc::new(Semaphore::new(3));
    let mut tasks = vec![];
    // 只对非CDN IP进行端口扫描
    for ip in non_cdn_ips.iter() {
        let permit = semaphore.clone();
        let ips_res = Arc::clone(&ips_res);
        let ip = ip.clone();
        let filename = filename.to_string();

        let task = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            match scan_ip_ports(&ip, Duration::from_millis(5000),filename).await {
                Ok(ports) => {
                    let mut ips_res = ips_res.lock().await;
                    // 将扫描结果转换为 ip:port 格式
                    let formatted_ports: Vec<String> = ports
                        .into_iter()
                        .map(|port| format!("{}:{}", ip, port))
                        .collect();
                    ips_res.ips.extend(formatted_ports);
                }
                Err(_e) => {
                    // outprint::Print::errprint(
                    //     format!("扫描IP {} 失败: {}", ip, e).as_str(),
                    // );
                }
            }
        });
        tasks.push(task);
    }
    join_all(tasks).await;
    let final_res = ips_res.lock().await;
    Ok(final_res.ips.res())
}

async fn filter_cdn_ips(ips: &Vec<String>) -> Vec<String> {
    let semaphore = Arc::new(Semaphore::new(10)); // 限制并发请求数
    let non_cdn_ips = Arc::new(Mutex::new(Vec::new()));

    outprint::Print::infoprint(format!("Start checking whether {} IPs are CDNs", ips.len()).as_str());

    let mut tasks = vec![];

    for ip in ips {
        let permit = semaphore.clone();
        let ip = ip.clone();
        let non_cdn_ips = Arc::clone(&non_cdn_ips);

        let task = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();

            // 去掉IP中可能含有的端口号
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
                    outprint::Print::passprint(
                        format!("Skip CDN IP {}: {}", clean_ip, reason).as_str(),
                    );
                }
            }
        });

        tasks.push(task);
    }

    join_all(tasks).await;

    let result = non_cdn_ips.lock().await.clone();
    outprint::Print::infoprint(
        format!(
            "CDN detection completed: {} IPs in total, {} non-CDN IPs initially screened out",
            ips.len(),
            result.len()
        )
            .as_str(),
    );

    result
}

// 判断IP是否为CDN
async fn is_cdn_ip(ip: &str) -> (bool, String) {
    // 方法: 检查本地已知的CDN CIDR列表
    match check_known_cdn_ranges(ip) {
        Some((is_cdn, reason)) if is_cdn => return (true, reason),
        _ => {}
    }
    // 默认认为不是CDN
    (false, String::new())
}

// 检查IP是否在已知的CDN IP范围内
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

// 检查IP是否在CIDR范围内
fn is_ip_in_cidr(ip: &std::net::IpAddr, cidr: &str) -> bool {
    if let Ok(network) = cidr.parse::<ipnet::IpNet>() {
        return network.contains(ip);
    }
    false
}

// 端口扫描函数
async fn scan_ip_ports(ip: &str, timeout_duration: Duration, filename: String) -> Result<Vec<u16>, Box<dyn Error + Send + Sync>> {
    let ip_addr = IpAddr::from_str(ip)?;
    let ports: Vec<u16> = (1..=65535).collect();
    let concurrency = 500;
    let num_threads = num_cpus::get().max(4);
    let max_open_ports = 100; // 最大开放端口数阈值

    let chunk_size = (ports.len() + num_threads - 1) / num_threads;
    let port_chunks: Vec<Vec<u16>> = ports
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    let mut open_ports = Vec::new();
    let open_ports_counter = Arc::new(Mutex::new(0));

    let tasks: Vec<_> = port_chunks
        .into_iter()
        .map(|chunk| {
            let open_ports_counter = Arc::clone(&open_ports_counter);
            task::spawn(async move {
                let mut results = Vec::new();
                let sub_chunks: Vec<Vec<u16>> = chunk
                    .chunks(concurrency)
                    .map(|sub_chunk| sub_chunk.to_vec())
                    .collect();

                for sub_chunk in sub_chunks {
                    let sub_results = stream::iter(sub_chunk.into_iter())
                        .map(|port| scan_port(ip_addr, port, timeout_duration))
                        .buffer_unordered(concurrency)
                        .collect::<Vec<_>>()
                        .await;

                    let mut counter = open_ports_counter.lock().await;
                    for (port, is_open) in sub_results {
                        if is_open {
                            *counter += 1;
                            if *counter > max_open_ports {
                                return Err(Box::new(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!("IP {} Mark as CDN", ip_addr),
                                )) as Box<dyn Error + Send + Sync>);
                            }
                            results.push(port);
                        }
                    }
                }
                Ok(results)
            })
        })
        .collect();

    for task in tasks {
        match task.await? {
            Ok(ports) => {
                open_ports.extend(ports);
            }
            Err(e) => {
                outprint::Print::errprint(e.to_string().as_str());
                return Ok(Vec::new()); // 返回空结果，不记录该IP的端口
            }
        }
    }
    // outprint::Print::infoprint("Port scan completed");
    // 对开放端口进行 banner 识别，使用多核并发
    if !open_ports.is_empty() {
        // outprint::Print::infoprint("Start partial banner identification of ports");
        let banner_concurrency = 300; // 控制 banner 扫描的并发数
        let num_threads = num_cpus::get().max(4);
        let chunk_size = (open_ports.len() + num_threads - 1) / num_threads;
        let port_chunks: Vec<Vec<u16>> = open_ports
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        let banner_tasks: Vec<_> = port_chunks
            .into_iter()
            .map(|chunk| {
                let filename = filename.clone();
                task::spawn(async move {
                    let sub_chunks: Vec<Vec<u16>> = chunk
                        .chunks(banner_concurrency)
                        .map(|sub_chunk| sub_chunk.to_vec())
                        .collect();

                    for sub_chunk in sub_chunks {
                        let sub_tasks = stream::iter(sub_chunk.into_iter())
                            .map(|port| identify_service(ip_addr, port, timeout_duration, &filename))
                            .buffer_unordered(banner_concurrency)
                            .collect::<Vec<_>>()
                            .await;

                        for result in sub_tasks {
                            if let Err(_e) = result {

                            }
                        }
                    }
                })
            })
            .collect();

        join_all(banner_tasks).await;
        // outprint::Print::infoprint("Port banner identification ends");
    }

    Ok(open_ports)
}

// 服务 banner 识别函数
async fn identify_service(ip: IpAddr, port: u16, timeout_duration: Duration, filename: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    // 跳过特定端口的 banner 扫描
    let skip_ports = [22, 21, 153, 445, 3306, 1521,5432,1433,6379,27017,9200, 53, 23];
    if skip_ports.contains(&port) {
        return Ok(());
    }

    let socket_addr = SocketAddr::new(ip, port);

    // 尝试 JDWP 识别
    if let Ok(is_jdwp) = check_jdwp(socket_addr, timeout_duration).await {
        if is_jdwp {
            outprint::Print::vulnportprint(
                format!("IP {}:{} Jdwp service detected", ip, port).as_str(),
            );
            let _ = other_save_to_file(&filename,format!("IP {}:{} Jdwp service detected", ip, port).as_str());
            return Ok(());
        }
    }

    // 尝试 ActiveMQ 识别
    if let Ok(is_activemq) = check_activemq(socket_addr, timeout_duration).await {
        if is_activemq {
            outprint::Print::vulnportprint(
                format!("IP {}:{} ActiveMQ service detected", ip, port).as_str(),
            );
            let _ = other_save_to_file(&filename,format!("IP {}:{} Jdwp service detected", ip, port).as_str());
            return Ok(());
        }
    }

    Ok(())
}

// 检查 JDWP 服务
async fn check_jdwp(socket_addr: SocketAddr, timeout_duration: Duration) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let stream = timeout(timeout_duration, TcpStream::connect(socket_addr)).await??;
    let mut stream = stream;
    // 发送 JDWP 握手字符串
    stream.write_all(b"JDWP-Handshake").await?;
    stream.flush().await?;

    // 读取响应
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

// 检查 ActiveMQ 服务
async fn check_activemq(socket_addr: SocketAddr, timeout_duration: Duration) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let stream = timeout(timeout_duration, TcpStream::connect(socket_addr)).await??;
    let mut stream = stream;

    // 发送简单的 OpenWire 协议帧（版本查询）
    let openwire_frame = b"\x00\x00\x00\x0f\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    stream.write_all(openwire_frame).await?;
    stream.flush().await?;

    // 读取响应
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

async fn scan_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> (u16, bool) {
    let socket_addr = SocketAddr::new(ip, port);
    let is_open = check_connection(socket_addr, timeout_duration).await;
    (port, is_open)
}

async fn check_connection(socket_addr: SocketAddr, timeout_duration: Duration) -> bool {
    timeout(timeout_duration, TcpStream::connect(socket_addr))
        .await
        .map(|stream| stream.is_ok() && stream.unwrap().local_addr().is_ok())
        .unwrap_or(false)
}