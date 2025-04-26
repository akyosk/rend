use std::error::Error;
use std::sync::Arc;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use futures::future::join_all;
use reqwest::Client;
use tokio::sync::{Mutex, Semaphore};
use serde_json::Value;
use crate::outprint;
use serde_json::json;
use reqwest::header::HeaderMap;
use base64::engine::Engine as _;
// use scraper::{Html, Selector};

struct InfoIPRes{
    ips: InfoPortRes
}

impl InfoIPRes{
    fn new() -> InfoIPRes{
        InfoIPRes{ips: InfoPortRes::new()}
    }
}

#[derive(Clone)]
pub struct ApiKeys{
    pub fofa:String,
    pub yt:String,
    pub shodan:String,
    pub quake:String,
}

struct InfoPortRes{
    ports: Vec<String>,
}

impl InfoPortRes{
    fn new() -> InfoPortRes{
        InfoPortRes{ports: Vec::new()}
    }
    fn push(&mut self, ports: String){
        self.ports.push(ports);
    }
    fn rt(&self) -> Vec<String>{
        self.ports.clone()
    }
    fn extend(&mut self, ports: Vec<String>){
        self.ports.extend(ports);
    }
    fn res(&self) -> Vec<String>{
        let mut ports = self.ports.clone();
        ports.sort();
        ports.dedup();
        ports
    }
}

#[async_trait]
trait InfoPort{
    async fn fetch(&self,ip:&str,api_keys:ApiKeys,client: &Client) -> Result<InfoPortRes,Box<dyn Error + Send + Sync>>;
}

struct ShodanIp;
struct FofaIp;
struct QuakeIp;
struct YtIp;

#[async_trait]
impl InfoPort for ShodanIp{
    async fn fetch(&self,ip:&str,api_keys:ApiKeys,client: &Client) -> Result<InfoPortRes,Box<dyn Error + Send + Sync>>{
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}",ip,api_keys.shodan);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success(){
            // outprint::Print::errprint(format!("Shodan error status code: {}", response.status()).as_str());
            return Ok(results)
        };
        let json_response = response.json::<Value>().await?;
        if let Some(ports) = json_response.get("ports").and_then(|p| p.as_array()){
            ports.into_iter().for_each(|port|{
                results.push(format!("{}:{}",ip,port))
            })
        }
        if results.ports.len() > 100 {
            outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
        }

        Ok(results)
    }
}

#[async_trait]
impl InfoPort for FofaIp{
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let base64_str = STANDARD.encode(format!("ip={}", ip));
        let url = format!("https://fofa.info/api/v1/search/all?key={}&qbase64={}&size=100&full=true", api_keys.fofa,base64_str);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok(results)
        }
        let json_response = response.json::<Value>().await?;
        let empty_vec = vec![];

        let data_array = json_response.get("results").and_then(|data| data.as_array()).unwrap_or(&empty_vec);

        data_array.iter().for_each(|data| {
            if let Some(ports) = data.get(2){
                if let Some(p) = ports.as_str() {
                    results.push(format!("{}:{}",ip,p))
                }
            }
        });
        if results.ports.len() > 100 {
            outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
        }

        Ok(results)
    }
}

#[async_trait]
impl InfoPort for QuakeIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let url = "https://quake.360.net/api/v3/search/quake_service";
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-quaketoken",
            api_keys.quake.parse()?,
        );
        let query = json!({
            "query": format!("ip: {}", ip), "start": 0, "size": 100,
        });
        let mut results = InfoPortRes::new();
        let response = client.post(url).json(&query).headers(headers).send().await?;
        if !response.status().is_success() {
            return Ok(results)
        }
        let json_response = response.json::<Value>().await?;
        if json_response.get("code").and_then(|code| code.as_u64()) != Some(0) {
            Ok(results)
        }else {
            let empty_vec = vec![];
            let data_array = json_response.get("data").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
            data_array.iter().for_each(|data| {
                if let Some(port) = data.get("port").and_then(|p| p.as_str()) {
                    results.push(format!("{}:{}",ip,port))
                }
            });
            if results.ports.len() > 100 {
                outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
            }

            Ok(results)
        }
    }
}

#[async_trait]
impl InfoPort for YtIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let query = STANDARD.encode(format!("ip=\"{}\"", ip));
        let url = format!("https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page=1&page_size=100&is_web=3&start_time=2024-01-01&end_time=2025-12-28",api_keys.yt,query);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            return Ok(results)
        }
        let json_response = response.json::<Value>().await?;
        if let Some(data) = json_response.get("data").and_then(|d| d.get("arr")).and_then(|d| d.as_array()) {
            data.iter().for_each(|data| {
                if let Some(port) = data.get("port").and_then(|o| o.as_str()) {
                    results.push(format!("{}:{}",ip,port))
                }
            });
        }
        if results.ports.len() > 50 {
            outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
        }

        Ok(results)
    }
}

pub async fn portmain(ips: &Vec<String>, client: Client, api_keys: ApiKeys) -> Result<Vec<String>, Box<dyn Error>> {
    let str_ip = format!("A total of {} IP addresses were received", ips.len());
    outprint::Print::infoprint(str_ip.as_str());

    // 先进行CDN检测
    let non_cdn_ips = filter_cdn_ips(ips, client.clone()).await;

    if non_cdn_ips.is_empty() {
        outprint::Print::infoprint("No non-CDN IP address detected, skipping API query");
        return Ok(Vec::new());
    }

    outprint::Print::infoprint(format!("{} non-CDN IPs detected, IP-PORT detection started", non_cdn_ips.len()).as_str());

    let fetchers: Vec<Arc<dyn InfoPort + Send + Sync>> = vec![
        Arc::new(FofaIp),
        Arc::new(QuakeIp),
        Arc::new(YtIp),
        Arc::new(ShodanIp),
    ];

    let ips_res = Arc::new(Mutex::new(InfoIPRes::new()));
    let semaphore = Arc::new(Semaphore::new(3));
    let mut tasks = vec![];

    // 只对非欺诈IP进行API查询
    for ip in non_cdn_ips.iter() {
        for fetcher in &fetchers {
            let premit = semaphore.clone();
            let fetch = Arc::clone(&fetcher);
            let client = client.clone();
            let api_keys = api_keys.clone();
            let ips_res = Arc::clone(&ips_res);
            let ip = ip.clone();
            let task = tokio::spawn(async move {
                let _permit = premit.acquire().await.unwrap();
                match fetch.fetch(&ip, api_keys, &client).await {
                    Ok(res) => {
                        let mut ips_res = ips_res.lock().await;
                        ips_res.ips.extend(res.rt());
                    }
                    _ => {}
                }
            });
            tasks.push(task);
        }
    }
    join_all(tasks).await;
    let final_res = ips_res.lock().await;
    Ok(final_res.ips.res())
}

async fn filter_cdn_ips(ips: &Vec<String>, client: Client) -> Vec<String> {
    let semaphore = Arc::new(Semaphore::new(10)); // 限制并发请求数
    let non_cdn_ips = Arc::new(Mutex::new(Vec::new()));

    outprint::Print::infoprint(format!("Start detecting whether {} IPs are CDNs...", ips.len()).as_str());

    let mut tasks = vec![];

    for ip in ips {
        let permit = semaphore.clone();
        let client = client.clone();
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

            match is_cdn_ip(&clean_ip, &client).await {
                (false, _) => {
                    let mut ips = non_cdn_ips.lock().await;
                    ips.push(ip);
                }
                (true, reason) => {
                    outprint::Print::errprint(format!("Skip CDN IP {}: {}", clean_ip, reason).as_str());
                }
            }
        });

        tasks.push(task);
    }

    join_all(tasks).await;

    let result = non_cdn_ips.lock().await.clone();
    outprint::Print::infoprint(format!("CDN detection completed: {} IPs in total, {} non-CDN IPs filtered out", ips.len(), result.len()).as_str());

    result
}

// 判断IP是否为CDN
async fn is_cdn_ip(ip: &str, client: &Client) -> (bool, String) {
    // 方法1: 使用ipinfo.io API检查ASN信息
    match check_ip_info(ip, client).await {
        Some((is_cdn, reason)) if is_cdn => return (true, reason),
        _ => {}
    }

    // // 方法2: 检查反向DNS记录是否含有CDN关键词
    // match check_reverse_dns(ip).await {
    //     Some((is_cdn, reason)) if is_cdn => return (true, reason),
    //     _ => {}
    // }

    // 方法3: 检查本地已知的CDN CIDR列表
    match check_known_cdn_ranges(ip) {
        Some((is_cdn, reason)) if is_cdn => return (true, reason),
        _ => {}
    }

    // 方法4: 检查IP138网站上关联的域名数量
    // match check_ip138_domains(ip, client).await {
    //     Some((is_cdn, reason)) if is_cdn => return (true, reason),
    //     _ => {}
    // }

    // 默认认为不是CDN
    (false, String::new())
}

// 通过ipinfo.io检查ASN信息
async fn check_ip_info(ip: &str, client: &Client) -> Option<(bool, String)> {
    // CDN公司的域名关键字列表
    let cdn_keywords = [
        "cdn",  "cloudflare","cloudfront",
        "cdnetworks", "limelight", "edgecast", "maxcdn",
        // 阿里云CDN相关关键字
        "alicdn"
    ];

    // 查询ipinfo.io
    let url = format!("https://ipinfo.io/{}/json", ip);

    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(data) = response.json::<serde_json::Value>().await {
                // 检查ASN
                if let Some(org) = data.get("org").and_then(|o| o.as_str()) {
                    // 检查组织名称中是否含有CDN关键词
                    for keyword in &cdn_keywords {
                        if org.to_lowercase().contains(keyword) {
                            return Some((true, format!("Organization name match: {}", org)));
                        }
                    }
                }

                // 检查主机名
                if let Some(hostname) = data.get("hostname").and_then(|h| h.as_str()) {
                    for keyword in &cdn_keywords {
                        if hostname.to_lowercase().contains(keyword) {
                            return Some((true, format!("Hostname match: {}", hostname)));
                        }
                    }
                }
            }
        }
        _ => {}
    }

    None
}


// 检查IP是否在已知的CDN IP范围内
fn check_known_cdn_ranges(ip: &str) -> Option<(bool, String)> {
    // 这里可以添加常见CDN提供商的IP段列表
    // 为简化示例，只列出几个示例IP段
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
                return Some((true, format!("The IP is in the network segment of {}", provider)));
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

// 新增: 检查IP138网站上关联的域名数量
// async fn check_ip138_domains(ip: &str, client: &Client) -> Option<(bool, String)> {
//     // 添加1秒延迟
//     tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
//
//     let url = format!("https://site.ip138.com/{}/", ip);
//
//     // 设置请求头
//     let mut headers = HeaderMap::new();
//     headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"));
//
//     // 发送请求
//     let response = match client.get(&url).headers(headers).send().await {
//         Ok(resp) => resp,
//         Err(_) => return None,
//     };
//
//     if !response.status().is_success() {
//         return None;
//     }
//
//     // 获取HTML内容
//     let html_content = match response.text().await {
//         Ok(text) => text,
//         Err(_) => return None,
//     };
//
//     // 解析HTML
//     let document = Html::parse_document(&html_content);
//
//     // 创建选择器
//     let li_selector = match Selector::parse("li") {
//         Ok(selector) => selector,
//         Err(_) => return None,
//     };
//
//     let date_span_selector = match Selector::parse("span.date") {
//         Ok(selector) => selector,
//         Err(_) => return None,
//     };
//
//     let a_selector = match Selector::parse("a") {
//         Ok(selector) => selector,
//         Err(_) => return None,
//     };
//
//     // 使用HashSet来存储不同的二级域名
//     use std::collections::HashSet;
//     let mut second_level_domains = HashSet::new();
//     let mut all_domains = Vec::new(); // 用于调试和记录
//
//     for li in document.select(&li_selector) {
//         // 确认li标签中有span.date元素
//         if li.select(&date_span_selector).next().is_some() {
//             // 查找a标签
//             if let Some(a_tag) = li.select(&a_selector).next() {
//                 if let Some(domain_text) = a_tag.text().next() {
//                     // 保存所有域名以便调试
//                     all_domains.push(domain_text.to_string());
//
//                     // 直接基于点号分割提取二级域名
//                     let parts: Vec<&str> = domain_text.split('.').collect();
//                     if parts.len() >= 2 {
//                         // 如果有两个或更多部分，取倒数第二个部分作为二级域名
//                         let second_level_domain = parts[parts.len() - 2].to_string();
//                         second_level_domains.insert(second_level_domain);
//                     }
//                 }
//             }
//         }
//     }
//
//     // 如果不同二级域名数量超过阈值，判定为CDN
//     let domain_count = second_level_domains.len();
//     if domain_count >= 20 {
//         return Some((true, format!("Found {} different second-level domain names associated with this IP", domain_count)));
//     }
//
//     None
// }