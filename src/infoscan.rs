use crate::outprint;
use crate::tofile;
use crate::cmsck;
use crate::port;
use crate::subdomain;
use async_trait::async_trait;
use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue,ACCEPT, ACCEPT_LANGUAGE, CACHE_CONTROL, CONNECTION, HOST, REFERER, USER_AGENT}};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{error::Error, fs, time::Duration};
use std::collections::HashMap;
use base64;
use toml;
use std::sync::Arc;
use tokio::sync::Mutex;
use regex::Regex;
use tokio::time::{sleep, Duration as TokioDuration};
use scraper::{Html, Selector};
use chrono::Local;
use futures::future::join_all;
use tokio::sync::Semaphore;
// 在文件顶部添加以下引入
use base64::engine::Engine as _;
use base64::engine::general_purpose::STANDARD;
use crate::icpscan::icpmain;

#[async_trait]
trait InfoFetcher{
    async fn fetch(&self,domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>>;
}
#[async_trait]
trait Displayinfo{
    async fn display(&mut self,domian:&str,threads: usize,client: Client,api_keys: ApiKeys,otherset:OtherSets);
}

#[allow(dead_code)]
#[derive(Debug, Deserialize,Clone)]
pub struct OtherSets {
    pub(crate) keywords: Vec<String>,
    pub(crate) excluded_extensions: Vec<String>,
    pub(crate) excluded_patterns: Vec<String>,
    pub(crate) pass_domain: Vec<String>,
    pub(crate) port_random_max: u16,
    pub(crate) port_random_min: u16,
    pub(crate) attack_port_number: usize,
    pub(crate) scan_port_max: u64,
}
#[derive(Debug, Deserialize)]
pub struct Config {
    api_keys: ApiKeys,
}

#[derive(Debug, Deserialize,Clone)]
pub struct ApiKeys {
    fofa_key: String,
    pub(crate) quake_key: String,
    zoomeye_key: String,
    daydaymap_key: String,
    shodan_key: String,
    securitytrails_key: String,
    hunter_key: String,
    pub(crate) yt_key: String,
    virustotal_key: String,
    viewdns_key: String,
    binaryedge_key: String,
    fullhunt_key: String,
    whoisxmlapi_key: String,
    dnsdump_key: String,
    bevigil_key:String,
    robtex_key:String,
    pub(crate) zone_key:String,
}
impl Config {
    pub fn from_default() -> Result<Self, Box<dyn Error>> {
        let content = include_str!("../config/api.toml"); // 默认嵌入配置
        let config: Config = toml::from_str(content)?;
        Ok(config)
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let content = fs::read_to_string(path)?; // 从指定路径读取配置文件
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}

struct InfoQuake;
struct InfoHunter;
struct InfoFofa;
struct InfoZoomeye;
struct InfoDaydaymap;
struct InfoSecuritytrails;
struct InfoShodan;
struct InfoYT;
struct InfoVirustotal;
struct InfoViewDNS;
struct InfoBinaryedge;
struct InfoFullhunt;
struct InfoWhoisxml;
struct InfoDnsdump;
struct InfoCrt;
struct InfoChaziyu;
struct InfoJldc;
struct InfoSitedossier;
struct InfoRapiddns;
struct InfoCertspotter;
struct InfoHackertarget;
struct InfoArchive;
struct InfoDnshistory;
struct InfoNetlas;
struct InfoC99NL;
struct InfoAlienvault;
struct InfoDnsarchive;
// struct InfoIP138;
struct InfoThreatcrowd;
struct InfoUrlscan;
struct InfoBevigil;
struct InfoDnsgrep;
struct InfoMyssl;
struct InfoRobtex;
struct InfoZone;
struct InfoResults{
    domain_list: Vec<String>,
    ip_list: Vec<String>,
    icp_list: Vec<String>,
    cdn_list: Vec<String>,
}

#[async_trait]
impl Displayinfo for InfoResults {
    async fn display(&mut self, domian:&str, threads: usize, client: Client, api_keys: ApiKeys, otherset:OtherSets) {
        let filename = format!("{}.txt",domian.replace('.', "_"));
        let mut cdns = self.cdn_list.clone();
        cdns.retain(|x| !x.is_empty());
        cdns.sort();
        cdns.dedup();

        let mut icps = self.icp_list.clone();
        // println!("{}",icps.len());
        if !icps.is_empty() {
            icps.retain(|x| !x.is_empty());
            icps.sort();
            icps.dedup();
            // println!("{:?}",icps);
            outprint::Print::infoprint(format!("Found {} ICP information", icps.len()).as_str());
            outprint::Print::infoprint("Start tracing ICP information");

            match icpmain(&icps, api_keys.clone()).await {
                Ok((ips, hostnames)) => {
                    self.domain_list.extend(hostnames);
                    self.ip_list.extend(ips);
                    let _ = tofile::icp_save_to_file(&filename, &icps).map_err(|e| {
                        outprint::Print::errprint(format!("Failed to save ICPs to file: {}", e).as_str());
                        e
                    });
                    outprint::Print::bannerprint(format!("ICP results saved to {}",&filename).as_str())
                }
                Err(_e) => {
                    // outprint::Print::errprint(format!("icpmain failed: {}", e).as_str());
                }
            }
        }
        outprint::Print::infoprint("Start organizing data");

        let mut domain_list = self.domain_list.clone();
        let mut ip_list = self.ip_list.clone();
        let mut ip_port_list = vec![];
        ip_list.retain(|x| !x.is_empty());
        ip_list.sort();
        ip_list.dedup();
        if !cdns.is_empty() {
            outprint::Print::infoprint("Start preliminary CDN filtering through CDN and fraudulent IP lists");
            ip_list.retain(|x| !cdns.contains(x));
            outprint::Print::bannerprint(format!("Successfully filtered out {} CDNs and fraudulent IPs", &cdns.len()).as_str());
        }

        let apis = port::ApiKeys{
            fofa:api_keys.fofa_key,
            quake:api_keys.quake_key,
            yt:api_keys.yt_key,
            shodan:api_keys.shodan_key,
            zoomeye:api_keys.zoomeye_key,
        };
        outprint::Print::infoprint("Start collecting IP port information");
        if let Ok(res) = port::portmain(&ip_list,&filename,client.clone(),apis, &otherset).await{
            ip_port_list.extend(res.clone());
            outprint::Print::bannerprint(format!("A total of {} IP port information were obtained",&res.len()).as_str());
            match tofile::ip_urls_save_to_file(&filename,&res) {
                Ok(_) => outprint::Print::bannerprint(format!("IP port information Results saved to {}",&filename).as_str()),
                Err(e) => outprint::Print::infoprint(format!("Error saving results: {}",e).as_str()),
            }
        }

        domain_list.retain(|x| !x.is_empty());
        domain_list.sort();
        domain_list.dedup();
        let pass_domain = &otherset.pass_domain;
        // 过滤掉不需要的域名
        domain_list.retain(|domain| {
            !pass_domain.iter().any(|blocked| domain.ends_with(blocked)) // 直接传 &String
        });

        match tofile::save_to_file(&filename, &domain_list, &ip_list) {
            Ok(_) => outprint::Print::bannerprint(format!("Results saved to {}",&filename).as_str()),
            Err(e) => outprint::Print::infoprint(format!("Error saving results: {}",e).as_str()),
        }
        outprint::Print::bannerprint(format!("Finally found {} subdomains and {} IPs and {} IPs-Ports", domain_list.len(), ip_list.len(),ip_port_list.len()).as_str());
        domain_list.extend(ip_port_list.clone());
        outprint::Print::infoprint("Start checking web service cms");
        let filename = filename.to_string();
        if let Err(_e) = cmsck::cmsmain(&filename,threads,client,domain_list,ip_list,otherset).await {

        }
    }
}
#[allow(dead_code)]
impl InfoResults {
    fn new() -> Self{
        InfoResults{
            domain_list:vec![],
            ip_list:vec![],
            icp_list:vec![],
            cdn_list:vec![],
        }

    }
    fn empty(&self) -> bool{
        self.domain_list.is_empty() || self.ip_list.is_empty()
    }
    fn merge(&mut self, other: InfoResults) {
        self.domain_list.extend(other.domain_list);
        self.ip_list.extend(other.ip_list);
        self.icp_list.extend(other.icp_list);
        self.cdn_list.extend(other.cdn_list);
    }
    fn clean_all(&mut self) {
        self.domain_list.retain(|x| !x.is_empty());
        self.domain_list.sort();
        self.domain_list.dedup();

        self.ip_list.retain(|x| !x.is_empty());
        self.ip_list.sort();
        self.ip_list.dedup();

        self.icp_list.retain(|x| !x.is_empty());
        self.icp_list.sort();
        self.icp_list.dedup();

        self.cdn_list.retain(|x| !x.is_empty());
        self.cdn_list.sort();
        self.cdn_list.dedup();
    }
}
#[async_trait]
impl InfoFetcher for InfoZone{
    async fn fetch(&self, domain: &str, keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = "https://0.zone/api/data/";
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let q = format!("root_domain={}",domain);
        let data = json!({
        "query": q,
        "query_type": "domain",
        "page": 1,
        "pagesize": 100,
        "zone_key_id": keys.zone_key
    });
        let response = client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&data)
            .send()
            .await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Zone error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }

        let mut results = InfoResults::new();
        let json_s: Value = response.json().await?;
        if let Some(data_array) = json_s["data"].as_array() {
            for entry in data_array {
                let domain = entry["domain"].as_str().unwrap_or("");
                let ip = entry["msg"]["ip"].as_str().unwrap_or("");
                results.domain_list.push(domain.to_string());
                results.ip_list.push(ip.to_string());
                // println!("{}|{}", domain, ip);
            }
        }
        let data2 = json!({
        "query": domain,
        "query_type": "site",
        "page": 1,
        "pagesize": 100,
        "zone_key_id": "1a77af65e7546736ce43f5e85c59fabf"
    });
        let response2 = client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&data2)
            .send()
            .await?;


        // 解析 JSON 响应
        let json_s: Value = response2.json().await?;

        // 遍历数据并打印 IP
        if let Some(data_array) = json_s["data"].as_array() {
            for entry in data_array {
                let ip = entry["ip"].as_str().unwrap_or("");
                results.ip_list.push(ip.to_string());
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Zone found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }

}
#[async_trait]
impl InfoFetcher for InfoRobtex {
    async fn fetch(&self, domain: &str, keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = format!("https://freeapi.robtex.com/pdns/forward/{}?key={}", domain,keys.robtex_key);
        let client = Client::builder().timeout(Duration::from_secs(5)).build()?;

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Robtex error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }
        let response_text = response.text().await?;
        // 存储解析后的数据
        let data: Vec<Value> = Vec::new();

        let domain_regex = Regex::new(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")?;
        let ip_regex = Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$")?;

        let mut results = InfoResults::new();
        let lines = response_text.lines();

        for line in lines {
            match serde_json::from_str::<Value>(line) {
                Ok(json_value) => {
                    if let Some(rrdata) = json_value["rrdata"].as_str() {
                        if domain_regex.is_match(rrdata) {
                            results.domain_list.push(rrdata.to_string());
                        } else if ip_regex.is_match(rrdata) {
                            results.ip_list.push(rrdata.to_string());
                        }
                    }
                }
                Err(_) => {
                    // 如果某行不是有效的 JSON 数据，跳过
                    continue;
                }
            }
        }

        // 打印所有包含 "rrdata" 字段的值
        for item in data {
            if let Some(rrdata) = item["rrdata"].as_str() {
                results.domain_list.push(rrdata.to_string());
                // println!("{}", rrdata);
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Robtex found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoMyssl {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = format!("https://myssl.com/api/v1/discover_sub_domain?domain={}", domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Myssl error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }
        let mut results = InfoResults::new();
        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;

        // 解析 "data" 数组中的 IP 和域名
        if let Some(data_array) = json["data"].as_array() {
            for item in data_array {
                if let (Some(ip), Some(domain)) = (item["ip"].as_str(), item["domain"].as_str()) {
                    results.ip_list.push(ip.to_string());
                    results.domain_list.push(domain.to_string());
                    // println!("IP: {}", ip);
                    // println!("Domain: {}", domain);
                }
            }
        };
        results.clean_all();
        outprint::Print::infoprint(format!("Myssl found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoDnsgrep {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = format!("https://www.dnsgrep.cn/subdomain/{}", domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "Cookie",
            "cf_clearance=2sTanrJw2CDVxo4JYDRfn65B7fjTrJ9gF3g.Rg7U5Bc-1743688955-1.2.1.1-EZ02SHu1TtvdoOOjLgLaMRtAYbmWTWwiFayG_3l9t2xAxHNuAjPnnq_.pq_RXF_95xo3Cc7ZpWrNC.e9U3NQiSSV9NwWxXArVR7sRbB761qbQTnpGloofKSgHRpQO9nuaJYsYZVCWra8UX5Udsn8ITx.n.eZx9k5.USI05TKEtXYykqYdneDcHP5zIHjeQRZvhQKxF2gtWbbhW1OUDHOCpS9VyIaOKVZFaoJim232WNfbUixI...A792lhQmZi1jKp0RhHKmH._9DlAfQzEcq1h_rDp7.4RH2sINLOklzYDkx2r1nEHyIzPBj_QCZENtPSmHIBBWt31s3yMiW0Fg5zx70LR4veyn4PUi7J.dqTfg8D1mzSwqbnfo_UFnVPTi".parse()?,
        );
        headers.insert(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15".parse()?
        );
        let response = client.get(url).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Dnsgrep error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }
        let mut results = InfoResults::new();
        // 解析 HTML
        let document = Html::parse_document(&response.text().await?);
        let td_selector = Selector::parse("td[data]").unwrap();

        // 正则匹配
        let domain_regex = Regex::new(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")?;
        let ip_regex = Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$")?;

        // let mut domains = Vec::new();
        // let mut ips = Vec::new();

        // 查找匹配的 <td data=*>
        for element in document.select(&td_selector) {
            if let Some(data_value) = element.value().attr("data") {
                let data_value = data_value.trim();

                if ip_regex.is_match(data_value) {
                    results.ip_list.push(data_value.to_string());
                    // ips.push(data_value.to_string());
                } else if domain_regex.is_match(data_value) {
                    results.domain_list.push(data_value.to_string());
                    // domains.push(data_value.to_string());
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Dnsgrep found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoBevigil {
    async fn fetch(&self,domain: &str,keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = format!("http://osint.bevigil.com/api/{}/subdomains/", domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Access-Token",
            keys.bevigil_key.parse()?,
        );
        let response = client.get(url).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Bevigil error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }
        let mut results = InfoResults::new();
        // 解析 JSON 响应
        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;

        // 遍历 subdomains 并打印
        if let Some(subdomains) = json["subdomains"].as_array() {
            for sub in subdomains {
                if let Some(subdomain) = sub.as_str() {
                    results.domain_list.push(subdomain.to_string());
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Bevigil found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoUrlscan {
    async fn fetch(&self,domain: &str,_keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}", domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Urlscan error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }
        let mut res_results = InfoResults::new();
        // 解析 JSON 响应
        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;

        // 确保 "results" 存在并且是数组
        if let Some(results) = json["results"].as_array() {
            for js in results {
                if let Some(task) = js.get("task") {
                    if let Some(domain) = task.get("domain").and_then(|d| d.as_str()) {
                        res_results.domain_list.push(domain.to_string());
                        // println!("{}", domain);
                    }
                    if let Some(ip) = js.get("page").and_then(|p| p.get("ip")).and_then(|ip| ip.as_str()) {
                        res_results.ip_list.push(ip.to_string());
                        // println!("{}", ip);
                    }
                } else if let Some(submitter) = js.get("submitter") {
                    if let Some(submit_task) = submitter.get("task") {
                        if let Some(domain) = submit_task.get("domain").and_then(|d| d.as_str()) {
                            res_results.domain_list.push(domain.to_string());
                            // println!("{}", domain);
                        }
                    }
                    if let Some(ip) = submitter.get("page").and_then(|p| p.get("ip")).and_then(|ip| ip.as_str()) {
                        res_results.ip_list.push(ip.to_string());
                    }
                }
            }
        }
        res_results.clean_all();
        outprint::Print::infoprint(format!("Urlscan found Domain {} | found IP {}",res_results.domain_list.len(), res_results.ip_list.len()).as_str());
        Ok(res_results)
    }
}
#[async_trait]
impl InfoFetcher for InfoThreatcrowd {
    async fn fetch(&self,domain: &str,_keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = format!("http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain={}", domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Threatcrowd error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }
        let mut results = InfoResults::new();
        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;

        // 提取 IP 地址
        if let Some(resolutions) = json["resolutions"].as_array() {
            for res in resolutions {
                if let Some(ip) = res["ip_address"].as_str() {
                    results.ip_list.push(ip.to_string());
                }
            }
        }

        // 提取子域名
        if let Some(subdomains) = json["subdomains"].as_array() {
            for sub in subdomains {
                if let Some(subdomain) = sub.as_str() {
                    results.domain_list.push(subdomain.to_string());
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Threatcrowd found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }

}
#[async_trait]
impl InfoFetcher for InfoDnsarchive{
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = format!("https://dnsarchive.net/search.php?q={}", domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Dnsarchive error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }

        let mut results = InfoResults::new();
        let body = response.text().await?; // 修复：必须 `await`

        let document = Html::parse_document(&body);
        let domain_selector = Selector::parse("td[data-label='Domain'] a").unwrap();
        let ipv4_selector = Selector::parse("td[data-label='IPv4'] a").unwrap();

        for element in document.select(&domain_selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(domain) = href.split('/').last() {
                    let res_domain = domain.trim_matches('.');
                    results.domain_list.push(String::from(res_domain));
                }
            }
        }

        for element in document.select(&ipv4_selector) {
            if let Some(ip) = element.text().next() {
                let res_ip = ip.trim();
                results.ip_list.push(String::from(res_ip));
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Dnsarchive found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }

}

// #[async_trait]
// impl InfoFetcher for InfoIP138 {
//     async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
//         let url = format!("https://chaziyu.com/{}/", domain);
//         let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
//         let response = client.get(&url).send().await?;
//         if !response.status().is_success() {
//             outprint::Print::errprint(format!("IP138 error status code: {}", response.status()).as_str());
//             return Ok(InfoResults::new())
//         }
//         let mut results = InfoResults::new();
//         let body = response.text().await?;
//         let document = Html::parse_document(&body);
//
//         // 选择 <tr class="J_link">
//         let row_selector = Selector::parse("tr.J_link").unwrap();
//         let td_selector = Selector::parse("td").unwrap();
//
//         // 遍历符合条件的 <tr>
//         for row in document.select(&row_selector) {
//             let tds: Vec<_> = row.select(&td_selector).collect();
//             if tds.len() > 1 {
//                 let domain = tds[1].text().collect::<Vec<_>>().join("").trim().to_string();
//                 results.domain_list.push(domain);
//             }
//         }
//         results.clean_all();
//         outprint::Print::infoprint(format!("IP138 found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
//         Ok(results)
//     }
//
// }
#[async_trait]
impl InfoFetcher for InfoFofa{
    async fn fetch(&self,domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        // let base64_str;
        // if domain.len() <= 8 {
        //     base64_str = STANDARD.encode(format!("domain=\"{}\"", domain));
        // } else {
        //     base64_str = STANDARD.encode(format!("\"{}\"", domain));
        // }
        let base64_str = STANDARD.encode(format!("domain=\"{}\"", domain));
        let url = format!("https://fofa.info/api/v1/search/all?key={}&qbase64={}&size=100&full=true", keys.fofa_key,base64_str);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Fofa error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        if let Some(errmsg) = json_response.get("errmsg").and_then(|err| err.as_str()) {
            outprint::Print::errprint(errmsg);
            return Ok(InfoResults::new())
        }
        let empty_vec = vec![];
        let mut results = InfoResults::new();
        let data_array = json_response.get("results").and_then(|data| data.as_array()).unwrap_or(&empty_vec);

        data_array.iter().for_each(|data| {
            // println!("{}",data);
            if let (Some(domain), Some(ip)) = (data.get(0), data.get(1)) {
                if let (Some(domain_str), Some(ip_str)) = (domain.as_str(), ip.as_str()) {
                    results.domain_list.push(String::from(domain_str));
                    results.ip_list.push(String::from(ip_str));
                    // println!("IP {}",  ip_str);
                }
            }
        });
        // outprint::Print::infoprint(format!("Fofa found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        results.clean_all();
        outprint::Print::infoprint(format!("Fofa found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoAlienvault{
    async fn fetch(&self,domain: &str,_keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Alienvault error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let empty_vec = vec![];
        let mut results = InfoResults::new();
        let data_array = json_response.get("passive_dns").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
        let ip_regex = Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$")?;
        data_array.iter().for_each(|data| {
            if let (Some(domain), Some(ip)) = (data.get("hostname"), data.get("address")) {
                if let (Some(domain_str), Some(ip_str)) = (domain.as_str(), ip.as_str()) {
                    results.domain_list.push(String::from(domain_str));
                    if ip_regex.is_match(ip_str){
                        results.ip_list.push(String::from(ip_str));
                    }

                }
            }
        });
        results.clean_all();
        outprint::Print::infoprint(format!("Alienvault found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }

}
#[async_trait]
impl InfoFetcher for InfoQuake {
    async fn fetch(&self, domain: &str, keys: &ApiKeys) -> Result<InfoResults, Box<dyn Error + Send + Sync>> {
        let url = "https://quake.360.net/api/v3/search/quake_service";
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-quaketoken",
            keys.quake_key.parse()?,
        );
        let query = json!({
            "query": format!("domain: {}", domain),
            "start": 0,
            "size": 100,
        });
        let response = client.post(url).json(&query).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Quake error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new());
        }
        let json_response = response.json::<Value>().await?;
        if json_response.get("code").and_then(|code| code.as_u64()) != Some(0) {
            if let Some(message) = json_response.get("message").and_then(|err| err.as_str()) {
                outprint::Print::errprint(message);
            }
            return Ok(InfoResults::new());
        }

        let empty_vec = vec![];
        let mut results = InfoResults::new();
        let data_array = json_response.get("data").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
        data_array.iter().for_each(|data| {
            if let (Some(domain), Some(ip)) = (
                data.get("domain").and_then(|domain| domain.as_str()),
                data.get("ip").and_then(|ip| ip.as_str()),
            ) {
                results.domain_list.push(String::from(domain));
                results.ip_list.push(String::from(ip));

                // 提取 icp.service.http.icp.main_licence.unit
                if let Some(unit) = data
                    .get("service")
                    .and_then(|service| service.get("http"))
                    .and_then(|http| http.get("icp"))
                    .and_then(|icp| icp.get("main_licence"))
                    .and_then(|main_licence| main_licence.get("unit"))
                    .and_then(|unit| unit.as_str())
                {
                    results.icp_list.push(String::from(unit));
                }
                // 检查 CDN 并输出对应 IP
                if let Some(components) = data.get("components").and_then(|c| c.as_array()) {
                    for component in components {
                        // if let Some(product_types) = component.get("product_type").and_then(|pt| pt.as_array()) {
                        //     for product_type in product_types {
                        //         if let Some(pt_str) = product_type.as_str() {
                        //             let pt_upper = pt_str.to_uppercase(); // 缓存大写字符串
                        //             if pt_upper.contains("CDN") || pt_upper.contains("扫描欺骗") {
                        //                 results.cdn_list.push(String::from(ip));
                        //                 // println!("IP {} is cdn", ip);
                        //             }
                        //         }
                        //     }
                        // }
                        if let (Some(product_types),Some(product_name_cn)) = (
                            component.get("product_type").and_then(|pt| pt.as_array()),
                            component.get("product_name_cn").and_then(|ptc| ptc.as_str())
                        ) {
                            if product_name_cn.contains("扫描欺骗") ||
                                product_name_cn.contains("Nullidentd") ||
                                product_name_cn.contains("KVIrc fake identd") ||
                                product_name_cn.contains("Cloudflare"){
                                results.cdn_list.push(String::from(ip));
                                // println!("IP {} is cdn", ip);
                                continue;
                            }
                            for product_type in product_types {
                                if let Some(pt_str) = product_type.as_str() {
                                    let pt_upper = pt_str.to_uppercase(); // 缓存大写字符串
                                    if pt_upper.contains("CDN") || pt_upper.contains("扫描欺骗") {
                                        results.cdn_list.push(String::from(ip));
                                        // println!("IP {} is cdn", ip);
                                        break;

                                    }
                                }
                            }
                        }

                    }
                }
            }
        });
        results.clean_all();
        outprint::Print::infoprint(
            format!(
                "Quake found Domain {} | found IP {} | found ICP {}",
                results.domain_list.len(),
                results.ip_list.len(),
                results.icp_list.len()
            ).as_str(),
        );
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoZoomeye{
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.zoomeye.ai/domain/search?q={}&type=1&page=1",domain);
        let mut headers = HeaderMap::new();
        headers.insert(
            "api-key",
            keys.zoomeye_key.parse()?
        );
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(url).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Zoomeye error code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let empty_vec = vec![];
        let mut results = InfoResults::new();
        let list_array = json_response.get("list").and_then(|name| name.as_array()).unwrap_or(&empty_vec);
        list_array.iter().for_each(|name| {
            if let (Some(domain), Some(ip)) = (
                name.get("name").and_then(|domain| domain.as_str()),
                name.get("ip").and_then(|ip| ip.as_array())
            ) {
                results.domain_list.push(domain.to_string());
                if !ip.is_empty(){
                    results.ip_list.extend(ip.iter().filter_map(|ip| ip.as_str()).map(String::from))
                }
            }
        });
        results.domain_list.retain(|x| !x.is_empty());
        results.domain_list.sort();
        results.domain_list.dedup();
        results.ip_list.retain(|x| !x.is_empty());
        results.ip_list.sort();
        results.ip_list.dedup();
        outprint::Print::infoprint(format!("Zoomeye found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)

    }
}
#[async_trait]
impl InfoFetcher for InfoDaydaymap {
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = "https://www.daydaymap.com/api/v1/raymap/search/all";
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "api-key",
            keys.daydaymap_key.parse()?
        );

        // 修改编码代码
        let base64_str = STANDARD.encode(format!("domain=\"{}\"", domain));
        // let base64_str = base64::encode(format!("domain=\"{}\"", domain));
        let query = json!({
            "page": 1,
            "page_size": 100,
            "keyword": base64_str,
        });

        let response = client.post(url).json(&query).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Daydaymap error code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        };
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(data) = json_response.get("data").and_then(|d| d.as_object()) {
            if let Some(list) = data.get("list").and_then(|l| l.as_array()) {
                for item in list {
                    if let (Some(domain),Some(ip)) = (
                        item.get("domain").and_then(|domain| domain.as_str()),
                        item.get("ip").and_then(|ip| ip.as_str())
                    ) {
                        results.domain_list.push(String::from(domain));
                        results.ip_list.push(String::from(ip));
                    }
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Daydaymap found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoSecuritytrails {
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains",domain);
        let url2 = format!("https://api.securitytrails.com/v1/history/{}/dns/a",domain);
        let mut headers = HeaderMap::new();
        headers.insert(
            "apikey",
            keys.securitytrails_key.parse()?,
        );
        headers.insert(
            "accept",
            "application/json".parse()?
        );
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response1 = client.get(&url).headers(headers.clone()).send().await?;
        sleep(TokioDuration::from_secs(3)).await;
        let response2 = client.get(&url2).headers(headers.clone()).send().await?;
        // let (response1, response2) = tokio::try_join!(
        //     client.get(&url).headers(headers.clone()).send(),
        //     client.get(&url2).headers(headers.clone()).send()
        // )?;
        if !response2.status().is_success() && !response1.status().is_success() {
            outprint::Print::errprint(format!("Securitytrails error code: {}", response1.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response1.json::<Value>().await?;
        let json_response2 = response2.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(subdomain) = json_response.get("subdomains").and_then(|d| d.as_array()) {
            subdomain.iter().for_each(|d| {
                if let Some(domain_str) = d.as_str(){
                    let res_domain = format!("{}.{}",domain_str,domain);
                    results.domain_list.push(String::from(res_domain));
                }
            });
        }
        if let Some(records) = json_response2.get("records").and_then(|d| d.as_array()) {
            records.iter().for_each(|record| {
                if let Some(values) = record.get("values").and_then(|v| v.as_array()) {
                    for value in values {
                        if let Some(ip) = value.get("ip").and_then(|i| i.as_str()) {
                            results.ip_list.push(String::from(ip));
                        }
                    }
                }
            })
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Securitytrails found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)

    }
}
#[async_trait]
impl InfoFetcher for InfoShodan {
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.shodan.io/shodan/host/search?key={}&query=hostname:*.{}&facets=country",keys.shodan_key,domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Shodan error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(matches) = json_response.get("matches").and_then(|d| d.as_array()) {
            for matche in matches{
                if let (Some(domains),Some(ip)) = (matche.get("hostnames").and_then(|h| h.as_array()),matche.get("ip_str").and_then(|i| i.as_str())) {
                    results.domain_list.extend(domains.iter().filter_map(|d| d.as_str().map(String::from)));
                    results.ip_list.push(String::from(ip));
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Shodan found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoHunter {
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let query = STANDARD.encode(format!("domain=\"{}\"", domain));
        // let query = base64::encode(format!("domain=\"{domain}\""));
        let url = format!("https://api.hunter.how/search?api-key={}&query={}&page=1&page_size=100&start_time=2024-01-01&end_time=2025-12-30",keys.hunter_key,query);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Hunter error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(data) = json_response.get("data").and_then(|d| d.get("list")).and_then(|d| d.as_array()) {
            data.iter().for_each(|data| {
                if let (Some(domain),Some(ip)) = (data.get("domain").and_then(|o| o.as_str()),data.get("ip").and_then(|i| i.as_str())) {
                    results.domain_list.push(String::from(domain));
                    results.ip_list.push(String::from(ip));
                }
            });
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Hunter found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoYT {
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let query = STANDARD.encode(format!("domain=\"{}\"", domain));
        // let query = base64::encode(format!("domain=\"{}\"",domain));
        let url = format!("https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page=1&page_size=100&is_web=3&start_time=2024-01-01&end_time=2025-12-28",keys.yt_key,query);
        let client = Client::builder().timeout(Duration::from_secs(10)).default_headers({
            let mut headers = HeaderMap::new();
            headers.insert("X-Forwarded-For", HeaderValue::from_static("127.0.0.1"));
            headers
        }).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("YT-Hunter error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        // println!("{:?}",json_response);
        if let Some(data) = json_response.get("data").and_then(|d| d.get("arr")).and_then(|d| d.as_array()) {
            data.iter().for_each(|data| {
                if let (Some(domain),Some(ip),Some(company)) = (data.get("domain").and_then(|o| o.as_str()),data.get("ip").and_then(|i| i.as_str()),data.get("company").and_then(|c| c.as_str())) {
                    results.domain_list.push(String::from(domain));
                    results.ip_list.push(String::from(ip));
                    // println!("{}",company.to_string());
                    results.icp_list.push(String::from(company));
                }
            });
        }
        results.clean_all();
        outprint::Print::infoprint(format!("YT-Hunter found Domain {} | found IP {} | found ICP {}",results.domain_list.len(), results.ip_list.len(),results.icp_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoVirustotal {
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let domain_url = format!("https://www.virustotal.com/api/v3/domains/{}/relationships/subdomains?limit=40",domain);
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept","application/json".parse()?,
        );
        headers.insert(
            "x-apikey",keys.virustotal_key.parse()?
        );
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&domain_url).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Virustotal error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(data) = json_response.get("data").and_then(|d| d.as_array()) {
            data.iter().for_each(|data| {
                if let Some(id) = data.get("id").and_then(|i| i.as_str()) {
                    results.domain_list.push(String::from(id));
                }
            });
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Virustotal found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoViewDNS {
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.viewdns.info/iphistory/?domain={}&apikey={}&output=json", domain,keys.viewdns_key);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("ViewDNS error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(data) = json_response.get("response").and_then(|d| d.get("records")).and_then(|d| d.as_array()) {
            data.iter().for_each(|data| {
                if let Some(ip) = data.get("ip").and_then(|i| i.as_str()) {
                    results.ip_list.push(String::from(ip));
                }
            });
        }
        results.clean_all();
        outprint::Print::infoprint(format!("ViewDNS found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoBinaryedge{
    async fn fetch(&self, domain: &str,keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.binaryedge.io/v2/query/domains/subdomain/{}",domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-key", keys.binaryedge_key.parse()?
        );
        let response = client.get(&url).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Binaryedg error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(events) = json_response.get("events").and_then(|e| e.as_array()) {
            events.iter().for_each(|event| {
                if let Some(events_str) = event.as_str(){
                    results.domain_list.push(String::from(events_str));
                }

            });
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Binaryedge found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());

        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoFullhunt {
    async fn fetch(&self, domain: &str, keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://fullhunt.io/api/v1/domain/{domain}/subdomains");
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key", keys.fullhunt_key.parse()?
        );
        let response = client.get(&url).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Fullhunt error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(hosts) = json_response.get("hosts").and_then(|h| h.as_array()) {
            hosts.iter().for_each(|host| {
                if let Some(hots) = host.as_str(){
                    results.domain_list.push(String::from(hots));
                }
            });

        }
        results.clean_all();
        outprint::Print::infoprint(format!("Fullhunt found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoWhoisxml {
    async fn fetch(&self, domain: &str, keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://subdomains.whoisxmlapi.com/api/v1?apiKey={}&domainName={}",keys.whoisxmlapi_key,domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Whoisxml error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(rec) = json_response.get("result").and_then(|e| e.get("records")).and_then(|e| e.as_array()) {
            rec.iter().for_each(|result| {
                if let Some(domain) = result.get("domain").and_then(|d| d.as_str()) {
                    results.domain_list.push(String::from(domain));
                }
            });
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Whoisxmlapi found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoDnsdump {
    async fn fetch(&self, domain: &str, keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.dnsdumpster.com/domain/{}",domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key",keys.dnsdump_key.parse()?);
        let response = client.get(&url).headers(headers).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Dnsdump error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(a) = json_response.get("a").and_then(|a| a.as_array()) {
            a.iter().for_each(|a| {
                if let Some(host) = a.get("host").and_then(|h| h.as_str()) {
                    results.domain_list.push(String::from(host));
                }
                if let Some(ips) = a.get("ips").and_then(|i| i.as_array()) {
                    ips.iter().for_each(|ip| {
                        if let Some(ip_str) = ip.get("ip").and_then(|i| i.as_str()) {
                            results.ip_list.push(String::from(ip_str));
                        }
                    })
                }
            });
        }
        if let Some(mx) = json_response.get("mx").and_then(|a| a.as_array()) {
            mx.iter().for_each(|a| {
                if let Some(host) = a.get("host").and_then(|h| h.as_str()) {
                    results.domain_list.push(String::from(host));
                }
                if let Some(ips) = a.get("ips").and_then(|i| i.as_array()) {
                    ips.iter().for_each(|ip| {
                        if let Some(ip_str) = ip.get("ip").and_then(|i| i.as_str()) {
                            results.ip_list.push(String::from(ip_str));
                        }
                    })
                }
            });
        }
        if let Some(ns) = json_response.get("ns").and_then(|a| a.as_array()) {
            ns.iter().for_each(|a| {
                if let Some(host) = a.get("host").and_then(|h| h.as_str()) {
                    results.domain_list.push(String::from(host));
                }
                if let Some(ips) = a.get("ips").and_then(|i| i.as_array()) {
                    ips.iter().for_each(|ip| {
                        if let Some(ip_str) = ip.get("ip").and_then(|i| i.as_str()) {
                            results.ip_list.push(String::from(ip_str));
                        }
                    })
                }
            });
        }
        if let Some(cname) = json_response.get("ns").and_then(|a| a.as_array()) {
            cname.iter().for_each(|a| {
                if let Some(host) = a.get("host").and_then(|h| h.as_str()) {
                    results.domain_list.push(String::from(host));
                }
                if let Some(ips) = a.get("ips").and_then(|i| i.as_array()) {
                    ips.iter().for_each(|ip| {
                        if let Some(ip_str) = ip.get("ip").and_then(|i| i.as_str()) {
                            results.ip_list.push(String::from(ip_str));
                        }
                    })
                }
            });
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Dnsdump found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());

        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoCrt {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://crt.sh/json?q={}",domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Crt error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(a) = json_response.as_array() {
            a.iter().for_each(|v| {
                if let (Some(cn),Some(_nv)) = (v.get("common_name").and_then(|n| n.as_str()),v.get("name_value").and_then(|n| n.as_str())) {
                    results.domain_list.push(String::from(cn));
                }
            })
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Crt found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());

        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoChaziyu {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://chaziyu.com/{}",domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Chaziyu error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let body = response.text().await?;
        let document = Html::parse_document(&body);
        let selector = Selector::parse("tr.J_link a").unwrap();

        // 收集子域名
        let mut results = InfoResults::new();
        for element in document.select(&selector) {
            if let Some(link) = element.text().next() {
                results.domain_list.push(link.trim().to_string());
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Chaziyu found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());

        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoJldc {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://jldc.me/anubis/subdomains/{}",domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Jldc error status code: {}", response.status()).as_str());
            return Ok(InfoResults::new())
        }
        let json_response = response.json::<Value>().await?;
        let mut results = InfoResults::new();
        if let Some(a) = json_response.as_array() {
            a.iter().for_each(|v| {
                if let Some(v_str) = v.as_str() {
                    results.domain_list.push(v_str.to_string());
                }
            })
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Jldc found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());

        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoSitedossier {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("http://www.sitedossier.com/parentdomain/{}/",domain);
        let mut headers = HeaderMap::new();
        let mut results = InfoResults::new();
        headers.insert(HOST, HeaderValue::from_static("www.sitedossier.com"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
        headers.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(
                "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            ),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            ),
        );
        headers.insert(REFERER, HeaderValue::from_static("http://www.sitedossier.com/audit/?41336"));
        headers.insert("Accept-Encoding", HeaderValue::from_static("gzip, deflate"));
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
        );
        headers.insert(CONNECTION, HeaderValue::from_static("close"));

        // 发送 HTTP 请求
        let client = reqwest::Client::builder().default_headers(headers).timeout(Duration::from_secs(5)).build()?;
        let response = client.get(&url).send().await?;

        if !response.status().is_success() {
            outprint::Print::errprint(format!("Sitedossier error status code: {}", response.status()).as_str());
            return Ok(results); // 返回空列表
        }

        // 解析 HTML 响应
        let body = response.text().await?;
        let document = Html::parse_document(&body);

        // 使用 CSS 选择器提取 <li> 标签内容
        let selector = Selector::parse("li a").unwrap();


        for element in document.select(&selector) {
            if let Some(link) = element.text().next() {
                // 提取并格式化域名
                let req_domain = link.split("://").last().unwrap_or("").trim_end_matches('/');
                results.domain_list.push(req_domain.to_string());
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Sitedossier found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoRapiddns{
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("http://rapiddns.io/subdomain/{}?full=1",domain);
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(
                "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            ),
        );
        let mut results = InfoResults::new();
        // 发送 HTTP 请求
        let client = reqwest::Client::builder().default_headers(headers).build()?;
        let response = client.get(&url).send().await?;

        if !response.status().is_success() {
            outprint::Print::errprint(format!("Rapiddns error status code: {}", response.status()).as_str());
            return Ok(results); // 返回空列表
        }

        let body = response.text().await?;
        let document = Html::parse_document(&body);
        let td_selector = Selector::parse("td").unwrap();
        for element in document.select(&td_selector) {
            let text = element.text().collect::<Vec<_>>().join("").trim().to_string();

            // 检查是否是域名
            if is_domain(&text) {
                results.domain_list.push(text);
            }
        }
        fn is_domain(text: &str) -> bool {
            // 使用简单的正则表达式匹配域名
            let domain_regex = regex::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$").unwrap();
            domain_regex.is_match(text)
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Rapiddns found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoCertspotter {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        let mut results = InfoResults::new();
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Certspotter error status code: {}", response.status()).as_str());
            return Ok(results);
        }
        let json_response = response.json::<Value>().await?;
        if let Some(a) = json_response.as_array() {
            a.iter().for_each(|v| {
                if let Some(v_str) = v.get("dns_names").and_then(|vt| vt.as_array()) {
                    v_str.iter().for_each(|v_str| {
                        if let Some(v_str_t) = v_str.as_str() {
                            let res = v_str_t.trim_matches('"');
                            results.domain_list.push(res.to_string());
                        }

                    })
                }
            })
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Certspotter found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoHackertarget {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://api.hackertarget.com/hostsearch/?q={}",domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        let mut results = InfoResults::new();
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Hackertarget error status code: {}", response.status()).as_str());
            return Ok(results);
        }
        let text = response.text().await?;

        for line in text.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if let Some(domain) = parts.get(0) {
                if !domain.is_empty() {
                    results.domain_list.push(domain.trim().to_string());
                }
            }
            if let Some(ip) = parts.get(1) {
                if !ip.is_empty() {
                    results.ip_list.push(ip.trim().to_string());
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Hackertarget found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoArchive {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=txt&fl=original&collapse=urlkey",domain);
        let client = Client::builder().timeout(Duration::from_secs(60)).build()?;
        let response = client.get(&url).send().await?;
        let mut results = InfoResults::new();
        if !response.status().is_success() {
            outprint::Print::errprint(format!("Archive error status code: {}", response.status()).as_str());
            return Ok(results);
        }
        let text = response.text().await?;
        let re = Regex::new(r"https?://([^/]+)/?").unwrap();
        if text.len() > 10{
            outprint::Print::bannerprint(format!("Found the historical web link record, you can visit the url: {} to get the details",url).as_str());
        }
        for line in text.lines() {
            if let Some(caps) = re.captures(line) {
                if let Some(domain) = caps.get(1) {
                    results.domain_list.push(domain.as_str().to_string());
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Archive found Domain {} | found IP {}",results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoDnshistory {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://dnshistory.org/subdomains/1/{}", domain);
        let mut headers = HeaderMap::new();
        let mut results = InfoResults::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        );

        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).headers(headers).send().await?;

        if !response.status().is_success() {
            outprint::Print::errprint(format!("Dnshistory error status code: {}", response.status()).as_str());
            return Ok(results);
        }
        let body = response.text().await?;
        let re = Regex::new(r#"<a href="/dns-records/(.*?)">"#).unwrap();

        for caps in re.captures_iter(&body) {
            if let Some(domain) = caps.get(1) {
                results.domain_list.push(domain.as_str().to_string());
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Dnshistory found Domain {} | found IP {}", results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoNetlas {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        let url = format!("https://app.netlas.io/api/domains/?q=domain:(domain:*.{}+AND+NOT+domain:{})&start=0&indices=", domain, domain);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let response = client.get(&url).send().await?;
        let mut results = InfoResults::new();

        if !response.status().is_success() {
            outprint::Print::errprint(format!("Netlas error status code: {}", response.status()).as_str());
            return Ok(results);
        }
        let json: Value = response.json().await?;

        if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(data) = item.get("data") {
                    if let Some(domain) = data.get("domain").and_then(|d| d.as_str()) {
                        results.domain_list.push(domain.trim().to_string());
                    }
                    if let Some(ips) = data.get("a").and_then(|a| a.as_array()) {
                        for ip in ips {
                            if let Some(ip_str) = ip.as_str() {
                                results.ip_list.push(ip_str.trim_matches('"').parse().unwrap());
                            }
                        }
                    }
                }
            }
        }
        results.clean_all();
        outprint::Print::infoprint(format!("Netlas found Domain {} | found IP {}", results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
#[async_trait]
impl InfoFetcher for InfoC99NL {
    async fn fetch(&self, domain: &str, _keys: &ApiKeys) -> Result<InfoResults,Box<dyn Error + Send + Sync>> {
        // 获取当前日期并格式化为 yyyy-MM-dd
        let current_date = Local::now().format("%Y-%m-%d").to_string();
        let url = format!(
            "https://subdomainfinder.c99.nl/scans/{}/{}",
            current_date, domain
        );
        let mut headers = HeaderMap::new();
        #[allow(dead_code)]
        let _results = InfoResults::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        );
        let mut results = InfoResults::new();

        // 初始化 HTTP 客户端
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

        // 发送 GET 请求
        let response = client.get(&url).headers(headers).send().await?;

        if !response.status().is_success() {
            outprint::Print::errprint(format!("C99NL error status code: {}", response.status()).as_str());
            return Ok(results);
        }
        let response_text = response.text().await?;

        // 正则匹配子域名
        let domain_regex = Regex::new(r"<a class='link sd' target='_blank' rel='noreferrer' href='//(.*?)'>")?;
        for cap in domain_regex.captures_iter(&response_text) {
            let domain = cap.get(1).unwrap().as_str().trim().to_string();
            results.domain_list.push(domain);
        }

        // 正则匹配 IP 地址
        let ip_regex = Regex::new(r"<a class='link ip' target='_blank' href='/geoip/(.*?)'>")?;
        for cap in ip_regex.captures_iter(&response_text) {
            let ip = cap.get(1).unwrap().as_str().trim().to_string();
            results.ip_list.push(ip);
        }
        results.clean_all();
        outprint::Print::infoprint(format!("C99NL found Domain {} | found IP {}", results.domain_list.len(), results.ip_list.len()).as_str());
        Ok(results)
    }
}
async fn build_client(arg: &HashMap<&str, String>) -> Result<Client, Box<dyn std::error::Error>> {
    // 解析 timeout，默认值为 30 秒
    let timeout = arg
        .get("timeout")
        .unwrap_or(&"20".to_string())
        .parse::<u64>()
        .unwrap_or(20);

    // 获取代理设置
    let default_proxy = "None".to_string();  // 提前创建并绑定到变量
    let proxy = arg.get("proxy").unwrap_or(&default_proxy);

    // 解析 ssl_verify，默认为 false
    let ssl_verify = arg
        .get("ssl_verify")
        .unwrap_or(&"false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // 构建客户端构造器
    let mut client_builder = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(timeout)) // 设置超时
        .danger_accept_invalid_certs(!ssl_verify); // 根据 ssl_verify 来决定是否接受无效证书

    // 设置代理
    if proxy != "None" {
        client_builder = client_builder.proxy(reqwest::Proxy::https(proxy)?);
    }

    // 解析 headers 字段并设置请求头
    let default_headers = "User-Agent: Windows server 2012 Google x86".to_string();
    let headers_str = arg.get("headers").unwrap_or(&default_headers);
    let mut headers = HeaderMap::new();
    parse_headers(headers_str, &mut headers);

    // 将解析的 headers 设置到客户端构建器
    client_builder = client_builder.default_headers(headers);

    // 返回构建的客户端
    Ok(client_builder.build()?)
}

fn parse_headers(input: &str, headers: &mut HeaderMap) {
    // 如果 input 是空的，直接返回
    if input.is_empty() {
        return;
    }

    // 解析每个键值对
    for pair in input.split(',') {
        if let Some((key, value)) = pair.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if let (Ok(header_name), Ok(header_value)) =
                (HeaderName::from_bytes(key.as_bytes()), HeaderValue::from_str(value))
            {
                headers.insert(header_name, header_value);
            }
        }
    }
}
pub async fn infomain(arg: HashMap<&str, String>, domain: &str, custom_config_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    let other_set_content = include_str!("../config/config.toml");
    let other_content: OtherSets = toml::from_str(other_set_content)?;

    let mut config = Config::from_default()?;
    if let Some(path) = custom_config_path {
        outprint::Print::infoprint(&format!("Loading user configuration from: {}", path));
        config = Config::from_file(path)?;
    }
    let api_keys = config.api_keys;

    let client = build_client(&arg).await?;
    let fetchers: Vec<Arc<dyn InfoFetcher + Send + Sync>> = vec![
        Arc::new(InfoFofa),
        Arc::new(InfoQuake),
        Arc::new(InfoZoomeye),
        Arc::new(InfoDaydaymap),
        Arc::new(InfoSecuritytrails),
        Arc::new(InfoShodan),
        Arc::new(InfoHunter),
        Arc::new(InfoYT),
        Arc::new(InfoVirustotal),
        Arc::new(InfoViewDNS),
        Arc::new(InfoBinaryedge),
        Arc::new(InfoFullhunt),
        Arc::new(InfoWhoisxml),
        Arc::new(InfoDnsdump),
        Arc::new(InfoCrt),
        Arc::new(InfoChaziyu),
        Arc::new(InfoJldc),
        Arc::new(InfoSitedossier),
        Arc::new(InfoRapiddns),
        Arc::new(InfoCertspotter),
        Arc::new(InfoHackertarget),
        Arc::new(InfoArchive),
        Arc::new(InfoDnshistory),
        Arc::new(InfoNetlas),
        Arc::new(InfoC99NL),
        Arc::new(InfoAlienvault),
        Arc::new(InfoDnsarchive),
        // Arc::new(InfoIP138),
        Arc::new(InfoThreatcrowd),
        Arc::new(InfoUrlscan),
        Arc::new(InfoBevigil),
        Arc::new(InfoDnsgrep),
        Arc::new(InfoMyssl),
        Arc::new(InfoRobtex),
        Arc::new(InfoZone),
    ];
    let threads = arg.get("threads").and_then(|t| t.parse::<usize>().ok()).unwrap_or(300);
    let combined_results = Arc::new(Mutex::new(InfoResults::new()));
    let semaphore = Arc::new(Semaphore::new(threads));

    let domains: Vec<String> = if arg.contains_key("file") {
        let file_path = arg.get("file").unwrap();
        outprint::Print::infoprint(&format!("Reading domains from file: {}", file_path));
        let content = fs::read_to_string(file_path)?;
        content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else if !domain.is_empty() {
        vec![domain.to_string()]
    } else {
        return Err("No domain or file specified".into());
    };

    for target_domain in domains.iter() {
        outprint::Print::infoprint(&format!("Processing domain: {}", target_domain));
        outprint::Print::infoprint("Start enumerating subdomains");
        let _ = subdomain::scan_subdomains(target_domain, threads).await;
        outprint::Print::infoprint("End of subdomain enumeration");
        outprint::Print::infoprint("Start information collection");

        let tasks: Vec<_> = fetchers.iter().map(|fetcher| {
            let permit = semaphore.clone();
            let combined_results = Arc::clone(&combined_results);
            let domain = target_domain.clone();
            let api_keys = api_keys.clone();
            let fetcher = Arc::clone(fetcher); // 克隆 Arc 以延长生命周期
            tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                match fetcher.fetch(&domain, &api_keys).await {
                    Ok(results) => {
                        let mut combined = combined_results.lock().await;
                        combined.merge(results);
                    }
                    Err(e) => {
                        outprint::Print::errprint(format!("Error for {}: {}", domain, e).as_str());
                    }
                }
            })
        }).collect();

        join_all(tasks).await;
    }

    let mut combined_results = combined_results.lock().await;

    if !combined_results.domain_list.is_empty() || !combined_results.ip_list.is_empty() {
        let display_domain = domains.first().unwrap_or(&"combined_results".to_string()).clone();
        combined_results.display(&display_domain, threads, client, api_keys, other_content).await;
    }

    Ok(())
}
