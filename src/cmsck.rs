use std::error::Error;
// use std::fmt::format;
use std::sync::Arc;
use futures::future::ok;
// use std::time::Duration;
use reqwest::{Client, Response};
use serde::Deserialize;
use ring::digest::{Context, Digest, SHA256};
use tokio::sync::Semaphore;
use scraper::{Html, Selector};
use tokio::sync::Mutex;
use reqwest::header::{HeaderMap, HeaderValue};
use crate::outprint;
use crate::craw;
use crate::vulns;
use crate::tofile;
use sha2::{Digest as Digest_sha2, Sha256 as Sha256_sha2};
use crate::tofile::editor_urls_save_to_file;
use crate::pocscan::pocsmain;
#[allow(dead_code)]
#[derive(Debug, Clone,Deserialize)]
struct FingerPrint {
    cms: String,
    rule: Vec<String>,
    location: String,
    logic: String,
    method:String,
}
impl FingerPrint {
    // 辅助函数，用于判断规则匹配
    fn matches_rule(&self, hash_string: &str, headers: &HeaderMap, response_text: &str) -> bool {
        match self.logic.as_str() {
            "or" => match self.method.as_str() {
                "faviconhash" => self.rule.iter().any(|kw| hash_string.contains(kw)),
                "header" => self.rule.iter().any(|kw| {
                    headers.iter().any(|(key, value)| {
                        key.as_str().contains(kw) || value.to_str().unwrap_or_default().contains(kw)
                    })
                }),
                _ => self.rule.iter().any(|kw| response_text.contains(kw)),
            },
            "and" => match self.method.as_str() {
                "faviconhash" => self.rule.iter().all(|kw| hash_string.contains(kw)),
                "header" => self.rule.iter().all(|kw| {
                    headers.iter().any(|(key, value)| {
                        key.as_str().contains(kw) || value.to_str().unwrap_or_default().contains(kw)
                    })
                }),
                _ => self.rule.iter().all(|kw| response_text.contains(kw)),
            },
            _ => false, // 默认逻辑处理为 false
        }
    }
}

#[allow(dead_code)]
enum Method {
    FaviconHash,
    Header,
    Body,
    Title,
    Unknown,
}
#[allow(dead_code)]
impl Method {
    #[allow(dead_code)]
    fn from_str(method: &str) -> Self {
        match method {
            "faviconhash" => Method::FaviconHash,
            "header" => Method::Header,
            "body" => Method::Body,
            "title" => Method::Body,
            _ => Method::Unknown,
        }
    }
}
#[derive(Debug, Clone,Deserialize)]
struct Finger {
    finger: Vec<FingerPrint>,
}
#[allow(dead_code)]
impl Finger {
    fn new() -> Self{
        Finger {
            finger: Vec::new(),
        }
    }

}
struct Rescraw{
    urls: Vec<String>,
}
impl Rescraw {
    fn new() -> Self {
        Self { urls: Vec::new() }
    }
    fn push(&mut self, url: Vec<String>){
        self.urls.extend(url)
    }
    fn rt(&self) -> Vec<String> {
        self.urls.clone()
    }
}
struct NotFound{
    url: Mutex<Vec<String>>,
}
impl NotFound {
    fn new() -> Self{
        NotFound{
            url: Mutex::new(Vec::new()),
        }
    }
    async fn push(&self, domain: String) {
        let mut urls = self.url.lock().await;
        urls.push(domain);
    }

    async fn take_all(&self) -> Vec<String> {
        let mut urls = self.url.lock().await;
        std::mem::take(&mut *urls) // 清空当前数据并返回旧数据
    }

}
struct Bypass{
    url: Mutex<Vec<String>>,
}
impl Bypass {
    fn new() -> Self{
        Bypass{
            url: Mutex::new(Vec::new()),
        }
    }
    async fn push(&self, domain: String) {
        let mut urls = self.url.lock().await;
        urls.push(domain);
    }

    async fn take_all(&self) -> Vec<String> {
        let mut urls = self.url.lock().await;
        std::mem::take(&mut *urls) // 清空当前数据并返回旧数据
    }

}
#[allow(dead_code)]
struct Resulturls{
    urls: Vec<String>,
}
#[allow(dead_code)]
impl Resulturls {
    fn push(&mut self, domain: Vec<String>) {
        self.urls.extend(domain);
    }
    fn results(&self) -> Vec<String> {
        self.urls.clone()
    }
}
fn calculate_hash_as_number(bytes: &[u8]) -> u32 {
    // 创建 SHA-256 哈希上下文
    let mut context = Context::new(&SHA256);
    context.update(bytes);
    let digest: Digest = context.finish();

    // 提取哈希的前 4 个字节，并将其作为一个 u32 编码
    let hash_bytes = &digest.as_ref()[..4]; // 取前 4 个字节
    u32::from_be_bytes(hash_bytes.try_into().unwrap()) // 转换为 u32
}


#[derive(Clone)]
struct Cmsck {
    client: Arc<Client>,
    not_found: Arc<NotFound>,
    ok_list: Arc<Mutex<Vec<String>>>,
    bypass_list: Arc<Bypass>,
}

impl Cmsck {
    /// 获取目标域名的主页内容
    pub async fn fetch_homepage(&self, domain: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let url = format!("{}/kindeditor/asp/upload_json.asp?dir=file", domain.trim_end_matches('/')); // 确保域名格式正确
        let response = self.client.get(&url).send().await?; // 发送 GET 请求
        let status = response.status();

        // 检查响应状态码
        if !status.is_success() {
            return Err(format!("Failed to fetch homepage: {} - {}", url, status).into());
        }

        // 获取 HTML 文本
        let html_text = response.text().await?;
        Ok(html_text)
    }
    async fn html_response(&self, url: &str) -> Result<Response, Box<dyn Error + Send + Sync>> {
        Ok(self.client.get(url).send().await?)
    }

    async fn ckhtml(&self,url:&str,status: &u64, html_text: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let document = Html::parse_document(&html_text); // 解析 HTML 文档
        let title_selector = Selector::parse("title").unwrap_or_else(|_| Selector::parse("*").unwrap());
        let title = if let Some(title_element) = document.select(&title_selector).next() {
            title_element.text().collect::<Vec<_>>().join("")
        } else {
            "Not found title".to_string()
        };
        let len_as_u64 = html_text.len() as u64;
        outprint::Print::okprint(url, status, &len_as_u64,title.as_str());
        Ok(())
    }
    async fn print_cms_response(
        &self,
        final_url: &str,
        response_text: &str,
        status_as_u64: &u64,
        domain: &str,
        fingerprints: &Finger,
        hash_string: String,
        headers: HeaderMap,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let len_as_u64 = response_text.len() as u64;
        self.ckhtml(final_url, status_as_u64, response_text).await?;
        let mut qc_list = vec![];
        for d in &fingerprints.finger {
            if d.matches_rule(&hash_string, &headers, response_text) {
                if !qc_list.contains(&d.cms) {
                    qc_list.push(d.cms.to_string());
                    outprint::Print::cmsprint(domain, status_as_u64, &len_as_u64, &d.cms);
                }
            }
        }
        Ok(()) // 修复：将小写的 ok(()) 改为大写的 Ok(())
    }
    async fn crawing(&self, domain: &str, fingerprints: &Finger) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let url = domain;
        let hash_url = format!("{}/favicon.ico", &url);
        let response = self.html_response(&url).await?;
        let response_hash = self.html_response(&hash_url).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let response_text = response.text().await?;
        let bytes = response_hash.bytes().await?;
        let hash_number = calculate_hash_as_number(&bytes);
        let hash_string = hash_number.to_string();

        match status {
            reqwest::StatusCode::OK | reqwest::StatusCode::FOUND => {
                let mut final_url = url.to_string();
                if status == reqwest::StatusCode::FOUND {
                    if let Some(location) = headers.get(reqwest::header::LOCATION) {
                        if let Ok(location_url) = location.to_str() {
                            final_url = location_url.to_string();
                            outprint::Print::bannerprint(&format!("Redirected to: {}", final_url));
                        }
                    }
                }
                {
                    let mut ok_list = self.ok_list.lock().await;
                    ok_list.push(final_url.clone());
                }
                // outprint::Print::infoprint("Start your first crawl");
                // 第一次爬取：获取初始 URL 列表
                let initial_links = craw::crawmain(&final_url, response_text.as_str()).await?;
                let status_as_u64 = status.as_u16() as u64;
                self.print_cms_response(&final_url, &response_text, &status_as_u64, domain, fingerprints, hash_string, headers).await?;

                // 定义黑名单域名和去重集合
                let excluded_domains = [
                    ".google.com",
                    ".baidu.com",
                    ".cloudflare.com",
                    ".youtube.com",
                    ".cloudflare-dns.com",
                    ".cloudflaressl.com",
                    ".bing.com",
                    ".yahoo.com",
                    ".amazon.com",
                    ".aapanel.com",
                    ".qq.com",
                    ".weibo.com",
                    ".bdstatic.com",
                    ".youdao.com",
                    ".yahoo.cn",
                    ".xunlei.com",
                    ".tudou.com",
                    ".people.com",
                    ".news.cn",
                    ".ludashi.com",
                    ".alipay.com",
                    ".ip138.com",
                    ".ips.com",
                    ".hao123.com",
                    ".google.cn",
                    ".google.hk",
                    ".facebook.com",
                    ".openresty.com"
                ];
                let mut unique_urls = std::collections::HashSet::new();
                let mut rescraw_list = Vec::new();

                // 处理第一次爬取的链接（去重 + 过滤）
                for url in initial_links {
                    if excluded_domains.iter().any(|domain| url.contains(domain)) {
                        continue; // 跳过黑名单域名
                    }
                    if unique_urls.insert(url.clone()) {
                        rescraw_list.push(url);
                    }
                }
                // outprint::Print::infoprint("Start the second crawl");
                // 二次爬取：遍历第一次的结果
                let mut second_crawl_results = Vec::new();
                for url in &rescraw_list {
                    let new_response = match self.html_response(url).await {
                        Ok(res) => res,
                        Err(_e) => {
                            // eprintln!("Failed to crawl {}: {}", url, e);
                            continue;
                        }
                    };
                    let new_response_text = new_response.text().await?;
                    let sub_links = craw::crawmain(url, new_response_text.as_str()).await?;

                    // 处理子链接（去重 + 过滤）
                    for link in sub_links {
                        if excluded_domains.iter().any(|domain| link.contains(domain)) {
                            continue; // 跳过黑名单域名
                        }
                        if unique_urls.insert(link.clone()) {
                            second_crawl_results.push(link);
                        }
                    }
                }

                // 合并两次结果
                rescraw_list.extend(second_crawl_results);

                Ok(rescraw_list)
            }
            reqwest::StatusCode::NOT_FOUND => {
                self.not_found.push(url.to_string()).await;
                Ok(vec![])
            }
            reqwest::StatusCode::FORBIDDEN => {
                self.bypass_list.push(url.to_string()).await;
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }
    // async fn crawing(&self, domain: &str, fingerprints: &Finger) -> Result<Vec<String>,Box<dyn Error + Send + Sync>> {
    //     let url = domain;
    //     let hash_url = format!("{}/favicon.ico", &url);
    //     let response = self.html_response(&url).await?;
    //     let response_hash = self.html_response(&hash_url).await?;
    //     let status = response.status();
    //     let headers = response.headers().clone();
    //     let response_text = response.text().await?;
    //     let bytes = response_hash.bytes().await?;
    //     let hash_number = calculate_hash_as_number(&bytes);
    //     let hash_string = hash_number.to_string();
    //
    //
    //     match status {
    //         reqwest::StatusCode::OK | reqwest::StatusCode::FOUND => {
    //             let mut final_url = url.to_string();
    //             if status == reqwest::StatusCode::FOUND {
    //                 if let Some(location) = headers.get(reqwest::header::LOCATION) {
    //                     if let Ok(location_url) = location.to_str() {
    //                         final_url = location_url.to_string();
    //                         outprint::Print::bannerprint(&format!("Redirected to: {}", final_url)); // 输出跳转连接
    //                         // self.found.push(url.to_string()).await;
    //                     }
    //                 }
    //             }
    //             {
    //                 let mut ok_list = self.ok_list.lock().await;
    //                 ok_list.push(final_url.clone());
    //             }
    //             // 新版检测cms
    //             let rescraw_list = craw::crawmain(&final_url, response_text.as_str()).await?;
    //             let status_as_u64 = status.as_u16() as u64;
    //             self.print_cms_response(&final_url, &response_text, &status_as_u64, domain, fingerprints, hash_string, headers).await?;
    //
    //
    //
    //             // 旧版检测cms
    //             // let rescraw_list = craw::crawmain(&final_url, response_text.as_str()).await?;
    //             // // let rescraw_list = craw::crawmain(&rescraw_list,response_text.as_str()).await?;
    //             // let status_as_u64 = status.as_u16() as u64;
    //             // let len_as_u64 = response_text.len() as u64;
    //             // self.ckhtml(&final_url,&status_as_u64,response_text.as_str()).await?;
    //             // let mut qc_list = vec![];
    //             // for d in &fingerprints.finger {
    //             //     if d.matches_rule(&hash_string, &headers, &response_text) {
    //             //         if !qc_list.contains(&d.cms) {
    //             //             qc_list.push(d.cms.to_string());
    //             //             outprint::Print::cmsprint(domain, &status_as_u64, &len_as_u64, &d.cms);
    //             //         }
    //             //     }
    //             // }
    //
    //
    //             // self.ok_found.push(final_url).await;
    //             Ok(rescraw_list.clone())
    //         }
    //         reqwest::StatusCode::NOT_FOUND => {
    //             self.not_found.push(url.to_string()).await;
    //             Ok(vec![])
    //         }
    //         reqwest::StatusCode::FORBIDDEN => {
    //             self.bypass_list.push(url.to_string()).await;
    //             Ok(vec![])
    //         }
    //         _ => {Ok(vec![])}
    //     }
    // }
    async fn scan_with_path(&self,domain: &str,path:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let client = Arc::new(Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(true).build()?);
        let url = format!("{}{}", domain,path);
        let response = self.client.get(&url).send().await?;
        let status = response.status(); // 先获取状态码
        let html_text = response.text().await?; // 再提取文本内容

        // let url = format!("{}{}", domain,path);
        // let response = client.get(&url).send().await?;
        // let status = response.status();
        // let html_text = response.text().await?;
        if status.is_success() {
            let status_as_u64 = status.as_u16() as u64;
            self.ckhtml(url.as_str(), &status_as_u64,html_text.as_str()).await?;
        }
        Ok(())

    }
    async fn scan_with_bypass(&self,url: &str,ip:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", HeaderValue::from_str(ip)?);  // 添加 X-Forwarded-For 头部
        let response = self.client.get(url).headers(headers).send().await?;
        let status = response.status(); // 先获取状态码
        let html_text = response.text().await?; // 再提取文本内容

        if status.is_success() {
            let status_as_u64 = status.as_u16() as u64;
            self.ckhtml(url, &status_as_u64,html_text.as_str()).await?;
        }
        Ok(())

    }

    pub async fn scan_with_path_t(&self, domain: &str, path: &str, homepage_hash: &[u8], homepage_length: usize,filename:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let client = Arc::new(Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(true).build()?);
        let url = format!("{}/{}", domain.trim_end_matches('/'), path.trim_start_matches('/'));
        let response = self.client.get(&url).send().await?;
        let status = response.status(); // 先获取状态码
        let html_text = response.text().await?; // 再提取文本内容

        // 检查状态码
        if !status.is_success() {
            // println!("{} -> Skipped due to non-success status: {}", url, status);
            return Ok(());
        }

        // 对比哈希值
        let current_hash = Sha256_sha2::digest(html_text.as_bytes());
        if current_hash.as_slice() == homepage_hash {
            // println!("{} -> Skipped as duplicate of homepage", url);
            return Ok(());
        }

        // 检查响应长度
        if html_text.len() == homepage_length {
            // println!("{} -> Skipped due to matching length with homepage", url);
            return Ok(());
        }

        // 如果不匹配，打印唯一响应
        // let status_as_u64 = status.as_u16() as u64;
        // self.ckhtml(url.as_str(), &status_as_u64,html_text.as_str()).await?;
        // println!("{} -> Unique response detected", url);
        let _ = editor_urls_save_to_file(filename,&url);
        Ok(())
    }
}


pub async fn cmsmain(filename:&str,threads: usize,client: Client,domains: Vec<String>,ip_list:Vec<String>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let file_content = include_str!("../config/finger.json");
    let fingerprints: Finger = match serde_json::from_str(&file_content) {
        Ok(fingerprints) => fingerprints,
        Err(e) => {
            outprint::Print::bannerprint(&format!("Error parsing JSON: {}", e));
            return Err(Box::new(e)); // 返回错误
        }
    };
    let fingerprints = Arc::new(fingerprints);
    let c = client.clone();
    let client = Arc::new(client);

    let not_found = Arc::new(NotFound::new());
    let ok_list = Arc::new(Mutex::new(Vec::new()));
    let bypass_list = Arc::new(Bypass::new());
    let crawer = Cmsck {
        client: Arc::clone(&client),
        not_found: Arc::clone(&not_found),
        ok_list: Arc::clone(&ok_list),
        bypass_list: Arc::clone(&bypass_list),
    };
    let mut req_domains = vec![];
    for domain in domains{
        if domain.starts_with("https://") || domain.starts_with("http://") {
            req_domains.push(domain.to_string());
        } else {
            req_domains.push(format!("http://{}", domain.to_string()));
            req_domains.push(format!("https://{}", domain.to_string()));

        };
    }

    let semaphore = Arc::new(Semaphore::new(threads)); // 并发限制
    let rescraw = Arc::new(Mutex::new(Rescraw::new()));
    let mut tasks = vec![];
    for domain in req_domains.clone() {
        let fingerprints = Arc::clone(&fingerprints);
        let crawer = crawer.clone();
        let semaphore = Arc::clone(&semaphore);
        let rescraw = Arc::clone(&rescraw);

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await;
            if let Ok(results) = crawer.crawing(&domain, &fingerprints).await {
                let mut rescraw = rescraw.lock().await;
                rescraw.push(results);
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await?;
    }
    // 调用yaml-poc
    outprint::Print::infoprint("Start loading yaml pocs file");
    // 调用 pocsmain 执行并发验证
    // println!("1");
    pocsmain(req_domains, c.clone()).await?;

    outprint::Print::infoprint("Yaml pocs execution ends");

    let ok_list_urls = ok_list.lock().await.clone();
    if !ok_list_urls.is_empty() {
        outprint::Print::infoprint("Start enumerating editor paths");
        // let paths = Arc::new(include_str!("../dict/path.txt").lines().map(String::from).collect::<Vec<_>>());
        let mut ok_list_tasks = Vec::new();

        let paths = Arc::new(
            include_str!("../dict/path.txt")
                .lines()
                .map(String::from)
                .collect::<Vec<_>>(),
        );

        let filenames = Arc::new(filename.to_string());
        for domain in ok_list_urls {
            let paths = Arc::clone(&paths); // 克隆 `Arc` 引用计数
            // let homepage_html = crawer.fetch_homepage(&domain).await?; // 获取主页内容
            // if homepage_html.is_empty() {
            //     continue;
            // }
            let homepage_html = match crawer.fetch_homepage(&domain).await {
                Ok(content) => content,
                Err(_e) => {
                    // outprint::Print::errprint(&format!("Error fetching homepage for {}: {}", domain, e));
                    // return Err(Box::<dyn Error + Send + Sync>::from(e));
                    continue;
                }
            };
            let homepage_hash = Sha256_sha2::digest(homepage_html.as_bytes()); // 计算主页的哈希值
            let homepage_length = homepage_html.len(); // 记录主页长度

            for path in paths.iter().cloned() { // 克隆路径，确保数据所有权
                let crawer = crawer.clone();
                let semaphore = Arc::clone(&semaphore);
                let domain = domain.clone(); // 克隆 domain，确保独立
                let homepage_hash = homepage_hash.clone(); // 克隆主页哈希值
                let homepage_length = homepage_length; // 直接传递长度（无需克隆）
                let filenames = Arc::clone(&filenames);
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await;
                    // let filenames = filenames.clone();

                    if let Err(_e) = crawer.scan_with_path_t(&domain, &path, &homepage_hash, homepage_length,&filenames).await {
                        // eprintln!("Error during ok_list path scan: {}", e);
                    }
                });

                ok_list_tasks.push(task);
            }
        }
        for task in ok_list_tasks {
            task.await?;
        }
        outprint::Print::infoprint("End of enumerating editor paths");
    }
    let not_found_urls = not_found.take_all().await;

    if !not_found_urls.is_empty() {
        outprint::Print::infoprint("Start enumerating 404 response paths");
        // let contents = fs::read_to_string("dict/path.txt")?;
        let contents = include_str!("../dict/path.txt");
        let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
        let mut notfound_tasks = vec![];

        for domain in not_found_urls {
            for path in lines.iter() {
                let crawer = crawer.clone();
                let path = path.clone(); // 确保路径的独立性
                let semaphore = semaphore.clone();
                let domain = domain.clone();
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await; // 限制并发
                    if let Err(_e) = crawer.scan_with_path(&domain, &path).await {
                        // outprint::Print::errprint(format!("Error crawling {}: {}", domain, e).as_str());
                    }
                });
                notfound_tasks.push(task);
            }
        }

        for task in notfound_tasks {
            task.await?;
        }
        outprint::Print::infoprint("End of enumeration 404 response path");
    }

    let bypass_urls = bypass_list.take_all().await;

    if !bypass_urls.is_empty() {
        outprint::Print::infoprint("Start Bypass 403 response urls");
        // let contents = include_str!("../dict/path.txt");
        // let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
        let mut bypass_tasks = vec![];

        for domain in bypass_urls.clone() {
            for ip in ip_list.iter() {
                let crawer = crawer.clone();
                let ip = ip.clone(); // 确保路径的独立性
                let semaphore = semaphore.clone();
                let domain = domain.clone();
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await; // 限制并发
                    if let Err(_e) = crawer.scan_with_bypass(&domain, &ip).await {
                        // outprint::Print::errprint(format!("Error crawling {}: {}", domain, e).as_str());
                    }
                });
                bypass_tasks.push(task);
            }
        }

        for task in bypass_tasks {
            task.await?;
        }
        outprint::Print::infoprint("End of enumeration 403 response urls");
        tofile::bypass_urls_save_to_file(filename,&bypass_urls)?;
        outprint::Print::bannerprint(format!("403 URL saving in: {} ",filename).as_str());
    }



    let rescraw_locked = rescraw.lock().await;
    if rescraw_locked.rt().is_empty() {
        return Ok(());
    }
    outprint::Print::bannerprint(format!("A total of {} URLs with parameters were found",rescraw_locked.rt().len()).as_str());
    #[allow(dead_code)]
    let res = rescraw_locked.rt();

    tofile::urls_save_to_file(filename,&res.clone())?;

    outprint::Print::bannerprint(format!("URL saving address with parameters: {} ",filename).as_str());
    outprint::Print::infoprint("Start detecting parameter vulnerabilities");
    let _ = vulns::vulnmain(threads,c,res).await;
    Ok(())
}
