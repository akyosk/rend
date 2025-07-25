use std::error::Error;
use std::sync::Arc;
use std::collections::HashSet;
use reqwest::{Client, Response};
use serde::Deserialize;
use ring::digest::{Context, Digest, SHA256};
use tokio::sync::Semaphore;
use scraper::{Html, Selector};
use tokio::sync::Mutex;
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::time::Duration;
use crate::outprint;
use crate::craw;
use crate::vulns;
use crate::tofile;
use sha2::{Digest as Digest_sha2, Sha256 as Sha256_sha2};
use crate::infoscan::{OtherSets};
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

struct Unauthorized{
    url: Mutex<Vec<String>>,
}
impl Unauthorized {
    fn new() -> Self{
        Unauthorized{
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
    unauthorized_list: Arc<Unauthorized>,

}

impl Cmsck {
    /// 获取目标域名的主页内容
    pub async fn fetch_homepage(&self, domain: &str) -> Result<(String,String), Box<dyn Error + Send + Sync>> {
        let url = format!("{}/kindedasaioadsjson", domain.trim_end_matches('/')); // 确保域名格式正确
        let response = self.client.get(&url).send().await?; // 发送 GET 请求
        let status = response.status();
        let resp_url = response.url().to_string();
        // 检查响应状态码
        if !status.is_success() {
            return Ok(("None".to_string(), domain.to_string()));
        }

        // 获取 HTML 文本
        let html_text = response.text().await?;

        Ok((html_text,resp_url))
    }
    async fn html_response(&self, url: &str) -> Result<Response, Box<dyn Error + Send + Sync>> {
        Ok(self.client.get(url).send().await?)
    }

    async fn ckhtml(&self,url:&str,status: &u64, html_text: &str,filename:&str,ip:Option<&str>) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let document = Html::parse_document(&html_text); // 解析 HTML 文档
        // let title_selector = Selector::parse("title").unwrap_or_else(|_| Selector::parse("*").unwrap());
        // let title = if let Some(title_element) = document.select(&title_selector).next() {
        //     title_element.text().collect::<Vec<_>>().join("")
        // } else {
        //     "Not found title".to_string()
        // };
        let title = self.gettitle(&html_text).await.unwrap_or("Not found title".to_string());
        let len_as_u64 = html_text.len() as u64;

        if ip.is_none() {
            outprint::Print::okprint(url, status, &len_as_u64,title.as_str());
            let _ = tofile::req_urls_save_to_file(filename,url, status, &len_as_u64,title.as_str(),None);
        } else {
            outprint::Print::vuln_bypass(url, status, &len_as_u64,title.as_str(),ip);
            let _ = tofile::req_urls_save_to_file(filename, url, status, &len_as_u64, title.as_str(), ip);
        }
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
        filename:&str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let len_as_u64 = response_text.len() as u64;
        self.ckhtml(final_url, status_as_u64, response_text,&filename,None).await?;
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
    async fn crawing(&self, domain: &str, fingerprints: &Finger,filename: &str,other_sets: &OtherSets) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
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
                let initial_links = craw::crawmain(&final_url, response_text.as_str(),other_sets).await?;
                let status_as_u64 = status.as_u16() as u64;
                self.print_cms_response(&final_url, &response_text, &status_as_u64, domain, fingerprints, hash_string, headers,&filename).await?;

                let mut unique_urls = std::collections::HashSet::new();
                let mut rescraw_list = Vec::new();

                // 处理第一次爬取的链接（去重 + 过滤）
                for url in initial_links {
                    if other_sets.pass_domain.iter().any(|domain| url.contains(domain)) {
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
                    let sub_links = craw::crawmain(url, new_response_text.as_str(),other_sets).await?;

                    // 处理子链接（去重 + 过滤）
                    for link in sub_links {
                        if other_sets.pass_domain.iter().any(|domain| link.contains(domain)) {
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
            reqwest::StatusCode::UNAUTHORIZED => {
                outprint::Print::unauthorizedprint(url);
                self.unauthorized_list.push(url.to_string()).await;

                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }
    async fn scan_with_path(&self,domain: &str,path:&str,filename:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let client = Arc::new(Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(true).build()?);
        let url = format!("{}{}", domain,path);
        let response = self.client.get(&url).timeout(Duration::from_secs(10)).send().await?;
        let status = response.status(); // 先获取状态码
        let html_text = response.text().await?; // 再提取文本内容

        if status.is_success() || status.as_u16() == 403 || status.as_u16() == 302 {
            if status.as_u16() == 403 {
                self.bypass_list.push(url.to_string()).await;
            }
            if html_text.len() != 0{
                let status_as_u64 = status.as_u16() as u64;
                self.ckhtml(url.as_str(), &status_as_u64,html_text.as_str(),&filename,None).await?;
            }



        }
        Ok(())

    }
    async fn scan_with_bypass(&self,url: &str,ip:&str,filename:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", HeaderValue::from_str(ip)?);  // 添加 X-Forwarded-For 头部
        let response = self.client.get(url).headers(headers).send().await?;
        let status = response.status(); // 先获取状态码
        let html_text = response.text().await?; // 再提取文本内容

        if status.is_success() || status.as_u16() == 302 {
            let status_as_u64 = status.as_u16() as u64;
            self.ckhtml(url, &status_as_u64,html_text.as_str(),&filename,Some(&ip)).await?;
        }
        Ok(())

    }
    async fn gettitle(&self,html_text: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let document = Html::parse_document(&html_text); // 解析 HTML 文档
        let title_selector = Selector::parse("title").unwrap_or_else(|_| Selector::parse("*").unwrap());
        let title = if let Some(title_element) = document.select(&title_selector).next() {
            title_element.text().collect::<Vec<_>>().join("")
        } else {
            "Not found title".to_string()

        };
        Ok(title)
    }
    pub async fn scan_with_path_t(&self, domain: &str, path: &str, homepage_hash: &[u8], homepage_length: usize,homepage_url:&str,filename:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let client = Arc::new(Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(true).build()?);
        let url = format!("{}/{}", domain.trim_end_matches('/'), path.trim_start_matches('/'));
        let response = self.client.get(&url).timeout(Duration::from_secs(5)).send().await?;
        let status = response.status(); // 先获取状态码
        if !status.is_success() {
            return Ok(());
        }
        let resp_url = response.url().as_str().to_string();
        let html_text = response.text().await?; // 再提取文本内容
        if html_text.clone().contains("404 Not Found") || html_text.clone().contains("\"code\":404,\"msg\":") {
            return Ok(());
        }

        // let resp_url = response.url().as_str();
        if resp_url == homepage_url {
            return Ok(());
        }
        if resp_url.contains("=") && resp_url.contains(homepage_url) {
            return Ok(());
        }

        // let document = Html::parse_document(&html_text);
        // let title_selector = Selector::parse("title").unwrap_or_else(|_| Selector::parse("*").unwrap());
        // let title = if let Some(title_element) = document.read().unwrap().select(&title_selector).next() {
        //     title_element.text().collect::<Vec<_>>().join("")
        // } else {
        //     return Ok(()); // 如果获取不到 title，直接返回
        // };
        let title = self.gettitle(html_text.as_str()).await;
        if let Ok(t) = title {
            if t == "Not found title" || t == "403 Forbidden" || t == "安全入口校验失败" {
                return Ok(());
            }
        }

        // 检查状态码
        if status.as_u16() == 403{
            self.bypass_list.push(url.to_string()).await;
        }
        if status.as_u16() == 302{
            self.bypass_list.push(url.to_string()).await;
            let status_as_u64 = status.as_u16() as u64;
            self.ckhtml(&url, &status_as_u64,html_text.as_str(),filename,None).await?;
        }


        // 对比哈希值
        let current_hash = Sha256_sha2::digest(html_text.as_bytes());
        if current_hash.as_slice() == homepage_hash {
            return Ok(());
        }

        // 检查响应长度
        if html_text.len() == homepage_length {
            return Ok(());
        }

        let status_as_u64 = status.as_u16() as u64;
        self.ckhtml(&url, &status_as_u64,html_text.as_str(),filename,None).await?;
        let _ = editor_urls_save_to_file(filename,&url);
        Ok(())
    }
}


pub async fn cmsmain(filename:&str,threads: usize,client: Client,domains: Vec<String>,mut ip_list:Vec<String>,otherset:OtherSets) -> Result<(), Box<dyn Error + Send + Sync>> {
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
    let otherset = Arc::new(otherset);
    let not_found = Arc::new(NotFound::new());
    let ok_list = Arc::new(Mutex::new(Vec::new()));
    let bypass_list = Arc::new(Bypass::new());
    let unauthorized_list = Arc::new(Unauthorized::new());
    let crawer = Cmsck {
        client: Arc::clone(&client),
        not_found: Arc::clone(&not_found),
        ok_list: Arc::clone(&ok_list),
        bypass_list: Arc::clone(&bypass_list),
        unauthorized_list: Arc::clone(&unauthorized_list),
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
    let req_domains_set: HashSet<String> = req_domains.into_iter().collect();
    let req_domains: Vec<String> = req_domains_set.into_iter().collect();
    let semaphore = Arc::new(Semaphore::new(threads)); // 并发限制
    let rescraw = Arc::new(Mutex::new(Rescraw::new()));
    let filename_clone = Arc::new(filename.to_string());
    let mut tasks = vec![];
    let _ = tofile::other_save_to_file(&filename,"\n[URLS CMS INFO]");
    for domain in req_domains.clone() {
        let otherset_clone = Arc::clone(&otherset);
        let filename = Arc::new(filename_clone.to_string());
        let fingerprints = Arc::clone(&fingerprints);
        let crawer = crawer.clone();
        let semaphore = Arc::clone(&semaphore);
        let rescraw = Arc::clone(&rescraw);
        let filename = Arc::clone(&filename);

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await;
            if let Ok(results) = crawer.crawing(&domain, &fingerprints,&filename,&otherset_clone).await {
                let mut rescraw = rescraw.lock().await;
                rescraw.push(results);
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await?;
    }


    let ok_list_urls = ok_list.lock().await.clone();
    let not_found_urls = not_found.take_all().await;
    let bypass_urls = bypass_list.take_all().await;
    let unauthorized_urls = unauthorized_list.take_all().await;
    // 调用yaml-poc
    outprint::Print::infoprint("Start loading yaml pocs file");
    // 调用 pocsmain 执行并发验证

    fn merge_and_deduplicate(vec1: Vec<String>, vec2: Vec<String>, vec3: Vec<String>,vec4: Vec<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        // 按顺序遍历所有元素，保留首次出现的元素
        for s in vec1.into_iter().chain(vec2).chain(vec3).chain(vec4) {
            if seen.insert(s.clone()) { // HashSet.insert() 返回是否是新插入
                result.push(s);
            }
        }

        result
    }
    let _ = tofile::other_save_to_file(&filename,"\n[VULNS INFO]");
    let pocs_req_domains = merge_and_deduplicate(ok_list_urls.clone(), not_found_urls.clone(), bypass_urls.clone(),unauthorized_urls.clone());
    pocsmain(pocs_req_domains, c.clone(),filename).await?;


    outprint::Print::infoprint("Yaml pocs execution ends");

    // let ok_list_urls = ok_list.lock().await.clone();
    if !unauthorized_urls.is_empty() {
        let _ = tofile::other_save_to_file(filename,"\n[401 URLS]");
        tofile::bypass_urls_save_to_file(&filename, &unauthorized_urls)?;
        outprint::Print::bannerprint(format!("401 URL saving in: {} ",filename).as_str());
    }
    if !ok_list_urls.is_empty() {
        outprint::Print::infoprint("Start enumerating editor paths");
        let _ = tofile::other_save_to_file(filename,"\n[URLS PATH INFO]");
        // let paths = Arc::new(include_str!("../dict/path.txt").lines().map(String::from).collect::<Vec<_>>());
        let mut ok_list_tasks = Vec::new();
        let paths = Arc::new(
            include_str!("../dict/path.txt")
                .lines()
                .map(String::from)
                .collect::<Vec<_>>(),
        );
        let filename = Arc::new(filename.to_string());
        for domain in ok_list_urls {
            let paths = Arc::clone(&paths); // 克隆 `Arc` 引用计数
            let (homepage_html, homepage_url) = match crawer.fetch_homepage(&domain).await {
                Ok(content) => content,
                Err(_e) => {
                    // eprintln!("Failed to fetch homepage for {}: {}", domain, e);
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
                let homepage_url = homepage_url.clone();
                let filename = Arc::clone(&filename);
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await;
                    // let filenames = filenames.clone();
                    if let Err(_e) = crawer.scan_with_path_t(&domain, &path, &homepage_hash, homepage_length,&homepage_url,&filename).await {
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
    // let not_found_urls = not_found.take_all().await;

    if !not_found_urls.is_empty() {
        outprint::Print::infoprint("Start enumerating 404 response paths");
        // let contents = fs::read_to_string("dict/path.txt")?;
        let contents = include_str!("../dict/path.txt");
        let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
        let mut notfound_tasks = vec![];
        let filename = Arc::new(filename.to_string());
        for domain in not_found_urls {
            for path in lines.iter() {
                let crawer = crawer.clone();
                let path = path.clone(); // 确保路径的独立性
                let semaphore = semaphore.clone();
                let domain = domain.clone();
                let filename = Arc::clone(&filename);
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await; // 限制并发
                    if let Err(_e) = crawer.scan_with_path(&domain, &path,&filename).await {
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

    // let bypass_urls = bypass_list.take_all().await;

    if !bypass_urls.is_empty() {
        outprint::Print::infoprint("Start Bypass 403 response urls");
        let _ = tofile::other_save_to_file(filename,"\n[403 Bypass URLS]");
        // let contents = include_str!("../dict/path.txt");
        // let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
        let mut bypass_tasks = vec![];
        ip_list.push("127.0.0.1".to_string()); // 绕xff
        let filename = Arc::new(filename.to_string());
        for domain in bypass_urls.clone() {
            for ip in ip_list.iter() {
                let crawer = crawer.clone();
                let ip = ip.clone(); // 确保路径的独立性
                let semaphore = semaphore.clone();
                let domain = domain.clone();
                let filename = Arc::clone(&filename);
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await; // 限制并发
                    if let Err(_e) = crawer.scan_with_bypass(&domain, &ip,&filename).await {
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
        tofile::bypass_urls_save_to_file(&filename, &bypass_urls)?;
        outprint::Print::bannerprint(format!("403 URL saving in: {} ",filename).as_str());
    }



    let rescraw_locked = rescraw.lock().await;
    if rescraw_locked.rt().is_empty() {
        return Ok(());
    }
    outprint::Print::bannerprint(format!("A total of {} URLs with parameters were found",rescraw_locked.rt().len()).as_str());
    #[allow(dead_code)]
    let mut res = rescraw_locked.rt();

    fn filter_domains(res: &mut Vec<String>, pass_domain: &[&str]) {
        res.retain(|s| !pass_domain.iter().any(|&domain| s.contains(domain)));
    }
    // 过滤res
    let pass_domain: Vec<&str> = otherset.pass_domain.iter().map(|s| s.as_str()).collect();
    filter_domains(&mut res, &pass_domain);

    // // 输出结果
    // println!("过滤后的res: {:?}", res);

    tofile::urls_save_to_file(&filename, &res.clone())?;

    outprint::Print::bannerprint(format!("URL saving address with parameters: {} ",filename).as_str());
    outprint::Print::infoprint("Start detecting parameter vulnerabilities");
    let _ = vulns::vulnmain(threads,c,res).await;
    Ok(())
}
