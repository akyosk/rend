
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use reqwest::{Client, Response};
use serde::Deserialize;
use ring::digest::{Context, Digest, SHA256};
use tokio::sync::Semaphore;
use scraper::{Html, Selector};
use tokio::sync::Mutex;
use crate::outprint;
use crate::craw;
use crate::vulns;
use crate::tofile;
#[derive(Debug, Clone,Deserialize)]
struct FingerPrint {
    cms: String,
    keyword: Vec<String>,
    location: String,
    method:String,
}
enum Method {
    FaviconHash,
    Header,
    Keyword,
    Unknown,
}

impl Method {
    fn from_str(method: &str) -> Self {
        match method {
            "faviconhash" => Method::FaviconHash,
            "header" => Method::Header,
            "keyword" => Method::Keyword,
            _ => Method::Unknown,
        }
    }
}
#[derive(Debug, Clone,Deserialize)]
struct Finger {
    fingerprint: Vec<FingerPrint>,
}
impl Finger {
    fn new() -> Self{
        Finger {
            fingerprint: Vec::new(),
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
struct Resulturls{
    urls: Vec<String>,
}
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
}

impl Cmsck {
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
    async fn crawing(&self, domain: &str, fingerprints: &Finger) -> Result<Vec<String>,Box<dyn Error + Send + Sync>> {
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
            reqwest::StatusCode::OK => {
                let rescraw_list = craw::crawmain(&url,response_text.as_str()).await?;
                let status_as_u64 = status.as_u16() as u64;
                let len_as_u64 = response_text.len() as u64;
                self.ckhtml(&url,&status_as_u64,response_text.as_str()).await?;
                let mut qc_list = vec![];
                for d in &fingerprints.fingerprint {
                    match d.method.as_str() {
                        "faviconhash" if d.keyword.iter().all(|kw| hash_string.contains(kw)) => {
                            if !qc_list.contains(&d.cms){
                                qc_list.push(d.cms.to_string());
                                outprint::Print::cmsprint(domain, &status_as_u64, &len_as_u64, &d.cms);
                            }

                        }
                        "header" if d.keyword.iter().all(|kw| {
                            headers.iter().any(|(key, value)| {
                                key.as_str().contains(kw) || value.to_str().unwrap_or_default().contains(kw)
                            })
                        }) => {
                            if !qc_list.contains(&d.cms){
                                qc_list.push(d.cms.to_string());
                                outprint::Print::cmsprint(domain, &status_as_u64, &len_as_u64, &d.cms);
                            }

                        }
                        _ if d.location != "header" && d.keyword.iter().all(|kw| response_text.contains(kw)) => {
                            if !qc_list.contains(&d.cms){
                                qc_list.push(d.cms.to_string());
                                outprint::Print::cmsprint(domain, &status_as_u64, &len_as_u64, &d.cms);
                            }

                        }
                        _ => {}
                    }

                }
                Ok(rescraw_list.clone())
            }
            reqwest::StatusCode::NOT_FOUND => {
                self.not_found.push(url.to_string()).await;
                Ok(vec![])
            }
            _ => {Ok(vec![])}
        }
    }
    async fn notfound(&self,domain: &str,path:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let client = Arc::new(Client::builder().timeout(Duration::from_secs(10)).danger_accept_invalid_certs(true).build()?);
        let url = format!("{}{}", domain,path);
        let response = client.get(&url).send().await?;
        let status = response.status();
        let html_text = response.text().await?;
        if status.is_success() {
            let status_as_u64 = status.as_u16() as u64;
            self.ckhtml(url.as_str(), &status_as_u64,html_text.as_str()).await?;
        }
        Ok(())

    }
}


pub async fn cmsmain(filename:&str,threads: usize,client: Client,domains: Vec<String>) -> Result<(), Box<dyn Error + Send + Sync>> {
    // let file_content = fs::read_to_string("config/finger.json")?;
    let file_content = include_str!("../config/finger.json");
    let fingerprints: Finger = serde_json::from_str(&file_content)?;
    let fingerprints = Arc::new(fingerprints);
    let c = client.clone();
    let client = Arc::new(client);

    let not_found = Arc::new(NotFound::new());
    let crawer = Cmsck {
        client: Arc::clone(&client),
        not_found: Arc::clone(&not_found),
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
    for domain in req_domains {
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
    let not_found_urls = not_found.take_all().await;
    if !not_found_urls.is_empty() {
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
                    if let Err(e) = crawer.notfound(&domain, &path).await {
                        // outprint::Print::errprint(format!("Error crawling {}: {}", domain, e).as_str());
                    }
                });
                notfound_tasks.push(task);
            }
        }

        for task in notfound_tasks {
            task.await?;
        }

    }


    let rescraw_locked = rescraw.lock().await;
    if rescraw_locked.rt().is_empty() {
        return Ok(());
    }
    outprint::Print::bannerprint(format!("A total of {} URLs with parameters were found",rescraw_locked.rt().len()).as_str());
    outprint::Print::infoprint("Start detecting parameter vulnerabilities");
    let res = rescraw_locked.rt();
    tofile::urls_save_to_file(filename.clone(),&res.clone())?;
    outprint::Print::bannerprint(format!("URL saving address with parameters: {} ",filename.clone()).as_str());
    let _ = vulns::vulnmain(threads,c,res).await;
    Ok(())
}
