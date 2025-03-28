// pocscan.rs
use reqwest::{Client, header::{HeaderMap, HeaderValue, HeaderName}};
use serde::Deserialize;
use std::{collections::HashMap, error::Error, time::Duration, sync::Arc};
// use bytes::BufMut;
use tokio::sync::Semaphore;
// use futures::StreamExt;
use crate::outprint::Print;
use crate::tofile::yaml_vuln_save_to_file;
#[derive(Debug, Deserialize, Clone)]
struct Poc {
    metch: String,
    path: String,
    body: Vec<String>,
    #[serde(rename = "matchers-condition")]
    matchers_condition: String,
    name: String,
    header: Option<HashMap<String, String>>,
    data: Option<String>,
    json: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Pocs {
    pocs: Vec<Poc>,
}

impl Pocs {
    pub fn from_yaml(content: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(serde_yaml::from_str(content)?)
    }
}

async fn send_request(client: &Client, base_url: &str, poc: &Poc) -> Result<String, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", base_url, poc.path);
    let mut headers = HeaderMap::new();

    if let Some(header_map) = &poc.header {
        for (k, v) in header_map {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes())?,
                HeaderValue::from_str(v)?,
            );
        }
    }

    let request_builder = match poc.metch.to_lowercase().as_str() {
        "get" => client.get(&url).headers(headers),
        "post" => {
            let body = match &poc.json {
                Some(data) => serde_json::to_string(data)?,
                None => match &poc.data {
                    Some(data) => serde_urlencoded::to_string(data)?,
                    None => String::new(),
                },
            };
            client.post(&url).headers(headers).body(body)
        }
        _ => client.get(&url).headers(headers),
    };

    let response = request_builder
        .timeout(Duration::from_secs(20))
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {  // 400+ 状态码直接返回
        return Ok(String::new());
    }
    Ok(response.text().await?)
    // const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
    //
    // // 根据响应头预判响应大小
    // let content_length = response.content_length().unwrap_or(0) as usize;
    // let initial_capacity = match content_length {
    //     0 => 0,  // 空响应不分配内存
    //     len if len <= MAX_RESPONSE_SIZE => len.min(4096),  // 小响应预分配
    //     _ => MAX_RESPONSE_SIZE  // 大响应直接预分配最大值
    // };
    //
    // // 使用BytesMut提升内存效率
    // let mut body = bytes::BytesMut::with_capacity(initial_capacity);
    // let mut stream = response.bytes_stream();
    //
    // // 使用异步流处理优化
    // let mut total_size = 0;
    // while let Some(chunk) = stream.next().await {
    //     let chunk = chunk?;
    //     let chunk_size = chunk.len();
    //
    //     // 提前终止逻辑
    //     if total_size + chunk_size > MAX_RESPONSE_SIZE {
    //         let remaining = MAX_RESPONSE_SIZE - total_size;
    //         body.extend_from_slice(&chunk[..remaining]);
    //         break;
    //     }
    //
    //     // 按需扩容策略
    //     if body.remaining_mut() < chunk_size {
    //         body.reserve(chunk_size.min(MAX_RESPONSE_SIZE - total_size));
    //     }
    //
    //     body.extend_from_slice(&chunk);
    //     total_size += chunk_size;
    //
    //     // 小响应提前退出
    //     if content_length > 0 && total_size >= content_length {
    //         break;
    //     }
    // }

    // 零拷贝转换（仅当需要String时）
    // if body.is_empty() {
    //     Ok(String::new())
    // } else {
    //     Ok(String::from_utf8_lossy(&body.freeze()).into_owned())
    // }
}

fn check_vulnerability(response: &str, poc: &Poc) -> bool {
    let check_any = |text: &str| poc.body.iter().any(|s| text.contains(s));
    let check_all = |text: &str| poc.body.iter().all(|s| text.contains(s));

    match poc.matchers_condition.as_str() {
        "or" => check_any(response),
        "and" => check_all(response),
        _ => false,
    }
}

async fn check_poc(client: Client, base_url: String, poc: Poc,filename:&str) {
    match send_request(&client, &base_url, &poc).await {
        Ok(response) => {
            if check_vulnerability(&response, &poc) {
                let name = poc.name.clone();
                let url = format!("{}{}", base_url, poc.path);
                yaml_vuln_save_to_file(filename, &name,&url).expect("TODO: panic message");
                Print::yamlvulnprint(&name, &url);
                
            }
        }
        Err(_e) => {
            // eprintln!("Request failed: {}", e);
        }
    }
}

pub async fn pocsmain(targets: Vec<String>, client: Client,filename:&str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let yaml_content = include_str!("../config/pocs.yaml");
    let pocs = Pocs::from_yaml(yaml_content)?;

    // 限制最大并发数为200
    let semaphore = Arc::new(Semaphore::new(200));
    let mut tasks = vec![];
    let filename_arc = Arc::new(filename.to_string());
    for target in targets {
        for poc in &pocs.pocs {
            let filename_clone = Arc::clone(&filename_arc);
            let client = client.clone();
            let target = target.clone();
            let poc = poc.clone();
            let semaphore = semaphore.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.expect("Semaphore acquire failed");
                check_poc(client, target, poc,&filename_clone).await;
            }));
        }
    }

    futures::future::join_all(tasks).await;
    Ok(())
}