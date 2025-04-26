// pocscan.rs
use reqwest::{Client, header::{HeaderMap, HeaderValue, HeaderName}};
use serde::Deserialize;
use std::{collections::HashMap, error::Error, time::Duration, sync::{Arc, Mutex}};
use tokio::sync::Semaphore;
use crate::outprint::Print;
use crate::tofile::yaml_vuln_save_to_file;

// 匹配yaml中的实际结构
#[derive(Debug, Deserialize, Clone)]
struct Matcher {
    #[serde(rename = "type")]
    matcher_type: String,
    part: String,
    words: Vec<String>,
    condition: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Request {
    method: String,
    path: String,
    matchers: Vec<Matcher>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct Poc {
    #[allow(dead_code)]
    id: String,
    name: String,
    requests: Vec<Request>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Pocs {
    pocs: Vec<Poc>,
}

// 定义一个结构来存储检测到的漏洞信息
#[derive(Debug, Clone)]
struct VulnInfo {
    name: String,
    url: String,
}

impl Pocs {
    pub fn from_yaml(content: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(serde_yaml::from_str(content)?)
    }
}

struct ResponseData {
    headers: HeaderMap,
    body: String,
}

async fn send_request(client: &Client, base_url: &str, request: &Request) -> Result<ResponseData, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", base_url, request.path);
    let mut headers = HeaderMap::new();

    if let Some(header_map) = &request.headers {
        for (k, v) in header_map {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes())?,
                HeaderValue::from_str(v)?,
            );
        }
    }

    // 设置默认Content-Type如果是POST请求但没有指定
    if request.method.to_lowercase() == "post" && !headers.contains_key("content-type") {
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    }

    // 判断是否只需要检查header
    let only_check_headers = request.matchers.iter().all(|m| m.part == "header");

    let response = if only_check_headers {
        // 如果只需检查header，使用HEAD请求
        client.head(&url)
            .headers(headers)
            .timeout(Duration::from_secs(30))  // 可以缩短HEAD请求的超时时间
            .send()
            .await?
    } else {
        // 否则使用原来的请求方式
        let request_builder = match request.method.to_lowercase().as_str() {
            "get" => client.get(&url).headers(headers),
            "post" => {
                let body = request.body.clone().unwrap_or_default();
                client.post(&url).headers(headers).body(body)
            }
            _ => client.get(&url).headers(headers),
        };

        request_builder
            .timeout(Duration::from_secs(20))
            .send()
            .await?
    };

    let status = response.status();
    if !status.is_success() {  // 400+ 状态码直接返回
        return Ok(ResponseData {
            headers: HeaderMap::new(),
            body: String::new(),
        });
    }

    // 保存响应头
    let headers = response.headers().clone();

    // 获取响应体 - 只有在非HEAD请求时才获取
    let body = if only_check_headers {
        String::new()  // HEAD请求不需要读取body
    } else {
        response.text().await?
    };

    Ok(ResponseData { headers, body })
}

fn check_vulnerability(response: &ResponseData, matcher: &Matcher) -> bool {
    if matcher.matcher_type != "word" {
        return false;  // 只处理word类型的匹配器
    }

    match matcher.part.as_str() {
        "body" => {
            // 匹配响应体
            let check_any = |text: &str| matcher.words.iter().any(|s| text.contains(s));
            let check_all = |text: &str| matcher.words.iter().all(|s| text.contains(s));

            match matcher.condition.as_str() {
                "or" => check_any(&response.body),
                "and" => check_all(&response.body),
                _ => false,
            }
        },
        "header" => {
            // 匹配响应头
            let check_header_any = || {
                for word in &matcher.words {
                    // 检查是否有任何响应头的值包含指定的字符串
                    for (_, value) in response.headers.iter() {
                        if let Ok(value_str) = value.to_str() {
                            if value_str.contains(word) {
                                return true;
                            }
                        }
                    }
                    // 或者检查Content-Type头是否匹配
                    if response.headers.get("content-type").map_or(false, |v| {
                        v.to_str().map_or(false, |s| s.contains(word))
                    }) {
                        return true;
                    }
                }
                false
            };

            let check_header_all = || {
                matcher.words.iter().all(|word| {
                    response.headers.iter().any(|(_, value)| {
                        value.to_str().map_or(false, |s| s.contains(word))
                    }) ||
                        response.headers.get("content-type").map_or(false, |v| {
                            v.to_str().map_or(false, |s| s.contains(word))
                        })
                })
            };

            match matcher.condition.as_str() {
                "or" => check_header_any(),
                "and" => check_header_all(),
                _ => false,
            }
        },
        _ => false, // 不支持的部分
    }
}

async fn check_poc(client: Client, base_url: String, poc: Poc, vuln_results: Arc<Mutex<Vec<VulnInfo>>>) {
    for request in &poc.requests {
        match send_request(&client, &base_url, request).await {
            Ok(response) => {
                // 检查所有匹配器
                for matcher in &request.matchers {
                    if check_vulnerability(&response, matcher) {
                        let name = poc.name.clone();
                        let url = format!("{}{}", base_url, request.path);

                        // 将结果存入共享的漏洞列表中
                        {
                            let mut results = vuln_results.lock().unwrap();
                            results.push(VulnInfo { name: name.clone(), url: url.clone() });
                        }

                        // 仅打印结果，不写入文件
                        Print::yamlvulnprint(&name, &url);
                        break;  // 匹配到一个就跳出当前request的检查
                    }
                }
            }
            Err(_) => {
                // 请求失败，静默处理
            }
        }
    }
}

pub async fn pocsmain(targets: Vec<String>, client: Client, filename: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let yaml_content = include_str!("../config/pocs.yaml");
    let pocs = Pocs::from_yaml(yaml_content)?;

    let semaphore = Arc::new(Semaphore::new(200));
    let mut tasks = vec![];

    // 创建一个共享的漏洞结果列表
    let vuln_results: Arc<Mutex<Vec<VulnInfo>>> = Arc::new(Mutex::new(Vec::new()));

    for target in targets {
        for poc in &pocs.pocs {
            let client = client.clone();
            let target = target.clone();
            let poc = poc.clone();
            let semaphore = semaphore.clone();
            let vuln_results = vuln_results.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.expect("Semaphore acquire failed");
                check_poc(client, target, poc, vuln_results).await;
            }));
        }
    }

    // 等待所有任务完成
    futures::future::join_all(tasks).await;

    // 所有检测完成后，统一将结果写入文件
    let results = vuln_results.lock().unwrap();
    if !results.is_empty() {
        // 批量写入文件
        let mut success = true;
        for vuln in results.iter() {
            if let Err(_e) = yaml_vuln_save_to_file(filename, &vuln.name, &vuln.url) {
                // eprintln!("保存漏洞信息失败: {}", e);
                success = false;
            }
        }

        if success {
            Print::bannerprint(format!("{} vulnerability information has been saved to the file {}", results.len(), filename).as_str());
        }
    }

    Ok(())
}