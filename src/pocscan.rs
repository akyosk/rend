// pocscan.rs
use reqwest::{Client, header::{HeaderMap, HeaderValue, HeaderName}};
use serde::Deserialize;
use std::{collections::HashMap, error::Error, time::Duration};
use url::Url;
use crate::outprint::Print;

#[derive(Debug, Deserialize, Clone)]
struct Poc {
    metch: String,
    path: String,
    body: Vec<String>,
    #[serde(rename = "matchers-condition")]
    matchers_condition: String,
    name: String,
    header: Option<HashMap<String, String>>,
    data: Option<HashMap<String, String>>,
    json: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Pocs {
    pocs: Vec<Poc>,
}

impl Pocs {
    pub fn from_yaml(content: &str) -> Result<Self, Box<dyn Error>> {
        Ok(serde_yaml::from_str(content)?)
    }
}

async fn send_request(client: &Client, base_url: &str, poc: &Poc) -> Result<String, Box<dyn Error>> {
    let mut url = Url::parse(base_url)?;
    url.path_segments_mut()
        .map_err(|_| "Invalid base URL")?
        .pop_if_empty()
        .extend(poc.path.split('/').filter(|s| !s.is_empty()));

    let mut headers = HeaderMap::new();
    if let Some(header_map) = &poc.header {
        for (k, v) in header_map {
            let name = HeaderName::from_bytes(k.as_bytes())?;
            let value = HeaderValue::from_str(v)?;
            headers.insert(name, value);
        }
    }

    let request_builder = match poc.metch.to_lowercase().as_str() {
        "get" => client.get(url.as_str()).headers(headers),
        "post" => {
            let body = match &poc.json {
                Some(data) => serde_json::to_string(data)?,
                None => match &poc.data {
                    Some(data) => serde_urlencoded::to_string(data)?,
                    None => String::new(),
                },
            };
            client.post(url.as_str()).headers(headers).body(body)
        }
        _ => client.get(url.as_str()).headers(headers),
    };

    let response = request_builder
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    response.text().await.map_err(|e| e.into())
}

fn check_vulnerability(response: &str, poc: &Poc) -> bool {
    let check_any = |text: &str| poc.body.iter().any(|s| text.contains(s));
    let check_all = |text: &str| poc.body.iter().all(|s| text.contains(s));

    match poc.matchers_condition.as_str() {
        "or" => check_any(response),
        "and" => check_all(response),
        _ => false
    }
}

async fn check_poc(client: Client, base_url: String, poc: Poc) {
    match send_request(&client, &base_url, &poc).await {
        Ok(response) => {
            if check_vulnerability(&response, &poc) {
                let name = poc.name.clone();
                let url = format!("{}{}", base_url, poc.path);
                Print::yamlvulnprint(&name, &url);
            }
        }
        Err(_e) => {
            // 可以选择记录错误日志
        }
    }
}

pub async fn pocsmain(targets: Vec<String>, client: Client) -> Result<(), Box<dyn Error>> {
    let yaml_content = include_str!("../config/pocs.yaml");
    let pocs = Pocs::from_yaml(yaml_content)?;

    let mut tasks = vec![];
    for target in targets {
        for poc in &pocs.pocs {
            let client = client.clone();
            let target = target.clone();
            let poc = poc.clone();

            tasks.push(tokio::spawn(async move {
                check_poc(client, target, poc).await
            }));
        }
    }

    futures::future::join_all(tasks).await;
    Ok(())
}