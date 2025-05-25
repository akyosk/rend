use reqwest::{Client, header::{HeaderMap, HeaderValue}};
use serde_json::{Value, json};
use std::error::Error;
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures::future::try_join_all;
use std::string::String;
use futures::future::BoxFuture;
use crate::outprint;
use crate::infoscan::ApiKeys;
fn clean_and_dedup(list: &mut Vec<String>) {
    list.retain(|x| !x.is_empty());
    list.sort();
    list.dedup();
}
pub async fn zone(icp: &str, keys: &ApiKeys) -> Result<(Vec<String>, Vec<String>), Box<dyn Error + Send + Sync>> {
    let url = "https://0.zone/api/data/";
    let client = Client::builder().build()?;

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));

    let data = json!({
        "query": icp,
        "query_type": "site",
        "page": 1,
        "pagesize": 100,
        "zone_key_id": keys.zone_key
    });

    let response = client
        .post(url)
        .headers(headers)
        .json(&data)
        .send()
        .await?;
    let mut ips = Vec::new();
    let mut hostnames = Vec::new();
    if !response.status().is_success() {
        return Ok((ips, hostnames));
    }

    let result: Value = response.json().await?;
    let empty_vec = vec![];
    let data_array = result.get("data").and_then(|data| data.as_array()).unwrap_or(&empty_vec);

    for item in data_array {
        if let (Some(ip), Some(mut ssl_hostname)) = (
            item.get("ip").and_then(|ip| ip.as_str()),
            item.get("ssl_hostname").and_then(|host| host.as_str()),
        ) {
            if ssl_hostname.starts_with("*.") {
                ssl_hostname = ssl_hostname.trim_start_matches("*.");
            }
            ips.push(ip.to_string());
            hostnames.push(ssl_hostname.to_string());

        }
    }
    hostnames.retain(|x| !x.is_empty());
    hostnames.sort();
    hostnames.dedup();
    clean_and_dedup(&mut ips);
    // ips.retain(|x| !x.is_empty());
    // ips.sort();
    // ips.dedup();
    outprint::Print::infoprint(
        format!(
            "Zone found Domain {} | found IP {}",
            hostnames.len(),
            ips.len(),
        ).as_str(),
    );

    Ok((ips, hostnames))
}

pub async fn quake(domain: &str, keys: &ApiKeys) -> Result<(Vec<String>, Vec<String>), Box<dyn Error + Send + Sync>> {
    let url = "https://quake.360.net/api/v3/search/quake_service";
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-quaketoken",
        keys.quake_key.parse()?,
    );
    let query = json!({
        "query": format!("icp_keywords: \"{}\"", domain),
        "start": 0,
        "size": 100,
    });
    let response = client.post(url).json(&query).headers(headers).send().await?;
    let mut ips = Vec::new();
    let mut hostnames = Vec::new();
    if !response.status().is_success() {
        outprint::Print::errprint(format!("Quake error status code: {}", response.status()).as_str());
        return Ok((ips, hostnames));
    }
    let json_response = response.json::<Value>().await?;
    if json_response.get("code").and_then(|code| code.as_u64()) != Some(0) {
        if let Some(message) = json_response.get("message").and_then(|err| err.as_str()) {
            outprint::Print::errprint(message);
        }
        return Ok((ips, hostnames));
    }

    let empty_vec = vec![];
    let data_array = json_response.get("data").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
    data_array.iter().for_each(|data| {
        if let (Some(domain), Some(ip)) = (
            data.get("domain").and_then(|domain| domain.as_str()),
            data.get("ip").and_then(|ip| ip.as_str()),
        ) {
            hostnames.push(domain.to_string());
            ips.push(ip.to_string());
        }
    });
    clean_and_dedup(&mut ips);
    clean_and_dedup(&mut hostnames);
    // hostnames.retain(|x| !x.is_empty());
    // hostnames.sort();
    // hostnames.dedup();
    // ips.retain(|x| !x.is_empty());
    // ips.sort();
    // ips.dedup();
    outprint::Print::infoprint(
        format!(
            "Quake found Domain {} | found IP {}",
            hostnames.len(),
            ips.len()
        ).as_str(),
    );
    Ok((ips, hostnames))
}

pub async fn yt_hunter(domain: &str, keys: &ApiKeys) -> Result<(Vec<String>, Vec<String>), Box<dyn Error + Send + Sync>> {
    let query = STANDARD.encode(format!("icp.name==\"{}\"", domain));
    let url = format!(
        "https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page=1&page_size=100&is_web=3&start_time=2024-01-01&end_time=2025-12-28",
        keys.yt_key, query
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .default_headers({
            let mut headers = HeaderMap::new();
            headers.insert("X-Forwarded-For", HeaderValue::from_static("127.0.0.1"));
            headers
        })
        .build()?;
    let response = client.get(&url).send().await?;
    let mut ips = Vec::new();
    let mut hostnames = Vec::new();
    if !response.status().is_success() {
        outprint::Print::errprint(format!("YT-Hunter error status code: {}", response.status()).as_str());
        return Ok((ips, hostnames));
    }
    let json_response = response.json::<Value>().await?;
    if let Some(data) = json_response.get("data").and_then(|d| d.get("arr")).and_then(|d| d.as_array()) {
        data.iter().for_each(|data| {
            if let (Some(domain), Some(ip)) = (
                data.get("domain").and_then(|o| o.as_str()),
                data.get("ip").and_then(|i| i.as_str()),
            ) {
                hostnames.push(domain.to_string());

                ips.push(ip.to_string());
            }
        });
    }
    clean_and_dedup(&mut ips);
    clean_and_dedup(&mut hostnames);
    // hostnames.retain(|x| !x.is_empty());
    // hostnames.sort();
    // hostnames.dedup();
    // ips.retain(|x| !x.is_empty());
    // ips.sort();
    // ips.dedup();
    outprint::Print::infoprint(
        format!("YT-Hunter found Domain {} | found IP {}", hostnames.len(), ips.len()).as_str(),
    );
    Ok((ips, hostnames))
}

pub async fn icpmain(
    icps: &Vec<String>,
    api_keys: ApiKeys,
) -> Result<(Vec<String>, Vec<String>), Box<dyn Error + Send + Sync>> {
    let mut all_ips = Vec::new();
    let mut all_hostnames = Vec::new();

    // 为每个 ICP 并发调用三个查询函数
    for icp in icps {
        // 使用 BoxFuture 统一 Future 类型
        let tasks: Vec<BoxFuture<_>> = vec![
            Box::pin(zone(icp, &api_keys)),
            Box::pin(quake(icp, &api_keys)),
            Box::pin(yt_hunter(icp, &api_keys)),
        ];

        let results = try_join_all(tasks).await?;

        // 合并结果
        for (ips, hostnames) in results {
            all_ips.extend(ips);
            all_hostnames.extend(hostnames);
        }
    }

    // 去重
    // all_ips.sort();
    // all_ips.dedup();
    // all_hostnames.sort();
    // all_hostnames.dedup();
    clean_and_dedup(&mut all_ips);
    clean_and_dedup(&mut all_hostnames);

    // 输出合并后的结果
    outprint::Print::infoprint(
        format!(
            "Total found Domains: {} | Total found IPs: {}",
            all_hostnames.len(),
            all_ips.len()
        ).as_str(),
    );

    Ok((all_ips, all_hostnames))
}