use tokio::task;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use std::sync::{Arc};
use tokio::sync::Semaphore;
// use std::collections::HashSet;
use crate::outprint;
use std::net::IpAddr;

fn read_wordlist() -> Vec<String> {
    include_str!("../dict/subdomain.txt")
        .lines()
        .map(|line| line.trim().to_string())
        .collect()
}

// 检查是否是泛解析域名
async fn is_wildcard(domain: &str, resolver: Arc<TokioAsyncResolver>) -> bool {
    let test_subdomain = format!("random-nonexistent-subdomain.{}", domain);
    match resolver.lookup_ip(test_subdomain).await {
        Ok(response) => !response.iter().collect::<Vec<_>>().is_empty(),
        Err(_) => false,
    }
}

pub async fn scan_subdomains(domain: &str, threads: usize) -> Result<(), Box<dyn std::error::Error>> {
    let wordlist = read_wordlist();
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    )?;
    let resolver = Arc::new(resolver);
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut tasks = Vec::new();

    // 检查是否存在泛解析
    let wildcard_ips = if is_wildcard(domain, Arc::clone(&resolver)).await {
        resolver.lookup_ip(format!("random-nonexistent-subdomain.{}", domain))
            .await
            .map(|r| r.iter().collect::<Vec<_>>())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // 使用 Arc 包裹 wildcard_ips
    let wildcard_ips = Arc::new(wildcard_ips);

    for subdomain in wordlist {
        let full_domain = format!("{}.{}", subdomain, domain);
        let resolver = Arc::clone(&resolver);
        let semaphore = Arc::clone(&semaphore);
        let wildcard_ips = Arc::clone(&wildcard_ips);

        let task = task::spawn(async move {
            let _permit = semaphore.acquire().await;
            if let Ok(response) = resolver.lookup_ip(full_domain.clone()).await {
                let ips: Vec<_> = response.iter().collect();

                // 过滤掉泛解析 IP 以及以 198. 开头的 IP
                let valid_ips: Vec<IpAddr> = ips
                    .iter()
                    .filter(|ip| !wildcard_ips.contains(ip))  // 排除泛解析
                    .filter(|ip| !ip.to_string().starts_with("198.")) // 排除 198. 开头的 IP
                    .cloned()
                    .collect();

                if !valid_ips.is_empty() {
                    outprint::Print::bannerprint(&format!("Found: {} -> {:?}", full_domain, valid_ips));
                }
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await?;
    }

    Ok(())
}