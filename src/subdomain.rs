use tokio::task;
use std::error::Error;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use std::io::{self, BufRead};
use std::sync::Arc;
use tokio::sync::Semaphore;
use crate::outprint::Print;
/// 读取子域名字典文件
fn read_wordlist() -> Vec<String> {
    // 使用 include_str! 引入文件内容
    include_str!("../dict/subdomain.txt")
        .lines()
        .map(|line| line.trim().to_string())
        .collect()
}


/// 扫描子域名
pub async fn scan_subdomains(domain: &str, threads: usize) -> Result<(), Box<dyn Error>> {
    // 读取子域名字典
    let wordlist = read_wordlist();

    // 配置异步 DNS 解析器
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;
    let resolver = Arc::new(resolver);

    // 创建信号量，用于控制并发
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut tasks = Vec::new();

    for subdomain in wordlist {
        let full_domain = format!("{}.{}", subdomain, domain);
        let resolver = Arc::clone(&resolver);
        let semaphore = Arc::clone(&semaphore);

        // 创建异步任务
        let task = task::spawn(async move {
            let _permit = semaphore.acquire().await;
            if let Ok(response) = resolver.lookup_ip(full_domain.clone()).await {
                let s = format!("Found: {} -> {:?}", full_domain, response.iter().collect::<Vec<_>>());
                Print::bannerprint(s.as_str());
            }
        });
        tasks.push(task);
    }

    // 等待所有任务完成
    for task in tasks {
        task.await?;
    }

    Ok(())
}

