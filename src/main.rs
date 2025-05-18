use std::collections::HashMap;
use std::fs;
use clap::{Arg, Command};
use rand::Rng;
mod outprint;
mod infoscan;
mod tofile;
mod cmsck;
mod craw;
mod vulns;
mod port;
mod subdomain;
mod pocscan;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let banner = [r#"
                            .___
_______   ____    ____    __| _/
\_  __ \_/ __ \  /    \  / __ |
 |  | \/\  ___/ |   |  \/ /_/ |
 |__|    \___  >|___|  /\____ |
             \/      \/      \/
Author: akyo    Version: 0.0.5"#,
"
***************************************************
***************************************************
********01110010 01100101 01101110 01100100********
***************************************************
***************************************************
Author: akyo    Version: 0.0.5",
        r#"
                   _________
_________________________  /
__  ___/  _ \_  __ \  __  /
_  /   /  __/  / / / /_/ /
/_/    \___//_/ /_/\__,_/
Author: akyo    Version: 0.0.5"#
    ];
    // outprint::Print::bannerprint(banner);
    let random_string = banner
        .get(rand::thread_rng().gen_range(0..banner.len()))
        .unwrap_or(&"No string selected");
    outprint::Print::bannerprint(format!("{}", random_string).as_str());

    let rand_str = vec![
        "Tools are prohibited from being used in illegal ways",
        "I will become stronger",
        "I'm super fast",
        "I'll make the job a breeze",
        "Tear target ······",
        "Make domain names more transparent",
        "I support at least 30+ search engines",
        "Look what I found",
        "Search everything",
    ];
    let random_string = rand_str
        .get(rand::thread_rng().gen_range(0..rand_str.len()))
        .unwrap_or(&"No string selected");
    outprint::Print::bannerprint(format!("[!]{}", random_string).as_str());

    let args = Command::new("rend")
        .version("0.0.5")
        .author("akyo")
        .about("Subdomain scan and vulns check")
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .value_name("DOMAIN")
                .help("Specifies the domain to use")
                .conflicts_with("file")
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("FILE")
                .help("Specifies a file containing multiple domains to scan")
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .help("Sets the timeout duration in seconds")
                .default_value("15")
        )
        .arg(
            Arg::new("proxy")
                .long("proxy")
                .short('p')
                .help("Sets the proxy server URL")
                .value_name("STRING")
                .default_value("")
        )
        .arg(
            Arg::new("ssl_verify")
                .long("ssl-verify")
                .value_name("BOOL")
                .default_value("false")
                .help("Enables or disables SSL verification (true/false)")
        )
        .arg(
            Arg::new("headers")
                .long("headers")
                .help("Adds custom headers in the format 'Key: Value, Key2: Value2'")
                .value_name("HEADERS")
                .default_value("User-Agent: Mozilla/4.0 (compatible; MSIE Version; Operating System)")
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .help("Sets the Work Threads")
                .default_value("300")
        )
        .arg(
            Arg::new("rend-config")
                .long("rend-config")
                .value_name("CONFIG_PATH")
                .help("Specifies a custom config file path"),
        )
        .arg_required_else_help(true)
        .get_matches();

    // 处理传入的配置文件路径
    if let Some(config_path) = args.get_one::<String>("rend-config") {
        if !fs::metadata(config_path).is_ok() {
            eprintln!("Error: Configuration file '{}' does not exist.", config_path);
            return Err("Configuration file not found".into());
        }
    }

    // 解析其他参数
    let mut arg = HashMap::new();
    if let Some(domain) = args.get_one::<String>("domain") {
        outprint::Print::infoprint(format!("Load Domain: {}", domain).as_str());
        arg.insert("domain", domain.clone());
    }
    if let Some(file_path) = args.get_one::<String>("file") {
        outprint::Print::infoprint(format!("Load File: {}", file_path).as_str());
        arg.insert("file", file_path.clone());
    }
    let threads = args.get_one::<String>("threads").unwrap();
    outprint::Print::infoprint(format!("Load Threads: {}", threads).as_str());
    let headers = args.get_one::<String>("headers").unwrap();
    outprint::Print::infoprint(format!("Load Header: {}", headers).as_str());
    let proxy = args.get_one::<String>("proxy").unwrap();
    if !proxy.is_empty() {
        outprint::Print::infoprint(format!("Load Proxy: {}", proxy).as_str());
    } else {
        outprint::Print::infoprint("Load Proxy: Null");
    }

    let timeout = args.get_one::<String>("timeout").unwrap();
    outprint::Print::infoprint(format!("Load Timeout: {}", timeout).as_str());
    let ssl = args.get_one::<String>("ssl_verify").unwrap();
    outprint::Print::infoprint(format!("Load SSL: {}", ssl).as_str());

    // 根据参数调用 infomain
    let domain = args.get_one::<String>("domain").map(|s| s.as_str()).unwrap_or("");
    match infoscan::infomain(arg, domain, args.get_one::<String>("rend-config").map(|s| s.as_str())).await {
        Ok(_) => outprint::Print::infoprint("Work End"),
        Err(e) => outprint::Print::errprint(format!("Error: {}", e).as_str()),
    }

    Ok(())
}