mod outprint;
mod infoscan;
mod tofile;
mod cmsck;
mod craw;
mod vulns;
mod port;
mod subdomain;
use std::collections::HashMap;
use clap::{Arg, Command};
use clap::builder::TypedValueParser;

#[tokio::main]
async fn main() {
    let banner = r#"
                            .___
_______   ____    ____    __| _/
\_  __ \_/ __ \  /    \  / __ |
 |  | \/\  ___/ |   |  \/ /_/ |
 |__|    \___  >|___|  /\____ |
             \/      \/      \/
Author: akyo    Version: 0.0.2"#;
    outprint::Print::bannerprint(banner);
    let args = Command::new("rend")
        .version("0.0.1")
        .author("akyo")
        .about("Subdomain scan and vulns check")
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .value_name("DOMAIN")
                .help("Specifies the domain to use")
                .required(true)
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .help("Sets the timeout duration in seconds")
                .default_value("10")
        )
        .arg(
            Arg::new("proxy")
                .long("proxy")
                .short('p')
                .help("Sets the proxy server URL")
                .value_name("BOOL")
                .default_value("")
        )
        .arg(
            Arg::new("ssl_verify")
                .long("ssl-verify")
                .value_name("BOOL")
                .default_value("true")
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
        ).get_matches();
    let domain = args.get_one::<String>("domain").unwrap();
    let timeout: u64 = args
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .expect("Timeout must be a number");
    let proxy = args.get_one::<String>("proxy").unwrap();
    let ssl_verify = args.get_one::<String>("ssl_verify").unwrap().parse::<bool>().unwrap_or(true);
    let headers = args.get_one::<String>("headers").unwrap();
    let threads = args.get_one::<String>("threads").unwrap().parse::<usize>().expect("Threads must be a number");
    outprint::Print::infoprint(format!("Domain: {}", domain).as_str());
    outprint::Print::infoprint(format!("{}", args.get_one::<String>("headers").unwrap()).as_str());
    outprint::Print::infoprint(format!("Timeout: {} seconds", timeout).as_str());
    outprint::Print::infoprint(format!("Proxy: {}", if proxy.is_empty() { "None" } else { proxy }).as_str());
    outprint::Print::infoprint(format!("SSL Verification: {}", ssl_verify).as_str());
    outprint::Print::infoprint(format!("Work Threads: {}", threads).as_str());
    let mut arg = HashMap::new();
    arg.insert("domain", domain.clone());
    arg.insert("timeout", timeout.to_string());
    arg.insert("proxy", if proxy.is_empty() { "None".to_string() } else { proxy.clone() });
    arg.insert("ssl_verify", ssl_verify.to_string());
    arg.insert("headers", headers.to_string());
    arg.insert("threads", threads.to_string());
    match infoscan::infomain(arg,domain).await {
        Ok(_) => outprint::Print::infoprint("Word End"),
        Err(e) =>
            outprint::Print::errprint(format!("Error: {}", e).as_str()),
    }
}