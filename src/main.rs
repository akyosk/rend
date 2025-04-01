// use chrono::format;
use std::collections::HashMap;
use std::fs;
use clap::{Arg, Command};
// use clap::builder::TypedValueParser;
// use crate::infoscan::Config;

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
async fn main() -> Result<(), Box<dyn std::error::Error>> { // 将返回类型更改为 Result
    let banner = r#"
                            .___
_______   ____    ____    __| _/
\_  __ \_/ __ \  /    \  / __ |
 |  | \/\  ___/ |   |  \/ /_/ |
 |__|    \___  >|___|  /\____ |
             \/      \/      \/
Author: akyo    Version: 0.0.3"#;
    outprint::Print::bannerprint(banner);

    let args = Command::new("rend")
        .version("0.0.3")
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
        // .arg(
        //     Arg::new("update")
        //         .long("update")
        //         .help("Check for updates")
        //         .action(clap::ArgAction::SetTrue) // 设置为布尔标志
        // )
        .arg(
            Arg::new("rend-config")
                .long("rend-config")
                .value_name("CONFIG_PATH")
                .help("Specifies a custom config file path"),
        ).get_matches();

    // 检查是否需要更新e
    // let update = args.get_flag("update"); // 检查是否启用
    // if update {
    //     update::check_and_update()?; // 执行更新逻辑
    //     return Ok(())
    // }

    // 处理传入的配置文件路径
    if let Some(config_path) = args.get_one::<String>("rend-config") {
        if !fs::metadata(config_path).is_ok() {
            // outprint::Print::infoprint(format!("Loading user configuration from: {}", config_path));
        // } else {
            eprintln!("Error: Configuration file '{}' does not exist.", config_path);
            return Err("Configuration file not found".into());
        }
    }

    // 解析其他参数
    let domain = args.get_one::<String>("domain").unwrap();
    outprint::Print::infoprint(format!("Domain: {}", domain).as_str());

    let mut arg = HashMap::new();
    arg.insert("domain", domain.clone());
    match infoscan::infomain(arg, domain, args.get_one::<String>("rend-config").map(|s| s.as_str())).await {
        Ok(_) => outprint::Print::infoprint("Work End"),
        Err(e) => outprint::Print::errprint(format!("Error: {}", e).as_str()),
    }

    Ok(()) // 返回 Ok
}
