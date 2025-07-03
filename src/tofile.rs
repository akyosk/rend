use std::fs::OpenOptions;
use std::io::{self, Write};
// use reqwest::Url;

pub fn save_to_file(file_name: &str, domains: &[String], ips: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "\n[Subdomains]")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }
    writeln!(file, "\n[IPs]")?;
    for ip in ips {
        writeln!(file, "{}", ip)?;
    }

    Ok(())
}
pub fn vuln_save_to_file(file_name: &str, domains: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "\n[Vulns]")?;
    for domain in domains {
        writeln!(file, "[*] {}", domain)?;
    }

    Ok(())
}

pub fn realip_to_file(file_name: &str, domains: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "[Real-IP]")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }

    Ok(())
}

pub fn yaml_vuln_save_to_file(file_name: &str, name:&str,domains: &str) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "[*] | {} | {}", name,domains)?;

    Ok(())
}
pub fn ip_urls_save_to_file(file_name: &str, domains: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "[IP-PORTS]")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }

    Ok(())
}
pub fn urls_save_to_file(file_name: &str, domains: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "\n[Parameters]")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }

    Ok(())
}
pub fn bypass_urls_save_to_file(file_name: &str, domains: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;

    for domain in domains {
        writeln!(file, "{}", domain)?;
    }

    Ok(())
}
pub fn editor_urls_save_to_file(file_name: &str, url: &str) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "{}", url)?;
    Ok(())
}

pub fn req_urls_save_to_file(file_name: &str,domain: &str, status: &u64, lens: &u64, title: &str,ip:Option<&str>) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    if ip.is_none() {
        writeln!(file, "{}", format!("[!][{}] [ Status -> {} ] | [ Len -> {} ] | [ Title -> {} ]", domain, status, lens, title))?;
    } else {
        writeln!(file, "{}", format!("[!][{}] [ Status -> {} ] | [ Len -> {} ] | [ Title -> {} ] | [IP -> {}]", domain, status, lens, title,ip.unwrap_or("N/A")))?;
    }

    Ok(())
}

pub fn other_save_to_file(file_name: &str,other:&str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "{}", other)?;
    Ok(())
}

pub fn icp_save_to_file(file_name: &str, domains: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "[ICP]")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }

    Ok(())
}