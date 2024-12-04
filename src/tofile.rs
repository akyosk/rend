use std::fs::OpenOptions;
use std::io::{self, Write};

pub fn save_to_file(file_name: &str, domains: &[String], ips: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "Subdomains:")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }
    writeln!(file, "\nIPs:")?;
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
    writeln!(file, "Vulns:")?;
    for domain in domains {
        writeln!(file, "[*] {}", domain)?;
    }

    Ok(())
}
pub fn ip_urls_save_to_file(file_name: &str, domains: &[String]) -> io::Result<()> {
    // 打开文件（如果文件不存在则创建，存在则追加内容）
    let mut file = OpenOptions::new()
        .create(true) // 如果文件不存在则创建
        .append(true) // 如果文件存在则追加内容
        .open(file_name)?;
    writeln!(file, "IP-PORTS:")?;
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
    writeln!(file, "Parameters:")?;
    for domain in domains {
        writeln!(file, "{}", domain)?;
    }

    Ok(())
}

