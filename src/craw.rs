use crate::outprint::Print;
use crate::tofile;
use regex::Regex;
use std::collections::HashSet;
use std::error::Error;
use futures::stream::StreamExt;

#[allow(dead_code)]
struct Links{
    urls:Vec<String>,
    parse_urls:Vec<String>,
}
#[allow(dead_code)]
impl Links{
    fn new()->Self{
        Links{
            urls:vec![],
            parse_urls:vec![],
        }
    }
    fn push(&mut self, url:&str){
        self.parse_urls.push(url.to_string());
    }
    fn parse_results(&self) -> Vec<String>{
        self.parse_urls.clone()
    }
}
#[derive(Debug,Clone)]
struct LinkScan;
impl LinkScan {
    async fn crawler(&self, url: &str, html:&str,

    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let mut list_r: Vec<String> = Vec::new();

        // Define regex patterns
        let page_pattern = Regex::new(r#"["'](?:page|path)["']\s*:\s*"\s*(\S+?)\s*""#)?;
        let href_pattern = Regex::new(r#"(?i)href(?:"|'|["']|["']\s*:\s*["']|[\s=:]\s*["'])(https?://\S+?|/\S+?|.*?)["']"#)?;
        let src_pattern = Regex::new(r#"(?i)src(?:"|'|["']|["']\s*:\s*["']|[\s=:]\s*["'])(https?://\S+?|/\S+?|.*?)["']"#)?;
        let link_pattern = Regex::new(r#"(?i)link(?:"|'|["']|["']\s*:\s*["']|[\s=:]\s*["'])(https?://\S+?|/\S+?|.*?)["']"#)?;
        let url_pattern = Regex::new(r#"(?i)url(?:"|'|["']|["']\s*:\s*["']|[\s=:]\s*["'])(https?://\S+?|/\S+?|.*?)["']"#)?;
        let srcset_pattern = Regex::new(r#"(?i)srcset(?:"|'|["']|["']\s*:\s*["']|[\s=:]\s*["'])(https?://\S+?|/\S+?|.*?)["']"#)?;

        let amazon_key = Regex::new(r#"AKIA[A-Za-z0-9]{16}"#)?;
        let google_key = Regex::new(r#"GOOG[\w\W]{10,30}"#)?;
        let azure_key = Regex::new(r#"AZ[A-Za-z0-9]{34,40}"#)?;
        let ibm_key = Regex::new(r#"IBM[A-Za-z0-9]{10,40}"#)?;
        let ali_key = Regex::new(r#"LTAI[A-Za-z0-9]{12,20}"#)?;
        let tencent_key = Regex::new(r#"^AKID[A-Za-z0-9]{13,20}"#)?;
        // let huawei_key = Regex::new(r#"[A-Z0-9]{20}"#)?;
        let jd_key = Regex::new(r#"JDC_[A-Z0-9]{28,32}"#)?;
        let volcengine_key = Regex::new(r#"AKLT[a-zA-Z0-9-_]{0,252}"#)?;
        let uc_key = Regex::new(r#"UC[A-Za-z0-9]{10,40}"#)?;
        let qy_key = Regex::new(r#"QY[A-Za-z0-9]{10,40}$"#)?;
        let kingsoft_key = Regex::new(r#"^AKLT[a-zA-Z0-9-_]{16,28}"#)?;
        let ctc_key = Regex::new(r#"CTC[A-Za-z0-9]{10,60}"#)?;
        let ltc_key = Regex::new(r#"LTC[A-Za-z0-9]{10,60}"#)?;
        let yd_key = Regex::new(r#"YD[A-Za-z0-9]{10,60}"#)?;
        let yy_key = Regex::new(r#"YY[A-Za-z0-9]{10,40}"#)?;
        let regex_list = vec![
            ("Amazon Key", &amazon_key),
            ("Google Key", &google_key),
            ("Azure Key", &azure_key),
            ("IBM Key", &ibm_key),
            ("Alibaba Key", &ali_key),
            ("Tencent Key", &tencent_key),
            // ("Huawei Key", &huawei_key),
            ("JD Key", &jd_key),
            ("Volcengine Key", &volcengine_key),
            ("UC Key", &uc_key),
            ("QY Key", &qy_key),
            ("Kingsoft Key", &kingsoft_key),
            ("CTC Key", &ctc_key),
            ("LTC Key", &ltc_key),
            ("YD Key", &yd_key),
            ("YY Key", &yy_key),
        ];
        let mut keys_res = vec![]; // 修改为 Vec<String>
        let mut qc_res = vec![];
        for (name, regex) in regex_list {
            for matched in regex.find_iter(&html) {
                if qc_res.contains(&matched.as_str()) {
                    // 将格式化后的字符串直接推入 Vec<String>
                    let key_entry = format!("Found KEY in {} {}: {}", url, name, matched.as_str());
                    keys_res.push(key_entry.clone()); // 存入 keys_res
                    Print::vulnprint(&key_entry); // 打印时用引用
                }else {
                    // 不存在则添加
                    qc_res.push(matched.as_str());
                }
            }
        }
        if !keys_res.is_empty() {
            tofile::vuln_save_to_file("vulns.txt", &keys_res)?; // 无需改变调用
        }


        // Extract all matches
        let mut all_links: HashSet<String> = HashSet::new();
        all_links.extend(page_pattern.captures_iter(&html).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string())));
        all_links.extend(href_pattern.captures_iter(&html).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string())));
        all_links.extend(src_pattern.captures_iter(&html).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string())));
        all_links.extend(link_pattern.captures_iter(&html).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string())));
        all_links.extend(url_pattern.captures_iter(&html).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string())));
        all_links.extend(srcset_pattern.captures_iter(&html).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string())));

        // Process links
        for mut link in all_links {
            if link.contains("(") || link.contains("{") || link.contains(",") {
                continue;
            }
            if link.contains(";") {
                link = link.split(';').next().unwrap_or_default().to_string();
            }

            if !link.contains("://") {
                let base = format!("{}//{}", url.split('/').next().unwrap(), url.split('/').nth(2).unwrap());
                link = format!("{}/{}", base, link.trim_matches(&['*', '@', '{', '}', '(', ')', '/', ' '][..]));
            } else if link.starts_with("//") {
                let protocol = url.split("://").next().unwrap_or("http");
                link = format!("{}:{}", protocol, link.trim_matches(&['*', '@', '{', '}', '(', ')', '/', ' '][..]));
            }

            if !list_r.contains(&link) {
                list_r.push(link.clone());
            }
        }

        Ok(list_r)
    }

}

pub async fn crawmain(url:&str,html:&str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let link_scan = LinkScan;
    let result = link_scan.crawler(&url,&html).await?;
    Ok(result)

}