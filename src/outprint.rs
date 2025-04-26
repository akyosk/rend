use colored::Colorize;
pub struct Print;
impl Print{
    pub fn okprint(domain: &str, status: &u64, lens: &u64, title: &str){
        println!("{}",format!("[!][{}] [ Status -> {} ] | [ Len -> {} ] | [ Title -> {} ]", domain, status, lens, title).blue());
    }
    pub fn vuln_bypass(domain: &str, status: &u64, lens: &u64, title: &str,ip: Option<&str>){
        println!("{}",format!("{}[{}] [ Status -> {} ] | [ Len -> {} ] | [ Title -> {} ] | [IP -> {}]","[!]".red(), domain, status, lens, title,ip.unwrap_or("N/A")).blue().bold());
    }
    pub fn cmsprint(domain: &str, status: &u64, lens: &u64,finger: &str){
        println!("{}",format!("[*][CMS][{}] | {} | {} | {} |", domain, status, lens, finger).magenta().bold());
    }
    pub fn errprint(err:&str){
        println!("{}",format!("[{}] {}","Err",err).yellow());
    }
    pub fn infoprint(data:&str){
        println!("{}",format!("[INFO] {}",data).blue());
    }
    pub fn vulnprint(url:&str){ println!("{}",format!("{} {}","[*]".red(),url.blue()).bold()) }
    pub fn yamlvulnprint(name:&str,url:&str){ println!("{}",format!("{} {} : {}","[*]".red(),name,url).blue().bold()) }
    pub fn bannerprint(banner:&str){ println!("{}",banner.blue().bold()) }
    pub fn otherprint(banner:&str){ println!("{}",format!("{} Find sensitive path in URL: {}","[+]".purple(),banner).blue().bold()) }
}