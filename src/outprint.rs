use colored::Colorize;
pub struct Print;
impl Print{
    pub fn okprint(domain: &str, status: &u64, lens: &u64, title: &str){
        println!("{}",format!("[!][{}] [ Status -> {} ] | [ Len -> {} ] | [ Title -> {} ]", domain, status, lens, title).blue());
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
    pub fn vulnprint(url:&str){
        println!("{}",format!("[+] {}",url).red().bold())
    }
    pub fn yamlvulnprint(name:&str,url:&str){ println!("{}",format!("[*] POC '{}' potentially found at: {}",name,url).red().bold()) }
    pub fn bannerprint(banner:&str){
        println!("{}",banner.blue().bold())
    }
}