// use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use futures::future::join_all;
use reqwest::Client;
use tokio::sync::{Mutex, Semaphore};
use serde_json::Value;
use crate::outprint;
use serde_json::json;
use reqwest::header::HeaderMap;
use base64::engine::Engine as _;
struct InfoIPRes{
    ips: InfoPortRes
}
impl InfoIPRes{
    fn new() -> InfoIPRes{
        InfoIPRes{ips: InfoPortRes::new()}
    }
}
#[derive(Clone)]
pub struct ApiKeys{
    pub fofa:String,
    pub yt:String,
    pub shodan:String,
    pub quake:String,
}
struct InfoPortRes{
    ports: Vec<String>,
}
impl InfoPortRes{
    fn new() -> InfoPortRes{
        InfoPortRes{ports: Vec::new()}
    }
    fn push(&mut self, ports: String){
        self.ports.push(ports);
    }
    fn rt(&self) -> Vec<String>{
        self.ports.clone()
    }
    fn extend(&mut self, ports: Vec<String>){
        self.ports.extend(ports);
    }
    fn res(&self) -> Vec<String>{
        let mut ports = self.ports.clone();
        ports.sort();
        ports.dedup();
        ports
    }

}
#[async_trait]
trait InfoPort{
    async fn fetch(&self,ip:&str,api_keys:ApiKeys,client: &Client) -> Result<InfoPortRes,Box<dyn Error + Send + Sync>>;
}
struct ShodanIp;
struct FofaIp;
struct QuakeIp;
struct YtIp;
#[async_trait]
impl InfoPort for ShodanIp{
    async fn fetch(&self,ip:&str,api_keys:ApiKeys,client: &Client) -> Result<InfoPortRes,Box<dyn Error + Send + Sync>>{
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}",ip,api_keys.shodan);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success(){
            // outprint::Print::errprint(format!("Shodan error status code: {}", response.status()).as_str());
            return Ok(results)
        };
        let json_response = response.json::<Value>().await?;
        if let Some(ports) = json_response.get("ports").and_then(|p| p.as_array()){
            ports.into_iter().for_each(|port|{
                results.push(format!("{}:{}",ip,port))
            })
        }
        if results.ports.len() > 100 {
            outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
        }
        // } else {
        //     outprint::Print::infoprint(format!("Shodan found IP Ports {} ",results.ports.len()).as_str());
        // }

        Ok(results)
    }
    
}
#[async_trait]
impl InfoPort for FofaIp{
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let base64_str = STANDARD.encode(format!("ip={}", ip));
        // let base64_str = base64::encode(format!("ip={}", ip));
        let url = format!("https://fofa.info/api/v1/search/all?key={}&qbase64={}&size=100&full=true", api_keys.fofa,base64_str);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            // outprint::Print::errprint(format!("Fofa error status code: {}", response.status()).as_str());
            return Ok(results)
        }
        let json_response = response.json::<Value>().await?;
        // if let Some(errmsg) = json_response.get("errmsg").and_then(|err| err.as_str()) {
        //     outprint::Print::errprint(errmsg);
        //     return Ok(results)
        // }
        let empty_vec = vec![];

        let data_array = json_response.get("results").and_then(|data| data.as_array()).unwrap_or(&empty_vec);

        data_array.iter().for_each(|data| {
            if let Some(ports) = data.get(2){
                if let Some(p) = ports.as_str() {
                    results.push(format!("{}:{}",ip,p))
                }
            }
        });
        if results.ports.len() > 100 {
            outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
        }
        // } else {
        //     outprint::Print::infoprint(format!("Fofa found IP Ports {} ",results.ports.len()).as_str());
        // }

        Ok(results)
    }
    
}
#[async_trait]
impl InfoPort for QuakeIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let url = "https://quake.360.net/api/v3/search/quake_service";
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-quaketoken",
            api_keys.quake.parse()?,
        );
        let query = json!({
            "query": format!("ip: {}", ip), "start": 0, "size": 100,
        });
        let mut results = InfoPortRes::new();
        let response = client.post(url).json(&query).headers(headers).send().await?;
        if !response.status().is_success() {
            // outprint::Print::errprint(format!("Quake error status code: {}", response.status()).as_str());
            return Ok(results)
        }
        let json_response = response.json::<Value>().await?;
        if json_response.get("code").and_then(|code| code.as_u64()) != Some(0) {
            // if let Some(message) = json_response.get("message").and_then(|err| err.as_str()) {
            //     outprint::Print::errprint(message);
            // }
            Ok(results)
        }else {
            let empty_vec = vec![];
            let data_array = json_response.get("data").and_then(|data| data.as_array()).unwrap_or(&empty_vec);
            data_array.iter().for_each(|data| {
                if let Some(port) = data.get("port").and_then(|p| p.as_str()) {
                    results.push(format!("{}:{}",ip,port))
                }
            });
            if results.ports.len() > 100 {
                outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
            }
            // } else {
            //     outprint::Print::infoprint(format!("Quake found IP Ports {}",results.ports.len()).as_str());
            // }


            Ok(results)
        }
    }

}
#[async_trait]
impl InfoPort for YtIp {
    async fn fetch(&self, ip: &str, api_keys: ApiKeys, client: &Client) -> Result<InfoPortRes, Box<dyn Error + Send + Sync>> {
        let query = STANDARD.encode(format!("ip=\"{}\"", ip));
        // let query = base64::encode(format!("ip=\"{}\"",ip));
        let url = format!("https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page=1&page_size=100&is_web=3&start_time=2024-01-01&end_time=2025-12-28",api_keys.yt,query);
        let response = client.get(&url).send().await?;
        let mut results = InfoPortRes::new();
        if !response.status().is_success() {
            // outprint::Print::errprint(format!("YT error status code: {}", response.status()).as_str());
            return Ok(results)
        }
        let json_response = response.json::<Value>().await?;
        if let Some(data) = json_response.get("data").and_then(|d| d.get("arr")).and_then(|d| d.as_array()) {
            data.iter().for_each(|data| {
                if let Some(port) = data.get("port").and_then(|o| o.as_str()) {
                    results.push(format!("{}:{}",ip,port))
                }
            });
        }
        if results.ports.len() > 50 {
            outprint::Print::errprint(format!("The ip {} may be cdn to exclude collection results", ip).as_str());
        }
        // } else {
        //     outprint::Print::infoprint(format!("YT found IP Ports {}",results.ports.len()).as_str());
        // }

        Ok(results)
    }

}
pub async fn portmain(ips:&Vec<String>, client: Client, api_keys: ApiKeys) -> Result<Vec<String>, Box<dyn Error>> {

    let fetchers:Vec<Arc<dyn InfoPort + Send + Sync>> = vec![
        Arc::new(FofaIp),
        Arc::new(QuakeIp),
        Arc::new(YtIp),
        Arc::new(ShodanIp),
    ];

    let ips_res = Arc::new(Mutex::new(InfoIPRes::new()));
    let semaphore = Arc::new(Semaphore::new(3));
    let mut tasks = vec![];
    // let api_keys = ApiKeys {
    //     fofa: api_keys.get("fofa").cloned().ok_or("Missing fofa key")?,
    //     quake: api_keys.get("quake").cloned().ok_or("Missing quake key")?,
    //     yt: api_keys.get("yt").cloned().ok_or("Missing yt key")?,
    //     shodan: api_keys.get("shodan").cloned().ok_or("Missing shodan key")?,
    // };
    for ip in ips.iter().cloned() {
        for fetcher in &fetchers {
            let premit = semaphore.clone();
            let fetch = Arc::clone(&fetcher);
            let client = client.clone();
            let api_keys = api_keys.clone();
            let ips_res = Arc::clone(&ips_res);
            let ip = ip.clone();
            let task = tokio::spawn(async move {
                let _permit = premit.acquire().await.unwrap();
                match fetch.fetch(&ip, api_keys, &client).await {
                    Ok(res) => {
                        let mut ips_res = ips_res.lock().await;
                        ips_res.ips.extend(res.rt());
                    }
                    _ => {}

                }
            });
            tasks.push(task);
        }
    }
    join_all(tasks).await;
    let final_res = ips_res.lock().await;
    // println!("{:?}",final_res.ips.rt());
    Ok(final_res.ips.res())

}