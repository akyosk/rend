# Rend

![GitHub last commit](https://img.shields.io/github/last-commit/akyosk/rend)
![Issues](https://img.shields.io/github/issues/akyosk/rend)

# ⚠️ 免责声明 ⚠️
本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款。 

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。


## 📅 2024-12-04

**rend是一款前期快速打点，薄弱点快速扫描工具**

![image-20241204135558006](img/image-20241204135558006.png)

## 🔥 功能

- **整合多个搜索引擎进行资产收集**
- **内置finger指纹库进行指纹识别**
- **各类厂商Key值检测**
- **自动Fuzz404**
- **根据查询域名的所有IP结果Bypass403**
- **子域名枚举**
- **根据域名结果反查IP**
- **内置简单漏洞检测机制，遇到带参链接自动替换，进行以下检测**
  - **SQL**
  - **RCE**
  - **SSRF**
  - **FILE READ**
- **增加yaml漏洞模版,调用是对404/200/403响应结果进行漏洞验证**
- **对IP结果进行简单cdn判断并执行端口收集，将结果传入指纹漏洞识别**
- **各类结果进行文件保存**

**支持引擎如下:**

| 序号 |                          搜索引擎                          |                                                                                                               网站                                                                                                                | 是否支持 |       是否需要API       |
|:--:|:------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:----:|:-------------------:|
| 1  |                       daydaymap                        |                                                                                                     https://dnsdumpster.com                                                                                                     |  ✅   |          ✅          |
| 2  |                       hunter.how                       |                                                                                                       https://hunter.how                                                                                                        |  ✅   |          ✅          |
| 3  |                        Chaziyu                         |                                                                                                      https://chaziyu.com/                                                                                                       |  ✅   |          ❌          |
| 4  |                         crt.sh                         |                                                                                                         https://crt.sh/                                                                                                         |  ✅   |          ❌          |
| 5  |                      whoisxmlapi                       |                                                                                                   https://www.whoisxmlapi.com                                                                                                   |  ✅   |          ✅          |
| 6  |                       binaryedge                       |                                                                                            https://app.binaryedge.io/services/query                                                                                             |  ✅   |          ✅          |
| 7  |                         quake                          |                                                                                                     https://www.zoomeye.org                                                                                                     |  ✅   |          ✅          |
| 8  |                           鹰图                           |                                                                                                   https://hunter.qianxin.com                                                                                                    |  ✅   |          ✅          |
| 9  |                        zoomeye                         |                                                                                                     https://www.zoomeye.org                                                                                                     |  ✅   |          ✅          |
| 10 |                        Rapiddns                        |                                                                                                      https://rapiddns.io/                                                                                                       |  ✅   |          ❌          |
| 11 |                      Sitedossier                       |                                                                                                   http://www.sitedossier.com/                                                                                                   |  ✅   |          ❌          |
| 12 |                        jldc.me                         |                                                                                               https://jldc.me/anubis/subdomains/                                                                                                |  ✅   |          ❌          |
| 13 |                        ViewDNS                         |                                                                                                    https://api.viewdns.info                                                                                                     |  ✅   |          ✅          |
| 14 |                         C99NL                          |                                                                                              https://subdomainfinder.c99.nl/scans                                                                                               |  ✅   |          ❌          |
| 15 |                       Alienvault                       |                                                                                                   https://otx.alienvault.com/                                                                                                   |  ✅   |          ❌          |
| 16 |                       Dnshistory                       |                                                                                              https://dnshistory.org/subdomains/1/                                                                                               |  ✅   |          ❌          |
| 17 |                      Hackertarget                      |                                                                                           https://api.hackertarget.com/hostsearch/?q=                                                                                           |  ✅   |          ❌          |
| 18 |                      Certspotter                       |                                                                                                  https://api.certspotter.com/                                                                                                   |  ✅   |          ❌          |
| 19 |                        Fullhunt                        |                                                                                                      https://fullhunt.io/                                                                                                       |  ✅   |          ✅          |
| 20 |                          fofa                          |                                                                                                      https://fofa.info/api                                                                                                      |  ✅   |          ✅          |
| 21 |                      dnsdumpster                       |                                                                                                   https://api.dnsdumpster.com                                                                                                   |  ✅   |          ✅          |
| 22 |                       virustotal                       |                                                                                                   https://www.virustotal.com                                                                                                    |  ✅   |          ✅          |
| 23 |                         shodan                         |                                                                                                     https://www.shodan.io/                                                                                                      |  ✅   |          ✅          |
| 24 |                         Netlas                         |                                                                                                      https://app.netlas.io                                                                                                      |  ✅   |          ❌          |
| 25 |                     Securitytrails                     |                                                                                                   https://securitytrails.com                                                                                                    |  ✅   |          ✅          |
| 26 |                        archive                         |                                                                                                     https://web.archive.org                                                                                                     |    ✅   |          ❌          |
| 27 |                       dnsarchive                       |                                                                                                     https://dnsarchive.net                                                                                                      |   ✅   |          ❌          |
| 28 |                         censys                         |                                                                                                    https://search.censys.io                                                                                                     |  ❌   |          ✅          |
| 29 |                         ip138                          |                                                                                                      https://chaziyu.com/                                                                                                       |    ✅  |          ❌          |
| 30 |                      threatcrowd                       |                                                                                                  http://ci-www.threatcrowd.org                                                                                                  |    ✅   |          ❌          |
| 31 |                        urlscan                         |                                                                                                       https://urlscan.io/                                                                                                       |     ✅   |          ❌          |
| 32 |                        bevigil                         |                                                                                                    http://osint.bevigil.com                                                                                                     |      ✅   |          ✅          |
| 33 |                        dnsgrep                         |                                                                                                     https://www.dnsgrep.cn/                                                                                                     |      ✅    |          ❌          |
| 34 |                         myssl                          |                                                                                                       https://myssl.com/                                                                                                        |      ✅     |    ❌                |
| 35 |                    robtex                             |                       https://freeapi.robtex.com                                                                                                                                                                                |       ✅     |           ✅          |



## 💻 安装

~~~text
git clone https://github.com/akyosk/rend.git
~~~

## ⚙️ 编译前配置

**api.toml位于config目录下**
![image-20241204141247015.png](img/image-20241204141247015.png)

## 🎉 编译

**注：本项目为rust项目,需提前安装rust环境**
~~~text
cd rend && cargo build --release
~~~

**注：编译文件处与target/release目录下**

## ⚡️ 使用

~~~text
./rend -h或--help
~~~

![image-20241204140411914](img/image-20241204140411914.png)
~~~text
# 域名扫描
./rend -d domain.com
# 编译后也可指定其他api.toml文件执行,指定的toml优先级最高
./rend -d domain.com --rend-config otherApi.toml
~~~


## 🌍 作者闲谈

**第一次学习Rust，并使用Rust写下了这个工具，很多东西还不是很清楚，后续慢慢改进，不喜轻喷**😝

