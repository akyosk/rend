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
- **内置简单漏洞检测机制，遇到带参链接自动替换，进行以下检测**
  - **SQL**
  - **RCE**
  - **SSRF**
  - **FILE READ**
- **对IP结果进行简单cdn判断并执行端口收集，将结果传入指纹漏洞识别**
- **各类结果进行文件保存**

**支持引擎如下:**

| 序号 |    搜索引擎    |                    网站                    | 是否支持 | 是否需要API |
|:--:| :------------: |:----------------------------------------:|:----:| :---------: |
| 1  |   daydaymap    |         https://dnsdumpster.com          |  ✅   |      ✅      |
| 2  |   hunter.how   |            https://hunter.how            |  ✅   |      ✅      |
| 3  |    Chaziyu     |           https://chaziyu.com/           |  ✅   |      ❌      |
| 4  |     crt.sh     |             https://crt.sh/              |  ✅   |      ❌      |
| 5  |  whoisxmlapi   |       https://www.whoisxmlapi.com        |  ✅   |      ✅      |
| 6  |   binaryedge   | https://app.binaryedge.io/services/query |  ✅   |      ✅      |
| 7  |     quake      |         https://www.zoomeye.org          |  ✅   |      ✅      |
| 8  |      鹰图      |        https://hunter.qianxin.com        |  ✅   |      ✅      |
| 9  |    zoomeye     |         https://www.zoomeye.org          |  ✅   |      ✅      |
| 10 |    Rapiddns    |                 https://rapiddns.io/                         |  ✅   |      ❌      |
| 11 |  Sitedossier   |                 http://www.sitedossier.com/                         |  ✅   |      ❌      |
| 12 |    jldc.me     |              https://jldc.me/anubis/subdomains/                            |  ✅   |      ❌      |
| 13 |    ViewDNS     | https://app.binaryedge.io/services/query |  ✅   |      ✅      |
| 14 |     C99NL      |              https://subdomainfinder.c99.nl/scans                            |  ✅   |      ❌      |
| 15 |   Alienvault   |                                          |  ✅   |      ❌      |
| 16 |   Dnshistory   |         https://dnshistory.org/subdomains/1/                                 |  ✅   |      ❌      |
| 17 |  Hackertarget  |                https://api.hackertarget.com/hostsearch/?q=                          |  ✅   |      ❌      |
| 18 |  Certspotter   |                         https://api.certspotter.com/                 |  ✅   |      ❌      |
| 19 |    Fullhunt    |           https://fullhunt.io/           |  ✅   |      ✅      |
| 20 |      fofa      |          https://fofa.info/api           |  ✅   |      ✅      |
| 21 |  dnsdumpster   |                    https://api.dnsdumpster.com                      |  ✅   |      ✅      |
| 22 |   virustotal   |        https://www.virustotal.com        |  ✅   |      ✅      |
| 23 |     shodan     |          https://www.shodan.io/          |  ✅   |      ✅      |
| 24 |     Netlas     |                 https://app.netlas.io                         |  ✅   |      ❌      |
| 25 | Securitytrails |        https://securitytrails.com        |  ✅   |      ✅      |
| 26 |     censys     |                                          |  ❌   |      ✅      |



## 💻 安装

~~~shell
git clone https://github.com/akyosk/rend.git
~~~

## ⚙️ 编译前配置

**config.toml位于config目录下**
![image-20241204141247015.png](img/image-20241204141247015.png)

## 🎉 编译

~~~shell
cd rend && cargo build --release
~~~

**注：编译文件处与target/debug目录下**

## ⚡️ 使用

~~~shell
./rend -h或--help
~~~

![image-20241204140411914](img/image-20241204140411914.png)

## 🌍 作者杂谈

**第一次学习Rust，并使用Rust写下了这个工具，很多东西还不是很清楚，后续慢慢改进，不喜轻喷**😝

