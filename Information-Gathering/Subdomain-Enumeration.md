# 子域名枚举

**子域名枚举是信息收集中关键的一步，细节很大程度决定战果。本文参考The Art of Subdomain Enumeration，加上实践运用进行总结。**

### **被动枚举**

**一、证书透明度**

证书

<pre>当通过HTTPS访问web时，网站向浏览器提供数字证书，此证书用于识别网站的主机名，由证书颁发机构(CA,Certificate Authority)颁发。</pre>



证书透明度

<pre>证书透明度(Certificate Transparency)简称CT，主要用于将证书记录到公开的[CT log](https://www.certificate-transparency.org/known-logs)中，日志可以被任何人浏览。 </pre>

 通过CT log搜索 

```
https://crt.sh/
https://censys.io/
https://developers.facebook.com/tools/ct/
https://google.com/transparencyreport/https/ct/
```

利用crt.sh，一行代码收集子域名，代码是从国外漏洞赏金猎人那里拷贝的，更多[one line](https://github.com/mark-zh/BugBountyTips/blob/master/信息收集/one-line.md)，后面持续更新。 

```bash
curl -fsSL -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0" "https://crt.sh/?CN=%25.github.com" | sort -n | uniq -c | grep -o -P '(?<=\<TD\>).*(?=\<\/TD\>)' | sed -e '/white-space:normal/d'
```

![image-20191127165204927](C:\Users\wubo\MyNote\Images\image-20191127165204927.png)

**二、搜索引擎**

推荐DuckDuckGo，just enjoy it。 

```
谷歌
必应
DuckDuckGo
百度
```

**三、DNS数据聚合**

利用第三方服务进行DNS枚举，它们聚集大量DNS数据集，可以通过它们查找子域。常见第三方服务例如DNSdumpster和Netcraft。 

推荐[Sublist3r神器](https://github.com/aboul3la/Sublist3r)，Sublist3r神器集成了Netcraft、Virustotal、ThreatCrowd、DNSdumpster和ReverseDNS等等，你值得拥有。 

**四、ASN**

ASN(Autonomous System Numbers)自治系统编号。互联网可以认为由自治系统组成，例如一个全球公司，各国都有分公司，每个分公司都是一个自治系统，为了便于管理，需要给每个系统进行编号，对应的编号称为ASN。

通过域名，可以查询ASN。[此处查询](https://bgp.he.net/)

 ![img](C:\Users\wubo\MyNote\Images\1574049064_5dd2152829d46.jpg!small) 

 通过ASN，可以查询属于ASN的所有IP范围 

```bash
whois -h whois.radb.net  -- '-i origin AS36459' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq
```

**五、SAN**

SAN(Subject Alternate Name)主题备用名称，主题备用名称证书简单来说，在需要多个域名，将其用于各项服务时，可使用SAN证书。允许在安全证书中使用subjectAltName字段将多种值与证书关联，这些值被称为主题备用名称。名称可包括：IP地址、DNS名称等。 

 ![img](C:\Users\wubo\MyNote\Images\1574049162_5dd2158a9cd01.jpg!small) 

appsecco提供的脚本 

```bash
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(openssl x509 -noout -text -in <(openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \-connect xx.com:443))
```

![image-20191127171900069](C:\Users\wubo\MyNote\Images\image-20191127171900069.png)

### **主动枚举**

**一、字典枚举**

神器layer 等

**二、DNS区域传送**

经典的一个漏洞

```
dig @ns.example.com example=.com AXFR
```

**三、DNSSEC区域漫步**

DNSSEC(Domain Name System Security Extensions)，DNS安全扩展，主要用于验证DNS数据来源和数据是否被篡改。

DNSSEC通过向现有DNS记录添加签名来增强安全性，这些签名与常见记录类型一起存储。由于加密签名，DNSSEC处理不存在域时存在问题，可以区域遍历。

对使用NSEC记录的DNSSEC区域，使用ldns-walk测试区域遍历

```
ldns-walk @8.8.8.8 iana.org
```

利用[nsec3walker](https://dnscurve.org/nsec3walker.html)收集NSEC3哈希值并破解哈希值

```bash
# Collect NSEC3 hashes of a domain
./collect insecuredns.com > insecuredns.com.collect
# Undo the hashing, expose the sub-domain information.
./unhash < insecuredns.com.collect > insecuredns.com.unhash
```

```bash
# Listing only the sub-domain part from the unhashed data
cat icann.org.unhash | grep "icann" | awk '{print $2;}'
```

**四、DNS记录**

<p>
    CNAME   别名记录，把一个域名解析到另一个域名 
    SPF     SPF是通过域名的TXT记录来进行设置的，SPF记录列出了所有被授权代表域名发送电子邮件的主机
</p>

CNAME

```
dig xxx.com cname
```

SPF

```
dig +short txt xxx.com | grep spf
```

![image-20191127182414863](C:\Users\wubo\MyNote\Images\image-20191127182414863.png)

[利用脚本](https://github.com/0xbharath/assets-from-spf) 

**五、HTTP headers**

<pre>Content-Security-Policy     简而言之就是白名单，主要用于防范XSS</pre>

[利用脚本](https://github.com/0xbharath/domains-from-csp)

### **自动化工具**

<pre>    <a href="https://github.com/OWASP/Amass">Amass</a><br/>    Layer</pre>



