# **log4shell-everything** – One place for all valuable things about Log4Shell.
### A continually updated page for valuable Log4Shell resources and useful links.
Last update: Monday, 15 December 2021, 02:17 ET 

## Background 
Security teams all over the world are rushing to deal with the new critical zero-day vulnerability dubbed Log4Shell.
<br>
This vulnerability in Apache Log4j, a popular open-source Java logging library, has the potential to enable threat actors to compromise systems at scale.
<br>
Read more about this in our [blog post](https://www.mitiga.io/blog/log4shell-everything-in-one-place).

Here is a curated list of everything that you should know, and everything you should do.


## Detection

Name|Description|Source|Link|
:---|:---|:---|:---|
Logout4Shell|Use Log4Shell vulnerability to vaccinate a victim server against Log4Shell|GitHub/Cybereason|[Link](https://github.com/Cybereason/Logout4Shell)|
log4shell-detector|Detector for Log4Shell exploitation attempts|GitHub/Neo23x0|[Link](https://github.com/Neo23x0/log4shell-detector)|
Log4ShellScanner|Scans and catches callbacks of systems that are impacted by Log4J Log4Shell vulnerability across specific headers|GitHub/mwarnerblu|[Link](https://github.com/mwarnerblu/Log4ShellScanner)|
burp-log4shell|Log4Shell scanner for Burp Suite|GitHub/silentsignal|[Link](https://github.com/silentsignal/burp-log4shell)|
nse-log4shell|Nmap NSE scripts to check against Log4Shell vulnerabilities|Githuib/Diverto|[Link](https://github.com/Diverto/nse-log4shell)|
Log4jScanner|Scans only internal subnets for vulnerable log4j|Githuib/proferosec|[Link](https://github.com/proferosec/log4jScanner)|


## Remediation

Name|Description|Source|Link|
:---|:---|:---|:---|
Malicious domains|List of callback servers, used by attackers|Greynoise|[Link](https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8)|
Malicious IPs|List of scanning IP addresses|Greynoise|[Link](https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217)|
Hashes for vulnerable Log4J version|A list created to help organizations find vulnerable versions|GitHub/mubix|[Link](https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes)|
Log4Shell sample vulnerable application |A vulnerable Spring Boot web application|GitHub/christophetd|[Link](https://github.com/christophetd/log4shell-vulnerable-app)|
Log4j Hotpatch|Tool that hotpatches a running JVM process|Amazon/Corretto|[Link](https://github.com/corretto/hotpatch-for-apache-log4j2)|


## Vendor Advisories and Affected Componenets

Name|Description|Source|Link|
:---|:---|:---|:---|
Log4jAttackSurface|List of manufacturers and components affected by the Log4j vulnerability|YfryTchsGD|[Link](https://github.com/YfryTchsGD/Log4jAttackSurface)|
AWS - Security Bulletins|Update for Apache Log4j2 Issue |AWS|[Link](https://aws.amazon.com/security/security-bulletins/AWS-2021-006/)|
Google Cloud|Google Cloud’s security advisory|Google Cloud|[Link](https://cloud.google.com/log4j2-security-advisory)|
Apache Logging Services|Apache Log4j security vulnerabilities|Apache|[Link](https://logging.apache.org/log4j/2.x/security.html)|
Microsoft Security blog|Guidance for preventing, detecting, and hunting for Apache Log4j2 Issue |Microsoft|[Link](https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/)|
Salesforce|Update for Apache Log4j2 Issue |Salesforce|[Link](https://status.salesforce.com/generalmessages/826)|
Cisco|Log4j Developer Response|Cisco|[Link](https://blogs.cisco.com/developer/log4jdevresponse01?ccid=appdynamics-page&dtid=linkedin&oid=michaelchenetz-fy22-q2-0000-log4jdevresponse01-ww)|
Log4Shell log4j vulnerability (CVE-2021-44228) - cheat-sheet reference guide|List of vendors' responses|Tech Solvency / Royce Williams|[Link](https://www.techsolvency.com/story-so-far/cve-2021-44228-log4j-log4shell/)|
Security Advisories / Bulletins linked to Log4Shell |List of vendors' responses|GitHub/SwitHak|[Link](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592)|
log4j-log4shell-affected|Lists of affected components and affected apps/vendors|GitHub/authomize|[Link](https://github.com/authomize/log4j-log4shell-affected)|


## Indicators of Compromise

Name|Description|Source|Link|
:---|:---|:---|:---|
Indicators-of-Compromise|List of IoC to detect exploits of Log4Sell|Blumira|[Link](https://github.com/Blumira/Indicators-of-Compromise/tree/main/CVE-2021-44228)|
Log4Shell（CVE-2021-44228) related attacks IOCs|List of Indicators of compromise related Log4Sell attack|GitHub/RedDrip7|[Link](https://github.com/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs)|
Exploitation-of-Log4j2|List of Indicators of compromise identified by Threatview.io|GitHub/Malwar3Ninja|[Link](https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228/blob/main/Threatview.io-log4j2-IOC-list)|
List of IP and Domains|Domains and IP’s that have been observed to listen for incoming connections|nccgroup|[Link](https://research.nccgroup.com/2021/12/12/log4shell-reconnaissance-and-post-exploitation-network-detection/)|
Log4Shell-IOCs|A list of IOC feeds and threat reports focused on the recent Log4Shell exploit |GitHub/curated-intel|[Link](https://github.com/curated-intel/Log4Shell-IOCs)|



## Notable Blog Posts and Tweets
Communities, lists, discussion boards, newsletters, channels, chats, etc.

Name|Description|Source|Link|
:---|:---|:---|:---|
Aggregated Log4j Help Guide|List of dozens of open source resources including: Update/Patch, Vendor Advisories, Vulnerability/Exploitation Detections, and much more.|NCC Group|[Link](https://www.reddit.com/r/blueteamsec/comments/rd38z9/log4j_0day_being_exploited/)|
Video - Log4j Industry Impact|Video discussing Log4j and it’s potential impacts across the ecosystem|Youtube|[Link](https://www.youtube.com/watch?v=5-GkpxbZ9Zw)|
Log4Shell Vulnerability Tester|Free tool to test whether your applications are vulnerable|Huntress|[Link](https://log4shell.huntress.com)|
Non-Technical Log4j Breakdown|Explaining Log4j for non-technical people|Twitter/@Emy|[Link](https://twitter.com/entropyqueen_/status/1469606438632833027)|
Log4Shell Report|Booklet including Vulnerability Assessment & Mitigation w/ dozens of additional resources.|The Cyber Security Hub (1.3 Million Followers)|[Link](https://www.linkedin.com/posts/the-cyber-security-hub_log4shell-exploit-report-activity-6875729462323945472-6y6n)|
Detecting Log4j in Your Applications|How to detect Log4j Vulnerability in your applications|InfoWorld|[Link](https://www.infoworld.com/article/3644492/how-to-detect-the-log4j-vulnerability-in-your-applications.html)|
Govcert Log4j Update|Log4j in a nutshell. From attack to prevention.|Swiss Govcert|[Link](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)|
Video - Log4j Detection|Exactly what you need to know about log4j , how to demo it, detect it, & how to respond.|Youtube|[Link](https://www.youtube.com/watch?v=GvS-V27kFps)|
Check Point Log4j Inforgraphic|Inforgraphics and statistics|Check Point|[Link](https://www.checkpoint.com/wp-content/uploads/log4j-pandemic-visualization.jpg)|
Second log4j Vulnerability  🆕  |Details about CVE-2021-45046|LunaSec|[Link](https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/)|

<br>

## Log4Shell Explained
![Log4Shell Explained](/assets/log4shell_explained.png)

<br>

## Contact us
In order to add items to the list, email us at [contact@mitiga.io](mailto:contact@mitiga.io) or [contact as directly](https://www.linkedin.com/in/ormatt).