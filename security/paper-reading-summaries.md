

Security data source

Information about security vulnerabilities can be gathered from various sources namely vulnerability databases. Some of them are publicly accessible (like OSVDB, NVD, CVE, etc.), and free others can be consulted after payment of a certain amount (like SecureBase by SPI Dynamics).

<br/>

Action enforcement suggestions	

To maintain users' systems secure and fully operational, people need to spend most of their time consulting security advisories in order to identify which of these vulnerabilities really represent a threat for their systems and to determine which countermeasures (e.g., installing a patch, modifying a firewall rule, etc.) must be applied

<br/>

现存的安全领域的数据库或spec：


Common Configuration Enumeration (CCE）
Common Weakness Enumerations (CWE)
National Vulnerability Database (NVD)
Common Vulnerability Scoring System (CVSS)


Project Narrows中的ArkSec Scanner使用的是CVSS 3.1的标准。
在CVSS中，分成3类metric group：
![image](https://raw.githubusercontent.com/4everming/research/main/security/paper-reading-summaries/cvss-metricgroup.png)

<br/>

https://www.first.org/cvss/v3.1/specification-document


kubebench是否用了CCE？ 
