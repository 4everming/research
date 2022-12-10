

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



”Security assessment framework for educational ERP systems“  这篇文章感觉略水，主要想要解决由CVE到CWE的匹配/关联的问题。 用的方式就是聚类/词频分析之类。 from 沙特的学校，好吧


“Remediation_of_Application-Specific_Security_Vulnerabilities_at_Runtime”
漏洞exploit行为产生的系统调用与正常的系统调用序列有明显的区别：
方法：
1.异常检测---较高的假阳性率 因为训练时，很难模拟覆盖程序所有的正常行为
2.基于规则的匹配--- 较低的假阳性率 但无法检测出新的攻击或者与已知攻击的变种攻击
综合两种方法


