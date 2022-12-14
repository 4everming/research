

Security data source

Information about security vulnerabilities can be gathered from various sources namely vulnerability databases. Some of them are publicly accessible (like OSVDB, NVD, CVE, etc.), and free others can be consulted after payment of a certain amount (like SecureBase by SPI Dynamics).

<br/>

Action enforcement suggestions	

To maintain users' systems secure and fully operational, people need to spend most of their time consulting security advisories in order to identify which of these vulnerabilities really represent a threat for their systems and to determine which countermeasures (e.g., installing a patch, modifying a firewall rule, etc.) must be applied

<br/>

现存的安全领域的数据库或spec：


#### Common Configuration Enumeration (CCE）  kubebench是否用了CCE？ 
#### Common Weakness Enumerations (CWE)
#### National Vulnerability Database (NVD)
#### Common Vulnerability Scoring System (CVSS)



通用弱点评价体系（CVSS）是由NIAC开发、FIRST维护的一个开放并且能够被产品厂商免费采用的标准。利用该标准，可以对弱点进行评分，进而帮助我们判断修复不同弱点的优先等级。
CVSS : Common Vulnerability Scoring System，即“通用漏洞评分系统”，是一个“行业公开标准，其被设计用来评测漏洞的严重程度，并帮助确定所需反应的紧急度和重要度”。
https://www.first.org/cvss/v3.1/specification-document

Project Narrows中的ArkSec Scanner使用的是CVSS 3.1的标准。
在CVSS中，分成3类metric group：
![image](https://raw.githubusercontent.com/4everming/research/main/security/paper-reading-summaries/cvss-metricgroup.png)

#### Base Metric Group (usually provided/defined by security/hardware/software vendors, such as Cicso/Redhat...)
该分数与配置无关，假定所有的完成攻击需要的条件都已经具备。
###### AV：分数从高到低 (N-A-L-P)
###### AC：the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability. 分数越高，复杂度越低。(Low, High)
###### PR: The Base Score is greatest if no privileges are required.(None, Low, High)
###### UI: This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. The Base Score is greatest when no user interaction is required. (None, Required)

###### Scope: whenever the impact of a vulnerability breaches a security/trust boundary and impacts components outside the security scope in which vulnerable component resides, a Scope change occurs. (Unchanged, Changed)

#### Temporal Metric Group (usually provided/defined by security vendors, not mandatory):
reflects the characteristics of a vulnerability that may change over time but not across user environments. For example, the presence of a simple-to-use exploit kit would increase the CVSS score, while the creation of an official patch would decrease it.
#### Environmental Metric Group(usually provided/defined by users, not mandatory)
The presence of security controls which may mitigate some or all consequences of a successful attack, and the relative importance of a vulnerable system within a technology infrastructure.



<br/>



CVSS得分基于一系列维度上的测量结果，这些测量维度被称为量度（Metrics）。漏洞的最终得分最大为10，最小为0。
而目前risk scanner的scale是0～5，why？
<br/>
<img width="797" alt="image" src="https://user-images.githubusercontent.com/12963596/207510597-da001825-2f6d-41f7-9f70-2ab843e991ec.png">








Papers：
”Security assessment framework for educational ERP systems“  这篇文章感觉略水，主要想要解决由CVE到CWE的匹配/关联的问题。 用的方式就是聚类/词频分析之类。 from 沙特的学校，好吧









“Remediation_of_Application-Specific_Security_Vulnerabilities_at_Runtime”
漏洞exploit行为产生的系统调用与正常的系统调用序列有明显的区别：
方法：
1.异常检测---较高的假阳性率 因为训练时，很难模拟覆盖程序所有的正常行为
2.基于规则的匹配--- 较低的假阳性率 但无法检测出新的攻击或者与已知攻击的变种攻击
综合两种方法


