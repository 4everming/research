

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

###### C(Confidentiality): This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. 泄漏信息的密级？ (High, Low, None)

###### I(Integrity): 对完整性的影响。 (High,Low,None)

###### A(Availability): 对被攻击系统可用性的影响。(High, Low, None)



#### Temporal Metric Group (usually provided/defined by security vendors, not mandatory):
The Temporal metrics measure the current state of exploit techniques or code availability, the existence of any patches or workarounds, or the confidence in the description of a vulnerability.
Reflects the characteristics of a vulnerability that may change over time but not across user environments. For example, the presence of a simple-to-use exploit kit would increase the CVSS score, while the creation of an official patch would decrease it.


###### E(Exploit Code Maturity): Publication of proof-of-concept code, functional exploit code, or sufficient technical details necessary to exploit the vulnerability. The more easily a vulnerability can be exploited, the higher the vulnerability score. (Not Definded, High, Functional, Proof-of-concpept, Unproven)

###### RL(Remediation Level): The less official and permanent a fix, the higher the vulnerability score. (Not defined, Unavailable, Workaround, Temporary Fix, Official Fix)

###### RC(Report Confidence): Sometimes only the existence of vulnerabilities is publicized, but without specific details. For example, an impact may be recognized as undesirable, but the root cause may not be known. (Not Defined, Confirmed, Reasonable, Unknown)

#### Environmental Metric Group(usually provided/defined by users, not mandatory)
The presence of security controls which may mitigate some or all consequences of a successful attack, and the relative importance of a vulnerable system within a technology infrastructure.
If an IT asset supports a business function for which Availability is most important, the analyst can assign a greater value to Availability relative to Confidentiality and Integrity. Each Security Requirement has three possible values: Low, Medium, or High.

###### CR,IR,AR
The full effect on the environmental score is determined by the corresponding Modified Base Impact metrics. That is, these metrics modify the environmental score by reweighting the Modified Confidentiality, Integrity, and Availability impact metrics. 

Note that the Confidentiality Requirement will not affect the Environmental score if the (Modified Base) confidentiality impact is set to None. Also, increasing the Confidentiality Requirement from Medium to High will not change the Environmental score when the (Modified Base) impact metrics are set to High. This is because the Modified Impact Sub-Score (part of the Modified Base Score that calculates impact) is already at a maximum value of 10.

###### Modified Base Metrics
These metrics enable the analyst to override individual Base metrics based on specific characteristics of a user’s environment. Characteristics that affect Exploitability, Scope, or Impact can be reflected via an appropriately modified Environmental Score.
与Base metric一一对应。在计算分数前，直接改写Base metrics的值。默认是default，即不对Base metric做任何改动。

<br/>



CVSS得分基于一系列维度上的测量结果，这些测量维度被称为量度（Metrics）。漏洞的最终得分最大为10，最小为0。
而目前risk scanner的scale是0～5。
<br/>








Papers：
”Security assessment framework for educational ERP systems“  这篇文章感觉略水，主要想要解决由CVE到CWE的匹配/关联的问题。 用的方式就是聚类/词频分析之类。 from 沙特的学校，好吧





“Remediation_of_Application-Specific_Security_Vulnerabilities_at_Runtime”
漏洞exploit行为产生的系统调用与正常的系统调用序列有明显的区别：
方法：
1.异常检测---较高的假阳性率 因为训练时，很难模拟覆盖程序所有的正常行为
2.基于规则的匹配--- 较低的假阳性率 但无法检测出新的攻击或者与已知攻击的变种攻击
综合两种方法


