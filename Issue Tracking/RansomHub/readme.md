# [Ransomware Profile Report] RansomHub

## Overview
1. [Information](#1-information)
2. [Target](#2-target)
3. [Procedures](#3-procedures)
4. [Impact](#4-impact)
5. [MITRE ATT&CK Metrics](#5-mitre-attck-metrics)
6. [Reference](#6-reference)

## 1. Information

2024년 2월 중순, 새로운 랜섬웨어 그룹인 RansomHub가 등장하였다. 폐쇄된 랜섬웨어 그룹의 일부 대형 affiliate를 유치하여 현재 가장 활발한 활동을 보이고 있으며 서비스형 랜섬웨어(RaaS)를 통해 랜섬웨어 생태계를 장악하고 있다.

RansomHub는 ALPHV의 활동 종료와 함께 등장하였다. 2024년 2월 12일, ALPHV의 랜섬웨어 계열사 "Notchy"는 미국 의료 시스템 관리 회사인 Change Healthcare를 공격했다. 이 회사는 160만 명 이상의 의료 전문가, 7만 개의 약국, 8천 개의 의료 시설을 연결하는 중요한 역할을 했다. Change Healthcare는 ALPHV에 2,200만 달러의 몸값을 지불했으나, ALPHV는 Notchy와 수익을 나누지 않았다. 이 사건이 ALPHV의 마지막 공격이 되었으며, 이후 RansomHub는 ALPHV의 전 핵심 계열사인 Noberus를 영입하고 Scattered Spider와 협력하며 활발히 활동하고 있다.5

**2024년 9월** , RansomHub는 **74명의 새로운 피해자를** 확보 하여 전체 랜섬웨어 피해자의 **19%를** 차지했으며 , **2024년 8월** 의 **72명** 에서 증가한 수치를 보였다.

![[그림 1] 증가하는 RansomHub 피해자 (자료 - check point)](img/image.png/)

[그림 1] 증가하는 RansomHub 피해자 (자료 - check point)

## 2. Target

RansomHub의 영향은 전세계적이지만, 주로 미국 기반 기업, 특히 교육 및 기술 분야를 타겟으로 삼았다.

- 타겟 국가 : 미국, 말레이시아, 인도
    
    ![[그림 2] 2024년 1월부터 9월까지 타겟 국가 (자료 - trendmicro)](img/image%201.png)
    
    [그림 2] 2024년 1월부터 9월까지 타겟 국가 (자료 - trendmicro)
    

- 타겟 산업 : 교육 분야
    
    ![[그림 3] 2024년 1월부터 9월까지 타겟 산업 
    (자료 - trendmicro)](img/image%202.png)
    
    [그림 3] 2024년 1월부터 9월까지 타겟 산업 
    (자료 - trendmicro)
    

## 3. Procedures

![[그림 4] 2024년 RansomHub 공격 시나리오 (자료 - KARA 랜섬웨어 동향 보고서)](img/image%203.png)

[그림 4] 2024년 RansomHub 공격 시나리오 (자료 - KARA 랜섬웨어 동향 보고서)

RansomHub는 초기 침투를 위해 CVE-2020-1472 취약점을 이용하여 피해 시스템에 접근한다. 지속적인 접근을 위하여 원격 관리 도구(RMM)을 이용해 정상적인 소프트웨어로 위장하여 원격 접속 및 명령을 실행한다. 탐지를 피하기 위하여 Gobfuscate 및 TDSSKiller 도구를 이용해 난독화 및 AV 우회를 한다. 최종 공격 단계에서 RansomHub 랜섬웨어를 사용하여 데이터 암호화 및 금전을 요구한다.

### Tools

---

| Discovery | RMM Tools | Defense Evasion | Credential Access | OffSec | Execution | Exfiltration | Impact | Command and Control |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Angry IP Scanner | AnyDesk | ThreatFire System Monitor driver | Mimikatz | Cobalt Strike | BITSAdmin | PSCP | RansomHub Ransomware | Atera |
| Nmap | Atera | POORTRY  | LaZagne | CrackMapExec | PsExec | RClone | iisreset.exe | Splashtop |
| SoftPerfect NetScan | N-Able | STONESTOP | SecretServerSecretStealer | Impacket |  | WinSCP | iisrstas.exe | AnyDesk |
|  | ScreenConnect | TOGGLEDEFENDER | Veeamp | Kerbrute |  |  |  | Ngrok |
|  | Splashtop | Gobfuscate  |  | Metasploit |  |  |  | Remmina |
|  |  | TDSSKiller |  | Sliver |  |  |  | ConnectWise Screen Connect |

### Vulnerabilities

---

| Vendor | Product | CVE | Description |
| --- | --- | --- | --- |
| Apache | ActiveMQ | CVE-2023-46604 | 인증이 취약하거나 세션 관리가 잘못되어 원격 코드 실행(RCE)을 가능하게 만드는 취약점 |
| Atlassian | Confluence Data Center & Server | CVE-2023-22515 | 인증되지 않은 공격자가 Confluence 서버에서 원격 코드 실행을 할 수 있도록 허용하는 취약점 |
| Citrix | NetScaler ADC & Gateway | CVE-2023-3519 | 원격 코드 실행 취약점으로, 공격자가 악의적인 코드 실행 |
| Fortinet | FortiOS SSL-VPN & FortiProxy | CVE-2023-27997 | 인증 없이 원격 코드 실행 |
| Fortinet | FortiClientEMS | CVE-2023-48788 | 인증 우회 취약점으로 인해 공격자가 인증 없이 민감한 기능에 접근 가능 |
| F5 | BIG-IP | CVE-2023-46747 | 원격 코드 실행 취약점으로, 공격자가 관리되지 않은 접근을 통해 악성 코드 실행 |
| Windows | NetLogon | CVE-2020-1472 ("ZeroLogon") | Windows NetLogon 프로토콜에서의 인증 문제를 이용해 도메인 컨트롤러를 공격자가 완전히 장악 |
| Windows | BITS | CVE-2020-0787 | 로컬 사용자 권한을 관리자 권한으로 상승 |
| Windows | SMBv1 | CVE-2017-0144 ("EternalBlue") | 인증 없이 원격으로 코드 실행이 가능 |

## 4. Impact

- RansomHub는 데이터를 암호한 후 랜섬노트를 생성하며 폴더에 .png 형식의 6글자 문자가 포함된 이미지 파일을 만든다.
- 고유의 난독화 기술을 사용하는데, 모든 문자열이 아닌 중요한 문자열만 각각 고유한 키로 인코딩되고 런타임에 디코딩 된다.
- Zerologon 취약점을 악용하여 초기 액세스 권한을 얻는다.
- RansomHub는 Mimikatz, RClone, PsExec와 같은 해킹 도구를 활용하여 공격을 전개하고, Gobfuscate를 사용하여 악성코드를 난독화하고 탐지를 어렵게 만드는 등 분석 및 방어를 어렵게 한다.
    - 랜섬웨어 페이로드는 Golang 언어로 작성되었으며, x25519 기반의 비대칭 알고리즘과 AES256, ChaCha20, xChaCha20 암호화 알고리즘을 사용하며 AST를 사용하여 난독화하기 때문에 분석이 어려움
    - TOGGLEDEFENDER, STONESTOP, POORTRY와 같은 도구를 사용하여 EDR(Endpoint Detection and Response) 또는 Windows Defender와 같은 보안 소프트웨어를 비활성화하거나 우회
    - 정상적인 원격 액세스 소프트웨어(RMM)를 악용하여 명령 및 제어(C2) 채널을 설정
    - WMIC.exe 유틸리티를 사용하여 섀도 복사본을 삭제
    - cmd.exe를 사용하여 다양한 Windows 유틸리티를 실행하여 다양한 다른 기술을 구현
    - wevtutil.exe 유틸리티를 사용하여 피해 시스템의 애플리케이션, 시스템 및 보안 이벤트 로그를 지움

### Knight, ALHPV, RansomHub

RansomHub 그룹은 Knight, ALHPV 랜섬웨어 그룹의 리브랜딩이다. 

- Knight(Cyclops) 리브랜딩
    
    RansomHub의 RaaS 운영 관리 패널은 Knight RaaS 패널과 디자인과 기능과 사용된 코드 및 랜섬노트, 실행 시 전달되는 인자가 상당 부분 유사하다. Knight가 활동을 종료한 시기와 RansomHub가 활동을 개시한 시기가 비슷해 RansomHub 랜섬웨어가 Knight 랜섬웨어 그룹의 후속 또는 대체일 수 있음을 시사한다.
    
    ![[그림 5] Knight(상), RansomHub(하) 명령줄 도움 (자료 - symantec)](img/image%204.png)
    
    [그림 5] Knight(상), RansomHub(하) 명령줄 도움 (자료 - symantec)
    

- ALHPV(BlackCat) 리브랜딩
    
    RansomHub 랜섬웨어는 ALHPV 랜섬웨어와 마찬가지로 암호화 구성을 정의하는 JSON이 코드에 내장되어 있고, 랜섬 노트에서 ALPHV 그룹의 랜섬 노트의 일부 문구가 발견되었다.
    
    ![[그림 6] RansomHub(상), ALHPV(하) 랜섬노트 일부 (자료 - KARA 랜섬웨어 동향 보고서)](img/image%205.png)
    
    [그림 6] RansomHub(상), ALHPV(하) 랜섬노트 일부 (자료 - KARA 랜섬웨어 동향 보고서)
    

### 다크웹 포럼에서의 활동

RansomHub는 다크웹에 자체 사이트를 운영하며, 탈취한 정보를 게시한다. 메인 화면에는 피해 기업의 URL, 데이터 크기 등의 정보가 표시되며, 정보 공개까지 남은 시간이 실시간으로 카운트 다운된다.

아래의 표는 RansomHub 사이트에 게시된 피해 정보의 일부분이며, 전체 내용은 [다음 페이지](https://www.notion.so/RansomHub-List-16bcc74eafd880fdbb68e106aba0b8bf?pvs=21)에서 확인 할 수 있다.

| URL | Visits | Data Size | Last View |
| --- | --- | --- | --- |
| diazfoodsolutions.es | 1721 | 30 GB | 2024-12-26 20:24 |
| sensualcollection.com | 3420 | 10 GB | 2024-12-24 21:10 |
| www.mccoyglobal.com | 3559 | 472GB | 2024-12-16 22:47 |
| **⋮** | **⋮** | **⋮** | **⋮** |
| www.al-shefafarm.ro(SOLD) | 137348 | 150GB | 2024-02-23 9:14 |
| www.ykp.com.br | 243382 | 150GB | 2024-02-07 22:27 |

RansomHub의 관리자로 추정되는 Koley가 RAMP 포럼에서 활동한다.

![[그림 7] RansomHub의 첫 번째 게시물 (자료 - forescout)](img/image%206.png)

[그림 7] RansomHub의 첫 번째 게시물 (자료 - forescout)

RansomHub는 2월 2일에 koley가 RAMP 포럼에서 새로운 RaaS 프로그램을 발표하였다.

![[그림 8] 다크웹 포럼에서 RansomHub 원격 암호화 기능 발표  (자료 - forescout)](img/image%207.png)

[그림 8] 다크웹 포럼에서 RansomHub 원격 암호화 기능 발표  (자료 - forescout)

Koley가 RAMP 포럼에 원격 암호화 기능에 대한 정보를 게시하였고, affiliate에게 ALPHV의 증거를 보관하라는 지시를 내렸다.

### 정책

RansomHub 사이트에 공격에 대한 몇 가지 공지사항을 게시하였다.

공지 내용의 주요 사항은 CIS, 쿠바, 북한, 중국을 공격의 대상으로 삼지 않으며 이미 대가를 지불한 피해 기업에 대한 재공격은 허용되자 않는다는 것이다. 또한 affiliate와의 마찰이 있을 경우 Ransomhub로 연락을 달라는 내용도 포함되어 있다.

![[그림 9] RansomHub에 게시된 공지 사항](img/image%208.png)

[그림 9] RansomHub에 게시된 공지 사항

## 5. MITRE ATT&CK Metrics

| Tactic | T-ID | Technique |
| --- | --- | --- |
| Initial Access | T1078 | Valid Accounts |
|  | T1566.004 | Phishing: Spearphishing Voice |
| Execution | T1047 | Windows Management Instrumentation |
|  | T1059.001 | Command and Scripting Interpreter: PowerShell |
|  | T1059.006 |  Command and Scripting Interpreter: Python |
|  | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| Persistence | T1136.001  | Create Account: Local Account |
|  | T1098  | Account Manipulation |
|  | T1547.001  | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
|  | T1547  | Boot or Logon Autostart Execution |
| Privilege Escalation | T1078.003  | Valid Accounts: Local Accounts |
|  | T1134.001  | Access Token Manipulation: Token Impersonation/Theft |
| Defense Evasion | T1027.013  | Obfuscated Files or Information: Encrypted/Encoded File |
|  | T1070.001 | Indicator Removal: Clear Windows Event Logs |
|  | T1112  | Modify Registry |
|  | T1222.001  | Windows File and Directory Permissions Modification |
|  | T1480  | Execution Guardrails |
|  | T1562 | Impair Defenses: Disable or Modify Tools |
|  | T1562.006  | Impair Defenses: Indicator Blocking |
|  | T1562.009  | Impair Defenses: Safe Mode Boot |
|  | T1564.003  | Hide Artifacts: Hidden Window |
| Credential Access | T1003  | OS Credential Dumping |
|  | T1003.003  | OS Credential Dumping: NTDS |
|  | T1110  | Brute Force |
|  | T1110.003 | Brute Force: Password Spraying |
|  | T1003.001  | OS Credential Dumping: LSASS Memory |
|  | T1555.005  | Credentials from Password Stores: Password Managers |
| Discovery | T1057  | Process Discovery |
|  | T1082  | System Information Discovery |
|  | T1083  | File and Directory Discovery |
|  | T1087.001  | Account Discovery: Local Account |
|  | T1135  | Network Share Discovery |
| Lateral Movement  | T1570 | Lateral Tool Transfer |
|  | T1021.004  | Remote Services: SSH |
| Command and Control | T1105 | Ingress Tool Transfer |
| Impact | T1486 | Data Encrypted for Impact |
|  | T1489 | Service Stop |
|  | T1490 | Inhibit System Recovery |
|  | T1529  | System Shutdown/Reboot |
| Exfiltration | T1567.002  | Exfiltration to Cloud Storage |

## 6. Reference

[https://github.com/crocodyli/ThreatActors-TTPs/blob/main/RansomHub/RansomHub-TTP.md](https://github.com/crocodyli/ThreatActors-TTPs/blob/main/RansomHub/RansomHub-TTP.md)

[https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/Tools/MostUsedTools.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/Tools/MostUsedTools.md)

[https://www.boannews.com/media/view.asp?idx=134969&kind=1&search=title&find=ransomhub](https://www.boannews.com/media/view.asp?idx=134969&kind=1&search=title&find=ransomhub)

https://www.ransomware.live/group/ransomhub

[https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a)

[https://www.trendmicro.com/vinfo/kr/security/news/ransomware-spotlight/ransomware-spotlight-ransomhub](https://www.trendmicro.com/vinfo/kr/security/news/ransomware-spotlight/ransomware-spotlight-ransomhub)

[https://www.security.com/threat-intelligence/ransomhub-knight-ransomware](https://www.security.com/threat-intelligence/ransomhub-knight-ransomware)

[https://www.forescout.com/blog/analysis-a-new-ransomware-group-emerges-from-the-change-healthcare-cyber-attack/](https://www.forescout.com/blog/analysis-a-new-ransomware-group-emerges-from-the-change-healthcare-cyber-attack/)

[https://www.guidepointsecurity.com/blog/worldwide-web-an-analysis-of-tactics-and-techniques-attributed-to-scattered-spider/](https://www.guidepointsecurity.com/blog/worldwide-web-an-analysis-of-tactics-and-techniques-attributed-to-scattered-spider/)
