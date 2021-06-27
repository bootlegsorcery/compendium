---
title: Active Information Gathering
tags: [Penetration Testing]
---
> ℹ️ Information gathering in which you interact directly with the target system/network.

# Port Scanning

[Classful Addressing](https://www.notion.so/ca7f8b4d642e44d09621e45cb91e443e)

## Unicorn Scan

[Unicornscan](https://tools.kali.org/information-gathering/unicornscan)

```bash
# Performing a Network Sweep
sudo unicornscan -mT $RHOSTS/$CLASS

# Single target - Standard
sudo unicornscan $RHOST

# Single Target - Full Range
sudo unicornscan $RHOST:0-65535
```

## NetDiscover (ARP Scan)

```bash
sudo netdiscover -r $RHOSTS/$CLASS
```

## Nmap

```bash
# Performing a Network Sweep, skipping the port scan.
nmap -sP 10.10.10.10/24

# Single Target - w/ banner grabbing and OS finger printing, with greppable format
nmap $RHOST10.10.10.10 -sV -O -oG -
```

# Service Enumeration

## Port 21 - FTP

```bash
ftp $RHOST

# Anonymous login
nmap --script=ftp-anon -p 21 $RHOST

# Bruteforce logins
nmap --script=ftp-brute -p 21 $RHOST
```

## Port 25 - SMTP

```bash
nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344, smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $RHOST
```

## Port 80 - HTTP

```bash
nikto -h $RHOST

curl $RHOST/robots.txt

# Suggested Wordlist: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Suggested extensions to look for: php, pl, sh, asp, html, json, py, cfm, aspx, rb, cgi
dirbuster

gobuster dir -u $URL -w $WORDLIST

ffuf -w $WORDLIST -u <https://$RHOST/FUZZ>
```

### Wordpress

```bash
nmap --script=http-wordpress* -p $RPORT $RHOST

# Enumerate
wpscan --url $RHOST --enumerate u[$LOW-$HIGH]vp

# Bruteforce
wpscan --url $RHOST --usernames [$USER_WORDLIST] --passwords [$PASS_WORDLIST]
```

## Port 110 - POP3

```bash
# List of services running RPC
# RPC can help find NFS-shares
rpcbind -p $RHOST

nmap --script="pop3-capabilities,pop3-ntlm-info" -sV -p $RPORT $RHOST #All are default scripts
```

## Port 135 - MSRPC

```bash
# Micro$oft RPC port
nmap 192.168.0.101 --script=msrpc-enum

rpcclient -U "" $RHOST
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```

## Port 139/445 - SMB

```bash
enum4linux [-u $USER][-p $PASS] $RHOST

smbmap [-u $USER][-p $PASS] -H $RHOST

smbclient -L \\\\\\\\$RHOST\\\\$SHARE [-U $USER] [$PASS] --option='client min protocol=NT1'

# Find NetBIOS info
nmblookup -A $RHOST

rpcclient -U "" -N $RHOST
    enumdomusers

# Info dump
nmap --script=smb-enum*.nse -p 139,445 $RHOST

# OS discovery
nmap --script=smb-os-discovery.nse -p 139,445 $RHOST

# Scan for known vulnerabilties
nmap --script=smb-vuln* -p 139,445 $RHOST
```

## Port 161 - SNMP

```bash
snmpwalk -c public -v1 $RHOST

snmpcheck -t $RHOST -c public

onesixtyone -c $NAMES_FILE -i $RHOST_FILE

snmpenum -t $RHOST
```

## Port 443 - HTTPS

```bash
nmap -sV --script=ssl-heartbleed $RHOST
```

## Port 2049 - NFS

```bash
# Enumeration
showmount -e $RHOST

# Mounting
mount $RHOST:/ /tmp/NFS
mount -t $RHOST:/ /tmp/NFS
```

## Port 5900 - VNC

```bash
vncviewer $RHOST
```

# Local Enumeration

## Linux Enumeration Script

[rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

[LinEnum.sh](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/22042460-159f-4d8c-b5c2-65f2dbd38000/LinEnum.sh)

[sleventyeleven/linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker/)

[linuxprivchecker.py](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f8f1ed84-76ca-4cff-8802-fb5654d8616c/linuxprivchecker.py)

[pentestmonkey/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check/)

[upc.sh](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7a3054bc-b98b-4b30-9194-2b7cba2693fc/upc.sh)

## Windows Enumeration Scripts

[AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/)

[windows-exploit-suggester.py](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8613451d-adec-4878-af77-d32b4f1710e2/windows-exploit-suggester.py)

[pentestmonkey/windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)

[windows_privesc_check.py](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/de5ddd93-9336-45da-af6c-101776fe5f28/windows_privesc_check.py)

[rasta-mouse/Sherlock](https://github.com/rasta-mouse/Sherlock)

[Sherlock.ps1](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/19410994-c904-4d38-aaf6-adf6e6914fdd/Sherlock.ps1)

# DNS Enumeration

DNS Servers are the address books of the internet. As such, they store a wealth of knowledge about the layout of a target’s network.

### Manual Enumeration

```bash
# Find IP address from domain (Forward Lookup)
host $DOMAIN

# Find domain from IP address (Reverse Lookup)
host $IP

# Find Name Servers
host -t ns $DOMAIN

# Find Mail Servers
host -t mx $DOMAIN

# Perform a Zone Transfer
host -l $DOMAIN $NAME_SERVER
```

### DNSRecon

Performs an “Asynchronous Transfer Full Range”

```bash
dnsrecon -d $DOMAIN -t axfr
```

### DNSEnum

Performs a Zone Transfer

```bash
dnsenum $DOMAIN
```