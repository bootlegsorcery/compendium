---
title: Housekeeping
tags: [Penetration Testing]
---
# Reporting

[whoisflynn/OSCP-Exam-Report-Template](https://github.com/whoisflynn/OSCP-Exam-Report-Template/blob/master/OSCP-OS-XXXXX-Exam-Report_Template3.2.docx)

[OSCP-OS-XXXXX-Exam-Report_Template3.2.docx](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9f113ca5-f99c-4c50-83ff-35e1f5bdc344/OSCP-OS-XXXXX-Exam-Report_Template3.2.docx)

# Deleting Windows Admin Account

```bash
net user /delete jack sparrow
```

# Remove Windows User From Group

```bash
net localgroup $GROUP $USER /delete
```

# Fancy Print Information

## Windows SYSTEM

```bash
echo. && echo. && echo ---------- && echo whoami: && whoami && echo ---------- && echo root.txt: && type C:\\Users\\Administrator\\Desktop\\root.txt && echo. && echo ---------- && ipconfig
```

## Linux ROOT

```bash
echo ---------- && echo whoami: && whoami && echo ---------- && echo root.txt: && cat /root/root.txt && echo ---------- && ifconfig
```