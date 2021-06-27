---
title: Passive Information Gathering
tags: [Penetration Testing]
---
> ℹ️ Information gathering in which you gather information without directly interacting with the target or their systems.

# Physical Domain

-   Satellite Images
-   Drone Recon
-   Building Layouts

# Social Domain

-   Employees (name, job, phone number, managers, etc)
-   Pictures (any photo posted online which has seemingly mundane things in the background)

# Digital Domain

## Google Dorks

_Google is the world’s most popular search engine. As such, it knows a lot about everyone. It also has simple yet powerful filtering options. We can use this to our advantage._

[Offensive Security's Exploit Database Archive](https://www.exploit-db.com/google-hacking-database)

## Email Harvesting

Knowing _who_ you are attacking is just as important as knowing _what_ you’re attacking. Gathering email addresses can be a invaluable later in the later stages of a penetration test, especially when social engineering is required.

### [Hunter.io](http://Hunter.io)

[Find email addresses in seconds* Hunter (Email Hunter)](https://hunter.io/)

### theHarvester

[laramies/theHarvester](https://github.com/laramies/theHarvester)

```bash
theharvester -d $DOMAIN -l $RESULT_LIMIT -b $DATA_SOURCE
```

## Password Hunting

[Scylla](https://scylla.so/)

-   sublist3r
-   [https://ctr.sh/](https://ctr.sh/)
-   OWASP amass
-   [https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe)
-   [https://builtwith.com/](https://builtwith.com/)
-   [https://www.wappalyzer.com/](https://www.wappalyzer.com/)
-   whatweb
-   burpsuite can also be used to look at raw responses

## Indirect Active Information Gathering Services

There are some lovely companies out there that gather information on everyone, seemingly for the hell of it. Use these to get information generally reserved for the active information gathering stage.

[Shodan](https://www.shodan.io/)

[Netcraft](https://www.netcraft.com/)

[WHOIS Search, Domain Name, Website, and IP Tools - Who.is](https://who.is/)