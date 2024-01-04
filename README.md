# Crime-scene-investigation-Episose-1
Phishing Emails Alert:
Phishing Emails Alert:
1- Check Email Headers (SPF, DKIM, Message-ID, Sender && Return-path)
2- Inspect Email content
3- Verify SMTP IP in Virustotal, AbuseIPDB, X-Force, Talos intelligence
4- Investigate Attachments at Virustotal, urlscan, Any.run, joesandbox, Hybrid-Analysis
↪ Note: If Attachment is a domain, check registration time
5- Confirm if the user opened the Attachment
✍  https://lnkd.in/dfscKs4n


🦠 Malware Investigation:
1- Check File hash in threat intelligence
2- AV Action, ensure not deleted/cleaned/quarantined; create L2 ticket if needed
3- Examine File path to determine device infection source
4- Check Malware category - Contact user for known results like Ransomware
✍  https://lnkd.in/dpZdSziE


🤖 Brute Force Analysis:
1- Determine login operation origin (local or remote) by checking Source IP
2- Inspect destination IP/Service to identify targeted service
3- Review Logon Type to understand login method
4- Analyze Login Failure Reason to verify user legitimacy
5- Check IDS/IPS & WAF Logs for automation tool usage
6- Confirm successful or unsuccessful login

⚔ DoS/DDoS Attack Alert:
1- Check source IP(s) to determine local or remote origin
↪Note: If remote, check threat intelligence; if local, create L2 ticket to check the host
2- Verify if Destination IP still operational manually
3- Run "netstat -an" command for strange connections
4- Run ping command to detect dropped packets
✍ DDOS:  https://lnkd.in/eQ7zZzVt
✍ MaliciousNetworkBehaviour:  https://lnkd.in/ewVZy2cs

🚫 Proxy Logs Investigation (Communication to bad IP/domain):
1- Check Proxy Category to determine domain type
2- Review device action
3- Examine Destination IP/domain at AbuseIPDB, Virustotal, urlscan
↪Note: For a domain, check registration time
4- Confirm Destination Port
5- Check User-agent
6- Verify Bytes Sent && Bytes Received
7- Inspect request method
8- Scrutinize Referer Header
9- Validate Content-Type Header
↪Note: Detection also possible through SIEM Graph

📊 Windows Event Log Analysis (Login & Logout):
1- Check event id/name
2- Verify login type to understand login method
3- Confirm workstation for DNS Name
4- Review status and sub-status for failure
✍  https://lnkd.in/dpVJRJmY
✍  https://lnkd.in/d7ABVqjw
✍  https://lnkd.in/dgJfKpz2

🛑 Unknown Process Installation Investigation:
1- Check process name for anomalies
2- Examine process id to identify parent or child process
↪Note: If a child process, check creator process id to identify the parent process
3- Confirm creator process name to determine the process path
4- Check process hash in threat intelligence
5- Verify token elevation to understand the user's app privilege


                Phishing Email Analysis Tools

✔1-Email Header Analysis >>
- MXToolbox:  https://lnkd.in/gxaGmWcg
- Amazon:  https://lnkd.in/gsMav4i6
- MailHeader:  https://mailheader.org/

✔2-URL / IP Reputation Check
- Virustotal >>  https://lnkd.in/gNqxtn4d
- URLScan >>  https://urlscan.io/
- Talosintelligence >>  https://lnkd.in/g7uWdC5q
- AbuseIPdb >>  https://www.abuseipdb.com/
- IPinfo:  https://ipinfo.io/
- Check Phish >>  https://checkphish.ai/

✔3-File / Attachment / Malware Analysis
- File Hash check >>  https://lnkd.in/gNqxtn4d
- Anyrun Sandboxing >>  https://any.run/
- Hybrid-Analysis Sandboxing >>  https://lnkd.in/gaRGY8kB
- Joesandbox >>  https://lnkd.in/gTJJ9GiC
- Cuckoo Sandbox >>  https://cuckoo.cert.ee/
- VMRay >>  https://lnkd.in/gDytZZgz
- Triage >>  https://tria.ge/dashboard

✔4-Whois domain record
- Centralops >>  https://centralops.net/co/
- Domaintools >>  https://lnkd.in/gHMr7BqM

✔5-Phishing analysis tool
- Phish Tool >> https://www.phishtool.com/

✔6 - Miscellaneous
- Browser Sandbox >>  https://lnkd.in/gjA-QqdX
- EML file opener >>  https://lnkd.in/gBfPbqas

![image](https://github.com/AmadouMan/Crime-scene-investigation-Episose-1/assets/138404140/b1cd3972-00d1-49eb-8667-1a470982923d)

