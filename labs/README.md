# [Lab 1](./1/index.md)

## Topics

- nmap scanning
- dirb scanning
- phishing with AI
- whois

## Table of contents

- [Learning objectives](./1/index.md#learning-objectives)
- [Sandbox building blocks – containers](./1/index.md#sandbox-building-blocks--containers)
- [Start the sandbox](./1/index.md#start-the-sandbox)
  - [Notes](./1/index.md#notes)
- [Nmap](./1/index.md#nmap)
  - [Task: Scanning IP Blocks](./1/index.md#task-scanning-ip-blocks)
  - [Task: Scanning for running software and version numbers](./1/index.md#task-scanning-for-running-software-and-version-numbers)
  - [Task: Gather Victim Network Information: DNS](./1/index.md#task-gather-victim-network-information-dns)
  - [Task: Gather Victim Org Information](./1/index.md#task-gather-victim-org-information)
  - [Task: Wordlist Scanning](./1/index.md#task-wordlist-scanning)
- [dirb](./1/index.md#dirb)
  - [Task: Wordlist Scanning](./1/index.md#task-wordlist-scanning-1)
- [Generative AI](./1/index.md#generative-ai)
  - [Task: Phishing for Information](./1/index.md#task-phishing-for-information)
- [Web browser](./1/index.md#web-browser)
  - [Task: Search Open Technical Databases: WHOIS](./1/index.md#task-search-open-technical-databases-whois)
  - [Task: Search Victim-Owned Websites](./1/index.md#task-search-victim-owned-websites)
- [End of the lab](./1/index.md#end-of-the-lab)

# [Lab 2](./2/index.md)

## Topics

- metasploit
- wireshark
- exploit mitigation
- meterpreter

## Table of contents

- [Learning objectives](./2/index.md#learning-objectives)
- [Start the sandbox](./2/index.md#start-the-sandbox)
- [Metasploit](./2/index.md#metasploit)
  - [Task: Exploit Public-Facing Application](./2/index.md#task-exploit-public-facing-application)
- [Wireshark](./2/index.md#wireshark)
  - [Prerequisite: Enable packet capture for non-root users (kali) and start Wireshark](./2/index.md#prerequisite-enable-packet-capture-for-non-root-users-kali-and-start-wireshark)
  - [Task: Capture traffic of an exploit](./2/index.md#task-capture-traffic-of-an-exploit)
  - [Task: Search for traffic with exploit](./2/index.md#task-search-for-traffic-with-exploit)
- [Task: Detection and mitigation of the exploit](./2/index.md#task-detection-and-mitigation-of-the-exploit)
- [Task: Use Meterpreter for execution](./2/index.md#task-use-meterpreter-for-execution)
- [End of the lab](./2/index.md#end-of-the-lab)

# [Lab 3](./3/index.md)

## Topics

- password guessing
- priviledge escalation
- linpeas
- creating superuser account
- ssh server config
- ssh keys
- credential dumping
- password cracking
- cron job reverse shell
- turn off command history logging
- clearing logs
- attack detection
- attack mitigation

## Table of contents

- [Learning objectives](./3/index.md#learning-objectives)
- [Start the sandbox](./3/index.md#start-the-sandbox)
- [Attack](./3/index.md#attack)
  - [Task: Brute Force: Password Guessing](./3/index.md#task-brute-force-password-guessing)
  - [Task: Exploitation for Privilege Escalation](./3/index.md#task-exploitation-for-privilege-escalation)
  - [Task: Create Account: Local Account](./3/index.md#task-create-account-local-account)
  - [Task: Account Manipulation: SSH Authorized Keys](./3/index.md#task-account-manipulation-ssh-authorized-keys)
  - [Task: OS Credential Dumping: /etc/passwd and /etc/shadow and Brute Force: Password Cracking](./3/index.md#task-os-credential-dumping-etcpasswd-and-etcshadow-and-brute-force-password-cracking)
  - [Task: Scheduled Task/Job: Cron](./3/index.md#task-scheduled-taskjob-cron)
  - [Task: Impair Defenses: Impair Command History Logging](./3/index.md#task-impair-defenses-impair-command-history-logging)
  - [Task: Indicator Removal: Clear Linux or Mac System Logs](./3/index.md#task-indicator-removal-clear-linux-or-mac-system-logs)
- [Detection and mitigation](./3/index.md#detection-and-mitigation)
  - [Fail2ban](./3/index.md#fail2ban)
  - [Searching in system logs](./3/index.md#searching-in-system-logs)
- [End of the lab](./3/index.md#end-of-the-lab)

# [Lab 4](./4/index.md)

## Topics

- password guessing
- account discovery
- log enumeration
- meterpreter reverse shell
- exfiltration of sensitive documents
- reflection attack
- packet manipulation
    - scapy
- traffic analysis
    - tcpdump
    - wireshark

## Table of contents

- [Learning objectives](./4/index.md#learning-objectives)
- [Start the sandbox](./4/index.md#start-the-sandbox)
- [Sandbox Topology](./4/index.md#sandbox-topology)
- [Attack](./4/index.md#attack)
  - [Task: Brute Force: Password Guessing](./4/index.md#task-brute-force-password-guessing)
  - [Task: Account Discovery](./4/index.md#task-account-discovery)
  - [Task: Log Enumeration](./4/index.md#task-log-enumeration)
  - [Task: Remote Services and Valid Accounts](./4/index.md#task-remote-services-and-valid-accounts)
  - [Task: Create, deploy and use a reverse shell](./4/index.md#task-create-deploy-and-use-a-reverse-shell)
  - [Task: Search and collect sensitive documents](./4/index.md#task-search-and-collect-sensitive-documents)
  - [Task: Exfiltration Over C2 Channel](./4/index.md#task-exfiltration-over-c2-channel)
  - [Task: Network Denial of Service: Reflection Amplification](./4/index.md#task-network-denial-of-service-reflection-amplification)
- [Traffic analysis](./4/index.md#traffic-analysis)
  - [Task: Inspect C2 traffic](./4/index.md#task-inspect-c2-traffic)
- [End of the lab](./4/index.md#end-of-the-lab)

# [Lab 5](./5/index.md)

## Topics

- command injection
- brute forcing authentication
    - wfuzz
    - ffuf
    - hydra
- sql injection
    - manual
    - sqlmap
- password cracking

## Table of contents

- [Learning Objectives](./5/index.md#learning-objectives)
- [Sandbox](./5/index.md#sandbox)
- [Start the Sandbox](./5/index.md#start-the-sandbox)
- [Web Attacks](./5/index.md#web-attacks)
  - [Task: Command Injection](./5/index.md#task-command-injection)
  - [Task: Brute Force Using curl and wfuzz](./5/index.md#task-brute-force-using-curl-and-wfuzz)
  - [Task: Brute Force Using hydra](./5/index.md#task-brute-force-using-hydra)
  - [Task: SQL Injection](./5/index.md#task-sql-injection)
  - [Task: SQL Injection Using sqlmap](./5/index.md#task-sql-injection-using-sqlmap)
- [Switching to higher levels of DVWA security](./5/index.md#switching-to-higher-levels-of-dvwa-security)
- [End of the Lab](./5/index.md#end-of-the-lab)

# [Lab 6](./6/index.md)

## Topics

- traffic analysis
    - tshark
- command injection
- forced browsing
- brute forcing authentication
    - wfuzz
    - ffuf
    - hydra
- unrestricted file upload
- web shell attack
- cross site scripting attack
    - reflected
    - stored
    - dom based
- cross site request forgery attack
- man in the middle attack

## Table of contents

- [Learning Objectives](./6/index.md#learning-objectives)
- [Sandbox](./6/index.md#sandbox)
- [Start the Sandbox](./6/index.md#start-the-sandbox)
- [Web Attacks](./6/index.md#web-attacks)
  - [Task: tshark HTTP Traffic Analysis](./6/index.md#task-tshark-http-traffic-analysis)
  - [Task: Forced Browsing Attack](./6/index.md#task-forced-browsing-attack)
  - [Task: Brute Force Using wfuzz and ffuf](./6/index.md#task-brute-force-using-wfuzz-and-ffuf)
  - [Task: Unrestricted File Upload Attack](./6/index.md#task-unrestricted-file-upload-attack)
  - [Task: Cross-Site Scripting Attacks](./6/index.md#task-cross-site-scripting-attacks)
  - [Task: Cross-Site Request Forgery Attack](./6/index.md#task-cross-site-request-forgery-attack)
  - [Task: Man-in-the-Middle Attack](./6/index.md#task-man-in-the-middle-attack)
- [Feedback on Lab Sessions](./6/index.md#feedback-on-lab-sessions)
- [End of the Lab](./6/index.md#end-of-the-lab)
