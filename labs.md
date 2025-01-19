# Labs

## Lab 1

### Topics

- nmap scanning
- dirb scanning
- phishing with AI
- whois

### Table of contents

- [Learning objectives](./labs/1/index.md#learning-objectives)
- [Sandbox building blocks – containers](./labs/1/index.md#sandbox-building-blocks--containers)
- [Start the sandbox](./labs/1/index.md#start-the-sandbox)
  - [Notes](./labs/1/index.md#notes)
- [Nmap](./labs/1/index.md#nmap)
  - [Task: Scanning IP Blocks](./labs/1/index.md#task-scanning-ip-blocks)
  - [Task: Scanning for running software and version numbers](./labs/1/index.md#task-scanning-for-running-software-and-version-numbers)
  - [Task: Gather Victim Network Information: DNS](./labs/1/index.md#task-gather-victim-network-information-dns)
  - [Task: Gather Victim Org Information](./labs/1/index.md#task-gather-victim-org-information)
  - [Task: Wordlist Scanning](./labs/1/index.md#task-wordlist-scanning)
- [dirb](./labs/1/index.md#dirb)
  - [Task: Wordlist Scanning](./labs/1/index.md#task-wordlist-scanning-1)
- [Generative AI](./labs/1/index.md#generative-ai)
  - [Task: Phishing for Information](./labs/1/index.md#task-phishing-for-information)
- [Web browser](./labs/1/index.md#web-browser)
  - [Task: Search Open Technical Databases: WHOIS](./labs/1/index.md#task-search-open-technical-databases-whois)
  - [Task: Search Victim-Owned Websites](./labs/1/index.md#task-search-victim-owned-websites)
- [End of the lab](./labs/1/index.md#end-of-the-lab)

## Lab 2

### Topics

- metasploit
- wireshark
- exploit mitigation
- meterpreter

### Table of contents

- [Learning objectives](./labs/2/index.md#learning-objectives)
- [Start the sandbox](./labs/2/index.md#start-the-sandbox)
- [Metasploit](./labs/2/index.md#metasploit)
  - [Task: Exploit Public-Facing Application](./labs/2/index.md#task-exploit-public-facing-application)
- [Wireshark](./labs/2/index.md#wireshark)
  - [Prerequisite: Enable packet capture for non-root users (kali) and start Wireshark](./labs/2/index.md#prerequisite-enable-packet-capture-for-non-root-users-kali-and-start-wireshark)
  - [Task: Capture traffic of an exploit](./labs/2/index.md#task-capture-traffic-of-an-exploit)
  - [Task: Search for traffic with exploit](./labs/2/index.md#task-search-for-traffic-with-exploit)
- [Task: Detection and mitigation of the exploit](./labs/2/index.md#task-detection-and-mitigation-of-the-exploit)
- [Task: Use Meterpreter for execution](./labs/2/index.md#task-use-meterpreter-for-execution)
- [End of the lab](./labs/2/index.md#end-of-the-lab)

## Lab 3

### Topics

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

### Table of contents

- [Learning objectives](./labs/3/index.md#learning-objectives)
- [Start the sandbox](./labs/3/index.md#start-the-sandbox)
- [Attack](./labs/3/index.md#attack)
  - [Task: Brute Force: Password Guessing](./labs/3/index.md#task-brute-force-password-guessing)
  - [Task: Exploitation for Privilege Escalation](./labs/3/index.md#task-exploitation-for-privilege-escalation)
  - [Task: Create Account: Local Account](./labs/3/index.md#task-create-account-local-account)
  - [Task: Account Manipulation: SSH Authorized Keys](./labs/3/index.md#task-account-manipulation-ssh-authorized-keys)
  - [Task: OS Credential Dumping: /etc/passwd and /etc/shadow and Brute Force: Password Cracking](./labs/3/index.md#task-os-credential-dumping-etcpasswd-and-etcshadow-and-brute-force-password-cracking)
  - [Task: Scheduled Task/Job: Cron](./labs/3/index.md#task-scheduled-taskjob-cron)
  - [Task: Impair Defenses: Impair Command History Logging](./labs/3/index.md#task-impair-defenses-impair-command-history-logging)
  - [Task: Indicator Removal: Clear Linux or Mac System Logs](./labs/3/index.md#task-indicator-removal-clear-linux-or-mac-system-logs)
- [Detection and mitigation](./labs/3/index.md#detection-and-mitigation)
  - [Fail2ban](./labs/3/index.md#fail2ban)
  - [Searching in system logs](./labs/3/index.md#searching-in-system-logs)
- [End of the lab](./labs/3/index.md#end-of-the-lab)

## Lab 4

### Topics

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

### Table of contents

- [Learning objectives](./labs/4/index.md#learning-objectives)
- [Start the sandbox](./labs/4/index.md#start-the-sandbox)
- [Sandbox Topology](./labs/4/index.md#sandbox-topology)
- [Attack](./labs/4/index.md#attack)
  - [Task: Brute Force: Password Guessing](./labs/4/index.md#task-brute-force-password-guessing)
  - [Task: Account Discovery](./labs/4/index.md#task-account-discovery)
  - [Task: Log Enumeration](./labs/4/index.md#task-log-enumeration)
  - [Task: Remote Services and Valid Accounts](./labs/4/index.md#task-remote-services-and-valid-accounts)
  - [Task: Create, deploy and use a reverse shell](./labs/4/index.md#task-create-deploy-and-use-a-reverse-shell)
  - [Task: Search and collect sensitive documents](./labs/4/index.md#task-search-and-collect-sensitive-documents)
  - [Task: Exfiltration Over C2 Channel](./labs/4/index.md#task-exfiltration-over-c2-channel)
  - [Task: Network Denial of Service: Reflection Amplification](./labs/4/index.md#task-network-denial-of-service-reflection-amplification)
- [Traffic analysis](./labs/4/index.md#traffic-analysis)
  - [Task: Inspect C2 traffic](./labs/4/index.md#task-inspect-c2-traffic)
- [End of the lab](./labs/4/index.md#end-of-the-lab)

## Lab 5

### Topics

- command injection
- brute forcing authentication
    - wfuzz
    - ffuf
    - hydra
- sql injection
    - manual
    - sqlmap
- password cracking

### Table of contents

- [Learning Objectives](./labs/5/index.md#learning-objectives)
- [Sandbox](./labs/5/index.md#sandbox)
- [Start the Sandbox](./labs/5/index.md#start-the-sandbox)
- [Web Attacks](./labs/5/index.md#web-attacks)
  - [Task: Command Injection](./labs/5/index.md#task-command-injection)
  - [Task: Brute Force Using curl and wfuzz](./labs/5/index.md#task-brute-force-using-curl-and-wfuzz)
  - [Task: Brute Force Using hydra](./labs/5/index.md#task-brute-force-using-hydra)
  - [Task: SQL Injection](./labs/5/index.md#task-sql-injection)
  - [Task: SQL Injection Using sqlmap](./labs/5/index.md#task-sql-injection-using-sqlmap)
- [Switching to higher levels of DVWA security](./labs/5/index.md#switching-to-higher-levels-of-dvwa-security)
- [End of the Lab](./labs/5/index.md#end-of-the-lab)

## Lab 6

### Topics

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

### Table of contents

- [Learning Objectives](./labs/6/index.md#learning-objectives)
- [Sandbox](./labs/6/index.md#sandbox)
- [Start the Sandbox](./labs/6/index.md#start-the-sandbox)
- [Web Attacks](./labs/6/index.md#web-attacks)
  - [Task: tshark HTTP Traffic Analysis](./labs/6/index.md#task-tshark-http-traffic-analysis)
  - [Task: Forced Browsing Attack](./labs/6/index.md#task-forced-browsing-attack)
  - [Task: Brute Force Using wfuzz and ffuf](./labs/6/index.md#task-brute-force-using-wfuzz-and-ffuf)
  - [Task: Unrestricted File Upload Attack](./labs/6/index.md#task-unrestricted-file-upload-attack)
  - [Task: Cross-Site Scripting Attacks](./labs/6/index.md#task-cross-site-scripting-attacks)
  - [Task: Cross-Site Request Forgery Attack](./labs/6/index.md#task-cross-site-request-forgery-attack)
  - [Task: Man-in-the-Middle Attack](./labs/6/index.md#task-man-in-the-middle-attack)
- [Feedback on Lab Sessions](./labs/6/index.md#feedback-on-lab-sessions)
- [End of the Lab](./labs/6/index.md#end-of-the-lab)
