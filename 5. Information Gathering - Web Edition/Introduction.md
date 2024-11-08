***

### Web Reconnaissance

- Identifying Assets
- Discovering Hidden Information
- Analysing the Attack Surface
- Gathering Intelligence

- Active Reconnaissance
	- Port Scanning
	- Vulnerability Scanning
	- Network Mapping
	- Banner Grabbing
	- OS Fingerprinting
	- Service Enumeration
	- Web Spidering
- Passive Reconnaissance
	- Search Engine Queries
	- WHOIS Lookups
	- DNS
	- Web Archive Analysis
	- Social Media Analysis
	- Code Repositories

### WHOIS

- Lets you look up who is responsible for various online assets:
	- Domain Names
	- IP Address Blocks
	- Autonomous Systems
- `whois <domain name>`
- Each WHOIS record typically contains the following information:
	- Domain Name
	- Registrar
	- Registrant Contact
	- Administrative Contact
	- Technical Contact
	- Creation and Expiration Dates
	- Name Servers
- Check out this OG: [Elizabeth Feinler](https://en.wikipedia.org/wiki/Elizabeth_J._Feinler)
- Registration Data Access Protocol (RDAP): Offers a more granular and privacy-conscious approach to accessing domain registration data.
- [WhoisFreaks](https://whoisfreaks.com/): Helps in accessing historical WHOIS records. Can reveal changes in ownership, contact information, or technical details over time.

### DNS

- Translates domain names to IP addresses
- Checks local cache -> DNS resolver cache -> Root Name Server -> TLD Name Server -> Authoritative Name Server 
- `hosts` file is a simple text file used to map hostnames to IP addresses, providing a manual method of domain name resolution that bypasses the DNS process.
	- Windows: `C:\Windows\System32\drivers\etc\hosts`
	- Linux: `/etc/hosts`
```
127.0.0.1       localhost
192.168.1.10    devserver.local
```

- DNS Zone is a distinct part of the domain namespace that a specific entity or administrator manages. For example, `example.com` and all its subdomains (like `mail.example.com` or `blog.example.com`) would typically belong to the same DNS zone.
- The zone file, a text file residing on a DNS server, defines the resource records (discussed below) within this zone, providing crucial information for translating domain names into IP addresses.

| Record Type | Full Name                 | Description                                                                                                                                 | Zone File Example                                                                              |     |
| ----------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --- |
| `A`         | Address Record            | Maps a hostname to its IPv4 address.                                                                                                        | `www.example.com.` IN A `192.0.2.1`                                                            |     |
| `AAAA`      | IPv6 Address Record       | Maps a hostname to its IPv6 address.                                                                                                        | `www.example.com.` IN AAAA `2001:db8:85a3::8a2e:370:7334`                                      |     |
| `CNAME`     | Canonical Name Record     | Creates an alias for a hostname, pointing it to another hostname.                                                                           | `blog.example.com.` IN CNAME `webserver.example.net.`                                          |     |
| `MX`        | Mail Exchange Record      | Specifies the mail server(s) responsible for handling email for the domain.                                                                 | `example.com.` IN MX 10 `mail.example.com.`                                                    |     |
| `NS`        | Name Server Record        | Delegates a DNS zone to a specific authoritative name server.                                                                               | `example.com.` IN NS `ns1.example.com.`                                                        |     |
| `TXT`       | Text Record               | Stores arbitrary text information, often used for domain verification or security policies.                                                 | `example.com.` IN TXT `"v=spf1 mx -all"` (SPF record)                                          |     |
| `SOA`       | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |     |
| `SRV`       | Service Record            | Defines the hostname and port number for specific services.                                                                                 | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.`                             |     |
| `PTR`       | Pointer Record            | Used for reverse DNS lookups, mapping an IP address to a hostname.                                                                          | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.`                                            |     |

### Digging DNS

- DNS Tools 
	- `dig`
	- `nslookup`
	- `host`
	- `dnsenum`
	- `fierce`
	- `dnsrecon`
	- `theHarvester`

- Example Queries:

	```
	dig domain.com
	dig domain.com A
	dig domain.com AAAA
	dig domain.com MX
	dig domain.com NS
	dig domain.com TXT
	dig domain.com CNAME
	dig domain.com SOA
	dig @1.1.1.1 domain (Specifies a specific name server to query)
	dig +trace domain.com (Shows the full path of the 
	DNS resolution)
	dig -x 192.168.1.1 (Performs a reverse look up)
	dig +short domain.com
	dig +noall +answer domain.com
	dig domain.com ANY
	```

### Sub Domains 

- Development and Staging Environments
- Hidden Login Portals
- Legacy Applications
- Sensitive Information

- Subdomains are typically represented by `A` or `AAAA` records.
- `CNAME` records might be used to create aliases for subdomains, pointing them to other domains or subdomains.
- Two main approaches to subdomain enumeration:
	1. Active Subdomain Enumeration
		1. Attempting a DNS zone transfer
		2. Brute force enumeration (`dnsenum`, `ffuf`, `gobuster` can help in automating the process)
	2. Passive Subdomain Enumeration
		1. Relies on external sources of information to discover subdomains without directly querying the target DNS servers (Certificate Transparency (CT) logs, public repositories of SSL/TLS certificates. Often include a list of associated subdomains in their Subject Alternative Name (SAN) field.)
		2. Search Engines like Google or DuckDuckGo along side the search operators (`site:`)
- Subdomain enumeration tools:
	- [dnsenum](https://github.com/fwaeytens/dnsenum)
		- DNS Record Enumeration
		- Zone Transfer Attempts
		- Subdomain Brute-Forcing
		- Google Scraping
		- Reverse Lookup
		- WHOIS Lookups
		- `dnsenum --enum <domain name> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
	- [fierce](https://github.com/mschwager/fierce)
	- [dnsrecon](https://github.com/darkoperator/dnsrecon)
	- [amass](https://github.com/owasp-amass/amass)
	- [assetfinder](https://github.com/tomnomnom/assetfinder)
	- [puredns](https://github.com/d3mondev/puredns)

### DNS Zone Transfers

- Zone Transfer Requests (AXFR)
- SOA Record Transfer
- DNS Records Transmission
- Zone Transfer Complete
- Acknowledgement (ACK)
- `dig axfr @<dns server responsible for the server> <domain name>`

### Virtual Hosts

- Web servers can be configured to host multiple websites or applications on a single server, they achieve this through virtual hosting.
	- This is achieved by leveraging the HTTP host header in the HTTP request.
	- `VHost fuzzing` is a technique to discover public and non-public `subdomains` and `VHosts` by testing various hostnames against a known IP address.
	- Virtual hosts can also be configured to use different domains, not just subdomains. 
	- Browser Requests a Website -> Host Header Reveals the Domain -> Web Server Determines the Virtual Host (Check its Vhost conf file) -> Serves the right content.
- Types of virtual hosting:
	- Name-based Virtual Hosting (Based on host headers)
	- IP-Based Virtual Hosting (Based on IP addresses)
	- Port-Based Virtual Hosting (Based on port numbers)
- Virtual host fuzzing tools:
	- [gobuster](https://github.com/OJ/gobuster)
	- [Feroxbuster](https://github.com/epi052/feroxbuster)
	- [ffuf](https://github.com/ffuf/ffuf)
	- `gobuster vhost -u http://<target IP> -w <wordlist> --append-domain`
		- `-t` flag to increase the number of threads for faster scanning.
		- `-k` flag can ignore SSL/TLS certificate errors.
		- `-o` flag to save the output to a file for later analysis.

### Certificate Transparency Logs

- `Certificate Transparency` (`CT`) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates. Whenever a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs. Independent organisations maintain these logs and are open for anyone to inspect.
- This transparency serves several crucial purposes:
	- Early Detection of Rogue Certificates
	- Accountability for Certificate Authorities
	- Strengthening the Web PKI (Public Key Infrastructure)
- Gain access to a historical and comprehensive view of a domain's subdomains, including those that might not be actively used or easily guessable.
- CT logs can unveil subdomains associated with old or expired certificates. These subdomains might host outdated software or configurations, making them potentially vulnerable to exploitation.
- Searching CT logs:
	- [crt.sh](https://crt.sh/)
		- `curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]| select(.name_value | contains("dev")) | .name_value' | sort -u`
	- [Censys](https://search.censys.io/)

### Fingerprinting

- Helps with:
	- targeted attacks
	- Identifying Misconfigurations
	- Prioritizing Targets
	- Building a Comprehensive Profile
- Techniques:
	- Banner Grabbing
	- Analyzing HTTP headers
		- The `Server` header typically discloses the web server software, while the `X-Powered-By` header might reveal additional technologies like scripting languages or frameworks.
	- Probing for Specific Responses
	- Analyzing Page Content
- Tools:
	- `curl -I <domain name>`
	- Wappalyzer
	- BuiltWith
	- WhatWeb
	- Nmap
	- Netcraft
	- wafw00f
		- `pip3 install git+https://github.com/EnableSecurity/wafw00f`
		- `wafw00f <domain name>
	- Nikto
```
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program 
chmod +x ./nikto.pl

nikto -h <domain name> -Tuning b
```



