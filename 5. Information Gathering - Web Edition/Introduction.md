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

| Record Type | Full Name                 | Description                                                                                                                                 | Zone File Example                                                                              |
| ----------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `A`         | Address Record            | Maps a hostname to its IPv4 address.                                                                                                        | `www.example.com.` IN A `192.0.2.1`                                                            |
| `AAAA`      | IPv6 Address Record       | Maps a hostname to its IPv6 address.                                                                                                        | `www.example.com.` IN AAAA `2001:db8:85a3::8a2e:370:7334`                                      |
| `CNAME`     | Canonical Name Record     | Creates an alias for a hostname, pointing it to another hostname.                                                                           | `blog.example.com.` IN CNAME `webserver.example.net.`                                          |
| `MX`        | Mail Exchange Record      | Specifies the mail server(s) responsible for handling email for the domain.                                                                 | `example.com.` IN MX 10 `mail.example.com.`                                                    |
| `NS`        | Name Server Record        | Delegates a DNS zone to a specific authoritative name server.                                                                               | `example.com.` IN NS `ns1.example.com.`                                                        |
| `TXT`       | Text Record               | Stores arbitrary text information, often used for domain verification or security policies.                                                 | `example.com.` IN TXT `"v=spf1 mx -all"` (SPF record)                                          |
| `SOA`       | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
| `SRV`       | Service Record            | Defines the hostname and port number for specific services.                                                                                 | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.`                             |
| `PTR`       | Pointer Record            | Used for reverse DNS lookups, mapping an IP address to a hostname.                                                                          | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.`                                            |
