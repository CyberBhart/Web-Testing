# Testing Network Infrastructure Configuration

## Overview

Testing Network Infrastructure Configuration (WSTG-CONF-01) involves assessing the network infrastructure supporting a web application to ensure it is securely configured, minimizing vulnerabilities that could expose the application to attacks. According to OWASP, misconfigured network infrastructure can lead to unauthorized access, data leakage, or exploitation of network services. This test focuses on verifying secure configurations of servers, firewalls, load balancers, DNS, and TLS/SSL settings to mitigate network-level risks.

**Impact**: Misconfigured network infrastructure can lead to:
- Unauthorized access to servers or services via open ports or weak firewall rules.
- Data exposure from unencrypted communications or exposed administrative interfaces.
- Denial of Service (DoS) attacks exploiting misconfigured load balancers or servers.
- DNS misconfigurations enabling domain hijacking or phishing.

This guide provides a practical, hands-on methodology for testing network infrastructure configuration, adhering to OWASP’s WSTG-CONF-01, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing network infrastructure configuration, with setup and configuration instructions:

- **Nmap**: Scans for open ports, services, and software versions.
  - Install on Linux:
    ```bash
    sudo apt install nmap
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).

- **OpenSSL**: Tests TLS/SSL configurations for weak ciphers or protocols.
  - Install on Linux:
    ```bash
    sudo apt install openssl
    ```
  - Install on Windows/Mac: Pre-installed or download from [openssl.org](https://www.openssl.org/).

- **TestSSL**: Analyzes SSL/TLS settings for vulnerabilities.
  - Install:
    ```bash
    git clone https://github.com/drwetter/testssl.sh.git
    ```

- **DNSEnum**: Enumerates DNS records to detect misconfigurations.
  - Install:
    ```bash
    sudo apt install dnsenum
    ```
  - Alternative: `git clone https://github.com/fwaeytens/dnsenum.git`.

- **Nikto**: Scans web servers for misconfigurations and exposed interfaces.
  - Install:
    ```bash
    sudo apt install nikto
    ```

- **Burp Suite Community Edition**: Tests web server configurations and security headers.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Python (with python-nmap Library)**: Automates port scanning and TLS testing.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install python-nmap:
    ```bash
    pip install python-nmap
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CONF-01, focusing on testing open ports, firewall rules, TLS/SSL configurations, DNS settings, administrative interfaces, and software versions.

### 1. Scan for Open Ports and Services with Nmap

**Objective**: Identify unnecessary open ports or services that could be exploited.

**Steps**:
1. **Configure Nmap**:
   - Ensure permission to scan the target network (`example.com`).
2. **Perform Port Scan**:
   - Scan for open ports and services, including version detection.
   - Look for unexpected services (e.g., SSH, FTP, Telnet).
3. **Analyze Findings**:
   - Vulnerable: Unnecessary ports open (e.g., 22/SSH with weak credentials).
   - Expected secure response: Only required ports open (e.g., 80/HTTP, 443/HTTPS).

**Nmap Commands**:
- **Command 1**: Basic port scan:
  ```bash
  nmap -sS -p- example.com -oN nmap_scan.txt
  ```
- **Command 2**: Service and version detection:
  ```bash
  nmap -sV -O -p 22,80,443 example.com -oN nmap_version.txt
  ```

**Example Vulnerable Output**:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 (vulnerable)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X
```

**Remediation**:
- Close unnecessary ports:
  ```bash
  sudo ufw deny 22
  sudo ufw allow 80,443
  ```

**Tip**: Save Nmap output to a file (e.g., `nmap_scan.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Nmap outputs).

### 2. Test TLS/SSL Configuration with TestSSL

**Objective**: Ensure secure TLS/SSL settings to prevent interception or attacks.

**Steps**:
1. **Configure TestSSL**:
   - Navigate to `testssl.sh` directory.
2. **Run TLS/SSL Scan**:
   - Test the target server for weak ciphers, deprecated protocols (e.g., SSLv3), and misconfigurations.
3. **Analyze Findings**:
   - Vulnerable: Supports SSLv3, TLS 1.0, or weak ciphers (e.g., RC4).
   - Expected secure response: Only TLS 1.2/1.3 with strong ciphers.

**TestSSL Commands**:
- **Command 1**: Full TLS/SSL scan:
  ```bash
  ./testssl.sh --quiet example.com:443 > testssl_output.txt
  ```
- **Command 2**: Check for weak protocols:
  ```bash
  ./testssl.sh -P example.com:443
  ```

**Example Vulnerable Output**:
```
SSLv3: offered (NOT ok)
TLS 1.0: offered (NOT ok)
Weak cipher: RC4-MD5
```

**Remediation**:
- Configure secure TLS settings (e.g., Nginx):
  ```nginx
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
  ssl_prefer_server_ciphers on;
  ```

**Tip**: Save TestSSL output to a file (e.g., `testssl_output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., TestSSL outputs).

### 3. Enumerate DNS Configuration with DNSEnum

**Objective**: Detect DNS misconfigurations that could expose network details.

**Steps**:
1. **Configure DNSEnum**:
   - Ensure permission to query the target domain.
2. **Run DNS Enumeration**:
   - Attempt zone transfers and enumerate subdomains/records.
3. **Analyze Findings**:
   - Vulnerable: Zone transfers allowed or dangling records found.
   - Expected secure response: Zone transfers restricted; no sensitive records exposed.

**DNSEnum Commands**:
- **Command 1**: Enumerate subdomains:
  ```bash
  dnsenum --enum example.com -o dnsenum_output.txt
  ```
- **Command 2**: Attempt zone transfer:
  ```bash
  dnsenum --dnsserver ns1.example.com --enum example.com
  ```

**Example Vulnerable Output**:
```
Zone transfer successful:
subdomain1.example.com. IN A 192.168.1.10
internal.example.com. IN A 10.0.0.5
```

**Remediation**:
- Restrict zone transfers:
  ```bind
  acl "trusted" { 192.168.1.0/24; };
  zone "example.com" {
      type master;
      allow-transfer { trusted; };
  };
  ```

**Tip**: Save DNSEnum output to a file (e.g., `dnsenum_output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., DNS records).

### 4. Scan for Misconfigurations with Nikto

**Objective**: Identify web server misconfigurations or exposed interfaces.

**Steps**:
1. **Configure Nikto**:
   - Ensure permission to scan the target server.
2. **Run Nikto Scan**:
   - Scan for misconfigurations, outdated software, or exposed directories.
3. **Analyze Findings**:
   - Vulnerable: Exposed admin interfaces or outdated server versions.
   - Expected secure response: No sensitive directories or outdated software.

**Nikto Commands**:
- **Command 1**: Basic server scan:
  ```bash
  nikto -h example.com -output nikto_scan.txt
  ```
- **Command 2**: Scan with SSL:
  ```bash
  nikto -h https://example.com -ssl -output nikto_ssl.txt
  ```

**Example Vulnerable Output**:
```
+ Server: Apache/2.4.18 (vulnerable to CVE-2017-7679)
+ /admin/: Directory exposed
```

**Remediation**:
- Update server and restrict directories:
  ```apache
  <Directory /admin>
      Require all denied
  </Directory>
  ```

**Tip**: Save Nikto output to a file (e.g., `nikto_scan.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Nikto outputs).

### 5. Test Security Headers with Burp Suite

**Objective**: Verify security headers like HSTS to enforce secure communications.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope.
2. **Capture Responses**:
   - Access the application and check response headers for HSTS, CSP, etc.
3. **Analyze Findings**:
   - Vulnerable: Missing HSTS or weak headers.
   - Expected secure response: HSTS enabled (`max-age=31536000`).

**Burp Suite Commands**:
- **Command 1**: Check headers:
  ```
  HTTP History -> Select GET / -> Response tab -> Look for Strict-Transport-Security
  ```
- **Command 2**: Test without HTTPS:
  ```
  HTTP History -> Select GET / -> Send to Repeater -> Change to http://example.com -> Click Send -> Check redirect
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[No Strict-Transport-Security header]
```

**Remediation**:
- Enable HSTS:
  ```nginx
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  ```

**Tip**: Save response headers as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Automate Testing with Python Script

**Objective**: Automate port scanning and TLS/SSL testing.

**Steps**:
1. **Write Python Script**:
   - Create a script to scan ports and check TLS configurations:
     ```python
     import nmap
     import ssl
     import socket

     target = 'example.com'

     # Port scanning with Nmap
     nm = nmap.PortScanner()
     nm.scan(target, arguments='-sS -p-')
     print(f"Open ports for {target}:")
     for host in nm.all_hosts():
         for proto in nm[host].all_protocols():
             ports = nm[host][proto].keys()
             for port in ports:
                 state = nm[host][proto][port]['state']
                 service = nm[host][proto][port]['name']
                 print(f"Port {port}/{proto}: {state} ({service})")
                 if port not in [80, 443]:
                     print(f"Vulnerable: Unexpected port {port} open")

     # TLS/SSL protocol check
     context = ssl.create_default_context()
     with socket.create_connection((target, 443)) as sock:
         with context.wrap_socket(sock, server_hostname=target) as ssock:
             protocol = ssock.version()
             print(f"TLS Protocol: {protocol}")
             if protocol in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                 print(f"Vulnerable: Weak protocol {protocol}")
     ```
2. **Run Script**:
   - Install dependencies:
     ```bash
     pip install python-nmap
     ```
   - Execute:
     ```bash
     python3 test_network_config.py
     ```
3. **Analyze Findings**:
   - Vulnerable: Unexpected ports or weak TLS protocols detected.
   - Expected secure response: Only 80/443 open; TLS 1.2/1.3 used.

**Python Commands**:
- **Command 1**: Run network config test:
  ```bash
  python3 test_network_config.py
  ```
- **Command 2**: Test TLS protocol:
  ```bash
  python3 -c "import ssl, socket; context=ssl.create_default_context(); sock=socket.create_connection(('example.com', 443)); ssock=context.wrap_socket(sock, server_hostname='example.com'); print(ssock.version())"
  ```

**Example Vulnerable Output**:
```
Open ports for example.com:
Port 22/tcp: open (ssh)
Vulnerable: Unexpected port 22 open
TLS Protocol: TLSv1
Vulnerable: Weak protocol TLSv1
```

**Remediation**:
- Secure server configuration:
  ```bash
  sudo ufw deny 22
  ```
  ```nginx
  ssl_protocols TLSv1.2 TLSv1.3;
  ```

**Tip**: Save script output to a file (e.g., `python3 test_network_config.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).
