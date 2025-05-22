# **Fingerprint Web Server**

## **Overview**

Fingerprinting a web server (WSTG-INFO-02) involves identifying the web server software (e.g., Apache, Nginx, IIS), its version, operating system, and configuration details to uncover potential vulnerabilities or misconfigurations. According to OWASP, this reconnaissance phase is critical for understanding the target’s technology stack, which can reveal outdated software, known exploits, or insecure settings. Fingerprinting is typically passive or minimally interactive to avoid detection, making it a foundational step in penetration testing.

**Impact**: Exposed server details can lead to:
- Identification of outdated software with known vulnerabilities (e.g., CVE exploits).
- Discovery of misconfigurations (e.g., verbose error messages, default pages).
- Insight into the server’s operating system, aiding further attacks (e.g., privilege escalation).
- Mapping of the application stack for targeted exploitation.

This guide provides a step-by-step methodology for fingerprinting web servers, adhering to OWASP’s WSTG-INFO-02, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for web server fingerprinting, suitable for both novice and experienced testers:

- **Nmap**: Open-source tool for network scanning and service version detection.
- **Netcat (nc)**: Utility for manual HTTP requests to inspect server responses.
- **cURL**: Command-line tool for sending HTTP requests and analyzing headers.
- **Burp Suite Community Edition**: Intercepts and analyzes HTTP responses for server details.
- **Wappalyzer**: Browser extension to identify web server and application technologies.
- **WhatWeb**: Command-line tool for fingerprinting web servers and frameworks.
- **HTTPrint**: Tool for analyzing HTTP headers and server banners (less common but effective).
- **Shodan**: Search engine for identifying internet-connected servers and their software.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite for analysis.
- **BannerGrab**: Tool for extracting server banners from TCP services.

### **Tool Setup Instructions**

1. **Nmap**:
   - Install on Linux: `sudo apt install nmap`.
   - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).
   - Verify: `nmap --version`.
2. **Netcat**:
   - Install on Linux: `sudo apt install netcat`.
   - Install on Windows: Use `ncat` from Nmap package.
   - Verify: `nc -h`.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
5. **Wappalyzer**:
   - Install as a browser extension (Chrome/Firefox) from [wappalyzer.com](https://www.wappalyzer.com/).
   - Enable and visit target site to view results.
6. **WhatWeb**:
   - Install: `sudo apt install whatweb` or `gem install whatweb`.
   - Verify: `whatweb --version`.
7. **HTTPrint**:
   - Download from [softpedia.com](https://www.softpedia.com/get/Network-Tools/Network-Testing/httprint.shtml) (Windows/Linux).
   - Run: `./httprint -h`.
8. **Shodan**:
   - Sign up at [shodan.io](https://www.shodan.io/).
   - Use web interface or CLI: `pip install shodan`.
9. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite (127.0.0.1:8080).
10. **BannerGrab**:
    - Install on Linux: `sudo apt install bannergrab`.
    - Verify: `bannergrab --help`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-02, focusing on passive and active techniques to fingerprint web servers while minimizing detection risks.

### **1. Analyze HTTP Headers**

Examine HTTP response headers to identify server software, versions, and additional technologies.

**Steps**:
1. **Send HTTP Request with cURL**:
   - Query the target:
     ```bash
     curl -I http://example.com
     ```
   - Output: Headers revealing server details.
2. **Inspect Headers with Burp Suite**:
   - Configure browser to proxy through Burp Suite (127.0.0.1:8080).
   - Visit `http://example.com` and check “HTTP History” for responses.
   - Look for headers like:
     - `Server`: Web server software (e.g., `Apache/2.4.29`).
     - `X-Powered-By`: Backend technologies (e.g., `PHP/7.2.0`).
     - `X-AspNet-Version`: ASP.NET version (e.g., `4.0.30319`).
3. **Manual Request with Netcat**:
   - Connect to the server:
     ```bash
     nc example.com 80
     ```
   - Type:
     ```
     HEAD / HTTP/1.0
     Host: example.com
     
     ```
   - Press Enter twice to view headers.
4. **Document Findings**:
   - Note server software, version, and additional headers.
   - Save responses in Burp Suite’s “Logger” or a text file.

**Example Insecure Response**:
```
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/7.2.0
Content-Type: text/html
```

**Remediation**:
- Disable verbose headers in Apache:
  ```
  ServerTokens Prod
  ServerSignature Off
  ```
- Remove `X-Powered-By` in PHP (`php.ini`):
  ```
  expose_php = Off
  ```

### **2. Perform Service Version Detection with Nmap**

Use Nmap to identify the web server software, version, and operating system.

**Steps**:
1. **Run Basic Scan**:
   - Scan the target:
     ```bash
     nmap example.com
     ```
   - Output: Open ports (e.g., 80, 443) and basic service info.
2. **Enable Version Detection**:
   - Use `-sV` for detailed fingerprinting:
     ```bash
     nmap -sV -p 80,443 example.com
     ```
   - Output: Server software (e.g., `Apache httpd 2.4.29`) and protocols.
3. **Detect Operating System**:
   - Use `-O` for OS fingerprinting:
     ```bash
     nmap -O -sV example.com
     ```
   - Output: OS details (e.g., `Linux 4.x`).
4. **Analyze Results**:
   - Cross-reference versions with CVE databases (e.g., [cve.mitre.org](https://cve.mitre.org/)).
   - Note: Requires permission for active scanning.

**Example Output**:
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
OS details: Linux 4.4 - 4.15
```

**Remediation**:
- Update server software to the latest version.
- Use a reverse proxy (e.g., Nginx) to obscure backend server details.
- Restrict Nmap scans with a firewall (e.g., `iptables`).

### **3. Use Automated Fingerprinting Tools**

Leverage tools like WhatWeb, Wappalyzer, and HTTPrint to identify server and application details.

**Steps**:
1. **Run WhatWeb**:
   - Scan the target:
     ```bash
     whatweb http://example.com
     ```
   - Output: Server software, CMS, frameworks, and plugins.
2. **Use Wappalyzer**:
   - Open browser with Wappalyzer extension.
   - Visit `http://example.com` and view results (e.g., `Apache`, `PHP`, `WordPress`).
3. **Run HTTPrint**:
   - Execute:
     ```bash
     httprint -h example.com -s signatures.txt
     ```
   - Output: Server banner and fingerprint.
4. **Cross-Verify**:
   - Compare results across tools to confirm accuracy.
   - Note discrepancies (e.g., hidden servers behind proxies).

**Example WhatWeb Output**:
```
http://example.com [200 OK] Apache[2.4.29], PHP[7.2.0], Country[UNITED STATES][US], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)]
```

**Remediation**:
- Minimize server fingerprinting by removing identifiable headers.
- Use a Web Application Firewall (WAF) to obscure server details.

### **4. Query Shodan for Public Exposure**

Use Shodan to identify server details exposed to the internet.

**Steps**:
1. **Search Shodan**:
   - Query:
     ```
     hostname:example.com port:80
     ```
   - Look for:
     - Server banners (e.g., `Apache/2.4.29`).
     - Open ports and services.
2. **Analyze Results**:
   - Note software versions and IPs.
   - Cross-reference with scope to confirm relevance.
3. **Verify Findings**:
   - Use cURL to test identified endpoints:
     ```bash
     curl -I http://192.168.1.1
     ```

**Example Shodan Finding**:
- IP: `192.168.1.1`
- Banner: `Apache/2.4.29 (Ubuntu)`
- Port: `80`

**Remediation**:
- Restrict public access to sensitive IPs with firewalls.
- Update outdated software to mitigate known vulnerabilities.

### **5. Test Default Pages and Error Messages**

Check for default server pages or verbose error messages that reveal server details.

**Steps**:
1. **Access Common Paths**:
   - Test with cURL:
     ```bash
     curl http://example.com/server-status
     curl http://example.com/test.php
     ```
   - Look for default pages (e.g., Apache welcome page).
2. **Trigger Error Responses**:
   - Send invalid requests via Burp Suite:
     ```
     GET /nonexistent HTTP/1.1
     Host: example.com
     ```
   - Check for error pages revealing software (e.g., `Apache/2.4.29 Error`).
3. **Analyze with BannerGrab**:
   - Run:
     ```bash
     bannergrab example.com 80
     ```
   - Output: Server banner details.
4. **Document Findings**:
   - Save screenshots of default pages or error messages.
   - Log responses in Burp Suite.

**Example Insecure Response**:
```
HTTP/1.1 404 Not Found
Server: Apache/2.4.29 (Ubuntu)
Content-Type: text/html
<h1>Not Found</h1>
<p>Apache/2.4.29 (Ubuntu) Server at example.com Port 80</p>
```

**Remediation**:
- Disable default pages (e.g., remove `/server-status` in Apache).
- Customize error pages to avoid disclosing server details:
  ```
  ErrorDocument 404 /custom_404.html
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-02 with practical scenarios based on common web server fingerprinting patterns observed in penetration testing.

### **Test 1: Identify Outdated Apache Server**

Test for an outdated Apache server version with known vulnerabilities.

**Steps**:
1. **Run Nmap**:
   - Scan:
     ```bash
     nmap -sV -p 80 example.com
     ```
   - Output: `Apache httpd 2.4.18`.
2. **Check Headers with cURL**:
   - Query:
     ```bash
     curl -I http://example.com
     ```
   - Output: `Server: Apache/2.4.18 (Ubuntu)`.
3. **Verify Vulnerability**:
   - Search [cve.mitre.org](https://cve.mitre.org/) for `Apache 2.4.18`.
   - Example: CVE-2017-9798 (Optionsbleed).
4. **Analyze Impact**:
   - Confirm if server is exploitable with tools like Metasploit.

**Example Insecure Finding**:
```
HTTP/1.1 200 OK
Server: Apache/2.4.18 (Ubuntu)
```

**Example Secure Configuration**:
- Apache `httpd.conf`:
  ```
  ServerTokens Prod
  ServerSignature Off
  ```
- Update to latest Apache version (e.g., `2.4.62`).

**Remediation**:
- Apply security patches or upgrade Apache.
- Disable unnecessary modules (e.g., `mod_status`).

### **Test 2: Detect Exposed Server-Status Page**

Test for Apache’s `server-status` page revealing system details.

**Steps**:
1. **Access Page**:
   - Query:
     ```bash
     curl http://example.com/server-status
     ```
   - Check for response (e.g., server uptime, requests).
2. **Use Burp Suite**:
   - Send request:
     ```
     GET /server-status HTTP/1.1
     Host: example.com
     ```
   - Analyze response for sensitive data (e.g., internal IPs).
3. **Verify with Nmap**:
   - Scan for Apache modules:
     ```bash
     nmap --script http-apache-server-status example.com
     ```

**Example Insecure Finding**:
```
HTTP/1.1 200 OK
Server: Apache/2.4.29
Content-Type: text/html
<h1>Apache Server Status for example.com</h1>
Server Version: Apache/2.4.29 (Ubuntu)
Server Uptime: 120 days
```

**Example Secure Configuration**:
- Apache `httpd.conf`:
  ```
  <Location /server-status>
      Order deny,allow
      Deny from all
  </Location>
  ```

**Remediation**:
- Disable `mod_status` module.
- Restrict access to `/server-status` with authentication.

### **Test 3: Fingerprint IIS via Error Pages**

Test for Microsoft IIS server details in error pages.

**Steps**:
1. **Trigger Error**:
   - Send invalid request:
     ```bash
     curl http://example.com/nonexistent.aspx
     ```
   - Check for IIS error page.
2. **Analyze Headers**:
   - Use Burp Suite to capture:
     ```
     Server: Microsoft-IIS/8.5
     X-Powered-By: ASP.NET
     ```
3. **Run Nmap**:
   - Scan:
     ```bash
     nmap -sV -p 80 example.com
     ```
   - Output: `Microsoft-IIS/8.5`.

**Example Insecure Finding**:
```
HTTP/1.1 404 Not Found
Server: Microsoft-IIS/8.5
X-Powered-By: ASP.NET
```

**Example Secure Configuration**:
- IIS `web.config`:
  ```
  <system.webServer>
      <httpErrors errorMode="Custom" existingResponse="Replace">
          <remove statusCode="404" />
          <error statusCode="404" path="/custom_404.html" responseMode="File" />
      </httpErrors>
      <modules runAllManagedModulesForAllRequests="true">
          <remove name="ServerHeaderModule" />
      </modules>
  </system.webServer>
  ```

**Remediation**:
- Remove `Server` header via IIS configuration.
- Use custom error pages to hide server details.

### **Test 4: Identify Reverse Proxy with Shodan**

Test for a reverse proxy (e.g., Nginx) hiding backend server details.

**Steps**:
1. **Search Shodan**:
   - Query:
     ```
     hostname:example.com nginx
     ```
   - Output: `Nginx/1.14.0`.
2. **Check Headers**:
   - Query:
     ```bash
     curl -I http://example.com
     ```
   - Look for `Server: nginx/1.14.0`.
3. **Probe Backend**:
   - Test alternate ports or paths with Nmap:
     ```bash
     nmap -sV -p 1-1000 example.com
     ```
   - Check for backend server (e.g., Apache on port 8080).

**Example Insecure Finding**:
```
HTTP/1.1 200 OK
Server: nginx/1.14.0
X-Backend-Server: Apache/2.4.29
```

**Example Secure Configuration**:
- Nginx `nginx.conf`:
  ```
  server_tokens off;
  proxy_hide_header X-Backend-Server;
  ```

**Remediation**:
- Disable `server_tokens` in Nginx.
- Hide backend headers with `proxy_hide_header`.

## **Additional Tips**

- **Start Passive**: Use Shodan or header analysis to avoid active scanning detection.
- **Combine Tools**: Cross-verify Nmap results with WhatWeb and Wappalyzer for accuracy.
- **Gray-Box Testing**: If documentation is available, check for server configuration files.
- **Document Thoroughly**: Save all headers, Nmap outputs, and Shodan results in a report.
- **Bypass Defenses**: Test alternate ports (e.g., 8080, 8443) or use HTTP/1.0 requests to evade WAFs.
- **Stay Ethical**: Obtain explicit permission for active scans (e.g., Nmap) and avoid disrupting services.
- **Follow Best Practices**: Refer to OWASP’s Secure Headers Project for header remediation: [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).