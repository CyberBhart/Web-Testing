# **Enumerate Applications on Webserver**

## **Overview**

Enumerating applications on a web server (WSTG-INFO-04) involves identifying all web applications, services, or endpoints hosted on a target server, including their paths, versions, and technologies. This reconnaissance phase helps pentesters map the attack surface by discovering hidden or misconfigured applications, such as admin panels, APIs, or legacy systems. According to OWASP, this process is critical for understanding the server’s footprint and identifying potential vulnerabilities like outdated software or unprotected endpoints.

**Impact**: Exposed or misconfigured applications can lead to:
- Discovery of sensitive endpoints (e.g., `/admin`, `/api/v1`).
- Identification of outdated applications with known vulnerabilities.
- Exposure of development or staging environments.
- Increased attack surface for further exploitation (e.g., XSS, SQL injection).

This guide provides a step-by-step methodology for enumerating applications on a web server, adhering to OWASP’s WSTG-INFO-04, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for enumerating applications on a web server, suitable for both novice and experienced testers:

- **Nmap**: Open-source tool for scanning ports and identifying services.
- **GoBuster**: Tool for brute-forcing directories, files, and application endpoints.
- **DirBuster**: Alternative to GoBuster for enumerating application paths.
- **Burp Suite Community Edition**: Intercepts and crawls web applications to map endpoints.
- **OWASP ZAP**: Open-source web proxy for automated application discovery.
- **cURL**: Command-line tool for testing application URLs and responses.
- **Wappalyzer**: Browser extension to identify application technologies and frameworks.
- **WhatWeb**: Command-line tool for fingerprinting web applications.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **dnsdumpster**: Online tool for discovering subdomains and related applications.

### **Tool Setup Instructions**

1. **Nmap**:
   - Install on Linux: `sudo apt install nmap`.
   - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).
   - Verify: `nmap --version`.
2. **GoBuster**:
   - Install: `sudo apt install gobuster`.
   - Verify: `gobuster --version`.
   - Use wordlist: `/usr/share/wordlists/dirb/common.txt`.
3. **DirBuster**:
   - Download from [SourceForge](https://sourceforge.net/projects/dirbuster/).
   - Run: `java -jar DirBuster.jar`.
   - Configure with wordlists (e.g., `directory-list-2.3-medium.txt`).
4. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
5. **OWASP ZAP**:
   - Download from [owasp.org](https://www.zaproxy.org/download/).
   - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
   - Configure proxy: 127.0.0.1:8080.
6. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
7. **Wappalyzer**:
   - Install as a browser extension (Chrome/Firefox) from [wappalyzer.com](https://www.wappalyzer.com/).
   - Enable and visit target site to view results.
8. **WhatWeb**:
   - Install: `sudo apt install whatweb` or `gem install whatweb`.
   - Verify: `whatweb --version`.
9. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
10. **dnsdumpster**:
    - Access online at [dnsdumpster.com](https://dnsdumpster.com/).
    - No setup required.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-04, focusing on passive and active techniques to enumerate applications on a web server while minimizing detection risks.

### **1. Identify Hosted Applications via Port Scanning**

Use port scanning to discover services and applications running on the target server.

**Steps**:
1. **Run Basic Nmap Scan**:
   - Scan common ports:
     ```bash
     nmap example.com
     ```
   - Output: Open ports (e.g., 80, 443, 8080) and services (e.g., `http`, `https`).
2. **Enable Version Detection**:
   - Use `-sV` for detailed service fingerprinting:
     ```bash
     nmap -sV -p 80,443,8080,8443 example.com
     ```
   - Output: Application details (e.g., `Apache httpd 2.4.29`, `Tomcat 9.0.12`).
3. **Scan Non-Standard Ports**:
   - Scan a broader range:
     ```bash
     nmap -sV -p 1-65535 example.com
     ```
   - Look for hidden applications (e.g., admin panels on port 8080).
4. **Document Findings**:
   - Note ports, services, and versions.
   - Cross-reference with CVE databases (e.g., [cve.mitre.org](https://cve.mitre.org/)).

**Example Output**:
```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.29 ((Ubuntu))
8080/tcp open  http     Apache Tomcat/9.0.12
```

**Remediation**:
- Close unnecessary ports using a firewall (e.g., `iptables`).
- Update outdated applications to the latest versions.
- Use a reverse proxy to hide backend services.

### **2. Enumerate Application Paths with GoBuster**

Brute-force directories and files to discover application endpoints.

**Steps**:
1. **Run GoBuster**:
   - Enumerate paths with a wordlist:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html,js
     ```
   - Output: Discovered paths (e.g., `/admin`, `/api`, `/login.php`).
2. **Target Non-Standard Ports**:
   - Enumerate on alternate ports:
     ```bash
     gobuster dir -u http://example.com:8080 -w /usr/share/wordlists/dirb/common.txt
     ```
3. **Verify Findings**:
   - Test URLs with cURL:
     ```bash
     curl http://example.com/admin
     ```
   - Check for accessible applications or login pages.
4. **Document Results**:
   - Save URLs and response codes in a text file or Burp Suite’s “Logger”.

**Example Vulnerable Finding**:
- URL: `http://example.com/admin`
- Response: `HTTP/1.1 200 OK` with an admin login page.

**Remediation**:
- Restrict access to sensitive paths in Apache:
  ```
  <Location /admin>
      Order deny,allow
      Deny from all
      Allow from 127.0.0.1
  </Location>
  ```
- Require authentication for admin panels.

### **3. Crawl Applications with Burp Suite**

Use Burp Suite’s Spider or Crawler to map application endpoints.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope.
2. **Crawl the Site**:
   - In the “Target” tab, right-click `example.com` and select “Actively scan this host” or “Spider this host” (Community Edition limits apply).
   - Monitor “Site map” for discovered paths (e.g., `/dashboard`, `/api/v1`).
3. **Analyze Responses**:
   - Check HTTP responses for application details (e.g., CMS login pages, API endpoints).
   - Look for hidden forms or commented-out links.
4. **Document Findings**:
   - Export “Site map” or save screenshots of sensitive endpoints.

**Example Vulnerable Finding**:
- URL: `http://example.com/wordpress/wp-admin`
- Response: WordPress admin login page.

**Remediation**:
- Rename default admin paths (e.g., `/wp-admin` to `/custom-admin`).
- Implement HTTP authentication:
  ```
  <Location /wp-admin>
      AuthType Basic
      AuthName "Restricted Area"
      AuthUserFile /etc/apache2/.htpasswd
      Require valid-user
  </Location>
  ```

### **4. Fingerprint Applications with WhatWeb and Wappalyzer**

Identify application technologies, frameworks, and versions.

**Steps**:
1. **Run WhatWeb**:
   - Scan the target:
     ```bash
     whatweb http://example.com
     ```
   - Output: CMS (e.g., `WordPress 5.4.2`), frameworks (e.g., `PHP 7.2.0`), or plugins.
2. **Use Wappalyzer**:
   - Open browser with Wappalyzer extension.
   - Visit `http://example.com` and note technologies (e.g., `Drupal`, `Joomla`).
3. **Test Subdomains**:
   - Scan subdomains identified via dnsdumpster:
     ```bash
     whatweb http://app.example.com
     ```
4. **Cross-Verify**:
   - Compare results to confirm application versions.
   - Check CVE databases for known vulnerabilities.

**Example WhatWeb Output**:
```
http://example.com [200 OK] WordPress[5.4.2], PHP[7.2.0], Apache[2.4.29], Country[UNITED STATES][US]
```

**Remediation**:
- Update applications to the latest versions (e.g., WordPress 6.x).
- Remove version information from headers or responses.

### **5. Discover Subdomains with dnsdumpster**

Enumerate subdomains to identify additional applications.

**Steps**:
1. **Use dnsdumpster**:
   - Visit [dnsdumpster.com](https://dnsdumpster.com/).
   - Enter `example.com` and export results.
   - Output: Subdomains (e.g., `app.example.com`, `staging.example.com`).
2. **Verify Subdomains**:
   - Test with cURL:
     ```bash
     curl http://app.example.com
     ```
   - Check for hosted applications (e.g., APIs, admin panels).
3. **Scan with Nmap**:
   - Enumerate services on subdomains:
     ```bash
     nmap -sV app.example.com
     ```
4. **Document Findings**:
   - List subdomains and associated applications.

**Example Vulnerable Finding**:
- Subdomain: `staging.example.com`
- Response: `HTTP/1.1 200 OK` with a test application.

**Remediation**:
- Restrict public access to staging environments:
  ```
  <VirtualHost *:80>
      ServerName staging.example.com
      Order deny,allow
      Deny from all
      Allow from 192.168.1.0/24
  </VirtualHost>
  ```
- Remove unnecessary subdomains from DNS.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-04 with practical scenarios based on common application enumeration patterns observed in penetration testing.

### **Test 1: Discover Exposed Admin Panel**

Test for an unprotected admin panel on the web server.

**Steps**:
1. **Run GoBuster**:
   - Enumerate:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
     ```
   - Output: `/admin`.
2. **Test with cURL**:
   - Query:
     ```bash
     curl http://example.com/admin
     ```
   - Check for login page or direct access.
3. **Verify with Burp Suite**:
   - Send request:
     ```
     GET /admin HTTP/1.1
     Host: example.com
     ```
   - Analyze response for application details.

**Example Insecure Finding**:
- URL: `http://example.com/admin`
- Response: `HTTP/1.1 200 OK` with a login form.

**Example Secure Configuration**:
- Apache `.htaccess`:
  ```
  <Files "admin">
      AuthType Basic
      AuthName "Admin Area"
      AuthUserFile /etc/apache2/.htpasswd
      Require valid-user
  </Files>
  ```

**Remediation**:
- Require authentication for admin panels.
- Use non-standard paths for sensitive endpoints.

### **Test 2: Identify Outdated CMS**

Test for an outdated content management system (CMS) like WordPress.

**Steps**:
1. **Run WhatWeb**:
   - Scan:
     ```bash
     whatweb http://example.com
     ```
   - Output: `WordPress[5.4.2]`.
2. **Verify with Wappalyzer**:
   - Visit `http://example.com` with Wappalyzer enabled.
   - Confirm WordPress version.
3. **Check CVE Database**:
   - Search [cve.mitre.org](https://cve.mitre.org/) for `WordPress 5.4.2`.
   - Example: CVE-2020-4047 (XSS vulnerability).

**Example Insecure Finding**:
- URL: `http://example.com/wp-login.php`
- Response: WordPress 5.4.2 login page.

**Example Secure Configuration**:
- Update WordPress to latest version.
- Hide version in `functions.php`:
  ```php
  remove_action('wp_head', 'wp_generator');
  ```

**Remediation**:
- Regularly update CMS and plugins.
- Remove version metadata from responses.

### **Test 3: Find Staging Application on Subdomain**

Test for a staging application exposed via a subdomain.

**Steps**:
1. **Use dnsdumpster**:
   - Enter `example.com` and note subdomains (e.g., `staging.example.com`).
2. **Test Subdomain**:
   - Query:
     ```bash
     curl http://staging.example.com
     ```
   - Check for application presence.
3. **Run WhatWeb**:
   - Scan:
     ```bash
     whatweb http://staging.example.com
     ```
   - Output: Application details (e.g., `Django 2.2.10`).

**Example Insecure Finding**:
- URL: `http://staging.example.com`
- Response: Django debug page with stack trace.

**Example Secure Configuration**:
- Nginx `nginx.conf`:
  ```
  server {
      listen 80;
      server_name staging.example.com;
      return 403;
  }
  ```

**Remediation**:
- Restrict staging environments to internal networks.
- Disable debug modes in production.

### **Test 4: Enumerate API Endpoints**

Test for exposed API endpoints on the web server.

**Steps**:
1. **Run GoBuster**:
   - Enumerate:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x json,api
     ```
   - Output: `/api/v1`.
2. **Test with cURL**:
   - Query:
     ```bash
     curl http://example.com/api/v1
     ```
   - Check for API documentation or data.
3. **Crawl with OWASP ZAP**:
   - Configure ZAP proxy and spider `http://example.com`.
   - Analyze “Sites” for API endpoints.

**Example Insecure Finding**:
- URL: `http://example.com/api/v1/users`
- Response: JSON data with user details.

**Example Secure Configuration**:
- Apache `httpd.conf`:
  ```
  <Location /api>
      Order deny,allow
      Deny from all
      Allow from 192.168.1.0/24
  </Location>
  ```

**Remediation**:
- Require authentication for API endpoints.
- Use rate limiting to prevent enumeration.

## **Additional Tips**

- **Start Passive**: Use dnsdumpster and Wappalyzer to minimize active scanning.
- **Combine Tools**: Cross-verify GoBuster results with Burp Suite’s Crawler for comprehensive coverage.
- **Gray-Box Testing**: If documentation is available, check for references to subdomains or APIs.
- **Document Thoroughly**: Save all URLs, responses, and application details in a report.
- **Bypass Defenses**: Use case variations (e.g., `/ADMIN`, `/api/V1`) or alternate ports to evade WAFs.
- **Stay Ethical**: Obtain explicit permission for active scans (e.g., Nmap, GoBuster) and avoid disrupting services.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).