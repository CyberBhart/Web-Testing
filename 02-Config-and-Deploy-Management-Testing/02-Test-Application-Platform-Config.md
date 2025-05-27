# Testing Application Platform Configuration

## Overview

Testing Application Platform Configuration (WSTG-CONF-02) involves assessing the configuration of the web application’s platform (e.g., web servers, application servers, frameworks) to ensure it is securely configured, minimizing vulnerabilities that could expose the application to attacks. According to OWASP, misconfigured application platforms can lead to unauthorized access, information disclosure, or exploitation of default settings. This test focuses on verifying secure configurations of server software, frameworks, and related components to mitigate misconfiguration risks.

**Impact**: Misconfigured application platforms can lead to:
- Unauthorized access to sensitive files or directories.
- Information disclosure via verbose error messages or server banners.
- Exploitation of default or weak configurations.
- Security bypass due to improper access controls.

This guide provides a practical, hands-on methodology for testing application platform configuration, adhering to OWASP’s WSTG-CONF-02, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing application platform configuration, with setup and configuration instructions:

- **Nikto**: Scans web servers for misconfigurations and vulnerabilities.
  - Install on Linux:
    ```bash
    sudo apt install nikto
    ```

- **Burp Suite Community Edition**: Analyzes HTTP responses for headers and misconfigurations.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Nmap**: Detects server software versions and configurations.
  - Install on Linux:
    ```bash
    sudo apt install nmap
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).

- **Wfuzz**: Brute-forces directories and files to find exposed resources.
  - Install:
    ```bash
    pip install wfuzz
    ```

- **Curl**: Tests HTTP methods and error responses.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Gobuster**: Enumerates directories and file extensions.
  - Install:
    ```bash
    sudo apt install gobuster
    ```
  - Alternative: Download from [github.com/OJ/gobuster](https://github.com/OJ/gobuster).

- **Python (with Requests Library)**: Automates testing for misconfigurations and security headers.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CONF-02, focusing on testing server software versions, default configurations, directory/file access, error handling, security headers, HTTP methods, and framework settings.

### 1. Scan for Server Software Versions with Nmap

**Objective**: Identify outdated or vulnerable server software versions.

**Steps**:
1. **Configure Nmap**:
   - Ensure permission to scan the target (`example.com`).
2. **Run Version Scan**:
   - Detect web server (e.g., Apache, Nginx) and application server versions.
3. **Analyze Findings**:
   - Vulnerable: Outdated versions (e.g., Apache 2.4.18).
   - Expected secure response: Latest, patched versions.

**Nmap Commands**:
- **Command 1**: Version detection:
  ```bash
  nmap -sV -p 80,443 example.com -oN nmap_version.txt
  ```
- **Command 2**: Script scan for vulnerabilities:
  ```bash
  nmap --script http-enum,http-server-header -p 80,443 example.com -oN nmap_scripts.txt
  ```

**Example Vulnerable Output**:
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 (vulnerable to CVE-2017-7679)
```

**Remediation**:
- Update server software:
  ```bash
  sudo apt update
  sudo apt upgrade apache2
  ```

**Tip**: Save Nmap output to a file (e.g., `nmap_version.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Nmap outputs).

### 2. Check for Misconfigurations with Nikto

**Objective**: Identify default configurations, exposed files, or server misconfigurations.

**Steps**:
1. **Configure Nikto**:
   - Ensure permission to scan the target.
2. **Run Nikto Scan**:
   - Scan for default files, directories, or misconfigurations.
3. **Analyze Findings**:
   - Vulnerable: Exposed `/admin` or default files (e.g., `/server-status`).
   - Expected secure response: No sensitive resources exposed.

**Nikto Commands**:
- **Command 1**: Basic scan:
  ```bash
  nikto -h example.com -output nikto_scan.txt
  ```
- **Command 2**: Scan with SSL:
  ```bash
  nikto -h https://example.com -ssl -output nikto_ssl.txt
  ```

**Example Vulnerable Output**:
```
+ Server: Apache/2.4.18 (vulnerable)
+ /manager/html: Tomcat Manager exposed
```

**Remediation**:
- Secure Tomcat Manager:
  ```xml
  <!-- /conf/tomcat-users.xml -->
  <tomcat-users>
      <!-- Remove default users -->
  </tomcat-users>
  ```
  ```apache
  <Location /manager>
      Require ip 192.168.1.0/24
  </Location>
  ```

**Tip**: Save Nikto output to a file (e.g., `nikto_scan.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Nikto outputs).

### 3. Test Directory and File Access with Gobuster

**Objective**: Verify that sensitive directories and files are protected.

**Steps**:
1. **Configure Gobuster**:
   - Use a wordlist (e.g., `/usr/share/wordlists/dirb/common.txt`).
2. **Run Directory Brute-Force**:
   - Enumerate directories and files (e.g., `/admin`, `.bak`).
3. **Analyze Findings**:
   - Vulnerable: Accessible sensitive directories or files.
   - Expected secure response: HTTP 403 or 404 for sensitive paths.

**Gobuster Commands**:
- **Command 1**: Directory enumeration:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -o gobuster_dirs.txt
  ```
- **Command 2**: File extension enumeration:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x .bak,.conf,.xml -o gobuster_files.txt
  ```

**Example Vulnerable Output**:
```
/admin (Status: 200)
/config.bak (Status: 200)
```

**Remediation**:
- Restrict access:
  ```nginx
  location /admin {
      deny all;
  }
  location ~* \.(bak|conf|xml)$ {
      deny all;
  }
  ```

**Tip**: Save Gobuster output to a file (e.g., `gobuster_dirs.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Gobuster outputs).

### 4. Test Error Handling with Curl

**Objective**: Check for verbose error messages exposing sensitive information.

**Steps**:
1. **Trigger Errors**:
   - Send invalid requests to trigger error responses.
2. **Analyze Responses**:
   - Look for stack traces, database details, or internal paths.
3. **Analyze Findings**:
   - Vulnerable: Error messages reveal sensitive data.
   - Expected secure response: Generic error pages.

**Curl Commands**:
- **Command 1**: Trigger error with invalid path:
  ```bash
  curl -i http://example.com/nonexistent
  ```
- **Command 2**: Test invalid parameter:
  ```bash
  curl -i "http://example.com/page?id=invalid"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Error: SQLSTATE[42000]: Syntax error at /var/www/html/page.php:32
```

**Remediation**:
- Disable verbose errors (PHP):
  ```php
  ; php.ini
  display_errors = Off
  log_errors = On
  ```

**Tip**: Save Curl responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Security Headers with Burp Suite

**Objective**: Ensure security headers are properly configured.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope.
2. **Capture Responses**:
   - Check headers like CSP, X-Frame-Options, HSTS.
3. **Analyze Findings**:
   - Vulnerable: Missing or weak headers.
   - Expected secure response: All headers present (e.g., `X-Frame-Options: DENY`).

**Burp Suite Commands**:
- **Command 1**: Check headers:
  ```
  HTTP History -> Select GET / -> Response tab -> Look for X-Frame-Options, Content-Security-Policy
  ```
- **Command 2**: Test header absence:
  ```
  HTTP History -> Select GET / -> Send to Repeater -> Remove X-Frame-Options -> Click Send -> Check response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[No Content-Security-Policy]
```

**Remediation**:
- Add security headers (Nginx):
  ```nginx
  add_header X-Frame-Options "DENY" always;
  add_header Content-Security-Policy "default-src 'self'" always;
  ```

**Tip**: Save response headers as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test HTTP Methods with Curl

**Objective**: Verify that unsafe HTTP methods are disabled.

**Steps**:
1. **Test HTTP Methods**:
   - Send requests with methods like TRACE, PUT, DELETE.
2. **Analyze Responses**:
   - Check if methods are enabled.
3. **Analyze Findings**:
   - Vulnerable: TRACE or PUT enabled.
   - Expected secure response: HTTP 405 or 403.

**Curl Commands**:
- **Command 1**: Test TRACE method:
  ```bash
  curl -i -X TRACE http://example.com
  ```
- **Command 2**: Test PUT method:
  ```bash
  curl -i -X PUT http://example.com/test.txt -d "test"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
TRACE / HTTP/1.1
```

**Remediation**:
- Disable unsafe methods (Apache):
  ```apache
  <Limit TRACE PUT DELETE>
      Order deny,allow
      Deny from all
  </Limit>
  ```

**Tip**: Save Curl responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Automate Testing with Python Script

**Objective**: Automate testing for misconfigurations and security headers.

**Steps**:
1. **Write Python Script**:
   - Create a script to check headers, methods, and file access:
     ```python
     import requests

     target = 'http://example.com'

     # Check security headers
     response = requests.get(target)
     headers = response.headers
     required_headers = {
         'X-Frame-Options': 'DENY',
         'Content-Security-Policy': "default-src 'self'",
         'X-Content-Type-Options': 'nosniff'
     }
     print("Security Headers:")
     for header, expected in required_headers.items():
         value = headers.get(header, 'Missing')
         print(f"{header}: {value}")
         if value == 'Missing':
             print(f"Vulnerable: Missing {header}")

     # Test HTTP methods
     methods = ['TRACE', 'PUT']
     print("\nHTTP Methods:")
     for method in methods:
         response = requests.request(method, target)
         print(f"{method}: Status={response.status_code}")
         if response.status_code == 200:
             print(f"Vulnerable: {method} enabled")

     # Test sensitive files
     files = ['/admin', '/config.bak']
     print("\nSensitive Files:")
     for file in files:
         response = requests.get(f"{target}{file}")
         print(f"{file}: Status={response.status_code}")
         if response.status_code == 200:
             print(f"Vulnerable: {file} accessible")
     ```
2. **Run Script**:
   - Install dependencies:
     ```bash
     pip install requests
     ```
   - Execute:
     ```bash
     python3 test_platform_config.py
     ```
3. **Analyze Findings**:
   - Vulnerable: Missing headers, enabled methods, or accessible files.
   - Expected secure response: All headers present; methods disabled; files inaccessible.

**Python Commands**:
- **Command 1**: Run platform config test:
  ```bash
  python3 test_platform_config.py
  ```
- **Command 2**: Test security headers:
  ```bash
  python3 -c "import requests; r=requests.get('http://example.com'); h=r.headers; print('X-Frame-Options:', h.get('X-Frame-Options', 'Missing'))"
  ```

**Example Vulnerable Output**:
```
Security Headers:
X-Frame-Options: Missing
Vulnerable: Missing X-Frame-Options

HTTP Methods:
TRACE: Status=200
Vulnerable: TRACE enabled

Sensitive Files:
/admin: Status=200
Vulnerable: /admin accessible
```

**Remediation**:
- Secure configuration (Nginx):
  ```nginx
  server {
      add_header X-Frame-Options "DENY" always;
      location /admin {
          deny all;
      }
      if ($request_method !~ ^(GET|POST)$) {
          return 405;
      }
  }
  ```

**Tip**: Save script output to a file (e.g., `python3 test_platform_config.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).
