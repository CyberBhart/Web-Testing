# **Map Application Architecture**

## **Overview**

Mapping application architecture (WSTG-INFO-10) involves identifying the components, technologies, and structure of a web application’s infrastructure, including front-end, back-end, databases, APIs, and external services. This reconnaissance phase helps pentesters understand the application’s design, dependencies, and potential vulnerabilities, such as misconfigured servers, exposed services, or weak integration points. According to OWASP, mapping the architecture is critical for uncovering hidden components and tailoring subsequent tests to specific technologies or configurations.

**Impact**: Exposed or misconfigured architectural components can lead to:
- Exploitation of vulnerable services or outdated technologies (e.g., CVEs in Apache).
- Unauthorized access to backend systems or databases.
- Discovery of unprotected APIs or third-party integrations.
- Increased attack surface due to misconfigured load balancers or cloud services.

This guide provides a step-by-step methodology for mapping application architecture, adhering to OWASP’s WSTG-INFO-10, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for mapping application architecture, suitable for both novice and experienced testers:

- **Nmap**: Open-source tool for scanning ports and identifying services.
- **Burp Suite Community Edition**: Intercepts HTTP requests to analyze application components.
- **OWASP ZAP**: Open-source web proxy for automated discovery of architectural elements.
- **cURL**: Command-line tool for testing URLs and API endpoints.
- **Wappalyzer**: Browser extension to identify technologies and frameworks.
- **dnsdumpster**: Online tool for discovering subdomains and infrastructure details.
- **Shodan**: Search engine for identifying internet-connected devices and services.
- **Netcat (nc)**: Command-line tool for probing open ports and services.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **CloudSploit**: Tool for scanning cloud infrastructure (e.g., AWS, Azure) for misconfigurations.

### **Tool Setup Instructions**

1. **Nmap**:
   - Install on Linux: `sudo apt install nmap`.
   - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).
   - Verify: `nmap --version`.
2. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
3. **OWASP ZAP**:
   - Download from [owasp.org](https://www.zaproxy.org/download/).
   - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
   - Configure proxy: 127.0.0.1:8080.
4. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
5. **Wappalyzer**:
   - Install as a browser extension (Chrome/Firefox) from [wappalyzer.com](https://www.wappalyzer.com/).
   - Enable and visit target site to view results.
6. **dnsdumpster**:
   - Access online at [dnsdumpster.com](https://dnsdumpster.com/).
   - No setup required.
7. **Shodan**:
   - Sign up at [shodan.io](https://www.shodan.io/).
   - Install CLI: `pip install shodan`.
   - Verify: `shodan version`.
8. **Netcat (nc)**:
   - Install on Linux: `sudo apt install netcat`.
   - Install on Windows: Download from [nmap.org/ncat](https://nmap.org/ncat/).
   - Verify: `nc -h`.
9. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
10. **CloudSploit**:
    - Clone from GitHub: `git clone https://github.com/aquasecurity/cloudsploit.git`.
    - Install dependencies: `npm install`.
    - Configure cloud credentials (e.g., AWS keys).
    - Verify: `node index.js --help`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-10, focusing on passive and active techniques to map application architecture while minimizing detection risks.

### **1. Identify Infrastructure Components with Nmap**

Scan the target’s infrastructure to discover servers, services, and technologies.

**Steps**:
1. **Run Basic Nmap Scan**:
   - Scan common ports:
     ```bash
     nmap example.com
     ```
   - Output: Open ports (e.g., 80, 443, 3306) and services (e.g., `http`, `mysql`).
2. **Enable Version Detection**:
   - Use `-sV` for detailed service fingerprinting:
     ```bash
     nmap -sV -p 80,443,8080,8443 example.com
     ```
   - Output: Server details (e.g., `Apache 2.4.29`, `NGINX 1.18.0`).
3. **Scan Non-Standard Ports**:
   - Scan a broader range:
     ```bash
     nmap -sV -p 1-65535 example.com
     ```
   - Look for backend services (e.g., Redis on 6379, PostgreSQL on 5432).
4. **Document Findings**:
   - Note ports, services, versions, and potential databases or APIs.

**Example Output**:
```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.29 ((Ubuntu))
443/tcp  open  https    Apache httpd 2.4.29
3306/tcp open  mysql    MySQL 5.7.34
```

**Remediation**:
- Close unnecessary ports using a firewall:
  ```bash
  sudo iptables -A INPUT -p tcp --dport 3306 -j DROP
  ```
- Update outdated services to the latest versions.

### **2. Discover Subdomains and Infrastructure with dnsdumpster**

Identify subdomains and related infrastructure to map the application’s footprint.

**Steps**:
1. **Use dnsdumpster**:
   - Visit [dnsdumpster.com](https://dnsdumpster.com/).
   - Enter `example.com` and export results.
   - Output: Subdomains (e.g., `api.example.com`, `db.example.com`).
2. **Verify Subdomains**:
   - Test with cURL:
     ```bash
     curl https://api.example.com
     ```
   - Check for hosted services (e.g., APIs, admin panels).
3. **Scan Subdomains with Nmap**:
   - Enumerate services:
     ```bash
     nmap -sV api.example.com
     ```
   - Look for additional components (e.g., Node.js, MongoDB).
4. **Document Findings**:
   - List subdomains, services, and their roles (e.g., API server, database).

**Example Vulnerable Finding**:
- Subdomain: `db.example.com`
- Response: `MySQL 5.7.34` on port 3306.

**Remediation**:
- Restrict database access:
  ```bash
  # my.cnf
  [mysqld]
  bind-address = 127.0.0.1
  ```
- Remove unnecessary subdomains from DNS.

### **3. Analyze Application Technologies with Wappalyzer and Burp Suite**

Identify front-end, back-end, and database technologies used by the application.

**Steps**:
1. **Run Wappalyzer**:
   - Open browser with Wappalyzer extension.
   - Visit `http://example.com` and note technologies (e.g., `React`, `PHP`, `MySQL`).
2. **Inspect Headers with Burp Suite**:
   - Configure browser to proxy through Burp Suite.
   - Check “HTTP History” for headers like `X-Powered-By: PHP/7.4.3` or `Server: NGINX`.
3. **Analyze Responses**:
   - Look for framework signatures (e.g., `<meta name="generator" content="WordPress">`).
   - Check for API frameworks (e.g., `Django` in error pages).
4. **Document Findings**:
   - Save technologies, versions, and their roles (e.g., front-end, back-end).

**Example Wappalyzer Output**:
```
Technologies:
- Front-end: React 16.13.1
- Back-end: Node.js
- Database: MongoDB
```

**Remediation**:
- Remove version headers in Node.js:
  ```javascript
  app.use((req, res, next) => {
      res.removeHeader('X-Powered-By');
      next();
  });
  ```
- Update technologies to the latest versions.

### **4. Probe APIs and External Services**

Identify APIs and third-party services integrated into the application.

**Steps**:
1. **Crawl with OWASP ZAP**:
   - Configure ZAP proxy and spider `http://example.com`.
   - Check “Sites” for API endpoints (e.g., `/api/v1`).
2. **Test APIs with cURL**:
   - Query:
     ```bash
     curl http://example.com/api/v1/health
     ```
   - Look for API frameworks (e.g., `Express`, `Flask`) or third-party services.
3. **Check for External Services**:
   - Inspect responses for third-party domains (e.g., `api.stripe.com`, `s3.amazonaws.com`).
   - Use Burp Suite to capture requests to external URLs.
4. **Document Findings**:
   - List APIs, external services, and their purposes (e.g., payment processing, storage).

**Example Vulnerable Finding**:
- URL: `http://example.com/api/v1/health`
- Response: `{"status": "ok", "version": "Express 4.17.1"}`

**Remediation**:
- Restrict API exposure:
  ```javascript
  app.get('/api/v1/health', (req, res) => {
      if (!req.headers['x-api-key']) {
          res.status(403).send('Unauthorized');
      }
  });
  ```
- Secure third-party integrations with least privilege.

### **5. Check Cloud and Infrastructure with Shodan and CloudSploit**

Analyze cloud infrastructure and internet-facing components for misconfigurations.

**Steps**:
1. **Search with Shodan**:
   - Query:
     ```bash
     shodan search hostname:example.com
     ```
   - Output: Exposed services (e.g., Elasticsearch, Redis).
2. **Run CloudSploit**:
   - Scan cloud infrastructure (if credentials available):
     ```bash
     node index.js --cloud aws --access_key <key> --secret_key <secret>
     ```
   - Output: Misconfigurations (e.g., open S3 buckets).
3. **Verify Findings**:
   - Test exposed services with Netcat:
     ```bash
     nc -v example.com 9200
     ```
   - Check for responses (e.g., Elasticsearch JSON).
4. **Document Findings**:
   - Save exposed services and cloud misconfigurations.

**Example Vulnerable Finding**:
- Shodan: `Elasticsearch 7.10.2` on `example.com:9200`.
- Response: `{"version": {"number": "7.10.2"}}`

**Remediation**:
- Restrict Elasticsearch access:
  ```yaml
  # elasticsearch.yml
  network.host: 127.0.0.1
  ```
- Secure cloud resources with IAM policies.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-10 with practical scenarios based on common application architecture mapping patterns observed in penetration testing.

### **Test 1: Exposed Database Port**

Test for an exposed database service in the application architecture.

**Steps**:
1. **Run Nmap**:
   - Scan:
     ```bash
     nmap -sV example.com -p 3306
     ```
   - Output: `MySQL 5.7.34`.
2. **Test with Netcat**:
   - Query:
     ```bash
     nc -v example.com 3306
     ```
   - Check for MySQL banner.
3. **Verify Vulnerability**:
   - Search [cve.mitre.org](https://cve.mitre.org/) for `MySQL 5.7.34`.

**Example Insecure Finding**:
```
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 5.7.34
```

**Example Secure Configuration**:
- Bind MySQL to localhost:
  ```bash
  # my.cnf
  [mysqld]
  bind-address = 127.0.0.1
  ```

**Remediation**:
- Firewall database ports.
- Update MySQL to the latest version.

### **Test 2: Exposed API Subdomain**

Test for an unprotected API subdomain in the architecture.

**Steps**:
1. **Use dnsdumpster**:
   - Enter `example.com` and note subdomains (e.g., `api.example.com`).
2. **Test with cURL**:
   - Query:
     ```bash
     curl https://api.example.com/v1/users
     ```
   - Check for data exposure.
3. **Analyze with Burp Suite**:
   - Capture requests to `api.example.com` and note frameworks.

**Example Insecure Finding**:
- URL: `https://api.example.com/v1/users`
- Response: `[{"id": 1, "name": "John"}]`

**Example Secure Configuration**:
- Require API authentication:
  ```javascript
  app.get('/v1/users', verifyToken, (req, res) => {
      res.json(users);
  });
  ```

**Remediation**:
- Implement JWT or OAuth for APIs.
- Restrict subdomain access.

### **Test 3: Misconfigured Cloud Storage**

Test for exposed cloud storage in the application architecture.

**Steps**:
1. **Run CloudSploit**:
   - Scan:
     ```bash
     node index.js --cloud aws --access_key <key> --secret_key <secret>
     ```
   - Output: Open S3 bucket.
2. **Test with cURL**:
   - Query:
     ```bash
     curl https://example-bucket.s3.amazonaws.com
     ```
   - Check for public files.
3. **Verify with Shodan**:
   - Search:
     ```bash
     shodan search s3 example.com
     ```

**Example Insecure Finding**:
- URL: `https://example-bucket.s3.amazonaws.com`
- Response: List of sensitive files.

**Example Secure Configuration**:
- Restrict S3 access:
  ```json
  {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*",
      "Condition": {
          "NotIpAddress": { "aws:SourceIp": "192.168.1.0/24" }
      }
  }
  ```

**Remediation**:
- Enable private bucket policies.
- Regularly audit cloud resources.

### **Test 4: Exposed Debugging Service**

Test for exposed debugging services in the architecture.

**Steps**:
1. **Run Nmap**:
   - Scan:
     ```bash
     nmap -sV example.com -p 8080
     ```
   - Output: `Apache Tomcat 9.0.12`.
2. **Test with cURL**:
   - Query:
     ```bash
     curl http://example.com:8080/manager
     ```
   - Check for admin panel.
3. **Analyze with OWASP ZAP**:
   - Spider `http://example.com:8080` for debugging endpoints.

**Example Insecure Finding**:
- URL: `http://example.com:8080/manager`
- Response: Tomcat manager login page.

**Example Secure Configuration**:
- Restrict Tomcat access:
  ```xml
  <!-- tomcat-users.xml -->
  <tomcat-users>
      <user username="admin" password="securepass" roles="manager-gui"/>
  </tomcat-users>
  ```

**Remediation**:
- Disable debugging services in production.
- Use strong credentials and IP restrictions.

## **Additional Tips**

- **Start Passive**: Use dnsdumpster and Wappalyzer to minimize active scanning.
- **Combine Tools**: Cross-verify Nmap results with Burp Suite for comprehensive mapping.
- **Gray-Box Testing**: If documentation is available, check for architecture diagrams or tech stacks.
- **Document Thoroughly**: Save all services, subdomains, and technologies in a report.
- **Bypass Defenses**: Test non-standard ports or subdomains to uncover hidden components.
- **Stay Ethical**: Obtain explicit permission for active scans (e.g., Nmap, CloudSploit).
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).