# Testing for Default Credentials

## Overview

Testing for Default Credentials (WSTG-AUTH-03) involves identifying services, web applications, APIs, or configuration endpoints that use default or predictable credentials, which attackers can exploit to gain unauthorized access. According to OWASP, default credentials (e.g., `admin/admin`, `root/root`) in web applications, databases, admin panels, APIs, or third-party services are a common vulnerability that can lead to system compromise. This test focuses on scanning for open services, testing default credentials in authentication endpoints, and checking for exposed configurations to mitigate risks.

**Impact**: Default credentials can lead to:
- Unauthorized access to sensitive systems or data.
- Complete system compromise, including data theft or malware deployment.
- Exploitation of admin panels or APIs to escalate privileges.
- Non-compliance with security standards (e.g., PCI DSS, ISO 27001).

This guide provides a practical, hands-on methodology for testing default credentials, adhering to OWASP’s WSTG-AUTH-03, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as scanning ports, brute-forcing credentials, or accessing systems may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing default credentials, with setup and configuration instructions:

- **Nmap**: Scans for open ports and services that may use default credentials.
  - Install on Linux:
    ```bash
    sudo apt install nmap
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).

- **Burp Suite Community Edition**: Intercepts and analyzes login requests to test default credentials.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **OWASP ZAP**: Scans and tests admin panels or login pages for default credentials.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Install and configure browser proxy: 127.0.0.1:8080.

- **Hydra**: Brute-forces default credentials on web applications or services.
  - Install on Linux:
    ```bash
    sudo apt install hydra
    ```
  - Install on Windows/Mac: Download from [kali.org](https://www.kali.org/tools/hydra/).

- **cURL**: Sends requests to test default credentials in APIs or configuration endpoints.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-03, focusing on identifying services, testing default credentials in web applications, databases, admin panels, APIs, and checking exposed configurations.

### 1. Identify Services Using Default Credentials with Nmap

**Objective**: Discover open ports and services that may use default credentials.

**Steps**:
1. Run Nmap to identify open ports and service versions for services like HTTP (80/443), MySQL (3306), Redis (6379), or MongoDB (27017):
   ```bash
   nmap -sV -p 80,443,3306,6379,27017 <target_ip>
   ```
2. For broader coverage, scan all ports to find additional services:
   ```bash
   nmap -sV <target_ip>
   ```
3. Analyze results for services vulnerable to default credentials.
4. Document findings for targeted credential testing.

**Example Secure Response**:
```
PORT     STATE  SERVICE  VERSION
80/tcp   closed http
3306/tcp closed mysql
```

**Example Vulnerable Response**:
```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache 2.4.41
3306/tcp open  mysql    MySQL 5.7.34
```

**Remediation**:
- Disable unused services (Node.js):
  ```javascript
  // Ensure only necessary services are exposed
  const http = require('http');
  http.createServer((req, res) => {
      res.writeHead(403);
      res.end('Service disabled');
  }).listen(80); // Replace with secure service or disable
  ```

**Tip**: Save Nmap output to a file (e.g., `nmap -oN scan.txt <target_ip>`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerable services (e.g., Nmap logs).

### 2. Test Default Credentials for Web Applications with Burp Suite

**Objective**: Verify that web application login pages do not allow default credentials.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Browse to the login page (e.g., `https://example.com/login`), submit credentials, and capture the POST request in “HTTP History”:
   ```
   HTTP History -> Select POST /login -> Verify Request Body contains username and password
   ```
3. In Burp Repeater, test default credentials like `admin/admin`:
   ```
   Repeater -> Change POST /login Body to username=admin&password=admin -> Click Send -> Check response
   ```
4. Analyze responses; expected secure response is an error indicating invalid credentials.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Login successful"}
```

**Remediation**:
- Block default credentials (Node.js):
  ```javascript
  app.post('/login', (req, res) => {
      const { username, password } = req.body;
      if (username === 'admin' && password === 'admin') {
          return res.status(403).json({ error: 'Default credentials not allowed' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save Burp Suite requests and responses in “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Default Credentials for Databases via Admin Panels with Burp Suite

**Objective**: Ensure database credentials in admin panels or management interfaces do not use default values.

**Steps**:
1. Use OWASP ZAP to identify admin panels or database management interfaces (e.g., `/db-admin`, `/phpmyadmin`).
2. Capture a login request to the database admin panel (e.g., `POST /db-admin/login`) in Burp Suite:
   ```
   HTTP History -> Select POST /db-admin/login -> Verify Request Body contains username and password
   ```
3. Test default database credentials like `root/root` or `admin/admin` in Burp Repeater:
   ```
   Repeater -> Change POST /db-admin/login Body to username=root&password=root -> Click Send -> Check response
   ```
4. Analyze responses; expected secure response is an error indicating invalid credentials.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Login successful"}
```

**Remediation**:
- Secure database admin access (Python/Flask):
  ```python
  @app.post('/db-admin/login')
  def db_admin_login():
      username, password = request.form['username'], request.form['password']
      if username == 'root' and password == 'root':
          return jsonify({'error': 'Default credentials disabled'}), 403
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Burp Suite requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Default Credentials for Third-Party Services with Hydra

**Objective**: Verify that third-party services (e.g., Redis, MongoDB) do not use default credentials.

**Steps**:
1. Use Nmap results to identify services like Redis (6379) or MongoDB (27017).
2. Test Redis for default or no credentials using Hydra:
   ```bash
   hydra -l "" -p password redis://<target_ip>:6379
   ```
3. Test MongoDB for default credentials like `admin/admin`:
   ```bash
   hydra -l admin -p admin mongodb://<target_ip>:27017
   ```
4. Analyze responses; expected secure response is an authentication failure or service not exposed.

**Example Secure Response**:
```
[6379][redis] host: <target_ip> login: none password: none [Authentication failed]
```

**Example Vulnerable Response**:
```
[6379][redis] host: <target_ip> login: none password: password
```

**Remediation**:
- Secure Redis authentication (Node.js):
  ```javascript
  const redis = require('redis');
  const client = redis.createClient({
      url: 'redis://<target_ip>:6379',
      password: 'StrongPass123!'
  });
  ```

**Tip**: Save Hydra output to a file (e.g., `hydra ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Hydra logs).

### 5. Check for Default Credentials in Exposed Configuration Endpoints with cURL

**Objective**: Ensure exposed configuration endpoints do not contain default credentials.

**Steps**:
1. Use Burp Suite or OWASP ZAP to identify configuration endpoints (e.g., `/api/config`, `/settings`).
2. Request the endpoint to check for exposed credentials:
   ```bash
   curl -i https://example.com/api/config
   ```
3. Search the response for default credentials like `admin`:
   ```bash
   curl https://example.com/api/config | grep -i "admin"
   ```
4. Analyze responses; expected secure response is no exposure or access denied.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin": "admin", "password": "admin"}
```

**Remediation**:
- Protect configuration endpoints (Python/Flask):
  ```python
  @app.get('/api/config')
  def config():
      return jsonify({'error': 'Access denied'}), 403
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Default Credentials in Admin Panels or CMS with OWASP ZAP

**Objective**: Verify that admin panels or CMS interfaces do not allow default credentials.

**Steps**:
1. Configure OWASP ZAP by setting up the browser proxy (127.0.0.1:8080) and enabling “Spider”.
2. Run a spider scan to identify admin panel URLs (e.g., `/admin`, `/wp-admin`):
   ```
   Spider -> Set URL to https://example.com -> Start Scan -> Identify /admin or /wp-admin
   ```
3. Test default credentials like `admin/admin`:
   ```
   Manual Request Editor -> POST https://example.com/admin -> Body: username=admin&password=admin -> Send
   ```
4. Analyze responses; expected secure response is an error indicating invalid credentials.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Login successful"}
```

**Remediation**:
- Restrict default credentials (Python/Flask):
  ```python
  @app.post('/admin/login')
  def admin_login():
      username, password = request.form['username'], request.form['password']
      if username == 'admin' and password == 'admin':
          return jsonify({'error': 'Default credentials disabled'}), 403
      return jsonify({'status': 'success'})
  ```

**Tip**: Save OWASP ZAP spider results and requests as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Default Credentials in API Endpoints with cURL

**Objective**: Ensure API authentication endpoints do not allow default credentials.

**Steps**:
1. Use Burp Suite to identify API endpoints like `/api/login` or `/api/auth`.
2. Test default credentials like `admin:admin`:
   ```bash
   curl -i -X POST -d '{"username":"admin","password":"admin"}' https://example.com/api/login
   ```
3. Test default API keys:
   ```bash
   curl -i -H "Authorization: Bearer default" https://example.com/api/protected
   ```
4. Analyze responses; expected secure response is an error indicating invalid credentials.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"token": "xyz123"}
```

**Remediation**:
- Secure API authentication (Node.js):
  ```javascript
  app.post('/api/login', (req, res) => {
      const { username, password } = req.body;
      if (username === 'admin' && password === 'admin') {
          return res.status(403).json({ error: 'Default credentials not allowed' });
      }
      res.json({ token: 'xyz123' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).