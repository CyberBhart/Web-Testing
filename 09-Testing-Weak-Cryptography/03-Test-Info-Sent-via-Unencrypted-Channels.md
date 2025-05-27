# Testing for Sensitive Information Sent via Unencrypted Channels

## Overview

Testing for Sensitive Information Sent via Unencrypted Channels (WSTG-CRYP-03) involves assessing web applications to identify instances where sensitive data, such as credentials, session tokens, or personal information, is transmitted over unencrypted protocols like HTTP, making it vulnerable to interception through man-in-the-middle (MITM) attacks or network sniffing. According to OWASP, unencrypted channels expose data to attackers, compromising confidentiality and potentially leading to unauthorized access or regulatory violations. This test focuses on inspecting HTTP traffic, form submissions, API calls, cookies, mixed content, and WebSocket connections to detect unencrypted sensitive data and ensure all communications use secure protocols (e.g., HTTPS with TLS).

**Impact**: Sending sensitive information over unencrypted channels can lead to:
- Exposure of user credentials, session tokens, or personal data (e.g., credit card numbers).
- Unauthorized access to user accounts or sensitive resources via intercepted data.
- Regulatory non-compliance (e.g., GDPR, PCI-DSS) and reputational damage.
- Increased risk of session hijacking or data manipulation.

This guide provides a practical, hands-on methodology for testing unencrypted data transmission, adhering to OWASP’s WSTG-CRYP-03, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for traffic interception, as capturing sensitive data may have legal implications.

## Testing Tools

The following tools are recommended for testing unencrypted data transmission, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and inspects HTTP traffic for unencrypted data.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Wireshark**: Captures and analyzes network traffic for unencrypted sensitive information.
  - Download from [wireshark.org](https://www.wireshark.org/).
  - Install on Linux:
    ```bash
    sudo apt install wireshark
    ```
  - Configure capture interface (e.g., `eth0`).

- **Browser Developer Tools**: Identifies mixed content and unencrypted requests.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **OWASP ZAP**: Automates detection of HTTP traffic and insecure configurations.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Run: `zap.sh` (Linux) or `zap.bat` (Windows).

- **cURL**: Sends requests to test for HTTP usage and inspect responses.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CRYP-03, focusing on intercepting and analyzing HTTP traffic, form submissions, API calls, cookies, mixed content, HSTS headers, URL parameters, and WebSocket connections to detect sensitive information sent over unencrypted channels.

### 1. Intercept HTTP Traffic with Burp Suite

**Objective**: Capture and inspect HTTP requests and responses to identify unencrypted sensitive data.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Traffic**:
   - Browse the application, log in, submit forms, or interact with APIs.
   - Check “HTTP History” for HTTP requests (e.g., `http://example.com/login`).
3. **Analyze Requests**:
   - Look for sensitive data (e.g., usernames, passwords, session tokens) in GET/POST parameters, headers, or response bodies.

**Burp Suite Commands**:
- **Command 1**: Filter for HTTP requests:
  ```
  HTTP History -> Filter -> Show only: Protocol=HTTP -> Check for sensitive data in requests
  ```
- **Command 2**: Inspect a login request:
  ```
  HTTP History -> Select POST /login -> Send to Repeater -> Check for username/password in body -> Verify Protocol=HTTP
  ```

**Example Vulnerable Request**:
```
POST http://example.com/login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret123
```

**Remediation**:
- Enforce HTTPS (Apache):
  ```apache
  <VirtualHost *:80>
      ServerName example.com
      Redirect permanent / https://example.com/
  </VirtualHost>
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 2. Capture Network Traffic with Wireshark

**Objective**: Analyze network traffic to detect unencrypted sensitive data.

**Steps**:
1. **Configure Wireshark**:
   - Select capture interface (e.g., `eth0`).
   - Apply filter: `http`.
2. **Capture Traffic**:
   - Browse the application or send requests to `http://example.com`.
   - Capture packets during login or API calls.
3. **Analyze Packets**:
   - Look for HTTP packets with sensitive data (e.g., `username=admin`).

**Wireshark Commands**:
- **Command 1**: Filter HTTP traffic:
  ```
  Capture Filter: http -> Start Capture -> Apply Display Filter: http.request.method == "POST"
  ```
- **Command 2**: Search for sensitive data:
  ```
  Display Filter: http contains "username" -> Right-click packet -> Follow -> HTTP Stream
  ```

**Example Vulnerable Packet**:
```
POST /login HTTP/1.1
Host: example.com
username=admin&password=secret123
```

**Remediation**:
- Enable TLS (Nginx):
  ```nginx
  server {
      listen 443 ssl;
      server_name example.com;
      ssl_certificate /etc/ssl/certs/example.com.crt;
      ssl_certificate_key /etc/ssl/private/example.com.key;
  }
  ```

**Tip**: Save packet capture (.pcap) and screenshots to a file (e.g., `wireshark-capture.pcap`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., packet captures).

### 3. Identify Mixed Content with Browser Developer Tools

**Objective**: Check for HTTP resources loaded on HTTPS pages, indicating unencrypted data transmission.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome.
2. **Check Console**:
   - Look for mixed content warnings (e.g., “Blocked loading mixed active content”).
3. **Inspect Network Tab**:
   - Verify resources (e.g., scripts, images) loaded via HTTP.

**Browser Developer Tools Commands**:
- **Command 1**: Check for mixed content:
  ```
  Console tab -> Look for warnings like "Mixed Content: http://example.com/script.js"
  ```
- **Command 2**: Inspect network resources:
  ```
  Network tab -> Reload page -> Filter by Protocol=HTTP -> Check resource content
  ```

**Example Vulnerable Finding**:
```
Mixed Content: The page at 'https://example.com' loaded 'http://example.com/user_data.js' over HTTP.
```

**Remediation**:
- Use HTTPS for all resources (HTML):
  ```html
  <script src="https://example.com/script.js"></script>
  ```

**Tip**: Save screenshots and network logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., console warnings).

### 4. Automate HTTP Detection with OWASP ZAP

**Objective**: Use automated scanning to identify unencrypted traffic and insecure configurations.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `http://example.com`).
2. **Run Active Scan**:
   - Scan for HTTP endpoints and insecure cookies.
3. **Analyze Results**:
   - Review Alerts tab for HTTP usage or missing secure flags.

**OWASP ZAP Commands**:
- **Command 1**: Scan for HTTP endpoints:
  ```
  Sites tab -> Right-click http://example.com -> Attack -> Active Scan -> Enable Information Disclosure -> Start Scan
  ```
- **Command 2**: Check for insecure cookies:
  ```
  Sites tab -> Right-click http://example.com -> Report -> Generate HTML Report -> Look for "Cookie No Secure Flag"
  ```

**Example Vulnerable Finding**:
- Alert: `Insecure Transmission - Sensitive data sent over HTTP`.

**Remediation**:
- Set secure cookies (PHP):
  ```php
  setcookie('session', 'abc123', ['secure' => true, 'httponly' => true]);
  ```

**Tip**: Save ZAP scan reports as HTML or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., ZAP alerts).

### 5. Test Endpoints with cURL

**Objective**: Manually send HTTP requests to verify unencrypted data transmission.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find HTTP endpoints (e.g., `http://example.com/login`).
2. **Send Requests**:
   - Use cURL to submit sensitive data over HTTP.
3. **Analyze Responses**:
   - Check for sensitive data in requests or responses.

**cURL Commands**:
- **Command 1**: Test a login form over HTTP:
  ```bash
  curl -i -X POST -d "username=admin&password=secret123" http://example.com/login
  ```
- **Command 2**: Check for sensitive data in GET request:
  ```bash
  curl -i http://example.com/profile?session=abc123
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"user_id": 123, "email": "admin@example.com"}
```

**Remediation**:
- Redirect HTTP to HTTPS (Nginx):
  ```nginx
  server {
      listen 80;
      server_name example.com;
      return 301 https://$server_name$request_uri;
  }
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Missing or Weak HSTS Headers

**Objective**: Test for missing or weak HSTS headers that fail to enforce HTTPS.

**Steps**:
1. **Send Request**:
   - Use `cURL` to check response headers for `Strict-Transport-Security`.
2. **Analyze Headers**:
   - Verify presence of `max-age`, `includeSubDomains`, and `preload`.
3. **Verify Findings**:
   - Use Browser Developer Tools to confirm HTTPS enforcement.

**cURL Commands**:
- **Command 1**: Check HTTPS headers:
  ```bash
  curl -I https://example.com
  ```
- **Command 2**: Test HTTP response:
  ```bash
  curl -I http://example.com
  ```

**Example Vulnerable Output**:
```
HTTP/1.1 200 OK
Content-Type: text/html
```
*(No `Strict-Transport-Security` header)*

**Remediation**:
- Enable HSTS (Apache):
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -I ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., header outputs).

### 7. Test Sensitive Data in URL Parameters

**Objective**: Test for sensitive data transmitted in URL query parameters over HTTP.

**Steps**:
1. **Capture Traffic**:
   - Configure Burp Suite to capture HTTP GET requests.
2. **Analyze Requests**:
   - Filter for query parameters with sensitive data (e.g., `session=abc123`).
3. **Verify Protocol**:
   - Confirm if requests use HTTP.

**Burp Suite Commands**:
- **Command 1**: Filter for sensitive GET requests:
  ```
  HTTP History -> Filter -> Show only: Method=GET, Protocol=HTTP -> Search for "session=" or "token="
  ```
- **Command 2**: Inspect a specific request:
  ```
  HTTP History -> Select GET /profile?session=abc123 -> Send to Repeater -> Verify Protocol=HTTP
  ```

**Example Vulnerable Request**:
```
GET http://example.com/profile?session=abc123 HTTP/1.1
Host: example.com
```

**Remediation**:
- Use POST for sensitive data (Python/Flask):
  ```python
  @app.route('/profile', methods=['POST'])
  def profile():
      session = request.form['session']
      return jsonify({'user': session})
  ```

**Tip**: Save Burp Suite requests as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 8. Test Unencrypted WebSocket Connections

**Objective**: Test for sensitive data sent over unencrypted WebSocket (`ws://`) connections.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load the application and press `F12` in Chrome.
2. **Check WebSocket Traffic**:
   - Filter for `ws://` connections in the Network tab.
3. **Analyze Messages**:
   - Inspect WebSocket messages for sensitive data (e.g., tokens).

**Browser Developer Tools Commands**:
- **Command 1**: Filter for WebSocket connections:
  ```
  Network tab -> Filter -> WS -> Check for ws://example.com/ws -> Inspect Messages
  ```
- **Command 2**: Verify connection:
  ```
  Network tab -> Right-click ws://example.com/ws -> Copy Link Address -> Test in Burp Repeater
  ```

**Example Vulnerable Finding**:
```
WebSocket connection to 'ws://example.com/ws' established.
Message: {"token": "abc123", "user": "admin"}
```

**Remediation**:
- Use secure WebSocket (JavaScript):
  ```javascript
  const socket = new WebSocket('wss://example.com/ws');
  ```

**Tip**: Save WebSocket logs or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., WebSocket messages).
