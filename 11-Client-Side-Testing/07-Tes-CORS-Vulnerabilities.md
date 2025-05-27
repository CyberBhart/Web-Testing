# Testing for Cross-Origin Resource Sharing (CORS) Vulnerabilities

## Overview

Testing for Cross-Origin Resource Sharing (CORS) vulnerabilities involves verifying that a web application enforces secure CORS policies to prevent unauthorized cross-origin requests. According to OWASP (WSTG-CLNT-07), CORS vulnerabilities arise when misconfigured CORS headers (e.g., `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`) allow untrusted origins to access sensitive resources, enabling attackers to steal data or perform unauthorized actions. This guide provides a hands-on methodology to identify and test CORS misconfigurations, focusing on permissive origin policies, credential handling, and header manipulation, with tools, commands, and remediation strategies.

**Impact**: CORS vulnerabilities can lead to:
- Unauthorized access to sensitive data (e.g., user profiles, API tokens).
- Data leakage to malicious websites via cross-origin requests.
- Facilitation of cross-site request forgery (CSRF) or other attacks.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-07, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as sending cross-origin requests may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing CORS vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and analyzes CORS headers.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to modify `Origin` headers and inspect responses.
  - **Note**: Check `Access-Control-Allow-Origin` in Burp’s Response tab.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for CORS misconfigurations.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with “CORS Misconfiguration” scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects network requests and CORS headers.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to monitor CORS headers (e.g., `Access-Control-Allow-Origin`).
  - Example command to test CORS programmatically:
    ```javascript
    fetch('http://example.com/api', { headers: { Origin: 'http://malicious.com' } })
      .then(res => console.log(res.headers.get('Access-Control-Allow-Origin')));
    ```
  - **Tip**: Firefox’s 2025 Network tab enhancements improve header inspection.

- **cURL and HTTPie**: Send HTTP requests to test CORS headers with custom `Origin` values.
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
      curl -i -H "Origin: http://malicious.com" http://example.com/api
      # HTTPie
      http http://example.com/api Origin:http://malicious.com
      ```

- **CORS-Scanner**: A Python-based tool for automated CORS misconfiguration testing.
  - Install:
    ```bash
    git clone https://github.com/chenjj/CORScanner.git
    cd CORScanner
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python cors_scan.py -u http://example.com/api
    ```
  - **Note**: Outputs permissive origins and credential issues.

- **Test Payloads**: Curated `Origin` headers for testing.
  - Sample payloads:
    - `http://malicious.com`
    - `null`
    - `http://subdomain.example.com.evil.com`
  - Resource: [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html).
  - **Tip**: Test payloads in `Origin` headers and monitor CORS responses.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-07, testing CORS vulnerabilities across permissive origins, credential handling, wildcard origins, origin reflection, and preflight requests.

### 1. Test Permissive Origin Policies

**Objective**: Ensure `Access-Control-Allow-Origin` does not allow untrusted origins.

**Steps**:
1. Identify CORS-enabled endpoints:
   - Use Network tab to find API endpoints (e.g., `/api/data`).
   - Check for `Access-Control-Allow-Origin` in responses.
2. Send a request with a malicious origin:
   ```bash
   curl -i -H "Origin: http://malicious.com" http://example.com/api
   ```
3. Check response headers:
   - Look for `Access-Control-Allow-Origin: http://malicious.com` or `*`.
   - Verify if sensitive data is returned.

**Example Secure Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
```
No access for `malicious.com`.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://malicious.com
```
Malicious origin allowed.

**Remediation**:
- Restrict allowed origins:
  ```javascript
  res.set('Access-Control-Allow-Origin', 'https://example.com');
  ```
- Validate origins server-side (e.g., in Node.js):
  ```javascript
  const allowedOrigins = ['https://example.com'];
  if (allowedOrigins.includes(req.headers.origin)) {
    res.set('Access-Control-Allow-Origin', req.headers.origin);
  }
  ```

**Tip**: Save request/response headers and Network tab screenshots in a report.

### 2. Test Credential Handling

**Objective**: Ensure `Access-Control-Allow-Credentials` is not enabled with permissive origins.

**Steps**:
1. Send a request with credentials and a malicious origin:
   ```bash
   curl -i -H "Origin: http://malicious.com" -H "Cookie: session=abc123" http://example.com/api
   ```
2. Check response headers:
   - Look for `Access-Control-Allow-Credentials: true` and `Access-Control-Allow-Origin: *` or `http://malicious.com`.
3. Test programmatically:
   ```javascript
   fetch('http://example.com/api', {
     headers: { Origin: 'http://malicious.com' },
     credentials: 'include'
   }).then(res => console.log(res.headers.get('Access-Control-Allow-Origin')));
   ```

**Example Secure Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
```
Credentials restricted to trusted origin.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
Credentials exposed to any origin.

**Remediation**:
- Disable credentials for wildcard origins:
  ```javascript
  if (req.headers.origin === 'https://example.com') {
    res.set({
      'Access-Control-Allow-Origin': req.headers.origin,
      'Access-Control-Allow-Credentials': 'true'
    });
  }
  ```
- Avoid wildcard origins with credentials:
  ```javascript
  res.set('Access-Control-Allow-Origin', 'https://example.com');
  ```

**Tip**: Log credential-related headers and response data in a report.

### 3. Test Wildcard Origin (`*`)

**Objective**: Ensure wildcard `Access-Control-Allow-Origin: *` is not used for sensitive endpoints.

**Steps**:
1. Send a request with a random origin:
   ```bash
   http http://example.com/api Origin:http://random.com
   ```
2. Check response headers:
   - Look for `Access-Control-Allow-Origin: *`.
3. Verify data exposure:
   - Check if sensitive data (e.g., user info) is returned.

**Example Secure Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
```
No wildcard origin.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```
Any origin allowed.

**Remediation**:
- Specify allowed origins:
  ```javascript
  res.set('Access-Control-Allow-Origin', 'https://example.com');
  ```
- Use dynamic origin validation:
  ```javascript
  const allowed = ['https://example.com', 'https://sub.example.com'];
  res.set('Access-Control-Allow-Origin', allowed.includes(req.headers.origin) ? req.headers.origin : '');
  ```

**Tip**: Save wildcard response headers and data exposure screenshots in a report.

### 4. Test Origin Reflection

**Objective**: Ensure the server does not blindly reflect the `Origin` header in `Access-Control-Allow-Origin`.

**Steps**:
1. Send requests with various origins:
   ```bash
   curl -i -H "Origin: http://evil.com" http://example.com/api
   curl -i -H "Origin: http://example.com.evil.com" http://example.com/api
   ```
2. Check response headers:
   - Look for `Access-Control-Allow-Origin` matching the injected origin.
3. Test with `null` origin:
   ```bash
   curl -i -H "Origin: null" http://example.com/api
   ```

**Example Secure Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
```
No reflection of untrusted origins.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://evil.com
```
Origin reflected unsafely.

**Remediation**:
- Validate origins against a whitelist:
  ```javascript
  const allowedOrigins = ['https://example.com'];
  res.set('Access-Control-Allow-Origin', allowedOrigins.includes(req.headers.origin) ? req.headers.origin : '');
  ```
- Reject `null` origins:
  ```javascript
  if (req.headers.origin === 'null') return res.status(403).send('Invalid Origin');
  ```

**Tip**: Document reflected origins and response headers in a report.

### 5. Test Preflight Request Misconfigurations

**Objective**: Ensure `OPTIONS` preflight requests do not allow unauthorized methods or headers.

**Steps**:
1. Send an `OPTIONS` request with a malicious origin:
   ```bash
   curl -i -X OPTIONS -H "Origin: http://malicious.com" -H "Access-Control-Request-Method: POST" http://example.com/api
   ```
2. Check response headers:
   - Look for `Access-Control-Allow-Methods` or `Access-Control-Allow-Headers` with permissive values.
3. Test programmatically:
   ```javascript
   fetch('http://example.com/api', {
     method: 'OPTIONS',
     headers: {
       Origin: 'http://malicious.com',
       'Access-Control-Request-Method': 'POST'
     }
   }).then(res => console.log(res.headers.get('Access-Control-Allow-Methods')));
   ```

**Example Secure Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Methods: GET
Access-Control-Allow-Origin: https://example.com
```
Restricted methods and origin.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Origin: http://malicious.com
```
Permissive methods and origin.

**Remediation**:
- Restrict allowed methods:
  ```javascript
  res.set('Access-Control-Allow-Methods', 'GET');
  ```
- Validate preflight origins:
  ```javascript
  if (req.headers.origin === 'https://example.com') {
    res.set('Access-Control-Allow-Origin', req.headers.origin);
  }
  ```

**Tip**: Save preflight response headers and method lists in a report.