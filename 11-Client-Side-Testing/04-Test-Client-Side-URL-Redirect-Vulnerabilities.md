# Testing for Client-Side URL Redirect Vulnerabilities

## Overview

Testing for Client-Side URL Redirect Vulnerabilities involves verifying that a web application prevents unauthorized redirection to untrusted URLs due to improper handling of user-controlled inputs. According to OWASP (WSTG-CLNT-04), client-side URL redirect vulnerabilities occur when applications use user inputs (e.g., URL parameters, form fields, or fragments) in redirection functions (e.g., `window.location`, `location.href`) without proper validation, allowing attackers to redirect users to malicious sites. This guide provides a hands-on methodology to identify and test such vulnerabilities, focusing on common redirection sinks (e.g., `location.assign()`, `location.replace()`) and sources (e.g., `location.search`, `location.hash`), with tools, commands, and remediation strategies.

**Impact**: Client-side URL redirect vulnerabilities can lead to:
- Phishing attacks by redirecting users to fake login pages.
- Malware distribution via malicious sites.
- Loss of user trust and reputational damage.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-04, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting redirect payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing client-side URL redirect vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and tests redirect parameters.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to modify and resend requests with redirect payloads.
  - **Note**: Check response headers (e.g., `Location`) and JavaScript in Burp’s Render tab.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for open redirect vulnerabilities.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan with “Client-side Open Redirect” scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects JavaScript and monitors redirection behavior.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Sources tab for JavaScript inspection and Network tab to track redirects.
  - Example command to find redirection sinks:
    ```javascript
    document.body.innerText.match(/window\.location|location\.href|location\.assign|location\.replace/g);
    ```
  - **Tip**: Firefox’s 2025 Network tab enhancements improve redirect tracing.

- **cURL and HTTPie**: Send HTTP requests to test redirect payloads in URL parameters or form data.
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
      curl -i "http://example.com/redirect?url=http://malicious.com"
      # HTTPie
      http "http://example.com/redirect?url=http://malicious.com"
      ```

- **XSStrike**: A Python-based tool for testing client-side vulnerabilities, including redirect issues.
  - Install:
    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python3 xsstrike.py -u "http://example.com/redirect?url=test" --dom
    ```
  - **Note**: Use `--dom` flag to focus on client-side redirection logic.

- **Redirect Payloads**: Curated payloads for manual and automated testing.
  - Sample payloads:
    - `http://malicious.com`
    - `//malicious.com`
    - `javascript:alert('xss')` (to test for XSS escalation)
  - Resource: [OWASP Open Redirect Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
  - **Tip**: Test payloads in URL parameters or form fields and monitor redirects.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-04, testing client-side URL redirect vulnerabilities across redirection sinks, URL parameters, form inputs, URL fragments, and potential XSS escalation.

### 1. Test Redirection Sinks (e.g., `window.location`, `location.href`)

**Objective**: Ensure redirection functions do not process unvalidated user input.

**Steps**:
1. Identify redirection sinks:
   - Open Browser Developer Tools (`F12` or `Ctrl+Shift+I`).
   - Navigate to Sources tab and search for `window.location`, `location.href`, `location.assign()`, or `location.replace()`.
   - Console command:
     ```javascript
     document.body.innerText.match(/window\.location|location\.href|location\.assign|location\.replace/g);
     ```
2. Intercept requests with Burp Suite:
   - Configure proxy (`127.0.0.1:8080`).
   - Send payload:
     ```bash
     http "http://example.com/redirect?url=http://malicious.com"
     ```
   - Analyze response for unvalidated redirects.
3. Test redirect execution:
   - Inject `http://malicious.com` into a URL parameter.
   - Observe if the browser redirects to the malicious site.

**Example Secure Response**:
```javascript
// Validated redirect prevents unauthorized sites
if (userUrl.startsWith('https://example.com')) {
  window.location = userUrl;
}
```
No redirect to `malicious.com`.

**Example Vulnerable Response**:
```javascript
// Unvalidated input triggers redirect
window.location = userUrl;
```
Browser redirects to `malicious.com`.

**Remediation**:
- Validate redirect URLs:
  ```javascript
  const allowedDomains = ['example.com', 'sub.example.com'];
  if (allowedDomains.some(domain => userUrl.includes(domain))) {
    location.href = userUrl;
  }
  ```
- Use relative URLs:
  ```javascript
  location.href = '/safe/path';
  ```

**Tip**: Save Burp Suite requests/responses and redirect screenshots in a report.

### 2. Test URL Parameter Injection

**Objective**: Ensure URL query parameters do not control redirection without validation.

**Steps**:
1. Identify redirect parameters:
   - Analyze URLs for parameters (e.g., `?url=`, `?redirect=`).
   - Example: `http://example.com/redirect?url=/home`.
2. Inject a malicious URL:
   ```bash
   http "http://example.com/redirect?url=http://malicious.com"
   ```
3. Check for redirect:
   - Load the URL and monitor the Network tab for redirection to `malicious.com`.

**Example Secure Response**:
```javascript
// Validated parameter prevents redirect
if (userUrl.match(/^\/[a-zA-Z0-9\/]+$/)) {
  location.assign(userUrl);
}
```
No redirect to external site.

**Example Vulnerable Response**:
```javascript
// Unvalidated parameter triggers redirect
location.assign(userUrl);
```
Browser redirects to `malicious.com`.

**Remediation**:
- Restrict to allowed URLs:
  ```javascript
  if (userUrl.startsWith('/')) {
    location.assign(userUrl);
  }
  ```
- Server-side validation (e.g., in Node.js):
  ```javascript
  if (req.query.url.startsWith('/')) {
    res.redirect(req.query.url);
  }
  ```

**Tip**: Log URL payloads and Network tab screenshots in a report.

### 3. Test Form Input Redirection

**Objective**: Ensure form inputs do not control redirection without validation.

**Steps**:
1. Locate redirect forms:
   - Identify forms with redirect-related fields (e.g., “return URL”).
   - Use Elements tab to inspect form structure.
2. Inject a malicious URL:
   - Enter `http://malicious.com` into a form field and submit.
3. Check for redirect:
   - Monitor the Network tab for redirection to `malicious.com`.

**Example Secure Response**:
```javascript
// Validated input prevents redirect
if (formInput.includes('example.com')) {
  location.href = formInput;
}
```
No redirect to external site.

**Example Vulnerable Response**:
```javascript
// Unvalidated input triggers redirect
location.href = formInput;
```
Browser redirects to `malicious.com`.

**Remediation**:
- Validate form inputs:
  ```javascript
  if (/^https:\/\/example\.com/.test(formInput)) {
    location.href = formInput;
  }
  ```
- Use a whitelist:
  ```javascript
  const safeUrls = ['/home', '/profile'];
  if (safeUrls.includes(formInput)) {
    location.href = formInput;
  }
  ```

**Tip**: Save form submissions and redirect screenshots in a report.

### 4. Test URL Fragment Injection

**Objective**: Ensure `location.hash` does not trigger unauthorized redirects.

**Steps**:
1. Inject a malicious URL in the fragment:
   ```bash
   http "http://example.com/page#http://malicious.com"
   ```
2. Analyze `location.hash` handling:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/location\.hash/g);
     ```
3. Check for redirect:
   - Load the URL and monitor for redirection.

**Example Secure Response**:
```javascript
// Validated fragment prevents redirect
if (!userHash.includes('http')) {
  location.href = userHash;
}
```
No redirect to `malicious.com`.

**Example Vulnerable Response**:
```javascript
// Unvalidated fragment triggers redirect
location.href = location.hash;
```
Browser redirects to `malicious.com`.

**Remediation**:
- Validate fragments:
  ```javascript
  if (/^#[a-zA-Z0-9]+$/.test(location.hash)) {
    location.href = location.hash;
  }
  ```
- Avoid using `location.hash` for redirects:
  ```javascript
  location.href = '/default';
  ```

**Tip**: Document fragment payloads and Network tab screenshots in a report.

### 5. Test for XSS Escalation

**Objective**: Ensure redirect vulnerabilities do not allow JavaScript execution (escalating to XSS).

**Steps**:
1. Inject a JavaScript URL payload:
   ```bash
   http "http://example.com/redirect?url=javascript:alert('xss')"
   ```
2. Check for execution:
   - Load the URL and observe for an alert pop-up.
3. Analyze response:
   - Use Console to detect script execution:
     ```javascript
     window.alert = () => console.log('XSS Detected');
     ```

**Example Secure Response**:
```javascript
// Validated input prevents execution
if (userUrl.startsWith('https://')) {
  location.href = userUrl;
}
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unvalidated input executes script
location.href = userUrl;
```
Alert box displays "xss".

**Remediation**:
- Block `javascript:` URLs:
  ```javascript
  if (!userUrl.startsWith('javascript:')) {
    location.href = userUrl;
  }
  ```
- Implement Content Security Policy (CSP):
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self';">
  ```

**Tip**: Document alert screenshots and response JavaScript in a report.