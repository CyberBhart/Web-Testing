# Testing for Client-Side Resource Manipulation

## Overview

Testing for Client-Side Resource Manipulation vulnerabilities involves verifying that a web application prevents unauthorized modification or loading of client-side resources (e.g., scripts, images, iframes) due to improper handling of user-controlled inputs. According to OWASP (WSTG-CLNT-06), these vulnerabilities occur when user inputs (e.g., URL parameters, form fields, or fragments) are used to define resource sources (e.g., `src` attributes) without proper validation or sanitization, allowing attackers to load malicious content. This guide provides a hands-on methodology to identify and test such vulnerabilities, focusing on common resource manipulation points (e.g., `<script>`, `<img>`, `<iframe>`), with tools, commands, and remediation strategies.

**Impact**: Client-side resource manipulation vulnerabilities can lead to:
- Execution of malicious scripts via unauthorized script sources.
- Phishing or malware distribution through manipulated images or iframes.
- Data leakage by loading resources from attacker-controlled servers.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-06, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting resource manipulation payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing client-side resource manipulation vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and tests for resource manipulation in parameters or forms.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to modify and resend requests with resource payloads.
  - **Note**: Check responses in Burp’s Render tab to visualize loaded resources.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for client-side vulnerabilities.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan with “Client-side Resource Manipulation” scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects DOM elements and monitors resource loading.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Elements tab to check resource attributes (e.g., `src`) and Network tab to track loaded resources.
  - Example command to find resource elements:
    ```javascript
    document.querySelectorAll('script[src], img[src], iframe[src]').forEach(e => console.log(e.outerHTML));
    ```
  - **Tip**: Firefox’s 2025 Network tab enhancements improve resource tracking.

- **cURL and HTTPie**: Send HTTP requests to test resource payloads in URL parameters or form data.
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
      curl -i "http://example.com/page?src=http://malicious.com/script.js"
      # HTTPie
      http "http://example.com/page?src=http://malicious.com/script.js"
      ```

- **XSStrike**: A Python-based tool for testing client-side vulnerabilities, including resource manipulation.
  - Install:
    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python3 xsstrike.py -u "http://example.com/page?src=test" --dom
    ```
  - **Note**: Use `--dom` flag to focus on client-side resource loading.

- **Resource Payloads**: Curated payloads for manual and automated testing.
  - Sample payloads:
    - `http://malicious.com/script.js`
    - `//malicious.com/image.png`
    - `javascript:alert('xss')` (to test for XSS escalation)
  - Resource: [OWASP Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html).
  - **Tip**: Test payloads in resource attributes and monitor Network tab.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-06, testing client-side resource manipulation vulnerabilities across script sources, image sources, iframe sources, form inputs, and URL fragments.

### 1. Test Script Source Manipulation

**Objective**: Ensure `<script>` tag `src` attributes do not load unvalidated user-controlled URLs.

**Steps**:
1. Identify `<script>` tags:
   - Open Browser Developer Tools (`F12` or `Ctrl+Shift+I`).
   - Use Elements tab to locate `<script>` tags with `src` attributes.
   - Console command:
     ```javascript
     document.querySelectorAll('script[src]').forEach(s => console.log(s.src));
     ```
2. Inject a malicious script URL:
   ```bash
   http "http://example.com/page?script=http://malicious.com/evil.js"
   ```
3. Check for manipulation:
   - Load the page and monitor Network tab for requests to `malicious.com`.
   - Inspect `<script>` tags for the injected URL.

**Example Secure Response**:
```html
<!-- Validated source prevents loading -->
<script src="/trusted.js"></script>
```
No request to `malicious.com`.

**Example Vulnerable Response**:
```html
<!-- Unvalidated source loads malicious script -->
<script src="http://malicious.com/evil.js"></script>
```
Network request to `malicious.com`.

**Remediation**:
- Validate script sources:
  ```javascript
  const allowedDomains = ['example.com'];
  if (allowedDomains.some(d => userSrc.includes(d))) {
    script.src = userSrc;
  }
  ```
- Use static script sources:
  ```html
  <script src="/static/trusted.js"></script>
  ```

**Tip**: Save Network tab screenshots and `<script>` tag contents in a report.

### 2. Test Image Source Manipulation

**Objective**: Ensure `<img>` tag `src` attributes do not load unvalidated user-controlled URLs.

**Steps**:
1. Identify `<img>` tags:
   - Search for `<img>` elements in Elements tab.
   - Console command:
     ```javascript
     document.querySelectorAll('img[src]').forEach(i => console.log(i.src));
     ```
2. Inject a malicious image URL:
   ```bash
   http "http://example.com/page?img=http://malicious.com/fake.png"
   ```
3. Check for manipulation:
   - Load the page and monitor Network tab for requests to `malicious.com`.
   - Verify `<img>` `src` in Elements tab.

**Example Secure Response**:
```html
<!-- Validated source prevents loading -->
<img src="/images/valid.png">
```
No request to `malicious.com`.

**Example Vulnerable Response**:
```html
<!-- Unvalidated source loads malicious image -->
<img src="http://malicious.com/fake.png">
```
Network request to `malicious.com`.

**Remediation**:
- Validate image sources:
  ```javascript
  if (userSrc.startsWith('/images/')) {
    img.src = userSrc;
  }
  ```
- Server-side validation (e.g., in Node.js):
  ```javascript
  if (req.query.img.startsWith('/')) {
    res.send(`<img src="${req.query.img}">`);
  }
  ```

**Tip**: Log payload responses and Network tab screenshots in a report.

### 3. Test Iframe Source Manipulation

**Objective**: Ensure `<iframe>` tag `src` attributes do not load unvalidated user-controlled URLs.

**Steps**:
1. Identify `<iframe>` tags:
   - Search for `<iframe>` elements in Elements tab.
   - Console command:
     ```javascript
     document.querySelectorAll('iframe[src]').forEach(f => console.log(f.src));
     ```
2. Inject a malicious iframe URL:
   ```bash
   http "http://example.com/page?frame=http://malicious.com"
   ```
3. Check for manipulation:
   - Load the page and monitor Network tab for requests to `malicious.com`.
   - Verify `<iframe>` `src` in Elements tab.

**Example Secure Response**:
```html
<!-- Validated source prevents loading -->
<iframe src="/trusted.html"></iframe>
```
No request to `malicious.com`.

**Example Vulnerable Response**:
```html
<!-- Unvalidated source loads malicious iframe -->
<iframe src="http://malicious.com"></iframe>
```
Network request to `malicious.com`.

**Remediation**:
- Validate iframe sources:
  ```javascript
  if (userSrc.includes('example.com')) {
    iframe.src = userSrc;
  }
  ```
- Use sandbox attributes:
  ```html
  <iframe src="/trusted.html" sandbox="allow-same-origin"></iframe>
  ```

**Tip**: Save iframe payloads and Network tab screenshots in a report.

### 4. Test Form Input Manipulation

**Objective**: Ensure form inputs do not control resource sources without validation.

**Steps**:
1. Locate form fields:
   - Identify fields like “image URL” or “script source” on the target page.
2. Inject a malicious resource URL:
   - Enter `http://malicious.com/evil.js` into a form field and submit.
3. Check for manipulation:
   - Monitor Network tab for requests to `malicious.com`.
   - Inspect DOM for injected resource elements.

**Example Secure Response**:
```html
<!-- Validated input prevents loading -->
<script src="/static/safe.js"></script>
```
No request to `malicious.com`.

**Example Vulnerable Response**:
```html
<!-- Unvalidated input loads resource -->
<script src="http://malicious.com/evil.js"></script>
```
Network request to `malicious.com`.

**Remediation**:
- Validate form inputs:
  ```javascript
  if (/^\/[a-zA-Z0-9\/]+$/.test(formInput)) {
    script.src = formInput;
  }
  ```
- Use a whitelist:
  ```javascript
  const safeSources = ['/scripts/valid.js'];
  if (safeSources.includes(formInput)) {
    script.src = formInput;
  }
  ```

**Tip**: Save form submissions and Network tab screenshots in a report.

### 5. Test URL Fragment Manipulation

**Objective**: Ensure `location.hash` does not control resource sources.

**Steps**:
1. Inject a malicious URL in the fragment:
   ```bash
   http "http://example.com/page#http://malicious.com/script.js"
   ```
2. Analyze `location.hash` handling:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/location\.hash/g);
     ```
3. Check for manipulation:
   - Load the URL and monitor Network tab for requests to `malicious.com`.

**Example Secure Response**:
```javascript
// Validated fragment prevents loading
if (!userHash.includes('http')) {
  script.src = userHash;
}
```
No request to `malicious.com`.

**Example Vulnerable Response**:
```javascript
// Unvalidated fragment loads resource
script.src = location.hash;
```
Network request to `malicious.com`.

**Remediation**:
- Validate fragments:
  ```javascript
  if (/^#[a-zA-Z0-9]+$/.test(location.hash)) {
    script.src = location.hash;
  }
  ```
- Avoid using `location.hash` for resources:
  ```javascript
  script.src = '/default.js';
  ```

**Tip**: Document fragment payloads and Network tab screenshots in a report.