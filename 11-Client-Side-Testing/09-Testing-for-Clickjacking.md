# Testing for Clickjacking Vulnerabilities

## Overview

Testing for Clickjacking vulnerabilities involves verifying that a web application prevents attackers from embedding its pages in malicious iframes to trick users into performing unintended actions. According to OWASP (WSTG-CLNT-09), clickjacking (also known as UI redressing) occurs when an attacker overlays a transparent iframe of a target page over a deceptive UI, causing users to interact with the target page unknowingly. This guide provides a hands-on methodology to identify and test clickjacking vulnerabilities, focusing on missing or weak anti-framing protections (e.g., `X-Frame-Options`, Content Security Policy) and frame-busting script effectiveness, with tools, commands, and remediation strategies.

**Impact**: Clickjacking vulnerabilities can lead to:
- Unauthorized actions (e.g., changing user settings, initiating transactions).
- Phishing attacks by mimicking legitimate UI elements.
- Session hijacking or data theft via unintended clicks.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-09, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as embedding target pages in iframes may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing clickjacking vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP responses to check for `X-Frame-Options` or Content Security Policy (CSP) headers.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Response tab to inspect headers.
  - **Note**: Burp’s embedded browser can render iframes for testing.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for analyzing HTTP headers and detecting missing anti-clickjacking protections.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser iframe testing.
  - Use Passive Scan to flag missing `X-Frame-Options` or weak CSP.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects HTTP headers and tests iframe embedding.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to check response headers (e.g., `X-Frame-Options`).
  - Example command to test iframe embedding:
    ```javascript
    var iframe = document.createElement('iframe');
    iframe.src = 'http://example.com';
    document.body.appendChild(iframe);
    ```
  - **Tip**: Firefox’s 2025 Network tab enhancements improve header inspection.

- **cURL and HTTPie**: Send HTTP requests to inspect response headers for anti-framing protections.
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
      curl -I http://example.com
      # HTTPie
      http --headers http://example.com
      ```

- **Clickjacking PoC Generator**: A tool to create proof-of-concept HTML pages for clickjacking tests.
  - Use online generators like [Clickjacking Tester](https://clickjacking-tester.herokuapp.com/) or create manually.
  - Example PoC (see Testing Methodology).
  - **Note**: Host PoCs on a controlled server for ethical testing.

- **Test Payloads**: Curated HTML/iframe payloads for testing.
  - Sample payload:
    ```html
    <iframe src="http://example.com" style="opacity:0.1; position:absolute; top:0; left:0; width:100%; height:100%"></iframe>
    ```
  - Resource: [OWASP Clickjacking Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).
  - **Tip**: Test payloads in a local HTML file and observe iframe rendering.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-09, testing clickjacking vulnerabilities across anti-framing headers, frame-busting scripts, iframe embedding, nested iframes, and user interaction simulation.

### 1. Test for Missing `X-Frame-Options` Header

**Objective**: Ensure the server includes `X-Frame-Options` to prevent iframe embedding.

**Steps**:
1. Send a request to the target page:
   ```bash
   curl -I http://example.com
   ```
2. Check response headers:
   - Look for `X-Frame-Options: DENY` or `SAMEORIGIN`.
   - Absence or invalid values indicate vulnerability.
3. Test iframe embedding:
   - Create a local HTML file:
     ```html
     <!DOCTYPE html>
     <html>
     <body>
       <iframe src="http://example.com" width="100%" height="500"></iframe>
     </body>
     </html>
     ```
   - Open in a browser and check if the page loads in the iframe.

**Example Secure Response**:
```http
HTTP/1.1 200 OK
X-Frame-Options: DENY
```
Iframe embedding blocked.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
```
No `X-Frame-Options`, iframe loads successfully.

**Remediation**:
- Set `X-Frame-Options`:
  ```http
  X-Frame-Options: DENY
  ```
- Server-side configuration (e.g., in Node.js):
  ```javascript
  res.set('X-Frame-Options', 'DENY');
  ```

**Tip**: Save response headers and iframe rendering screenshots in a report.

### 2. Test Frame-Busting Scripts

**Objective**: Ensure client-side frame-busting scripts prevent iframe embedding.

**Steps**:
1. Identify frame-busting scripts:
   - Use Browser Developer Tools to search for JavaScript:
     ```javascript
     document.body.innerText.match(/top\.location|self\.location/g);
     ```
2. Test iframe embedding:
   - Use the PoC HTML from Step 1 and check if the page breaks out of the iframe.
3. Attempt bypass:
   - Modify the PoC to include `sandbox` or `onbeforeunload`:
     ```html
     <iframe src="http://example.com" sandbox="allow-scripts" onbeforeunload="return false"></iframe>
     ```
   - Check if the frame-busting script is bypassed.

**Example Secure Response**:
```javascript
// Robust frame-busting
if (top !== self) {
  top.location = self.location;
}
```
Page redirects to top-level, breaking iframe.

**Example Vulnerable Response**:
```javascript
// Weak or no frame-busting
```
Page loads in iframe.

**Remediation**:
- Implement robust frame-busting:
  ```javascript
  if (top !== self) {
    top.location = self.location;
  }
  ```
- Combine with `X-Frame-Options`:
  ```http
  X-Frame-Options: SAMEORIGIN
  ```

**Tip**: Save JavaScript code and bypass attempt screenshots in a report.

### 3. Test Content Security Policy (CSP)

**Objective**: Ensure CSP `frame-ancestors` directive prevents unauthorized iframe embedding.

**Steps**:
1. Check CSP headers:
   ```bash
   http --headers http://example.com
   ```
2. Look for `frame-ancestors`:
   - Valid: `Content-Security-Policy: frame-ancestors 'self';`
   - Missing or permissive values (e.g., `*`) indicate vulnerability.
3. Test iframe embedding:
   - Use the PoC HTML from Step 1 and check if the page loads.

**Example Secure Response**:
```http
HTTP/1.1 200 OK
Content-Security-Policy: frame-ancestors 'self';
```
Iframe embedding blocked.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
```
No CSP or permissive `frame-ancestors`, iframe loads.

**Remediation**:
- Set CSP `frame-ancestors`:
  ```http
  Content-Security-Policy: frame-ancestors 'self';
  ```
- Server-side configuration (e.g., in PHP):
  ```php
  header("Content-Security-Policy: frame-ancestors 'self';");
  ```

**Tip**: Save CSP headers and iframe rendering screenshots in a report.

### 4. Test Nested Iframe Embedding

**Objective**: Ensure the page cannot be embedded in nested iframes to bypass protections.

**Steps**:
1. Create a nested iframe PoC:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
     <iframe src="http://malicious.com/middle.html">
       <iframe src="http://example.com"></iframe>
     </iframe>
   </body>
   </html>
   ```
2. Host on a local server (e.g., `python3 -m http.server 8000`).
3. Load the PoC and check if `example.com` renders in the nested iframe.
4. Test with `sandbox` attributes:
   ```html
   <iframe src="http://example.com" sandbox="allow-scripts"></iframe>
   ```

**Example Secure Response**:
```http
HTTP/1.1 200 OK
X-Frame-Options: DENY
```
Nested iframe blocked.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
```
Page loads in nested iframe.

**Remediation**:
- Use `X-Frame-Options: DENY`:
  ```http
  X-Frame-Options: DENY
  ```
- Add CSP:
  ```http
  Content-Security-Policy: frame-ancestors 'none';
  ```

**Tip**: Save nested iframe PoC code and rendering screenshots in a report.

### 5. Test User Interaction Simulation

**Objective**: Ensure sensitive actions (e.g., form submissions) are vulnerable to clickjacking.

**Steps**:
1. Create a clickjacking PoC:
   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <style>
       iframe { opacity: 0.1; position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
       button { position: absolute; top: 100px; left: 100px; }
     </style>
   </head>
   <body>
     <iframe src="http://example.com/settings"></iframe>
     <button onclick="alert('Fake Button')">Click Me!</button>
   </body>
   </html>
   ```
2. Host the PoC and load it in a browser.
3. Click the fake button and check if the iframe’s sensitive action (e.g., form submission) is triggered.
4. Verify with real user interaction:
   - Align the iframe over a sensitive button (e.g., “Change Password”).

**Example Secure Response**:
```http
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
```
Iframe blocked, no interaction possible.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
```
Iframe loads, and sensitive action is triggered.

**Remediation**:
- Prevent framing:
  ```http
  X-Frame-Options: DENY
  ```
- Require user confirmation for sensitive actions:
  ```javascript
  document.getElementById('submit').addEventListener('click', () => {
    if (confirm('Confirm action?')) {
      submitForm();
    }
  });
  ```

**Tip**: Save PoC code, interaction screenshots, and action outcomes in a report.
