# Testing for HTML Injection

## Overview

Testing for HTML Injection vulnerabilities involves verifying that a web application prevents the injection of arbitrary HTML content due to improper sanitization of user-controlled inputs. According to OWASP (WSTG-CLNT-03), HTML injection occurs when user inputs (e.g., form fields, URL parameters, or headers) are rendered as HTML without proper encoding or sanitization, allowing attackers to alter the page’s structure or content. This guide provides a hands-on methodology to identify and test HTML injection vulnerabilities, focusing on common injection points (e.g., form inputs, query parameters) and their impact on page rendering, with tools, commands, and remediation strategies.

**Impact**: HTML injection vulnerabilities can lead to:
- Web page defacement, altering the application’s appearance or content.
- Facilitation of phishing attacks by injecting malicious forms or links.
- Escalation to Cross-Site Scripting (XSS) if combined with JavaScript execution.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-03, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting HTML payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing HTML injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and tests for HTML injection in parameters or forms.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to modify and resend requests with HTML payloads.
  - **Note**: Check responses in Burp’s Render tab to visualize injected HTML.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for HTML injection vulnerabilities.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan with “Client-side Injection” scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects rendered HTML and identifies injection points.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Elements tab to check for injected HTML and Console for errors.
  - Example command to inspect DOM changes:
    ```javascript
    document.body.innerHTML.includes('<div>test</div>') ? console.log('Injection detected') : console.log('No injection');
    ```
  - **Tip**: Firefox’s 2025 DOM inspection improvements enhance element highlighting.

- **cURL and HTTPie**: Send HTTP requests to test HTML payloads in URL parameters or form data.
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
      curl -i "http://example.com/page?name=<div>test</div>"
      # HTTPie
      http "http://example.com/page?name=<div>test</div>"
      ```

- **XSStrike**: A Python-based tool for testing client-side injection vulnerabilities, including HTML injection.
  - Install:
    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python3 xsstrike.py -u "http://example.com/page?name=test" --dom
    ```
  - **Note**: Use `--dom` flag to focus on client-side rendering issues.

- **HTML Payloads**: Curated payloads for manual and automated testing.
  - Sample payloads:
    - `<div style="color:red">Injected Content</div>`
    - `<h1>Defaced Page</h1>`
    - `<form action="http://malicious.com"><input type="submit" value="Login"></form>`
  - Resource: [OWASP Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html).
  - **Tip**: Test payloads in form fields or URL parameters and inspect page rendering.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-03, testing HTML injection vulnerabilities across form inputs, URL parameters, client-side rendering, and potential XSS escalation.

### 1. Test Form Input Injection

**Objective**: Ensure user inputs in forms are not rendered as HTML without proper encoding.

**Steps**:
1. Identify input fields:
   - Open the target page and locate `<input>`, `<textarea>`, or `<select>` elements.
   - Use Browser Developer Tools (Elements tab) to inspect form structure.
2. Inject an HTML payload:
   - Enter `<div style="color:red">Injected</div>` into a form field (e.g., name, comment).
   - Submit the form and observe the response page.
3. Check for injection:
   - Use Elements tab to verify if the payload appears as rendered HTML (e.g., a red-colored div).
   - Example Console command:
     ```javascript
     document.body.innerHTML.includes('<div style="color:red">Injected</div>') && console.log('HTML Injection Found');
     ```

**Example Secure Response**:
```html
<!-- Encoded input prevents rendering -->
<p>User input: &lt;div style=&quot;color:red&quot;&gt;Injected&lt;/div&gt;</p>
```
Payload appears as text, not rendered HTML.

**Example Vulnerable Response**:
```html
<!-- Unencoded input renders HTML -->
<p>User input: <div style="color:red">Injected</div></p>
```
Red-colored div appears on the page.

**Remediation**:
- Encode HTML output:
  ```javascript
  document.getElementById('output').textContent = userInput;
  ```
- Use server-side encoding (e.g., in PHP):
  ```php
  echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
  ```

**Tip**: Save form submissions and rendered page screenshots in a report.

### 2. Test URL Parameter Injection

**Objective**: Ensure URL query parameters are not rendered as HTML without encoding.

**Steps**:
1. Identify injectable parameters:
   - Analyze URLs for parameters (e.g., `?name=value`).
   - Example: `http://example.com/page?name=John`.
2. Inject an HTML payload:
   ```bash
   http "http://example.com/page?name=<h1>Defaced</h1>"
   ```
3. Check for injection:
   - Load the URL and inspect the page for a rendered `<h1>` element.
   - Use Elements tab or Console:
     ```javascript
     document.body.innerHTML.includes('<h1>Defaced</h1>') && console.log('HTML Injection Found');
     ```

**Example Secure Response**:
```html
<!-- Encoded parameter prevents rendering -->
<p>Name: &lt;h1&gt;Defaced&lt;/h1&gt;</p>
```
Payload appears as text.

**Example Vulnerable Response**:
```html
<!-- Unencoded parameter renders HTML -->
<p>Name: <h1>Defaced</h1></p>
```
Large “Defaced” heading appears.

**Remediation**:
- Encode query parameters:
  ```javascript
  var safeInput = encodeURIComponent(userInput);
  document.getElementById('output').textContent = safeInput;
  ```
- Server-side encoding (e.g., in Node.js):
  ```javascript
  res.write(escapeHtml(req.query.name));
  ```

**Tip**: Log URL payloads and page rendering screenshots in a report.

### 3. Test Client-Side Rendering

**Objective**: Ensure client-side JavaScript does not render unsanitized HTML from user inputs.

**Steps**:
1. Identify client-side rendering:
   - Search JavaScript for DOM manipulation:
     ```javascript
     document.body.innerText.match(/innerHTML|insertAdjacentHTML/g);
     ```
2. Inject a payload via form or URL:
   ```bash
   http "http://example.com/page?message=<div>Injected</div>"
   ```
3. Check for injection:
   - Inspect the page for a rendered `<div>` element.
   - Use Console:
     ```javascript
     document.querySelector('div').textContent === 'Injected' && console.log('HTML Injection Found');
     ```

**Example Secure Response**:
```javascript
// Safe rendering with textContent
document.getElementById('message').textContent = userInput;
```
Payload appears as text.

**Example Vulnerable Response**:
```javascript
// Unsanitized innerHTML renders HTML
document.getElementById('message').innerHTML = userInput;
```
Injected div appears.

**Remediation**:
- Use `textContent`:
  ```javascript
  document.getElementById('message').textContent = userInput;
  ```
- If `innerHTML` is needed, sanitize:
  ```javascript
  document.getElementById('message').innerHTML = DOMPurify.sanitize(userInput);
  ```

**Tip**: Save JavaScript search results and rendered page screenshots in a report.

### 4. Test for XSS Escalation

**Objective**: Ensure HTML injection does not enable JavaScript execution (escalating to XSS).

**Steps**:
1. Inject a JavaScript-enabled HTML payload:
   ```bash
   http "http://example.com/page?name=<img src=x onerror=alert('xss')>"
   ```
2. Check for execution:
   - Load the URL or submit the form and observe for an alert pop-up.
3. Analyze response:
   - Use Elements tab to confirm if the payload is rendered as HTML.
   - Use Console to detect script execution:
     ```javascript
     window.alert = () => console.log('XSS Detected');
     ```

**Example Secure Response**:
```html
<!-- Encoded input prevents execution -->
<p>Input: &lt;img src=x onerror=alert(&#39;xss&#39;)&gt;</p>
```
No alert triggered.

**Example Vulnerable Response**:
```html
<!-- Unencoded input executes script -->
<p>Input: <img src=x onerror=alert('xss')></p>
```
Alert box displays "xss".

**Remediation**:
- Encode all outputs:
  ```javascript
  document.getElementById('output').textContent = userInput;
  ```
- Implement Content Security Policy (CSP):
  ```html
  <meta http-equiv="Content-Security-Policy" content="script-src 'self';">
  ```

**Tip**: Document alert screenshots and response HTML in a report.

### 5. Test Form Field Injection

**Objective**: Ensure form fields (e.g., comments, profiles) do not allow HTML injection.

**Steps**:
1. Locate form fields:
   - Identify fields like “bio” or “comment” on the target page.
2. Inject a payload:
   - Enter `<b>Bold Text</b>` into a comment field and submit.
3. Check for injection:
   - Inspect the page for bolded text.
   - Use Elements tab to confirm `<b>` tags are rendered.

**Example Secure Response**:
```html
<!-- Encoded input prevents rendering -->
<p>Comment: &lt;b&gt;Bold Text&lt;/b&gt;</p>
```
Payload appears as text.

**Example Vulnerable Response**:
```html
<!-- Unencoded input renders HTML -->
<p>Comment: <b>Bold Text</b></p>
```
Text appears bold.

**Remediation**:
- Encode form outputs:
  ```php
  echo htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
  ```
- Validate inputs server-side:
  ```javascript
  if (!/[<>&]/.test(comment)) {
    saveComment(comment);
  }
  ```

**Tip**: Save form submissions and rendered page screenshots in a report.