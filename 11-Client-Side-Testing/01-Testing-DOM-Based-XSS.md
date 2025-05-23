# Testing for DOM-Based Cross-Site Scripting (XSS)

## Overview

Testing for DOM-Based Cross-Site Scripting (XSS) involves verifying that a web application prevents malicious script execution in the Document Object Model (DOM) due to unsafe handling of user-controlled inputs. According to OWASP (WSTG-CLNT-01), DOM-based XSS occurs when client-side JavaScript processes user inputs (e.g., URL parameters, fragments, or form fields) and inserts them into the DOM without proper sanitization, allowing attackers to execute arbitrary JavaScript. This guide provides a hands-on methodology to identify and test DOM-based XSS vulnerabilities, focusing on common sources (e.g., `location.hash`, `document.referrer`) and sinks (e.g., `innerHTML`, `eval()`), with tools, commands, and remediation strategies.

**Impact**: DOM-based XSS vulnerabilities can lead to:
- Unauthorized execution of malicious JavaScript, compromising user sessions or data.
- Theft of sensitive information (e.g., cookies, tokens).
- Manipulation of the web application's UI or functionality.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide adheres to OWASP’s WSTG-CLNT-01, offering practical steps for black-box and gray-box testing, detailed tool setups, specific commands, and ethical considerations. **Ethical Note**: Obtain explicit permission before testing, as injecting payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing DOM-based XSS vulnerabilities, with setup and configuration instructions tailored for new pentesters:

- **Burp Suite Community Edition**: Intercepts requests, analyzes JavaScript, and fuzzes inputs for XSS testing. Includes DOM Invader for automated DOM XSS detection.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Install DOM Invader:
    1. Go to Extensions tab in Burp Suite.
    2. Search for “DOM Invader” and click “Add”.
    3. Enable DOM Invader in the browser (via Burp’s embedded browser or extension).
  - **Note**: DOM Invader automates sink detection but requires manual verification of findings.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and automated XSS scanning, with enhanced DOM XSS detection.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: 127.0.0.1:11000.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan for automated XSS detection, selecting “DOM-based XSS” in scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects JavaScript, manipulates the DOM, and tests payloads.
  - Access: Press F12 or Ctrl+Shift+I.
  - Use Sources tab for JavaScript inspection and Console for payload testing.
  - **Tip**: Use Console Utilities API (e.g., `$$('script')` to query DOM elements) and prefer Firefox for debugging large JavaScript files due to 2025 performance improvements.
  - Example command to find sinks:
    ```javascript
    $$('script').forEach(s => console.log(s.innerText.match(/innerHTML|eval/)));
    ```

- **cURL and HTTPie**: Send HTTP requests to test XSS payloads in URL parameters or headers.
  - **cURL**:
    - Install on Linux:
      ```bash
      sudo apt install curl
      ```
    - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
  - **HTTPie** (alternative, beginner-friendly):
    - Install on Linux/Mac:
      ```bash
      sudo apt install httpie
      ```
    - Install on Windows: Use `pip install httpie`.
    - Example (cURL vs. HTTPie):
      ```bash
      # cURL
      curl -i "http://example.com/page?input=<script>alert('xss')</script>"
      # HTTPie
      http "http://example.com/page?input=<script>alert('xss')</script>"
      ```

- **XSStrike**: A Python-based tool for automated XSS testing, including DOM-based XSS, with advanced payload generation.
  - Install:
    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python3 xsstrike.py -u "http://example.com/page?input=test" --dom
    ```
  - **Note**: Use `--dom` flag for DOM-based XSS testing.

- **JavaScript Payloads**: Curated XSS payloads for manual and automated testing.
  - Sample payloads:
    - `<script>alert('xss')</script>`
    - `<img src="x" onerror="alert('xss')">`
    - `javascript:alert(document.cookie)`
  - Resource: [OWASP XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) or [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection).
  - **Tip**: Test payloads in Browser Developer Tools Console to confirm execution.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-01, focusing on testing DOM-based XSS vulnerabilities across DOM sinks, URL fragments, dynamic code execution, content insertion, additional sources (`document.referrer`, `window.name`), JSONP endpoints, DOM clobbering, CSP effectiveness, and event handler injection.

### 1. Test DOM Sinks (e.g., `document.write()`, `innerHTML`)

**Objective**: Ensure dangerous DOM sinks do not process unsanitized user input, preventing XSS.

**Steps**:
1. Identify DOM sinks in JavaScript:
   - Open Browser Developer Tools (F12 or Ctrl+Shift+I).
   - Navigate to Sources tab and search for sinks like `document.write()`, `innerHTML`, `eval()`, or `setTimeout()`.
   - Example command in Console:
     ```javascript
     // Search for document.write in page scripts
     document.body.innerText.match(/document\.write\(/g);
     ```
2. Intercept requests with Burp Suite:
   - Configure Burp Suite proxy (127.0.0.1:8080).
   - Send a request with a test payload:
     ```bash
     curl -i "http://example.com/page?input=<script>alert('xss')</script>"
     # HTTPie alternative
     http "http://example.com/page?input=<script>alert('xss')</script>"
     ```
   - Analyze response for unsanitized DOM insertion.
3. Test payload execution:
   - Inject a payload like `<script>alert('xss')</script>` into a URL parameter or form field.
   - Observe if an alert pops up, indicating a vulnerability.

**Example Secure Response**:
```javascript
// Sanitized input prevents script execution
document.write("User input: " + DOMPurify.sanitize(userInput));
```
No alert is triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
document.write("User input: " + userInput);
```
An alert box displays "xss".

**Remediation**:
- Sanitize user input with DOMPurify:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  document.write("User input: " + cleanInput);
  ```
- Use safer alternatives like `textContent`:
  ```javascript
  document.getElementById("output").textContent = userInput;
  ```

**Tip**: Save Burp Suite intercepted requests and responses as screenshots. Log findings with timestamps and payload details in a report.

### 2. Test URL Fragment Injection

**Objective**: Ensure URL fragments (`location.hash`) are not unsafely inserted into the DOM.

**Steps**:
1. Inject a malicious payload into the URL fragment:
   ```bash
   curl -i "http://example.com/page#<script>alert('xss')</script>"
   # HTTPie alternative
   http "http://example.com/page#<script>alert('xss')</script>"
   ```
2. Observe page behavior:
   - Load the URL in a browser and check for an alert pop-up or DOM changes.
3. Analyze JavaScript handling of `location.hash`:
   - Use Browser Developer Tools to find code like:
     ```javascript
     document.write(document.location.hash);
     ```

**Example Secure Response**:
```javascript
// Sanitized fragment prevents execution
document.write("Page URL: " + DOMPurify.sanitize(document.location.hash));
```
No alert is triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized fragment executes script
document.write("Page URL: " + document.location.hash);
```
An alert box displays "xss".

**Remediation**:
- Sanitize URL fragments:
  ```javascript
  var cleanFragment = DOMPurify.sanitize(document.location.hash);
  document.getElementById("output").textContent = cleanFragment;
  ```
- Avoid `document.write()`; use `textContent` for safe DOM updates.

**Tip**: Document URL payloads and browser behavior in a report. Include screenshots of alert pop-ups for evidence.

### 3. Test for `eval()` and `setTimeout()/setInterval()` Injections

**Objective**: Ensure dynamic code execution functions do not process unsanitized user input.

**Steps**:
1. Identify `eval()`, `setTimeout()`, or `setInterval()` in JavaScript:
   - Use Browser Developer Tools, Sources tab, and search:
     ```javascript
     // Search for eval in Console
     document.body.innerText.match(/eval\(/g);
     ```
2. Inject a malicious payload:
   ```bash
   curl -i "http://example.com/page?input=<script>alert('xss')</script>"
   # HTTPie alternative
   http "http://example.com/page?input=<script>alert('xss')</script>"
   ```
3. Check for execution:
   - Load the URL or submit the form and observe for an alert pop-up.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
var sanitizedInput = DOMPurify.sanitize(userInput);
eval(sanitizedInput); // No harmful code executes
```
No alert is triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
eval(userInput);
```
An alert box displays "xss".

**Remediation**:
- Avoid `eval()`; use safer alternatives like `JSON.parse()`:
  ```javascript
  var parsedInput = JSON.parse(userInput);
  ```
- Sanitize inputs before dynamic execution:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  setTimeout(cleanInput, 1000); // Ensure safe input
  ```

**Tip**: Log JavaScript search results and payload outcomes in a report. Save Console output as evidence.

### 4. Test Dynamic Content Insertion (`innerHTML`)

**Objective**: Ensure `innerHTML` does not process unsanitized user input from forms or URL parameters.

**Steps**:
1. Identify `innerHTML` usage:
   - Use Browser Developer Tools to search for `innerHTML`:
     ```javascript
     document.body.innerText.match(/innerHTML/g);
     ```
2. Inject a malicious payload via URL or form:
   ```bash
   curl -i "http://example.com/page?message=<script>alert('xss')</script>"
   # HTTPie alternative
   http "http://example.com/page?message=<script>alert('xss')</script>"
   ```
3. Check if the payload executes:
   - Load the URL or submit the form and observe for an alert pop-up.

**Example Secure Response**:
```javascript
// Safe insertion with textContent
document.getElementById("message").textContent = userInput;
```
Payload is rendered as plain text.

**Example Vulnerable Response**:
```javascript
// Unsanitized innerHTML executes script
document.getElementById("message").innerHTML = userInput;
```
An alert box displays "xss".

**Remediation**:
- Use `textContent` for safe insertion:
  ```javascript
  document.getElementById("message").textContent = userInput;
  ```
- If `innerHTML` is required, sanitize with DOMPurify:
  ```javascript
  document.getElementById("message").innerHTML = DOMPurify.sanitize(userInput);
  ```

**Tip**: Save HTTP responses and screenshots of alert pop-ups in a report. Note parameter names and payloads tested.

### 5. Test for DOM-Based XSS via `document.referrer` and `window.name`

**Objective**: Ensure `document.referrer` and `window.name` inputs are not unsafely processed.

**Steps**:
1. Inject a payload via `Referer` header:
   ```bash
   curl -i -H "Referer: javascript:alert('xss')" "http://example.com/page"
   # HTTPie alternative
   http "http://example.com/page" Referer:"javascript:alert('xss')"
   ```
2. Inject a payload via `window.name`:
   - Open a new window in Browser Developer Tools Console:
     ```javascript
     window.name = "<script>alert('xss')</script>";
     window.location = "http://example.com/page";
     ```
3. Check JavaScript handling:
   - Search for `document.referrer` or `window.name` usage:
     ```javascript
     document.body.innerText.match(/document\.referrer|window\.name/g);
     ```
4. Observe for payload execution.

**Example Secure Response**:
```javascript
// Sanitized referrer prevents execution
document.getElementById("output").textContent = DOMPurify.sanitize(document.referrer);
```
No alert is triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized referrer executes script
document.getElementById("output").innerHTML = document.referrer;
```
An alert box displays "xss".

**Remediation**:
- Sanitize `document.referrer` and `window.name`:
  ```javascript
  var cleanReferrer = DOMPurify.sanitize(document.referrer);
  document.getElementById("output").textContent = cleanReferrer;
  ```

**Tip**: Log cURL/HTTPie commands and Console outputs in a report. Include browser behavior screenshots.

### 6. Test for JSONP-Based XSS

**Objective**: Ensure JSONP endpoints do not allow unsanitized callback names to execute scripts.

**Steps**:
1. Identify JSONP endpoints (e.g., `callback` parameter):
   - Use Burp Suite to intercept requests and find `?callback=` in URLs.
2. Inject a malicious callback:
   ```bash
   curl -i "http://example.com/jsonp?callback=alert(document.cookie)"
   # HTTPie alternative
   http "http://example.com/jsonp?callback=alert(document.cookie)"
   ```
3. Check response for script execution:
   - Load the URL in a browser and observe for an alert pop-up.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"error": "Invalid callback name"}
```
No script executes.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/javascript
alert(document.cookie)({"data": "test"});
```
An alert shows the cookie.

**Remediation**:
- Restrict callback names to alphanumeric values:
  ```javascript
  const callback = req.query.callback;
  if (!/^[a-zA-Z0-9_]+$/.test(callback)) {
      return res.status(400).json({ error: 'Invalid callback' });
  }
  res.send(`${callback}(${JSON.stringify(data)})`);
  ```
- Use JSON responses with proper headers:
  ```http
  Content-Type: application/json
  X-Content-Type-Options: nosniff
  ```

**Tip**: Save intercepted JSONP responses in Burp Suite. Document callback payloads and outcomes.

### 7. Test for DOM Clobbering

**Objective**: Ensure user-controlled HTML elements cannot overwrite DOM properties or variables.

**Steps**:
1. Inject HTML elements with clobberable names/IDs:
   - Use a form field or URL parameter:
     ```bash
     curl -i "http://example.com/page?input=%3Cform%20id=%22document%22%3E%3Cinput%20name=%22cookie%22%20value=%22malicious%22%3E%3C/form%3E"
     # HTTPie alternative
     http "http://example.com/page?input=<form id=\"document\"><input name=\"cookie\" value=\"malicious\"></form>"
     ```
2. Check JavaScript reliance on DOM properties:
   - Search for code like:
     ```javascript
     if (document.cookie) alert(document.cookie);
     ```
3. Observe for unexpected behavior (e.g., alert showing "malicious").

**Example Secure Response**:
```javascript
// Avoid clobberable properties
var safeCookie = document.cookie || '';
alert(safeCookie);
```
No malicious behavior occurs.

**Example Vulnerable Response**:
```javascript
// Clobbered document.cookie triggers wrong value
alert(document.cookie); // Shows "malicious"
```

**Remediation**:
- Avoid relying on clobberable DOM properties:
  ```javascript
  const safeValue = window.document.cookie || '';
  ```
- Sanitize HTML inputs:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  document.getElementById("output").innerHTML = cleanInput;
  ```

**Tip**: Document clobbering payloads and JavaScript behavior in a report. Include DOM inspection screenshots.

### 8. Test for Content Security Policy (CSP) Effectiveness

**Objective**: Ensure CSP prevents script execution even if payloads are injected.

**Steps**:
1. Check for CSP headers:
   ```bash
   curl -I "http://example.com" | grep Content-Security-Policy
   # HTTPie alternative
   http -h "http://example.com" | grep Content-Security-Policy
   ```
2. Inject a test payload:
   ```bash
   curl -i "http://example.com/page?input=%3Cscript%3Ealert('xss')%3C/script%3E"
   # HTTPie alternative
   http "http://example.com/page?input=<script>alert('xss')</script>"
   ```
3. Observe if CSP blocks the payload in the browser:
   - Use Browser Developer Tools, Console tab, to check for CSP violation errors.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Security-Policy: script-src 'self'; object-src 'none';
```
Browser Console: "Refused to execute inline script due to CSP."

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
(No CSP header or weak: script-src 'unsafe-inline')
```
An alert box displays "xss".

**Remediation**:
- Implement strict CSP:
  ```http
  Content-Security-Policy: script-src 'self'; object-src 'none'; default-src 'none';
  ```
- Avoid `unsafe-inline` or `unsafe-eval` in `script-src`.

**Tip**: Save cURL/HTTPie header outputs and Console CSP errors in a report. Note CSP policy details.

### 9. Test for Event Handler Injection

**Objective**: Ensure event handler attributes (e.g., `onerror`, `onclick`) do not execute unsanitized user input.

**Steps**:
1. Inject a payload targeting event handlers:
   ```bash
   curl -i "http://example.com/page?input=%3Cimg%20src=%22x%22%20onerror=%22alert('xss')%22%3E"
   # HTTPie alternative
   http "http://example.com/page?input=<img src=\"x\" onerror=\"alert('xss')\">"
   ```
2. Check JavaScript or HTML for event handler usage:
   - Search for dynamic attribute insertion:
     ```javascript
     document.body.innerText.match(/onerror|onclick/g);
     ```
3. Observe for payload execution in the browser.

**Example Secure Response**:
```javascript
// Safe insertion prevents execution
document.getElementById("output").textContent = userInput;
```
Payload is rendered as text.

**Example Vulnerable Response**:
```javascript
// Unsanitized attribute executes script
document.getElementById("output").innerHTML = userInput;
```
An alert box displays "xss".

**Remediation**:
- Use `textContent` for safe insertion:
  ```javascript
  document.getElementById("output").textContent = userInput;
  ```
- Sanitize inputs for attributes:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput, { ALLOWED_ATTR: ['id', 'class'] });
  document.getElementById("output").innerHTML = cleanInput;
  ```

**Tip**: Log payloads and browser behavior in a report. Include screenshots of event handler execution.
