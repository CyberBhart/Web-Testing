# Testing for DOM-Based Cross-Site Scripting (XSS)

## Overview

Testing for DOM-Based Cross-Site Scripting (XSS) involves verifying that a web application prevents malicious script execution in the Document Object Model (DOM) due to unsafe handling of user-controlled inputs. According to OWASP (WSTG-CLNT-01), DOM-based XSS occurs when client-side JavaScript processes user inputs (e.g., URL parameters, fragments, or form fields) and inserts them into the DOM without proper sanitization, allowing attackers to execute arbitrary JavaScript. This guide provides a hands-on methodology to identify and test DOM-based XSS vulnerabilities, focusing on common sources (e.g., `location.hash`, `location.search`, `document.referrer`) and sinks (e.g., `innerHTML`, `eval()`), with tools, commands, and remediation strategies.

**Impact**: DOM-based XSS vulnerabilities can lead to:
- Unauthorized execution of malicious JavaScript, compromising user sessions or data.
- Theft of sensitive information (e.g., cookies, tokens).
- Manipulation of the web application's UI or functionality.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-01, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing DOM-based XSS vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts requests, analyzes JavaScript, and fuzzes inputs. Includes DOM Invader for automated DOM XSS detection.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Install DOM Invader:
    1. Go to Extensions tab in Burp Suite.
    2. Search for “DOM Invader” and click “Add”.
    3. Enable DOM Invader in the browser (via Burp’s embedded browser or extension).
  - **Note**: DOM Invader automates sink detection but requires manual verification.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and automated XSS scanning, with DOM XSS detection.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan with “DOM-based XSS” scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects JavaScript, manipulates the DOM, and tests payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Sources tab for JavaScript inspection and Console for payload testing.
  - Example command to find sinks:
    ```javascript
    $$('script').forEach(s => console.log(s.innerText.match(/innerHTML|eval|document\.write/)));
    ```
  - **Tip**: Use Firefox for debugging large JavaScript files due to 2025 performance improvements.

- **cURL and HTTPie**: Send HTTP requests to test payloads in URL parameters or headers.
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
      curl -i "http://example.com/page?input=<script>alert('xss')</script>"
      # HTTPie
      http "http://example.com/page?input=<script>alert('xss')</script>"
      ```

- **XSStrike**: A Python-based tool for automated XSS testing, including DOM-based XSS.
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

- **JavaScript Payloads**: Curated payloads for manual and automated testing.
  - Sample payloads:
    - `<script>alert('xss')</script>`
    - `<img src="x" onerror="alert('xss')">`
    - `javascript:alert(document.cookie)`
  - Resource: [OWASP XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
  - **Tip**: Test payloads in Browser Developer Tools Console.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-01, testing DOM-based XSS vulnerabilities across DOM sinks, URL fragments, dynamic code execution, content insertion, additional sources, and event handler injection.

### 1. Test DOM Sinks (e.g., `document.write()`, `innerHTML`)

**Objective**: Ensure dangerous DOM sinks do not process unsanitized user input.

**Steps**:
1. Identify DOM sinks:
   - Open Browser Developer Tools (`F12` or `Ctrl+Shift+I`).
   - Navigate to Sources tab and search for sinks like `document.write()`, `innerHTML`, `eval()`, or `setTimeout()`.
   - Console command:
     ```javascript
     document.body.innerText.match(/document\.write|innerHTML|eval|setTimeout/g);
     ```
2. Intercept requests with Burp Suite:
   - Configure proxy (`127.0.0.1:8080`).
   - Send payload:
     ```bash
     http "http://example.com/page?input=<script>alert('xss')</script>"
     ```
   - Analyze response for unsanitized DOM insertion.
3. Test payload execution:
   - Inject `<script>alert('xss')</script>` into a URL parameter or form field.
   - Observe for an alert pop-up.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
document.write("User input: " + DOMPurify.sanitize(userInput));
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
document.write("User input: " + userInput);
```
Alert box displays "xss".

**Remediation**:
- Sanitize with DOMPurify:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  document.write("User input: " + cleanInput);
  ```
- Use `textContent`:
  ```javascript
  document.getElementById("output").textContent = userInput;
  ```

**Tip**: Save Burp Suite requests/responses and alert screenshots in a report.

### 2. Test URL Fragment Injection

**Objective**: Ensure `location.hash` is not unsafely inserted into the DOM.

**Steps**:
1. Inject a payload into the URL fragment:
   ```bash
   http "http://example.com/page#<script>alert('xss')</script>"
   ```
2. Observe page behavior:
   - Load URL in browser and check for an alert or DOM changes.
3. Analyze `location.hash` handling:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/location\.hash/g);
     ```

**Example Secure Response**:
```javascript
// Sanitized fragment prevents execution
document.write("Page URL: " + DOMPurify.sanitize(document.location.hash));
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized fragment executes script
document.write("Page URL: " + document.location.hash);
```
Alert box displays "xss".

**Remediation**:
- Sanitize fragments:
  ```javascript
  var cleanFragment = DOMPurify.sanitize(document.location.hash);
  document.getElementById("output").textContent = cleanFragment;
  ```
- Use `textContent` for DOM updates.

**Tip**: Document URL payloads and browser behavior with screenshots.

### 3. Test for `eval()` and `setTimeout()/setInterval()` Injections

**Objective**: Ensure dynamic code execution functions do not process unsanitized input.

**Steps**:
1. Identify `eval()`, `setTimeout()`, or `setInterval()`:
   - Use Browser Developer Tools:
     ```javascript
     document.body.innerText.match(/eval|setTimeout|setInterval/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?input=<script>alert('xss')</script>"
   ```
3. Check for execution:
   - Load URL or submit form and observe for an alert.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
var sanitizedInput = DOMPurify.sanitize(userInput);
eval(sanitizedInput);
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
eval(userInput);
```
Alert box displays "xss".

**Remediation**:
- Avoid `eval()`; use `JSON.parse()`:
  ```javascript
  var parsedInput = JSON.parse(userInput);
  ```
- Sanitize inputs:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  setTimeout(cleanInput, 1000);
  ```

**Tip**: Log JavaScript search results and payload outcomes with Console output.

### 4. Test Dynamic Content Insertion (`innerHTML`)

**Objective**: Ensure `innerHTML` does not execute unsanitized input.

**Steps**:
1. Identify `innerHTML` usage:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/innerHTML/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?message=<script>alert('xss')</script>"
   ```
3. Check for execution:
   - Load URL or submit form and observe for an alert.

**Example Secure Response**:
```javascript
// Safe insertion with textContent
document.getElementById("message").textContent = userInput;
```
Payload rendered as text.

**Example Vulnerable Response**:
```javascript
// Unsanitized innerHTML executes script
document.getElementById("message").innerHTML = userInput;
```
Alert box displays "xss".

**Remediation**:
- Use `textContent`:
  ```javascript
  document.getElementById("message").textContent = userInput;
  ```
- If `innerHTML` is needed, sanitize:
  ```javascript
  document.getElementById("message").innerHTML = DOMPurify.sanitize(userInput);
  ```

**Tip**: Save HTTP responses and alert screenshots in a report.

### 5. Test `location.search` Injection

**Objective**: Ensure `location.search` (URL query parameters) is not unsafely inserted into the DOM.

**Steps**:
1. Inject a payload into query parameters:
   ```bash
   http "http://example.com/page?search=<script>alert('xss')</script>"
   ```
2. Analyze `location.search` handling:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/location\.search/g);
     ```
3. Check for execution:
   - Load URL and observe for an alert.

**Example Secure Response**:
```javascript
// Sanitized query prevents execution
var query = DOMPurify.sanitize(location.search);
document.getElementById("output").textContent = query;
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized query executes script
document.getElementById("output").innerHTML = location.search;
```
Alert box displays "xss".

**Remediation**:
- Sanitize query parameters:
  ```javascript
  var cleanQuery = DOMPurify.sanitize(location.search);
  document.getElementById("output").textContent = cleanQuery;
  ```

**Tip**: Log query payloads and browser behavior with screenshots.

### 6. Test `document.cookie` Manipulation

**Objective**: Ensure `document.cookie` is not unsafely processed or exposed via DOM sinks.

**Steps**:
1. Inject a payload via a form or URL:
   ```bash
   http "http://example.com/page?input=<img src=x onerror=alert(document.cookie)>"
   ```
2. Analyze `document.cookie` usage:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/document\.cookie/g);
     ```
3. Check for execution or data exposure:
   - Observe for an alert showing cookies.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
document.getElementById("output").textContent = DOMPurify.sanitize(userInput);
```
No alert or cookie exposure.

**Example Vulnerable Response**:
```javascript
// Unsanitized input exposes cookies
document.getElementById("output").innerHTML = userInput;
```
Alert shows cookie data.

**Remediation**:
- Sanitize inputs:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  document.getElementById("output").textContent = cleanInput;
  ```
- Use `HttpOnly` cookies to prevent client-side access.

**Tip**: Document cookie exposure and alert screenshots in a report.
