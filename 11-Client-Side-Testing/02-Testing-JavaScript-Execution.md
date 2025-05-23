# Testing for JavaScript Execution

## Overview

Testing for JavaScript Execution involves identifying vulnerabilities where user-controlled input is executed as JavaScript code, allowing attackers to run arbitrary scripts in a user’s browser. According to OWASP (WSTG-CLNT-02), these vulnerabilities arise when client-side scripts process inputs (e.g., URL parameters, form fields, or `postMessage` data) unsafely via execution sinks like `eval()`, `setTimeout()`, `Function()`, or dynamic script creation. This guide provides a practical methodology to test for JavaScript execution vulnerabilities, covering common sinks (`eval()`, `innerHTML`, `postMessage`) and sources (URL parameters, form inputs), with tools, commands, and remediation strategies.

**Impact**: JavaScript execution vulnerabilities can lead to:
- Execution of malicious scripts, compromising user sessions or data.
- Theft of sensitive information (e.g., cookies, authentication tokens).
- Unauthorized actions or UI manipulation in the victim’s browser.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-02, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. **Ethical Note**: Obtain explicit permission before testing, as injecting payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are tailored for testing JavaScript execution vulnerabilities, with setup instructions optimized for new pentesters:

- **Browser Developer Tools (Chrome/Firefox)**: Inspects JavaScript for execution sinks (e.g., `eval()`, `postMessage`), tests payloads in the Console, and debugs Web Workers.
  - Access: Press F12 or Ctrl+Shift+I.
  - Use Sources tab for JavaScript inspection and Console for payload testing.
  - Example command to find sinks:
    ```javascript
    document.body.innerText.match(/eval|setTimeout|Worker|addEventListener.*message/g);
    ```
  - **Tip**: Use Firefox for large JavaScript files due to 2025 performance improvements.

- **Burp Suite Community Edition**: Intercepts HTTP requests to inject payloads into URL parameters or form fields.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Use Repeater tab for manual payload testing.
  - **Note**: Focus on HTTP interception; DOM Invader is not required for this guide.

- **XSStrike**: Automates XSS payload injection, targeting execution sinks like `eval()` and `setTimeout()`.
  - Install:
    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python3 xsstrike.py -u "http://example.com/page?input=test" --crawl --fuzzer
    ```
  - **Note**: Use `--crawl` for dynamic apps and `--fuzzer` for sink-specific payloads.

- **HTTPie**: Sends HTTP requests with payloads, offering beginner-friendly syntax and JSON support.
  - Install:
    ```bash
    sudo apt install httpie  # Linux/Mac
    pip install httpie      # Windows
    ```
  - Example:
    ```bash
    http "http://example.com/page?input=alert('xss')"
    ```

- **Postman**: Tests `postMessage` payloads and Web Worker inputs via WebSocket or JavaScript requests.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Use desktop app for WebSocket support.
  - Example: Create a WebSocket request to simulate `postMessage`:
    ```javascript
    window.postMessage("<script>alert('xss')</script>", "http://example.com");
    ```
  - **Note**: Ideal for cross-origin testing in Test 7.

- **JavaScript Payloads**: Curated payloads for manual testing of execution sinks.
  - Sample payloads:
    - `alert('xss')`
    - `<script>alert('xss')</script>`
    - `javascript:alert('xss')`
    - `<script>alert('xss')</script>` (for `postMessage`)
  - Resource: [PayloadsAllTheThings XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection).
  - **Tip**: Test payloads in Browser Developer Tools Console to confirm execution.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-02, testing JavaScript execution vulnerabilities across execution sinks (`eval()`, `setTimeout()`, `innerHTML`, `postMessage`, Web Workers), input sources (URL parameters, form fields), and modern APIs (Trusted Types, template literals).

### 1. Test `eval()` and `Function()` Constructor

**Objective**: Ensure `eval()` and `Function()` do not execute unsanitized user input as code.

**Steps**:
1. Identify `eval()` or `Function()` in JavaScript:
   - Open Browser Developer Tools (F12 or Ctrl+Shift+I).
   - Navigate to Sources tab and search:
     ```javascript
     document.body.innerText.match(/eval|Function/g);
     ```
2. Inject a malicious payload using HTTPie:
   ```bash
   http "http://example.com/page?input=alert('xss')"
   ```
3. Use Burp Suite to intercept and modify requests:
   - Send payload in Repeater: `input=alert('xss')`.
   - Check response for execution.
4. Test in browser:
   - Load URL or submit form and observe for an alert pop-up.

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
- Avoid `eval()` and `Function()`; use `JSON.parse()` for data:
  ```javascript
  var parsedInput = JSON.parse(userInput);
  ```
- Sanitize inputs:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  ```

**Tip**: Log JavaScript search results and payload outcomes in a report. Save Console output as evidence.

### 2. Test `setTimeout()` and `setInterval()`

**Objective**: Ensure `setTimeout()` and `setInterval()` do not execute unsanitized user input.

**Steps**:
1. Identify `setTimeout()` or `setInterval()` usage:
   - Use Browser Developer Tools, Sources tab:
     ```javascript
     document.body.innerText.match(/setTimeout|setInterval/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?input=alert('xss')"
   ```
3. Use XSStrike for automation:
   ```bash
   python3 xsstrike.py -u "http://example.com/page?input=test" --fuzzer
   ```
4. Check for execution:
   - Load URL or submit form and observe for an alert pop-up.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
var cleanInput = DOMPurify.sanitize(userInput);
setTimeout(cleanInput, 1000);
```
No alert is triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
setTimeout(userInput, 1000);
```
An alert box displays "xss".

**Remediation**:
- Sanitize inputs before dynamic execution:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  setTimeout(cleanInput, 1000);
  ```
- Use function references instead of strings:
  ```javascript
  setTimeout(() => console.log(userInput), 1000);
  ```

**Tip**: Save XSStrike output and screenshots of alert pop-ups in a report.

### 3. Test `innerHTML` and `document.write()`

**Objective**: Ensure `innerHTML` and `document.write()` do not execute unsanitized scripts.

**Steps**:
1. Identify `innerHTML` or `document.write()` usage:
   - Use Browser Developer Tools:
     ```javascript
     document.body.innerText.match(/innerHTML|document\.write/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?input=<script>alert('xss')</script>"
   ```
3. Use Burp Suite Repeater to test payloads:
   - Send: `input=<script>alert('xss')</script>`.
4. Check if payload executes in browser.

**Example Secure Response**:
```javascript
// Safe insertion with textContent
document.getElementById("output").textContent = userInput;
```
Payload is rendered as text.

**Example Vulnerable Response**:
```javascript
// Unsanitized innerHTML executes script
document.getElementById("output").innerHTML = userInput;
```
An alert box displays "xss".

**Remediation**:
- Use `textContent` for safe insertion:
  ```javascript
  document.getElementById("output").textContent = userInput;
  ```
- If `innerHTML` is needed, sanitize:
  ```javascript
  document.getElementById("output").innerHTML = DOMPurify.sanitize(userInput);
  ```

**Tip**: Document payloads and HTTP responses in a report. Include screenshots of execution.

### 4. Test `window.location` Assignments

**Objective**: Ensure `window.location` does not execute unsanitized JavaScript URLs.

**Steps**:
1. Identify `window.location` usage:
   - Use Browser Developer Tools:
     ```javascript
     document.body.innerText.match(/window\.location/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?redirect=javascript:alert('xss')"
   ```
3. Check for execution or navigation:
   - Load URL and observe for an alert or unexpected redirect.

**Example Secure Response**:
```javascript
// Validate URLs before assignment
if (userInput.startsWith('http')) {
    window.location = userInput;
}
```
No script executes.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
window.location = userInput;
```
An alert box displays "xss".

**Remediation**:
- Validate URLs:
  ```javascript
  if (/^https?:\/\//.test(userInput)) {
      window.location = userInput;
  }
  ```
- Sanitize inputs:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  ```

**Tip**: Log redirect payloads and browser behavior in a report.

### 5. Test Dynamic Script Element Creation

**Objective**: Ensure dynamic `<script>` elements or `script.src` do not execute malicious code.

**Steps**:
1. Identify script creation:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/createElement.*script|script\.src/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?script=javascript:alert('xss')"
   ```
3. Check for execution:
   - Load URL and observe for an alert pop-up.

**Example Secure Response**:
```javascript
// Validate script source
var src = userInput;
if (/^https:\/\/trusted\.com/.test(src)) {
    var s = document.createElement('script');
    s.src = src;
    document.head.appendChild(s);
}
```
No script executes.

**Example Vulnerable Response**:
```javascript
// Unsanitized script source executes
var s = document.createElement('script');
s.src = userInput;
document.head.appendChild(s);
```
An alert box displays "xss".

**Remediation**:
- Whitelist allowed script sources:
  ```javascript
  const allowed = ['https://trusted.com'];
  if (allowed.includes(userInput)) {
      var s = document.createElement('script');
      s.src = userInput;
  }
  ```

**Tip**: Save JavaScript search results and execution screenshots in a report.

### 6. Test Trusted Types Misconfiguration

**Objective**: Ensure Trusted Types policies prevent unsafe script execution.

**Steps**:
1. Check for Trusted Types usage:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/trustedTypes/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?input=<script>alert('xss')</script>"
   ```
3. Test in browser:
   - Observe if payload executes due to weak policy.

**Example Secure Response**:
```javascript
// Strict policy sanitizes input
var policy = trustedTypes.createPolicy('default', {
    createHTML: input => DOMPurify.sanitize(input)
});
document.getElementById('output').innerHTML = policy.createHTML(userInput);
```
No script executes.

**Example Vulnerable Response**:
```javascript
// Weak policy allows execution
var policy = trustedTypes.createPolicy('default', { createHTML: input => input });
document.getElementById('output').innerHTML = policy.createHTML(userInput);
```
An alert box displays "xss".

**Remediation**:
- Enforce strict Trusted Types:
  ```javascript
  var policy = trustedTypes.createPolicy('default', {
      createHTML: input => DOMPurify.sanitize(input)
  });
  ```

**Tip**: Log Trusted Types policy details and execution outcomes in a report.

### 7. Test `postMessage` Handlers

**Objective**: Ensure `postMessage` handlers do not execute unsanitized data.

**Steps**:
1. Identify `postMessage` listeners:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/addEventListener.*message/g);
     ```
2. Simulate a malicious `postMessage` using Postman:
   - Create a WebSocket request:
     ```javascript
     window.postMessage("<script>alert('xss')</script>", "http://example.com");
     ```
3. Alternatively, use an HTML page:
   ```html
   <script>
   window.opener.postMessage("<script>alert('xss')</script>", "http://example.com");
   </script>
   ```
4. Check for execution in the target window.

**Example Secure Response**:
```javascript
// Validate origin and sanitize data
window.addEventListener('message', e => {
    if (e.origin === 'http://example.com') {
        document.getElementById('output').textContent = e.data;
    }
});
```
No script executes.

**Example Vulnerable Response**:
```javascript
// Unsanitized data executes
window.addEventListener('message', e => {
    document.getElementById('output').innerHTML = e.data;
});
```
An alert box displays "xss".

**Remediation**:
- Validate `e.origin`:
  ```javascript
  if (e.origin !== 'http://example.com') return;
  ```
- Sanitize `e.data`:
  ```javascript
  document.getElementById('output').innerHTML = DOMPurify.sanitize(e.data);
  ```

**Tip**: Save Postman request logs and execution screenshots in a report.

### 8. Test JavaScript Template Literals

**Objective**: Ensure template literals do not lead to unsafe script execution.

**Steps**:
1. Identify template literals:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/`.*\${/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?input=alert('xss')"
   ```
3. Check for execution:
   - Observe if payload is evaluated (e.g., via `eval()`).

**Example Secure Response**:
```javascript
// Sanitized template literal
var cleanInput = DOMPurify.sanitize(userInput);
var output = `User: ${cleanInput}`;
document.getElementById('output').textContent = output;
```
No script executes.

**Example Vulnerable Response**:
```javascript
// Unsanitized template literal executes
var output = `User: ${userInput}`;
eval(`document.write("${output}");`);
```
An alert box displays "xss".

**Remediation**:
- Avoid `eval()` with template literals:
  ```javascript
  var output = `User: ${userInput}`;
  document.getElementById('output').textContent = output;
  ```
- Sanitize inputs:
  ```javascript
  var cleanInput = DOMPurify.sanitize(userInput);
  ```

**Tip**: Document template literal usage and execution outcomes in a report.

### 9. Test Web Workers

**Objective**: Ensure Web Workers do not execute unsanitized user input.

**Steps**:
1. Identify Web Worker usage:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/new Worker/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?worker=javascript:alert('xss')"
   ```
3. Use Postman to simulate Worker payload:
   - Send: `worker.postMessage("alert('xss')")`.
4. Check for execution in Worker context.

**Example Secure Response**:
```javascript
// Validate Worker URL
var workerUrl = userInput;
if (/^https:\/\/trusted\.com/.test(workerUrl)) {
    var worker = new Worker(workerUrl);
}
```
No script executes.

**Example Vulnerable Response**:
```javascript
// Unsanitized Worker URL executes
var worker = new Worker(userInput);
worker.postMessage(userInput);
```
An alert box displays "xss".

**Remediation**:
- Whitelist Worker URLs:
  ```javascript
  const allowed = ['https://trusted.com/worker.js'];
  if (allowed.includes(userInput)) {
      var worker = new Worker(userInput);
  }
  ```
- Sanitize messages:
  ```javascript
  worker.postMessage(DOMPurify.sanitize(userInput));
  ```

**Tip**: Log Worker payloads and execution screenshots in a report.