# Testing for JavaScript Execution

## Overview

Testing for JavaScript Execution vulnerabilities involves verifying that a web application prevents arbitrary client-side JavaScript code execution due to unsafe handling of user-controlled inputs. According to OWASP (WSTG-CLNT-02), JavaScript execution vulnerabilities occur when applications allow user inputs to be processed by dynamic code execution mechanisms (e.g., `eval()`, `Function` constructor, or WebAssembly) without proper validation or sanitization, enabling attackers to run malicious scripts. This guide provides a hands-on methodology to identify and test such vulnerabilities, focusing on common execution sinks (e.g., `eval()`, `new Function()`, `setTimeout()`) and sources (e.g., URL parameters, form inputs), with tools, commands, and remediation strategies.

**Impact**: JavaScript execution vulnerabilities can lead to:
- Execution of malicious scripts, compromising user sessions or data.
- Theft of sensitive information (e.g., cookies, local storage).
- Unauthorized modifications to the application’s behavior or UI.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-02, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing JavaScript execution vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts requests and analyzes JavaScript for execution sinks. DOM Invader can detect dynamic execution patterns.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Install DOM Invader:
    1. Go to Extensions tab in Burp Suite.
    2. Search for “DOM Invader” and click “Add”.
    3. Enable DOM Invader in the browser (via Burp’s embedded browser or extension).
  - **Note**: DOM Invader flags `eval()` and `Function` usage but requires manual confirmation.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for JavaScript execution vulnerabilities.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan with “Client-side JavaScript” scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects JavaScript, tests dynamic execution, and monitors runtime behavior.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Sources tab for JavaScript inspection and Console for payload testing.
  - Example command to find execution sinks:
    ```javascript
    document.body.innerText.match(/eval|Function|setTimeout|setInterval|WebAssembly/g);
    ```
  - **Tip**: Firefox’s 2025 debugger enhancements improve breakpoint handling for large scripts.

- **cURL and HTTPie**: Send HTTP requests to test payloads in URL parameters or form inputs.
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
      curl -i "http://example.com/page?code=alert('xss')"
      # HTTPie
      http "http://example.com/page?code=alert('xss')"
      ```

- **XSStrike**: A Python-based tool for testing client-side vulnerabilities, including JavaScript execution.
  - Install:
    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python3 xsstrike.py -u "http://example.com/page?code=test" --dom
    ```
  - **Note**: Use `--dom` flag to focus on client-side execution sinks.

- **JavaScript Payloads**: Curated payloads for manual and automated testing.
  - Sample payloads:
    - `alert('xss')`
    - `console.log(document.cookie)`
    - `(function(){alert('xss')})()`
  - Resource: [OWASP XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
  - **Tip**: Test payloads in Browser Developer Tools Console.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-02, testing JavaScript execution vulnerabilities across dynamic execution sinks, user-controlled inputs, WebAssembly misuse, and runtime manipulation.

### 1. Test Dynamic Execution Sinks (e.g., `eval()`, `Function`)

**Objective**: Ensure dynamic execution functions do not process unsanitized user input.

**Steps**:
1. Identify execution sinks:
   - Open Browser Developer Tools (`F12` or `Ctrl+Shift+I`).
   - Navigate to Sources tab and search for `eval()`, `new Function()`, `setTimeout()`, or `setInterval()`.
   - Console command:
     ```javascript
     document.body.innerText.match(/eval|Function|setTimeout|setInterval/g);
     ```
2. Intercept requests with Burp Suite:
   - Configure proxy (`127.0.0.1:8080`).
   - Send payload:
     ```bash
     http "http://example.com/page?code=alert('xss')"
     ```
   - Analyze response for unsanitized code execution.
3. Test payload execution:
   - Inject `alert('xss')` into a URL parameter or form field.
   - Observe for an alert pop-up.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
var sanitizedCode = userInput.replace(/[<>;]/g, '');
eval(sanitizedCode);
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
eval(userInput);
```
Alert box displays "xss".

**Remediation**:
- Avoid `eval()`; use `JSON.parse()` for data:
  ```javascript
  var parsedData = JSON.parse(userInput);
  ```
- Use strict input validation:
  ```javascript
  if (/^[a-zA-Z0-9]+$/.test(userInput)) {
    new Function(userInput)();
  }
  ```

**Tip**: Save Burp Suite requests/responses and alert screenshots in a report.

### 2. Test User-Controlled Inputs in `new Function()`

**Objective**: Ensure `new Function()` does not execute unsanitized user input from URL parameters or forms.

**Steps**:
1. Inject a payload into a URL parameter:
   ```bash
   http "http://example.com/page?func=alert(document.cookie)"
   ```
2. Analyze `new Function()` usage:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/new Function/g);
     ```
3. Check for execution:
   - Load URL and observe for an alert showing cookies.

**Example Secure Response**:
```javascript
// Validated input prevents execution
var safeInput = userInput.match(/^[a-zA-Z0-9]+$/);
if (safeInput) {
  var func = new Function(safeInput);
  func();
}
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
var func = new Function(userInput);
func();
```
Alert shows cookie data.

**Remediation**:
- Validate inputs strictly:
  ```javascript
  if (/^[a-zA-Z0-9]+$/.test(userInput)) {
    var func = new Function(userInput);
    func();
  }
  ```
- Avoid `new Function()`; use predefined functions:
  ```javascript
  const allowedFunctions = { log: () => console.log('safe') };
  allowedFunctions[userInput]?.();
  ```

**Tip**: Document URL payloads and browser behavior with screenshots.

### 3. Test `setTimeout()` and `setInterval()` Injections

**Objective**: Ensure `setTimeout()` and `setInterval()` do not execute unsanitized user input.

**Steps**:
1. Identify `setTimeout()` or `setInterval()`:
   - Use Browser Developer Tools:
     ```javascript
     document.body.innerText.match(/setTimeout|setInterval/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?callback=alert('xss')"
   ```
3. Check for execution:
   - Load URL or submit form and observe for an alert.

**Example Secure Response**:
```javascript
// Sanitized input prevents execution
var safeCallback = userInput.replace(/[<>;]/g, '');
setTimeout(safeCallback, 1000);
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized input executes script
setTimeout(userInput, 1000);
```
Alert box displays "xss".

**Remediation**:
- Validate callback inputs:
  ```javascript
  if (/^[a-zA-Z0-9]+$/.test(userInput)) {
    setTimeout(userInput, 1000);
  }
  ```
- Use function references:
  ```javascript
  setTimeout(() => console.log('safe'), 1000);
  ```

**Tip**: Log JavaScript search results and payload outcomes with Console output.

### 4. Test WebAssembly Misuse

**Objective**: Ensure WebAssembly modules do not execute untrusted user inputs or malicious code.

**Steps**:
1. Identify WebAssembly usage:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/WebAssembly/g);
     ```
2. Inject a malicious WebAssembly module (simulated):
   - Create a test module:
     ```javascript
     // Malicious WebAssembly (simulated)
     const maliciousWasm = new Uint8Array([0x00, 0x61, 0x73, 0x6d, ...]);
     WebAssembly.instantiate(maliciousWasm).then(module => {
       module.exports.exec();
     });
     ```
   - Inject via URL or form:
     ```bash
     http "http://example.com/page?wasm=maliciousWasm"
     ```
3. Check for execution:
   - Monitor Console for errors or unexpected behavior.

**Example Secure Response**:
```javascript
// Validated WebAssembly module
if (validateWasmModule(userWasm)) {
  WebAssembly.instantiate(userWasm).then(module => {
    module.exports.safeFunction();
  });
}
```
No malicious execution.

**Example Vulnerable Response**:
```javascript
// Unvalidated WebAssembly executes code
WebAssembly.instantiate(userWasm).then(module => {
  module.exports.exec();
});
```
Malicious code runs.

**Remediation**:
- Validate WebAssembly modules:
  ```javascript
  function validateWasmModule(wasm) {
    return wasm instanceof Uint8Array && wasm.length < 10000; // Example check
  }
  ```
- Use sandboxed execution:
  ```javascript
  WebAssembly.instantiateStreaming(fetch('trusted.wasm')).then(module => {
    module.exports.safeFunction();
  });
  ```

**Tip**: Save WebAssembly-related Console errors and execution logs in a report.

### 5. Test Runtime JavaScript Manipulation

**Objective**: Ensure runtime manipulation (e.g., via `document.createElement('script')`) does not execute untrusted code.

**Steps**:
1. Identify dynamic script creation:
   - Search JavaScript:
     ```javascript
     document.body.innerText.match(/createElement.*script/g);
     ```
2. Inject a payload:
   ```bash
   http "http://example.com/page?script=alert('xss')"
   ```
3. Check for execution:
   - Load URL and observe for an alert.

**Example Secure Response**:
```javascript
// Sanitized script content
var script = document.createElement('script');
script.textContent = DOMPurify.sanitize(userInput);
document.body.appendChild(script);
```
No alert triggered.

**Example Vulnerable Response**:
```javascript
// Unsanitized script executes code
var script = document.createElement('script');
script.textContent = userInput;
document.body.appendChild(script);
```
Alert box displays "xss".

**Remediation**:
- Sanitize script content:
  ```javascript
  var script = document.createElement('script');
  script.textContent = DOMPurify.sanitize(userInput);
  document.body.appendChild(script);
  ```
- Avoid dynamic script creation; use static scripts:
  ```javascript
  <script src="/trusted.js"></script>
  ```

**Tip**: Document script injection attempts and alert screenshots in a report.