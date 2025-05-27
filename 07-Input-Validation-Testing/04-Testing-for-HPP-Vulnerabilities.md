# Testing for HTTP Parameter Pollution (HPP) Vulnerabilities

## Overview

Testing for HTTP Parameter Pollution (HPP) vulnerabilities involves verifying that a web application correctly handles multiple HTTP parameters with the same name to prevent logic flaws, access control bypasses, or unintended behavior. According to OWASP (WSTG-INPV-05), HPP occurs when an application processes duplicate parameters (e.g., `?id=1&id=2`) in an unexpected way, such as prioritizing the first, last, or concatenated values, which attackers can exploit to manipulate application logic. This guide provides a hands-on methodology to identify and test HPP vulnerabilities, focusing on server-side and client-side parameter handling, API endpoints, and encoded parameters, with tools, commands, and remediation strategies.

**Impact**: HPP vulnerabilities can lead to:
- Bypassing authentication or authorization controls.
- Manipulating business logic (e.g., payment amounts, user roles).
- Triggering unexpected server behavior or errors.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-05, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting duplicate parameters may trigger security alerts or disrupt application functionality.

## Testing Tools

The following tools are recommended for testing HTTP Parameter Pollution vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject duplicate parameters.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `http://127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to add multiple parameters and Proxy > HTTP History to analyze responses.
  - **Note**: Use Param Miner extension to test parameter variations.

- **OWASP ZAP**: Tests parameter manipulation for HPP detection.
  - Download from [ZAP ZAP](https://www.zaproxy.org/download).
  - Configure browser proxy: `httpie` `127.0.0.1:8080`.
  - Use Manual Request Editor to inject duplicate parameters and Active Scan with HPP rules.
  - **Tip**: Enable HUD (Tools > Options > HUD) for in-browser testing.

- **cURL**: Sends HTTP requests with duplicate parameters.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se).
  - Example:
    ```bash
    curl -i "http://example.com/page?id=1&id=2"
    ```

- **HTTPie**: Beginner-friendly CLI tool for HTTP requests.
  - Install on Linux/Mac:
    ```bash
    sudo apt install httpie
    ```
  - Install on Windows: `pip install httpie`.
  - Example:
    ```bash
    http "http://example.com/page?id==1&id==2"
    ```

- **Postman**: GUI tool for testing parameter pollution in APIs.
  - Download from [Postman](https://www.postman.com/downloads).
  - Add duplicate parameters in the Params tab and send requests.
  - **Tip**: Use Scripts to automate HPP testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to parameter manipulation.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses with duplicate parameters.
  - **Note**: Firefox’s 2025 network analysis improvements enhance parameter testing.

- **HPP Finder**: Online tool for generating HPP payloads.
  - Access by searching “HPP Finder tool.”
  - Example: Generates `id=1&id=2` or encoded variations.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-05, testing HTTP Parameter Pollution vulnerabilities across parameter enumeration, logic manipulation, and specific contexts like server-side HPP, client-side HPP, API endpoints, and encoded parameters.

### 1. Identify Parameters for Testing

**Objective**: Locate user-controllable parameters in HTTP requests.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Look for URLs with query parameters (e.g., `?id=1`), forms, or API endpoints.
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Identify parameters (e.g., `id=1` in `GET /page?id=1`).
3. Inspect HTML with Developer Tools:
   - Open Elements tab (`Ctrl+Shift+I`).
   - Search (`Ctrl+F`) for `<input>`, `<form>`, `<select>`, or `<textarea>` tags.
   - Note hidden fields (e.g., `<input type="hidden" name="token">`).
4. List parameters:
   - Document query parameters, form fields, and headers.

**Example Parameters**:
- URL: `http://example.com/page?id=1`
- Form: `<input name="amount">`
- Hidden: `<input type="hidden" name="role" value="user">`

**Remediation**:
- Validate parameters server-side using allowlists:
  ```php
  if (!in_array($_GET['role'], ['user', 'admin'])) {
      die("Invalid role");
  }
  ```
- Log unexpected parameters:
  ```php
  error_log("Unexpected parameter: " . json_encode($_GET));
  ```

**Tip**: Save the parameter list in a report.

### 2. Test Server-Side HPP

**Objective**: Verify how the server handles duplicate parameters.

**Steps**:
1. Inject duplicate parameters:
   - Modify a request in Burp Repeater:
     ```http
     GET /page?id=1&id=2 HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?id=1&id=2"
     ```
2. Test POST requests:
   - Use Burp to modify form data:
     ```http
     POST /submit HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     amount=100&amount=200
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/submit amount==100 amount==200
     ```
3. Check responses:
   - Observe which value is processed (first, last, concatenated, or error).
   - Look for logic flaws (e.g., incorrect user ID, amount).
4. Test combinations:
   - Try valid and invalid values (e.g., `role=user&role=admin`).

**Example Vulnerable Code (PHP)**:
```php
$user_id = $_GET['id']; // Takes last value
// Process $user_id
echo "User: $user_id";
```
Test: `?id=1&id=2`
Result: Processes `id=2`.

**Example Secure Code (PHP)**:
```php
if (count($_GET['id']) > 1) {
    die("Multiple IDs not allowed");
}
$user_id = $_GET['id'];
echo "User: $user_id";
```
Test: `?id=1&id=2`
Result: Error.

**Remediation**:
- Check for multiple parameters:
  ```php
  if (is_array($_GET['id'])) die("Invalid request");
  ```
- Use frameworks that handle HPP safely (e.g., Django, Rails).

**Tip**: Save server responses in a report.

### 3. Test Client-Side HPP

**Objective**: Check if client-side scripts mishandle duplicate parameters.

**Steps**:
1. Identify JavaScript handling:
   - Use Developer Tools to find scripts parsing `window.location.search`.
   - Example:
     ```javascript
     const params = new URLSearchParams(window.location.search);
     const id = params.get('id');
     ```
2. Inject duplicate parameters:
   - Visit: `http://example.com/page?id=1&id=2`.
   - Use Burp to modify requests.
3. Check behavior:
   - Observe which value is used (first, last, or error).
   - Look for DOM changes or alerts.
4. Test malicious values:
   - Try `<script>alert(123)</script>` or `javascript:alert(123)`.

**Example Vulnerable Code (JavaScript)**:
```javascript
const params = new URLSearchParams(window.location.search);
document.getElementById('output').innerHTML = params.get('id');
```
Test: `?id=<script>alert(123)</script>&id=1`
Result: Alert executes.

**Example Secure Code (JavaScript)**:
```javascript
const params = new URLSearchParams(window.location.search);
const id = params.get('id');
if (params.getAll('id').length > 1) {
    console.error('Multiple IDs detected');
    return;
}
document.getElementById('output').textContent = id;
```
Test: `?id=<script>alert(123)</script>&id=1`
Result: Error logged, no execution.

**Remediation**:
- Check for multiple values:
  ```javascript
  if (params.getAll('id').length > 1) throw new Error('Invalid parameters');
  ```
- Sanitize outputs:
  ```javascript
  element.textContent = value;
  ```

**Tip**: Save client-side behaviors in a report.

### 4. Test HPP in API Endpoints

**Objective**: Verify if API endpoints mishandle duplicate parameters.

**Steps**:
1. Identify API endpoints:
   - Use Burp’s Site Map or Postman to find `/api/*` routes.
   - Example: `/api/transfer`, `/api/users`.
2. Inject duplicate parameters:
   - Send via Postman:
     ```http
     GET /api/transfer?amount=100&amount=200 HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/api/transfer?amount=100&amount=200"
     ```
3. Check responses:
   - Look for logic flaws (e.g., incorrect amount processed).
   - Test authenticated vs. unauthenticated requests.
4. Test JSON payloads:
   - Send:
     ```http
     POST /api/update HTTP/1.1
     Host: example.com
     Content-Type: application/json
     {"id":"1","id":"2"}
     ```

**Example Vulnerable Code (Node.js)**:
```javascript
app.get('/api/transfer', (req, res) => {
    const amount = req.query.amount; // Takes last value
    // Process transfer
    res.send(`Transferred ${amount}`);
});
```
Test: `?amount=100&amount=200`
Result: Transfers 200.

**Example Secure Code (Node.js)**:
```javascript
app.get('/api/transfer', (req, res) => {
    if (Array.isArray(req.query.amount)) {
        return res.status(400).send('Invalid parameters');
    }
    const amount = req.query.amount;
    res.send(`Transferred ${amount}`);
});
```
Test: `?amount=100&amount=200`
Result: `400 Bad Request`.

**Remediation**:
- Validate API inputs:
  ```javascript
  if (Array.isArray(req.query.amount)) throw new Error('Invalid input');
  ```
- Use strict parsing libraries.

**Tip**: Save API responses in a report.

### 5. Test HPP with Encoded Parameters

**Objective**: Check if encoded duplicate parameters bypass validation.

**Steps**:
1. Encode parameters:
   - Use HPP Finder or manual encoding (e.g., `id%3D1` for `id=1`).
   - Test: `?id=1&id%3D2`.
2. Inject with Burp:
   - Modify request:
     ```http
     GET /page?id=1&id%3D2 HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?id=1&id%3D2"
     ```
3. Check responses:
   - Observe if encoded parameters are processed differently.
   - Look for logic bypasses.
4. Test URL-encoded payloads:
   - Try: `?id=<script>alert(123)</script>&id%3D1`.

**Example Vulnerable Code (PHP)**:
```php
$user_id = $_GET['id'];
echo "User: $user_id";
```
Test: `?id=1&id%3D2`
Result: Processes `id=2`.

**Example Secure Code (PHP)**:
```php
if (count($_GET['id']) > 1) {
    die("Multiple IDs not allowed");
}
$user_id = urldecode($_GET['id']);
echo "User: $user_id";
```
Test: `?id=1&id%3D2`
Result: Error.

**Remediation**:
- Decode parameters before validation:
  ```php
  $id = urldecode($_GET['id']);
  ```
- Reject multiple parameters:
  ```php
  if (is_array($_GET['id'])) die("Invalid request");
  ```

**Tip**: Save encoded parameter responses in a report.
