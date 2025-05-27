# Testing for HTTP Incoming Requests Vulnerabilities

## Overview

Testing for HTTP Incoming Requests vulnerabilities, specifically HTTP Parameter Pollution (HPP), involves verifying that a web application properly handles multiple HTTP parameters with the same name to prevent attackers from manipulating application logic, bypassing security controls, or injecting malicious data. According to OWASP (WSTG-INPV-016), HPP occurs when an application or server inconsistently processes duplicate parameters in URLs, forms, or headers, potentially leading to unexpected behavior, such as overriding values, bypassing filters, or triggering logic flaws. This guide provides a hands-on methodology to test for HPP vulnerabilities, focusing on identifying parameter-handling endpoints, server-side HPP, client-side HPP, parameter precedence, filter bypass, logic bypass, and chained attacks, with tools, commands, payloads, and remediation strategies.

**Impact**: HTTP Parameter Pollution vulnerabilities can lead to:
- Bypassing authentication or authorization controls.
- Manipulation of application logic (e.g., payment amounts, user roles).
- Cross-site scripting (XSS) or other injection attacks via client-side pollution.
- Data tampering or exposure of sensitive information.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-016, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as HPP attacks may disrupt application logic, affect user data, or trigger unintended actions.

## Testing Tools

The following tools are recommended for testing HTTP Incoming Requests vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject duplicate parameters.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify endpoints.
  - **Note**: Use “Param Miner” extension to detect parameter handling.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with HPP rules; manually verify findings due to false positives.

- **cURL and HTTPie**: Send HTTP requests with duplicate parameters.
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
      curl -i "http://example.com/action?param=value1&param=value2"
      # HTTPie
      http "http://example.com/action?param=value1&param=value2"
      ```

- **Postman**: GUI tool for testing HPP in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send requests with multiple parameters.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to HPP payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Console tab for client-side effects.
  - **Note**: Firefox’s 2025 parameter inspection enhancements improve debugging.

- **Netcat (nc)**: Tests raw HTTP requests with custom parameter payloads.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET /action?param=value1&param=value2 HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-016, testing HTTP Parameter Pollution vulnerabilities across parameter-handling endpoints, server-side HPP, client-side HPP, parameter precedence, filter bypass, logic bypass, and chained attacks.

### Common HTTP Parameter Pollution Payloads

Below is a list of common payloads to test for HTTP Parameter Pollution vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid unintended logic disruption.

- **Server-Side HPP Payloads**:
  - `?param=value1&param=value2` (Duplicate parameters)
  - `?param=value1%26param=value2` (Encoded duplicate)
  - `?param[]=value1&param[]=value2` (Array notation)
  - `?param=value1,param2` (Comma-separated values)

- **Client-Side HPP Payloads**:
  - `?param=<script>alert(1)</script>&param=benign` (XSS injection)
  - `?param=malicious.js&param=trusted.js` (Script source manipulation)
  - `?param=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E&param=safe` (Encoded XSS)
  - `?param=data:malicious&param=data:safe` (Data URI injection)

- **Parameter Precedence Payloads**:
  - `?user=admin&user=user` (Tests first/last precedence)
  - `?amount=100&amount=1` (Value override)
  - `?role=user&role=admin` (Role escalation)
  - `?id=1&id=2` (ID manipulation)

- **Filter Bypass Payloads**:
  - `?param=safe%26param=malicious` (Encoded separator)
  - `?param=benign;param=malicious` (Semicolon separator)
  - `?param=safe%00param=malicious` (Null byte injection)
  - `?param=safe%20param=malicious` (Space-separated)

- **Logic Bypass Payloads**:
  - `?action=delete&action=view` (Action override)
  - `?access=public&access=private` (Access control bypass)
  - `?price=10&price=0` (Price tampering)
  - `?vote=1&vote=2` (Vote manipulation)

- **Chained Attack Payloads**:
  - `?param=<script>alert(1)</script>&param=benign&redir=/home` (HPP + XSS)
  - `?param=admin&param=user%0d%0aSet-Cookie:session=malicious` (HPP + Splitting)
  - `?param=safe&param=malicious;cmd=whoami` (HPP + Command Injection)
  - `?param=benign&param=malicious%26sql=1%3Bdrop%20table%20users` (HPP + SQL Injection)

**Note**: Payloads depend on the application’s parameter parsing (e.g., PHP, ASP.NET) and server (e.g., Apache, Nginx). Test payloads in query strings, POST bodies, headers, or JSON payloads where parameters are processed.

### 1. Identify Parameter-Handling Endpoints

**Objective**: Locate inputs or endpoints that process HTTP parameters.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, URLs, or APIs that accept parameters (e.g., search, login, payment).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `user=admin`, `amount=100`).
3. Inspect responses:
   - Check for parameter reflection or logic changes.
   - Use Developer Tools (`Ctrl+Shift+I`) to analyze parameter handling.
4. List endpoints:
   - Document query strings, form fields, headers, and JSON payloads.

**Example Endpoints**:
- URL: `http://example.com/search?query=test`
- Form: `<input name="user">`
- API: `POST /api/action` with `{"param": "value"}`

**Remediation**:
- Validate parameters:
  ```php
  if (!preg_match('/^[a-zA-Z0-9]+$/', $_GET['user'])) die("Invalid input");
  ```
- Use single parameter values:
  ```php
  $user = $_GET['user'][0]; // First value only
  ```

**Tip**: Save the endpoint list in a report.

### 2. Test for Server-Side HPP

**Objective**: Verify if duplicate parameters cause server-side logic errors.

**Steps**:
1. Identify parameter inputs:
   - Look for endpoints like `?user=admin`.
2. Inject HPP payloads:
   - Use Burp Repeater:
     ```http
     GET /action?user=admin&user=user HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/action?user=admin&user=user"
     ```
3. Check responses:
   - Look for unexpected behavior (e.g., admin access).
   - Test: `?amount=100&amount=1`.
4. Test POST requests:
   - Send: `user=admin&user=user` in body.

**Example Vulnerable Code (PHP)**:
```php
$user = $_GET['user'];
process_user($user);
```
Test: `?user=admin&user=user`
Result: Processes `admin` or `user` unpredictably.

**Example Secure Code (PHP)**:
```php
$user = is_array($_GET['user']) ? $_GET['user'][0] : $_GET['user'];
process_user($user);
```
Test: Processes only first value.

**Remediation**:
- Explicit parameter handling:
  ```php
  $user = array_shift((array)$_GET['user']));
  ```
- Reject duplicates:
  ```php
  if (count($_GET['user']) > 1) die("Invalid parameters");
  ```

**Tip**: Save logic error evidence in a report.

### 3. Test for Client-Side HPP

**Objective**: Check if duplicate parameters enable client-side attacks like XSS.

**Steps**:
1. Inject client-side payloads:
   - Test: `?param=benign&param=<script>alert(1)</script>`
   - Use Burp:
     ```http
     GET /page?param=benign&param=<script>alert(1)</script> HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for script execution or DOM manipulation.
   - Test: `?param=trusted.js&param=malicious.js`.
3. Inspect DOM:
   - Use Developer Tools to check reflected parameters.
4. Test encoded payloads:
   - Try: `?param=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E&param=safe`.

**Example Vulnerable Code (JavaScript)**:
```javascript
const params = new URLSearchParams(window.location.search);
document.write(params.get('param'));
```
Test: `?param=benign&param=<script>alert(1)</script>`
Result: Executes script.

**Example Secure Code (JavaScript)**:
```javascript
const params = new URLSearchParams(window.location.search);
const param = params.getAll('param')[0] || '';
document.write(escape(param));
```
Test: No execution.

**Remediation**:
- Escape output:
  ```javascript
  document.write(encodeURIComponent(param));
  ```
- Use first parameter:
  ```javascript
  params.getAll('param')[0];
  ```

**Tip**: Save XSS evidence in a report.

### 4. Test for Parameter Precedence

**Objective**: Determine how the application prioritizes duplicate parameters.

**Steps**:
1. Inject precedence payloads:
   - Test: `?role=user&role=admin`
   - Use cURL:
     ```bash
     curl -i "http://example.com/action?role=user&role=admin"
     ```
2. Check responses:
   - Look for role escalation or value override.
   - Test: `?id=1&id=2`.
3. Test variations:
   - Try: `?role=admin&role=user` (reverse order).
4. Use Burp Intruder:
   - Test multiple combinations.

**Example Vulnerable Code (ASP.NET)**:
```csharp
string role = Request.QueryString["role"];
ProcessRole(role);
```
Test: `?role=user&role=admin`
Result: Uses last value (`admin`).

**Example Secure Code (ASP.NET)**:
```csharp
string role = Request.QueryString.GetValues("role")?[0] ?? "";
ProcessRole(role);
```
Test: Uses first value.

**Remediation**:
- Define precedence:
  ```csharp
  string role = Request.QueryString.GetValues("role").FirstOrDefault();
  ```
- Log duplicates:
  ```csharp
  if (Request.QueryString.GetValues("role").Length > 1) LogWarning("Duplicate parameters");
  ```

**Tip**: Save precedence behavior in a report.

### 5. Test for Filter Bypass

**Objective**: Verify if HPP can bypass input filters.

**Steps**:
1. Inject bypass payloads:
   - Test: `?param=safe%26param=malicious`
   - Use Burp:
     ```http
     GET /action?param=safe%26param=malicious HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for unfiltered malicious input.
   - Test: `?param=safe;param=malicious`.
3. Test obfuscation:
   - Try: `?param=safe%00param=malicious`.
4. Use Postman for APIs:
   - Send: `{"param": "safe", "param": "malicious"}`.

**Example Vulnerable Code (PHP)**:
```php
$param = $_GET['param'];
if (strpos($param, 'malicious') === false) process($param);
```
Test: `?param=safe&param=malicious`
Result: Processes `malicious`.

**Example Secure Code (PHP)**:
```php
$param = is_array($_GET['param']) ? $_GET['param'][0] : $_GET['param'];
if (strpos($param, 'malicious') === false) process($param);
```
Test: Processes `safe`.

**Remediation**:
- Decode inputs:
  ```php
  $param = urldecode($_GET['param']);
  ```
- Reject suspicious inputs:
  ```php
  if (preg_match('/[;&%00]/', $param)) die("Invalid input");
  ```

**Tip**: Save bypass evidence in a report.

### 6. Test for Logic Bypass

**Objective**: Check if HPP can bypass application logic or security checks.

**Steps**:
1. Inject logic bypass payloads:
   - Test: `?action=view&action=delete`
   - Use cURL:
     ```bash
     curl -i "http://example.com/action?action=view&action=delete"
     ```
2. Check responses:
   - Look for unauthorized actions (e.g., deletion).
   - Test: `?price=10&price=0`.
3. Test critical functions:
   - Try: `?vote=1&vote=2`.
4. Use Burp Intruder:
   - Test multiple actions.

**Example Vulnerable Code (Python)**:
```python
action = request.args.get('action')
if action == 'view':
    view_item()
else:
    delete_item()
```
Test: `?action=view&action=delete`
Result: Deletes item.

**Example Secure Code (Python)**:
```python
action = request.args.getlist('action')[0] if request.args.getlist('action') else ''
if action == 'view':
    view_item()
else:
    abort(403)
```
Test: Views item.

**Remediation**:
- Use single value:
  ```python
  action = request.args.getlist('action')[0]
  ```
- Validate actions:
  ```python
  if action not in ['view', 'edit']: abort(403)
  ```

**Tip**: Save logic bypass evidence in a report.

### 7. Test for Chained Attacks

**Objective**: Verify if HPP can be combined with other vulnerabilities.

**Steps**:
1. Inject chained payloads:
   - Test: `?param=benign&param=<script>alert(1)</script>&redir=/home`
   - Use Burp:
     ```http
     GET /action?param=benign&param=<script>alert(1)</script>&redir=/home HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for XSS, splitting, or injection.
   - Test: `?param=admin&param=user%0d%0aSet-Cookie:session=malicious`.
3. Test other injections:
   - Try: `?param=safe&param=malicious;cmd=whoami`.
4. Use Netcat for raw requests:
   ```bash
   echo -e "GET /action?param=safe&param=malicious%3Bcmd=whoami HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
   ```

**Example Vulnerable Code (PHP)**:
```php
$param = $_GET['param'];
echo $param;
```
Test: `?param=benign&param=<script>alert(1)</script>`
Result: Executes XSS.

**Example Secure Code (PHP)**:
```php
$param = is_array($_GET['param']) ? $_GET['param'][0] : $_GET['param'];
echo htmlspecialchars($param, ENT_QUOTES, 'UTF-8');
```
Test: No XSS.

**Remediation**:
- Sanitize outputs:
  ```php
  echo htmlentities($param);
  ```
- Combine defenses:
  ```php
  $param = filter_var($param, FILTER_SANITIZE_STRING);
  if (count($_GET['param']) > 1) die("Invalid parameters");
  ```

**Tip**: Save chained attack evidence in a report.