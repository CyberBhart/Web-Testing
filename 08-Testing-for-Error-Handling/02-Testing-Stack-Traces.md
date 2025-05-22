# Testing for Stack Traces

## Overview

Testing for stack traces (WSTG-ERRH-02) involves assessing whether a web application or server exposes detailed error messages, known as stack traces, when encountering errors. According to OWASP, stack traces can reveal sensitive information, such as file paths, function names, database queries, or software versions, which attackers can exploit for reconnaissance or targeted attacks. This test focuses on provoking errors through invalid inputs, malformed requests, or unexpected conditions and analyzing responses for stack traces that indicate insecure error handling.

**Impact**: Stack trace exposure can lead to:
- Disclosure of system internals (e.g., file paths, framework versions).
- Facilitation of attack chaining (e.g., exploiting exposed database queries for SQL injection).
- Identification of vulnerable components (e.g., outdated libraries).
- Increased attack surface by revealing application logic or server configurations.

This guide provides a practical, hands-on methodology for testing stack trace vulnerabilities, adhering to OWASP’s WSTG-ERRH-02, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing stack trace vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to trigger errors.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends malformed or invalid requests to provoke stack traces.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tests API endpoints with invalid inputs to elicit detailed error responses.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Browser Developer Tools**: Inspects and modifies requests to analyze error handling.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **OWASP ZAP**: Automates detection of stack traces through fuzzing and scanning.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Run:
    ```bash
    zap.sh
    ```
    (Linux) or `zap.bat` (Windows).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-ERRH-02, focusing on triggering errors through invalid inputs, malformed requests, or unauthorized actions and analyzing responses for stack traces or sensitive debug information.

### 1. Trigger Application Errors with Burp Suite

**Objective**: Provoke errors by sending invalid inputs to application input points to elicit stack traces.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Input Points**:
   - Browse the application to identify forms, search fields, or API endpoints.
   - Capture requests in Burp Suite’s “HTTP History” (e.g., `POST /search`, `GET /profile?id=1`).
3. **Manipulate Inputs**:
   - Use Burp Repeater to send invalid data (e.g., strings in integer fields, special characters).
   - Test for unhandled exceptions or debug output.
4. **Analyze Response**:
   - Check for HTTP 500, stack traces, or sensitive details (e.g., file paths, function names).
   - Look for errors in HTTP 200 responses or redirects.

**Burp Suite Commands**:
- **Command 1**: Send invalid input to a parameter:
  ```
  HTTP History -> Select GET /profile?id=1 -> Send to Repeater -> Change id to id=abc -> Click Send -> Check Response for stack traces
  ```
- **Command 2**: Test form submission with malformed data:
  ```
  HTTP History -> Select POST /search -> Send to Repeater -> Change q=test to q=%27%20OR%201=1%20-- -> Click Send -> Inspect Response for debug info
  ```

**Example Request**:
```
GET /profile?id=abc HTTP/1.1
Host: example.com
Cookie: session=abc123
```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
Traceback (most recent call last):
  File "/var/www/app/index.php", line 45, in handleRequest
    $id = (int)$_GET['id'];
TypeError: Invalid type 'abc' for id
```

**Remediation**:
- Handle exceptions gracefully (PHP):
  ```php
  try {
      $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
      if ($id === false) throw new Exception('Invalid ID');
      $result = $db->query("SELECT * FROM users WHERE id = $id");
  } catch (Exception $e) {
      http_response_code(400);
      echo 'Invalid request';
      exit;
  }
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Trigger Server Errors with cURL

**Objective**: Send malformed HTTP requests to provoke server-level stack traces.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find URLs (e.g., `/index.php`, `/api/v1/users`).
   - Test nonexistent or invalid paths (e.g., `/invalid.php`).
2. **Send Malformed Requests**:
   - Use cURL to send invalid HTTP methods, headers, or URLs.
   - Test for HTTP 500, 404, or 400 errors with debug output.
3. **Analyze Response**:
   - Check for stack traces, server banners (e.g., Apache 2.4.41), or file paths.
   - Verify if errors expose system details.

**cURL Commands**:
- **Command 1**: Request an invalid resource:
  ```bash
  curl -i http://example.com/invalid.php
  ```
- **Command 2**: Send a malformed HTTP request:
  ```bash
  curl -i -H "Invalid-Header: %%%" -X GET http://example.com/index.php
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
Fatal error: Uncaught Exception in /var/www/html/server.php:123
Stack trace:
#0 /var/www/html/index.php(45): handleRequest()
```

**Remediation**:
- Suppress stack traces and hide server details (Apache):
  ```apache
  ErrorDocument 500 /error.html
  ServerTokens Prod
  php_flag display_errors Off
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Stack Traces with Postman

**Objective**: Provoke stack traces in API endpoints by sending invalid or malicious inputs.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/users`).
   - Import into Postman.
2. **Send Invalid Requests**:
   - Send malformed JSON, invalid parameters, or special characters.
   - Test with and without authentication.
3. **Analyze Response**:
   - Check for HTTP 500, stack traces, or debug details (e.g., code line numbers).
   - Verify if errors appear in JSON responses.

**Postman Commands**:
- **Command 1**: Send malformed JSON to an API:
  ```
  New Request -> POST http://example.com/api/v1/users -> Body -> raw -> JSON: {"name": "test", "age": "abc -> Headers: Authorization: Bearer abc123 -> Send
  ```
- **Command 2**: Test invalid parameter type:
  ```
  New Request -> GET http://example.com/api/v1/profile?id=abc -> Headers: Authorization: Bearer abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "error": "Traceback (most recent call last):\n  File \"/app/controllers/user.py\", line 67, in getUser\n    id = int(id)\nValueError: invalid literal for int() with base 10: 'abc'"
}
```

**Remediation**:
- Avoid debug output in APIs (Node.js):
  ```javascript
  const express = require('express');
  const app = express();
  app.use(express.json());
  app.post('/api/v1/users', (req, res) => {
      try {
          const age = parseInt(req.body.age);
          if (isNaN(age)) throw new Error('Invalid age');
          res.json({ status: 'success' });
      } catch (e) {
          res.status(400).json({ error: 'Invalid request' });
      }
  });
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Manipulate Requests with Browser Developer Tools

**Objective**: Modify form submissions or requests to trigger stack traces.

**Steps**:
1. **Inspect Input Points**:
   - Open Developer Tools (`F12`) on a form page (e.g., `http://example.com/search`).
   - Identify input fields and their expected types.
2. **Manipulate Inputs**:
   - Edit form data (e.g., change a number to a string) before submission.
   - Modify query parameters in URLs.
3. **Analyze Response**:
   - Check for stack traces, HTTP 500, or debug details in the DOM or network responses.
   - Verify if errors expose code or system information.

**Browser Developer Tools Commands**:
- **Command 1**: Modify form input to trigger an error:
  ```
  Elements tab -> Find <input name="id" type="number"> -> Edit as HTML -> Change value to "abc" -> Submit form
  ```
- **Command 2**: Edit query parameter in a request:
  ```
  Network tab -> Right-click GET /profile?id=1 -> Copy as cURL -> Modify id=abc -> Replay in terminal
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
StackTrace: /var/www/app/index.php:123 in UserController->getProfile()
```

**Remediation**:
- Validate inputs client-side and server-side (JavaScript):
  ```html
  <form onsubmit="return validate()">
      <input type="number" name="id" required>
      <script>
          function validate() {
              const id = document.querySelector('[name="id"]').value;
              if (!/^\d+$/.test(id)) {
                  alert('Invalid ID');
                  return false;
              }
              return true;
          }
      </script>
  </form>
  ```

**Tip**: Save screenshots and network logs from Developer Tools. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Automate Stack Trace Detection with OWASP ZAP

**Objective**: Use automated scanning to identify stack traces in error responses.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `http://example.com`).
2. **Run Fuzzing Scan**:
   - Fuzz input parameters with invalid data (e.g., strings, special characters).
   - Scan for stack traces or debug output.
3. **Analyze Results**:
   - Check Alerts tab for information disclosure or stack trace issues.
   - Verify findings manually with Burp Suite.

**OWASP ZAP Commands**:
- **Command 1**: Fuzz a parameter for stack traces:
  ```
  Sites tab -> Right-click GET http://example.com/profile?id=1 -> Attack -> Fuzzer -> Add Payloads: Strings (e.g., abc, %27) -> Start Fuzzer -> Check Responses
  ```
- **Command 2**: Run active scan for debug errors:
  ```
  Sites tab -> Right-click http://example.com -> Attack -> Active Scan -> Enable Information Disclosure -> Start Scan -> Check Alerts
  ```

**Example Vulnerable Finding**:
- Alert: `Information Disclosure - Stack Trace` with details: `File "/app/user.py", line 45`.

**Remediation**:
- Disable debug mode (Python/Flask):
  ```python
  from flask import Flask
  app = Flask(__name__)
  app.config['DEBUG'] = False
  ```

**Tip**: Save ZAP scan reports as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., ZAP alerts).
