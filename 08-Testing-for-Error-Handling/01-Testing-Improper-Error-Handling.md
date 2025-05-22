# Testing for Improper Error Handling

## Overview

Testing for improper error handling (WSTG-ERRH-01) involves assessing how a web application or server responds to errors triggered by invalid inputs, malformed requests, or unexpected conditions. According to OWASP, improper error handling can expose sensitive information, such as stack traces, database queries, file paths, or software versions, which attackers can use for reconnaissance or to chain attacks. This test focuses on provoking errors through various inputs (e.g., forms, APIs, URLs) and analyzing responses to identify leakage of sensitive data or insecure error handling practices.

**Impact**: Improper error handling can lead to:
- Exposure of system details (e.g., framework versions, database types).
- Facilitation of attack chaining (e.g., SQL injection from exposed queries).
- User confusion or application instability due to unhandled exceptions.
- Increased attack surface by revealing internal logic or misconfigurations.

This guide provides a practical, hands-on methodology for testing improper error handling, adhering to OWASP’s WSTG-ERRH-01, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing improper error handling, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to trigger errors.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends malformed or invalid requests to provoke server/application errors.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tests API endpoints with invalid inputs to elicit error responses.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Browser Developer Tools**: Inspects and modifies requests to analyze error handling.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **OWASP ZAP**: Automates error detection through fuzzing and scanning.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Run:
    ```bash
    zap.sh
    ```
    (Linux) or `zap.bat` (Windows).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-ERRH-01, focusing on triggering errors through invalid inputs, malformed requests, and unauthorized actions, then analyzing responses for sensitive information.

### 1. Trigger Application Errors with Burp Suite

**Objective**: Provoke errors by sending invalid inputs to application input points (e.g., forms, query parameters).

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Input Points**:
   - Browse the application to identify forms, search fields, or API endpoints.
   - Capture requests in Burp Suite’s “HTTP History” (e.g., `POST /search`, `GET /profile?id=1`).
3. **Manipulate Inputs**:
   - Use Burp Repeater to modify parameters (e.g., send a string to an integer field).
   - Test for errors like stack traces or database errors.
4. **Analyze Response**:
   - Check for HTTP 500, verbose error messages, or sensitive data (e.g., SQL queries, file paths).
   - Note if errors appear in HTTP 200 responses or redirects.

**Burp Suite Commands**:
- **Command 1**: Send invalid input to a search parameter:
  ```
  HTTP History -> Select GET /search?q=test -> Send to Repeater -> Modify q to q=abc' OR 1=1 -- -> Click Send -> Check Response for errors
  ```
- **Command 2**: Test integer parameter with a string:
  ```
  HTTP History -> Select GET /profile?id=1 -> Send to Repeater -> Change id to id=abc -> Click Send -> Inspect Response for stack traces
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
Error: Invalid integer value 'abc' in query: SELECT * FROM users WHERE id = abc
```

**Remediation**:
- Implement generic error handling (PHP):
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

**Objective**: Send malformed HTTP requests to provoke server-level errors.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find URLs (e.g., `/index.php`, `/api/v1/users`).
   - Test nonexistent paths (e.g., `/nonexistent`).
2. **Send Malformed Requests**:
   - Use cURL to send invalid HTTP methods, headers, or oversized URLs.
   - Test for HTTP 404, 403, or 500 errors.
3. **Analyze Response**:
   - Check for verbose error pages, server banners (e.g., Apache 2.4.41), or stack traces.
   - Verify if errors expose system details.

**cURL Commands**:
- **Command 1**: Request a nonexistent resource:
  ```bash
  curl -i http://example.com/nonexistent
  ```
- **Command 2**: Send an invalid HTTP method:
  ```bash
  curl -i -X INVALID http://example.com/index.php -H "Cookie: session=abc123"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 404 Not Found
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
Error: File /var/www/html/nonexistent not found
```

**Remediation**:
- Configure custom error pages (Apache):
  ```apache
  ErrorDocument 404 /error.html
  ErrorDocument 500 /error.html
  ServerTokens Prod
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Error Handling with Postman

**Objective**: Provoke errors in API endpoints by sending invalid or malicious inputs.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/users`).
   - Import into Postman.
2. **Send Invalid Requests**:
   - Send malformed JSON, invalid parameters, or oversized data.
   - Test with and without authentication.
3. **Analyze Response**:
   - Check for HTTP 400/500, stack traces, or database errors.
   - Verify if errors expose internal logic.

**Postman Commands**:
- **Command 1**: Send malformed JSON to an API:
  ```
  New Request -> POST http://example.com/api/v1/users -> Body -> raw -> JSON: {"name": "test", "age": "abc -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Test invalid parameter type:
  ```
  New Request -> GET http://example.com/api/v1/profile?id=abc -> Headers: Authorization: Bearer abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "error": "TypeError: Cannot cast 'abc' to Integer in /app/models/user.js:45"
}
```

**Remediation**:
- Sanitize API inputs (Node.js):
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

**Objective**: Modify form submissions or requests to trigger errors.

**Steps**:
1. **Inspect Input Points**:
   - Open Developer Tools (`F12`) on a form page (e.g., `http://example.com/search`).
   - Identify input fields and their expected types.
2. **Manipulate Inputs**:
   - Edit form data (e.g., change a number to a string) before submission.
   - Modify query parameters in URLs.
3. **Analyze Response**:
   - Check for verbose errors, HTTP 500, or redirects with error details.
   - Verify if errors appear in the DOM or network responses.

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
Error: Invalid input at /var/www/app/index.php:123
```

**Remediation**:
- Validate form inputs (JavaScript):
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

### 5. Automate Error Detection with OWASP ZAP

**Objective**: Use automated scanning to identify improper error handling.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `http://example.com`).
2. **Run Fuzzing Scan**:
   - Fuzz input parameters with invalid data (e.g., strings, special characters).
   - Scan for verbose errors or stack traces.
3. **Analyze Results**:
   - Check Alerts tab for information disclosure or error-related issues.
   - Verify findings manually with Burp Suite.

**OWASP ZAP Commands**:
- **Command 1**: Fuzz a search parameter:
  ```
  Sites tab -> Right-click GET http://example.com/search?q=test -> Attack -> Fuzzer -> Add Payloads: Strings (e.g., abc, ' OR 1=1 --) -> Start Fuzzer -> Check Responses
  ```
- **Command 2**: Run active scan for error handling:
  ```
  Sites tab -> Right-click http://example.com -> Attack -> Active Scan -> Enable Information Disclosure -> Start Scan -> Check Alerts
  ```

**Example Vulnerable Finding**:
- Alert: `Information Disclosure - Debug Error Message` with stack trace.

**Remediation**:
- Disable debug output (Python/Flask):
  ```python
  from flask import Flask
  app = Flask(__name__)
  app.config['DEBUG'] = False
  ```

**Tip**: Save ZAP scan reports as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., ZAP alerts).
