# Test Ability to Forge Requests

## Overview

Testing the ability to forge requests (WSTG-BUSL-02) involves assessing whether a web application allows attackers to craft or manipulate HTTP requests to bypass business logic or access unauthorized functionality. Forged requests exploit weak validation or improper session management, enabling actions like accessing another user’s data, performing privileged operations, or skipping workflow steps. According to OWASP, these vulnerabilities are context-specific and often require manual testing, as automated tools may miss subtle logic flaws.

**Impact**: The ability to forge requests can lead to:
- Unauthorized access to restricted resources (e.g., admin panels, user accounts).
- Bypassing critical business logic (e.g., skipping payment verification).
- Data integrity violations (e.g., modifying another user’s profile).
- Financial or operational damage due to unauthorized actions.

This guide provides a step-by-step methodology for testing the ability to forge requests, adhering to OWASP’s WSTG-BUSL-02, with practical tools, specific commands, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing the ability to forge requests, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints with crafted requests.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends custom HTTP requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects and modifies requests in Chrome/Firefox.
  - Access by pressing `F12` or right-clicking and selecting “Inspect”.
  - No setup required.

- **Python Requests Library**: Scripts automated HTTP tests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-02, focusing on crafting forged requests to bypass business logic, manipulate sessions, or abuse HTTP methods.

### 1. Capture and Analyze Requests with Burp Suite

**Objective**: Identify requests controlling business logic or sensitive functionality.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in “Target” tab.
2. **Capture Requests**:
   - Perform actions (e.g., login, access profiles, submit forms).
   - Review “HTTP History” for sensitive requests (e.g., `POST /profile/update`).
3. **Analyze Requests**:
   - Note parameters, cookies, headers, or tokens (e.g., `session_id`, `user_id`).

**Burp Suite Commands**:
- **Command 1**: Capture request:
  ```
  HTTP History -> Select GET /profile?user_id=123 -> Check Headers: Cookie: session_id=abc123 -> Send to Repeater
  ```
- **Command 2**: Export requests:
  ```
  Target -> Site Map -> Right-click example.com -> Copy URLs in Scope -> Paste to file
  ```

**Example Request**:
```
GET /profile?user_id=123 HTTP/1.1
Host: example.com
Cookie: session_id=abc123
```

**Remediation**:
- Validate session ownership (PHP):
  ```php
  if ($_GET['user_id'] != $_SESSION['user_id']) {
      http_response_code(403);
      exit('Unauthorized');
  }
  ```

**Tip**: Save “HTTP History” requests to Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., request details).

### 2. Forge Requests with Burp Suite Repeater

**Objective**: Craft modified requests to test unauthorized access or logic bypass.

**Steps**:
1. **Send to Repeater**:
   - Right-click a request in “HTTP History” and select “Send to Repeater”.
   - Modify parameters (e.g., `user_id=123` to `user_id=456`).
2. **Test Scenarios**:
   - Change user IDs (e.g., `user_id=admin`).
   - Alter roles (e.g., `role=user` to `role=admin`).
   - Replay requests out of sequence (e.g., skip authentication).
3. **Analyze Response**:
   - Check if the forged request is processed (e.g., returns another user’s data).

**Burp Suite Commands**:
- **Command 1**: Forge user ID:
  ```
  Repeater -> GET /profile?user_id=123 -> Change user_id=456 -> Send -> Check Response
  ```
- **Command 2**: Forge role:
  ```
  Repeater -> GET /dashboard?role=user -> Change role=admin -> Send -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
User Profile: admin@example.com
```

**Remediation**:
- Implement authorization checks (Express):
  ```javascript
  if (!req.session.isAdmin && req.query.role === 'admin') {
      res.status(403).send('Access denied');
  }
  ```

**Tip**: Save Repeater requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Forge API Requests with Postman

**Objective**: Test API endpoints for forged request vulnerabilities.

**Steps**:
1. **Import Endpoints**:
   - Identify APIs from Burp Suite (e.g., `/api/v1/users`).
   - Add to Postman.
2. **Craft Forged Requests**:
   - Send modified parameters (e.g., `GET /api/v1/users/456`).
   - Test unauthorized methods (e.g., `DELETE /api/v1/users/456`).
3. **Analyze Response**:
   - Check for unauthorized data or actions.

**Postman Commands**:
- **Command 1**: Forge user ID:
  ```
  New Request -> GET http://example.com/api/v1/users/456 -> Headers: Authorization: Bearer abc123 -> Send
  ```
- **Command 2**: Test DELETE:
  ```
  New Request -> DELETE http://example.com/api/v1/users/456 -> Headers: Authorization: Bearer abc123 -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "user_id": 456,
  "email": "otheruser@example.com"
}
```

**Remediation**:
- Enforce API authentication (Flask):
  ```python
  from flask import jsonify
  if not verify_token(request.headers.get('Authorization')):
      return jsonify({'error': 'Unauthorized'}), 403
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Modify Client-Side Requests with Browser Developer Tools

**Objective**: Test client-side request modifications to bypass server-side logic.

**Steps**:
1. **Access Network Tab**:
   - Open `http://example.com/profile`, press `F12`, and go to “Network” tab.
   - Perform an action (e.g., submit a form) and capture the request.
2. **Modify Request**:
   - Copy request as cURL, modify parameters (e.g., `user_id=456`), and resend using cURL or Postman.
3. **Analyze Response**:
   - Check if the server processes the forged request.

**Browser Developer Tools Commands**:
- **Command 1**: Copy request:
  ```
  Network -> Select POST /profile/update -> Right-click -> Copy as cURL
  ```
- **Command 2**: Modify and resend:
  ```
  curl -X POST http://example.com/profile/update -d "user_id=456" -H "Cookie: session_id=abc123"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Profile updated for otheruser@example.com
```

**Remediation**:
- Use session data (PHP):
  ```php
  $user_id = $_SESSION['user_id']; // Ignore client-side user_id
  ```

**Tip**: Save screenshots of modified requests and responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Automate Forged Requests with Python Requests

**Objective**: Automate testing of forged request variations.

**Steps**:
1. **Write Script**:
   - Create a script to test multiple user IDs.
2. **Run Script**:
   - Execute and analyze responses.
3. **Verify Findings**:
   - Cross-check with Burp Suite.

**Python Script**:
```python
import requests
import sys

url = 'http://example.com/profile'
cookies = {'session_id': 'abc123'}
user_ids = [123, 456, 'admin', 999999]

try:
    for user_id in user_ids:
        response = requests.get(url, cookies=cookies, params={'user_id': user_id}, timeout=5)
        print(f"User ID: {user_id}")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:100]}\n")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run script:
  ```bash
  python3 test_forge.py
  ```
- **Command 2**: Test single user ID:
  ```bash
  python3 -c "import requests; url='http://example.com/profile'; cookies={'session_id': 'abc123'}; params={'user_id': 456}; r=requests.get(url, cookies=cookies, params=params, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
User ID: 456
Status: 200
Response: User Profile: otheruser@example.com
```

**Remediation**:
- Validate permissions (Express):
  ```javascript
  if (req.query.user_id !== req.session.user_id) {
      res.status(403).send('Unauthorized');
  }
  ```

**Tip**: Save script output to a file (e.g., `python3 test_forge.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test CSRF Token Bypasses with Burp Suite

**Objective**: Verify if forged requests bypass CSRF protections.

**Steps**:
1. **Capture Form Submission**:
   - Use Burp Suite to capture a request with a CSRF token (e.g., `POST /profile/update`).
2. **Modify Token**:
   - Remove or reuse the token in a forged request.
3. **Analyze Response**:
   - Check if the request is processed without a valid token.

**Burp Suite Commands**:
- **Command 1**: Remove token:
  ```
  Repeater -> POST /profile/update -> Params -> Remove csrf_token -> Send -> Check Response
  ```
- **Command 2**: Reuse token:
  ```
  Repeater -> POST /profile/update -> Params -> Use previous csrf_token -> Send -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
- Validate CSRF token (PHP):
  ```php
  if (!validate_csrf_token($_POST['csrf_token'])) {
      http_response_code(403);
      exit('Invalid CSRF token');
  }
  ```

**Tip**: Save Repeater requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Session Token Manipulation with Postman

**Objective**: Check if forged session tokens allow unauthorized access.

**Steps**:
1. **Capture Request**:
   - Identify a request with a session token (e.g., `Authorization: Bearer abc123`).
2. **Forge Token**:
   - Modify the token (e.g., use another user’s token or alter JWT payload).
3. **Analyze Response**:
   - Check for access to restricted resources.

**Postman Commands**:
- **Command 1**: Forge token:
  ```
  New Request -> GET http://example.com/api/v1/profile -> Headers: Authorization: Bearer xyz456 -> Send
  ```
- **Command 2**: Verify access:
  ```
  New Request -> GET http://example.com/api/v1/profile -> Headers: Authorization: Bearer xyz456 -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"user_id": 456, "email": "otheruser@example.com"}
```

**Remediation**:
- Verify tokens (Express):
  ```javascript
  const jwt = require('jsonwebtoken');
  if (!jwt.verify(token, 'secret')) {
      res.status(403).send('Invalid token');
  }
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 8. Test HTTP Method Override Forgery with cURL

**Objective**: Verify if method override headers allow unauthorized actions.

**Steps**:
1. **Identify Endpoint**:
   - Find an endpoint (e.g., `POST /api/v1/users`).
2. **Send Override Request**:
   - Add `X-HTTP-Method-Override: DELETE` to a `POST` request.
3. **Analyze Response**:
   - Check if the server processes the overridden method.

**cURL Commands**:
- **Command 1**: Test override:
  ```
  curl -X POST -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer abc123" http://example.com/api/v1/users/123
  ```
- **Command 2**: Verify without override:
  ```
  curl -X POST -H "Authorization: Bearer abc123" http://example.com/api/v1/users/123
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "User deleted"}
```

**Remediation**:
- Block overrides (Flask):
  ```python
  from flask import jsonify
  if 'X-HTTP-Method-Override' in request.headers:
      return jsonify({'error': 'Method override not allowed'}), 403
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).