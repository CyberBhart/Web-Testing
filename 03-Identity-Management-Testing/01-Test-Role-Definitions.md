# Test Role Definitions

## Overview

Testing for Role Definitions (WSTG-IDNT-01) involves assessing a web application’s role-based access control (RBAC) system to ensure that user roles are clearly defined, appropriately assigned, and strictly enforced to prevent unauthorized access or actions. According to OWASP, poorly defined or misconfigured roles can allow users to access sensitive data or functionalities beyond their privileges, violating the principle of least privilege and segregation of duties. This test focuses on identifying all roles, mapping their permissions, verifying access controls, testing role assignments, validating session tokens, and checking database query restrictions to detect misconfigurations or vulnerabilities that could lead to privilege escalation or unauthorized access.

**Impact**: Weak role definitions can lead to:
- Unauthorized access to sensitive data or administrative functions (e.g., a User accessing Admin features).
- Privilege escalation by exploiting overlapping or excessive permissions.
- Non-compliance with regulatory standards (e.g., GDPR, HIPAA) due to inadequate access controls.
- Operational risks from lack of segregation of duties (e.g., a user approving their own actions).

This guide provides a practical, hands-on methodology for testing role definitions, adhering to OWASP’s WSTG-IDNT-01, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as accessing restricted endpoints or manipulating roles may disrupt live systems or violate policies.

## Testing Tools

The following tools are recommended for testing role definitions, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test role-based access controls.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints for role enforcement and permission leaks.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests with modified role parameters to test access controls.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side interfaces for role information or permission indicators.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **OWASP ZAP**: Automates detection of access control issues through scanning and fuzzing.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Run: `zap.sh` (Linux) or `zap.bat` (Windows).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-IDNT-01, focusing on identifying roles, mapping permissions, testing access controls, role assignments, session tokens, and database queries to detect misconfigurations or vulnerabilities.

### 1. Identify Roles with Burp Suite

**Objective**: Enumerate all roles in the application by analyzing user interfaces, API responses, and traffic.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Traffic**:
   - Browse the application as different users (e.g., Admin, User) or create test accounts.
   - Check “HTTP History” for role indicators (e.g., `role=user`, `role_id=1`).
3. **Analyze Responses**:
   - Identify role names or IDs in cookies, parameters, or API responses (e.g., `{"role": "admin"}`).

**Burp Suite Commands**:
- **Command 1**: Capture role in API response:
  ```
  HTTP History -> Select GET /api/user/profile -> Check response for {"role": "user"} -> Save to Logger
  ```
- **Command 2**: Test role parameter:
  ```
  HTTP History -> Select GET /dashboard?role_id=1 -> Send to Repeater -> Change role_id=2 -> Click Send
  ```

**Example Vulnerable Response**:
```
{
  "user_id": 123,
  "role": "admin"
}
```

**Remediation**:
- Avoid exposing role details (Node.js):
  ```javascript
  app.get('/api/user/profile', (req, res) => {
      res.json({ user_id: req.user.id }); // Exclude role
  });
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Role Permissions with Postman

**Objective**: Map and test permissions assigned to each role by accessing restricted endpoints.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find endpoints (e.g., `/admin`, `/api/users`).
   - Import into Postman.
2. **Test Access**:
   - Authenticate as a low-privilege user and access high-privilege endpoints.
3. **Analyze Responses**:
   - Check for HTTP 200 instead of 403 or 401.

**Postman Commands**:
- **Command 1**: Test admin endpoint:
  ```
  New Request -> GET http://example.com/admin -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test role manipulation:
  ```
  New Request -> POST http://example.com/api/user -> Body -> JSON: {"role": "admin"} -> Headers: Authorization: Bearer user_token -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"users": [{"id": 1, "name": "Admin"}]}
```

**Remediation**:
- Enforce role checks (Python/Flask):
  ```python
  from flask import Flask, request
  app = Flask(__name__)
  @app.route('/admin')
  def admin():
      if request.user.role != 'admin':
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'data': 'Admin content'})
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 3. Test Role Manipulation with cURL

**Objective**: Attempt to manipulate role parameters to bypass access controls.

**Steps**:
1. **Identify Role Parameters**:
   - Use Burp Suite to find parameters (e.g., `role_id=1`).
2. **Send Modified Requests**:
   - Use cURL to alter role parameters (e.g., `role=user` to `role=admin`).
3. **Analyze Responses**:
   - Check for HTTP 200 or sensitive data exposure.

**cURL Commands**:
- **Command 1**: Test role parameter:
  ```bash
  curl -i -b "session=abc123; role=user" http://example.com/admin
  ```
- **Command 2**: Modify role in POST:
  ```bash
  curl -i -X POST -d "role=admin" http://example.com/api/user
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Admin Dashboard
```

**Remediation**:
- Validate roles server-side (Node.js):
  ```javascript
  app.post('/api/user', (req, res) => {
      if (req.body.role && req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Cannot modify role' });
      }
      // Process request
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Inspect Role Indicators with Browser Developer Tools

**Objective**: Analyze client-side interfaces for role information or permission leaks.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome.
2. **Inspect Elements**:
   - Check DOM for role indicators (e.g., `<div class="admin-panel">`).
3. **Test Manipulation**:
   - Modify DOM to enable hidden features and verify access.

**Browser Developer Tools Commands**:
- **Command 1**: Search for role indicators:
  ```
  Elements tab -> Ctrl+F -> Search "role" or "admin" -> Inspect classes
  ```
- **Command 2**: Modify DOM:
  ```
  Elements tab -> Find <button class="admin-only" disabled> -> Edit as HTML -> Remove disabled -> Click button
  ```

**Example Vulnerable Script**:
```javascript
if (document.cookie.includes('role=user')) {
    document.getElementById('adminPanel').style.display = 'none';
}
```

**Remediation**:
- Enforce server-side controls (HTML/JavaScript):
  ```html
  <button class="admin-only" onclick="checkAccess()">Admin Action</button>
  <script>
      async function checkAccess() {
          const res = await fetch('/api/check-access');
          if (res.status !== 200) alert('Unauthorized');
      }
  </script>
  ```

**Tip**: Save screenshots and script excerpts. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., DOM changes).

### 5. Test Segregation of Duties with OWASP ZAP

**Objective**: Automate testing for segregation of duties and access control issues.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `https://example.com`).
2. **Run Active Scan**:
   - Fuzz role parameters or test endpoints with user credentials.
3. **Analyze Results**:
   - Check Alerts for unauthorized access or escalation.

**OWASP ZAP Commands**:
- **Command 1**: Fuzz role parameter:
  ```
  Sites tab -> Right-click GET http://example.com/dashboard?role_id=1 -> Attack -> Fuzzer -> Add Payloads: admin, 2 -> Start Fuzzer
  ```
- **Command 2**: Run access control scan:
  ```
  Sites tab -> Right-click https://example.com -> Attack -> Active Scan -> Enable Access Control Testing -> Start Scan
  ```

**Example Vulnerable Finding**:
- Alert: `Access Control - Unauthorized Access to /admin`.

**Remediation**:
- Implement segregation of duties (Python/Flask):
  ```python
  @app.route('/approve')
  def approve():
      if request.user.role == 'submitter':
          return jsonify({'error': 'Cannot approve own submission'}), 403
      return jsonify({'status': 'Approved'})
  ```

**Tip**: Save ZAP scan reports as HTML or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., ZAP alerts).

### 6. Test Role Assignment During Account Creation

**Objective**: Test if users can manipulate role assignments during registration.

**Steps**:
1. **Capture Registration**:
   - Configure Burp Suite to intercept POST requests to `/register`.
2. **Modify Role**:
   - Alter role parameters (e.g., `role=user` to `role=admin`).
3. **Analyze Response**:
   - Check if the account is assigned the modified role.

**Burp Suite Commands**:
- **Command 1**: Capture registration:
  ```
  HTTP History -> Filter -> Show only: Method=POST, URL contains "register" -> Check for role parameters
  ```
- **Command 2**: Modify role:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Change role=user to role=admin -> Click Send
  ```

**Example Vulnerable Request**:
```
POST http://example.com/register HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
username=test&password=secret123&role=admin
```

**Remediation**:
- Assign roles server-side (Python/Flask):
  ```python
  @app.route('/register', methods=['POST'])
  def register():
      username = request.form['username']
      password = request.form['password']
      role = 'user'  # Hardcode default role
      return jsonify({'status': 'Registered'})
  ```

**Tip**: Save Burp Suite requests as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 7. Test Role-Based Session Token Validation

**Objective**: Test if session tokens are validated against server-side roles.

**Steps**:
1. **Capture Token**:
   - Log in as a low-privilege user and capture the token in Postman.
2. **Test Restricted Endpoint**:
   - Use the token to access high-privilege endpoints.
3. **Analyze Response**:
   - Check for unauthorized access (HTTP 200 vs. 403).

**Postman Commands**:
- **Command 1**: Test admin endpoint:
  ```
  New Request -> GET http://example.com/admin -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test modified token:
  ```
  New Request -> GET http://example.com/admin -> Headers: Authorization: Bearer modified_jwt_token -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"data": "Admin content"}
```

**Remediation**:
- Validate token role (Python/Flask):
  ```python
  @app.route('/admin')
  def admin():
      token = request.headers.get('Authorization').split()[1]
      decoded = decode_jwt(token)  # Custom JWT decode
      if decoded['role'] != 'admin':
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'data': 'Admin content'})
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 8. Test Role-Based Access to Database Queries

**Objective**: Test if role-based controls prevent unauthorized database access.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find database-querying endpoints (e.g., `/api/users`).
2. **Send Requests**:
   - Use cURL as a low-privilege user to query the endpoint.
3. **Analyze Response**:
   - Check for restricted data exposure.

**cURL Commands**:
- **Command 1**: Test API with cookies:
  ```bash
  curl -i -b "session=abc123; role=user" http://example.com/api/users
  ```
- **Command 2**: Test with token:
  ```bash
  curl -i -X GET -H "Authorization: Bearer user_token" http://example.com/api/users
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
[{"id": 1, "name": "Admin"}, {"id": 2, "name": "User"}]
```

**Remediation**:
- Restrict queries by role (Python/Flask):
  ```python
  @app.route('/api/users')
  def get_users():
      if request.user.role != 'admin':
          return jsonify({'error': 'Unauthorized'}), 403
      users = db.query('SELECT * FROM users WHERE role != "admin"')
      return jsonify(users)
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).
