# Test Account Provisioning Process

## Overview

Testing the Account Provisioning Process (WSTG-IDNT-03) involves assessing a web application’s mechanisms for creating, modifying, suspending, and deleting user accounts to ensure they are secure, restricted to authorized roles, properly audited, and resilient to injection or token misuse. According to OWASP, weaknesses in account provisioning can allow attackers to create unauthorized accounts, escalate privileges, maintain access to deactivated accounts, or bypass security controls, compromising system security and integrity. This test focuses on validating access controls, input handling, role assignments, account deactivation, rate limiting, audit logging, and session token validation during the account lifecycle to identify vulnerabilities that could lead to unauthorized access or privilege escalation.

**Impact**: Weaknesses in the account provisioning process can lead to:
- Unauthorized account creation or modification with elevated privileges (e.g., admin access).
- Continued access by deactivated accounts due to incomplete suspension.
- Privilege escalation through parameter tampering, injection, or token misuse.
- Data integrity issues or regulatory non-compliance from unaudited or insecure provisioning actions.

This guide provides a practical, hands-on methodology for testing the account provisioning process, adhering to OWASP’s WSTG-IDNT-03, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as provisioning tests may create, modify, or delete accounts, potentially disrupting live systems or violating terms of service.

## Testing Tools

The following tools are recommended for testing the account provisioning process, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates provisioning requests to test access controls and audit logging.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints for provisioning vulnerabilities and token validation.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends crafted requests to verify provisioning restrictions and input validation.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side interfaces for provisioning controls or exposed parameters.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates tests for provisioning endpoints and rate limiting.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-IDNT-03, focusing on testing account creation, modification, deletion, input validation, access controls, rate limiting, audit logging, and session token validation in the provisioning process.

### 1. Test Unauthorized Account Creation with Burp Suite

**Objective**: Verify that only authorized roles can create accounts and that new accounts have appropriate privileges.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Creation Request**:
   - Log in as a low-privilege user or unauthenticated user.
   - Attempt to access `/admin/users/create`.
3. **Manipulate Parameters**:
   - Modify role parameters (e.g., `role=admin`).

**Burp Suite Commands**:
- **Command 1**: Test unauthorized creation:
  ```
  HTTP History -> Select POST /admin/users/create -> Send to Repeater -> Set Cookie: session=user_token -> Click Send
  ```
- **Command 2**: Manipulate role:
  ```
  HTTP History -> Select POST /admin/users/create -> Send to Repeater -> Change JSON: {"email": "test@example.com", "password": "Secure123"} to {"email": "test@example.com", "password": "Secure123", "role": "admin"} -> Click Send
  ```

**Example Vulnerable Response**:
```
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
- Restrict creation to admins (Node.js):
  ```javascript
  app.post('/admin/users/create', (req, res) => {
      if (req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Unauthorized' });
      }
      res.json({ status: 'success', role: 'user' });
  });
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Account Modification with Postman

**Objective**: Check if users can modify their own or others’ account attributes without authorization.

**Steps**:
1. **Identify Modification Endpoint**:
   - Use Burp Suite to find POST `/api/users/update`.
   - Import into Postman.
2. **Test Unauthorized Modifications**:
   - Authenticate as a low-privilege user and modify role or `user_id`.
3. **Analyze Responses**:
   - Check for HTTP 200 or successful modification.

**Postman Commands**:
- **Command 1**: Test role modification:
  ```
  New Request -> POST http://example.com/api/users/update -> Body -> JSON: {"user_id": 123, "role": "admin"} -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test another user’s account:
  ```
  New Request -> POST http://example.com/api/users/update -> Body -> JSON: {"user_id": 456, "email": "hacked@example.com"} -> Headers: Authorization: Bearer user_token -> Send
  ```

**Example Vulnerable Response**:
```
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
- Validate permissions (Python/Flask):
  ```python
  @app.post('/api/users/update')
  def update_user():
      user_id = request.json['user_id']
      if request.user.role != 'admin' or user_id != request.user.id:
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 3. Test Account Deletion with cURL

**Objective**: Verify that deleted or suspended accounts cannot access the system.

**Steps**:
1. **Identify Deletion Endpoint**:
   - Use Burp Suite to find POST `/api/users/delete`.
2. **Test Deletion**:
   - Attempt to delete own or another user’s account.
3. **Test Post-Deletion Access**:
   - Log in with deleted account credentials.

**cURL Commands**:
- **Command 1**: Test unauthorized deletion:
  ```bash
  curl -i -X POST -b "session=user_token" -d "user_id=456" http://example.com/api/users/delete
  ```
- **Command 2**: Test login post-deletion:
  ```bash
  curl -i -X POST -d "email=test@example.com&password=Secure123" http://example.com/login
  ```

**Example Vulnerable Response**:
```
[Deletion]
HTTP/1.1 200 OK
{"status": "Account deleted"}
[Post-deletion login]
HTTP/1.1 200 OK
{"status": "Logged in"}
```

**Remediation**:
- Invalidate sessions (Node.js):
  ```javascript
  app.post('/api/users/delete', (req, res) => {
      if (req.user.role !== 'admin') {
          return res.status(403).json({ error: 'Unauthorized' });
      }
      req.session.destroy();
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Inspect Provisioning Interface with Browser Developer Tools

**Objective**: Analyze client-side interfaces for exposed provisioning controls or parameters.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/admin/users` and press `F12` in Chrome.
2. **Inspect Forms**:
   - Check for hidden fields (e.g., `role=user`).
3. **Test Manipulation**:
   - Modify fields (e.g., `role=admin`) and submit.

**Browser Developer Tools Commands**:
- **Command 1**: Inspect hidden field:
  ```
  Elements tab -> Find <input type="hidden" name="role" value="user"> -> Edit as HTML -> Change value="admin" -> Submit form
  ```
- **Command 2**: Enable disabled button:
  ```
  Elements tab -> Find <button class="create-user" disabled> -> Edit as HTML -> Remove disabled -> Click button
  ```

**Example Vulnerable Form**:
```html
<form action="/admin/users/create">
    <input type="hidden" name="role" value="admin">
    <input type="email" name="email">
    <button type="submit">Create</button>
</form>
```

**Remediation**:
- Validate server-side (PHP):
  ```php
  if ($_POST['role'] && $_SESSION['user_role'] !== 'admin') {
      die(json_encode(['error' => 'Unauthorized']));
  }
  ```

**Tip**: Save screenshots and network logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., form submissions).

### 5. Test Rate Limiting with Python Requests

**Objective**: Attempt automated provisioning actions to verify rate limiting or anti-automation controls.

**Steps**:
1. **Write Python Script**:
   - Create a script for multiple account creation requests.
2. **Run Script**:
   - Analyze responses for HTTP 429.
3. **Verify Findings**:
   - Check if accounts are created without restrictions.

**Python Commands**:
- **Command 1**: Run provisioning test:
  ```bash
  python3 test_provisioning.py
  ```
  ```python
  # test_provisioning.py
  import requests
  import time
  url = 'http://example.com/api/users/create'
  headers = {'Authorization': 'Bearer user_token'}
  for i in range(5):
      data = {'email': f'test{i}@example.com', 'password': 'Secure123', 'role': 'user'}
      response = requests.post(url, json=data, headers=headers)
      print(f"Attempt {i+1}: Status={response.status_code}, Response={response.text[:100]}")
      if response.status_code == 429:
          print("Rate limiting detected")
          break
      time.sleep(1)
  ```
- **Command 2**: Test single creation:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/api/users/create', json={'email': 'test@example.com', 'password': 'Secure123'}, headers={'Authorization': 'Bearer user_token'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status=200, Response={"status": "success"}
Attempt 5: Status=200, Response={"status": "success"}
```

**Remediation**:
- Implement rate limiting (Python/Flask):
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.remote_addr)
  @app.route('/api/users/create', methods=['POST'])
  @limiter.limit('5 per hour')
  def create_user():
      return jsonify({'status': 'success'})
  ```

**Tip**: Save script output to a file (e.g., `python3 test_provisioning.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).

### 6. Test Audit Logging of Provisioning Actions

**Objective**: Test if account provisioning actions are logged for accountability.

**Steps**:
1. **Perform Provisioning Actions**:
   - Use Burp Suite to create, modify, or delete accounts.
2. **Check Logs**:
   - Look for log-related endpoints (e.g., `/api/logs`).
3. **Test Log Access**:
   - Attempt to access logs as a low-privilege user.

**Burp Suite Commands**:
- **Command 1**: Capture provisioning action:
  ```
  HTTP History -> Select POST /admin/users/create -> Send to Repeater -> Submit -> Check for log-related responses
  ```
- **Command 2**: Test log access:
  ```
  HTTP History -> Select GET /api/logs -> Send to Repeater -> Set Cookie: session=user_token -> Click Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"logs": [{"action": "user_created", "user_id": 123}]}
```

**Remediation**:
- Secure logging (Python/Flask):
  ```python
  @app.route('/admin/users/create', methods=['POST'])
  def create_user():
      if request.user.role != 'admin':
          return jsonify({'error': 'Unauthorized'}), 403
      email = request.form['email']
      log_action('user_created', request.user.id, email)
      return jsonify({'status': 'success'})
  @app.route('/api/logs')
  def get_logs():
      if request.user.role != 'admin':
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify(get_audit_logs())
  ```

**Tip**: Save Burp Suite requests as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., log access).

### 7. Test Session Token Validation During Provisioning

**Objective**: Test if session tokens are validated during provisioning actions.

**Steps**:
1. **Capture Token**:
   - Log in as a low-privilege user and capture the token in Postman.
2. **Test Provisioning**:
   - Send provisioning requests with the user’s token.
3. **Test Token Reuse**:
   - Reuse or modify the token and check server response.

**Postman Commands**:
- **Command 1**: Test provisioning with token:
  ```
  New Request -> POST http://example.com/api/users/create -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test modified token:
  ```
  New Request -> POST http://example.com/api/users/create -> Headers: Authorization: Bearer modified_jwt_token -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "success"}
```

**Remediation**:
- Validate tokens (Python/Flask):
  ```python
  @app.route('/api/users/create', methods=['POST'])
  def create_user():
      token = request.headers.get('Authorization').split()[1]
      decoded = decode_jwt(token)  # Custom JWT decode
      if decoded['role'] != 'admin' or not is_valid_token(token):
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 8. Test Input Validation for Provisioning Requests

**Objective**: Test for injection vulnerabilities in provisioning inputs.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find `/api/users/create`.
2. **Send Malicious Inputs**:
   - Test SQL or XSS injections.
3. **Analyze Responses**:
   - Check for errors or successful injection.

**cURL Commands**:
- **Command 1**: Test SQL injection:
  ```bash
  curl -i -X POST -d "email=' OR '1'='1&password=Secure123" http://example.com/api/users/create
  ```
- **Command 2**: Test XSS injection:
  ```bash
  curl -i -X POST -d "username=<script>alert(1)</script>&password=Secure123" http://example.com/api/users/create
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
SQL Error: You have an error in your SQL syntax...
```

**Remediation**:
- Sanitize inputs (Python/Flask):
  ```python
  @app.route('/api/users/create', methods=['POST'])
  def create_user():
      email = request.form['email']
      if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
          return jsonify({'error': 'Invalid email'}), 400
      conn = sqlite3.connect('users.db')
      conn.execute('INSERT INTO users (email) VALUES (?)', (email,))
      conn.commit()
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).
