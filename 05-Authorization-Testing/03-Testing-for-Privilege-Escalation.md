# Testing for Privilege Escalation

## Overview

Testing for Privilege Escalation (WSTG-AUTHZ-03) involves verifying that the application prevents users from escalating their privileges to access unauthorized resources or perform restricted actions. According to OWASP, vulnerabilities such as role manipulation, profile tampering, condition tampering, IP spoofing, path traversal, or weak session management can allow attackers to gain higher privileges (e.g., admin access). This test focuses on evaluating role validation, session integrity, input sanitization, and access controls to ensure robust privilege enforcement.

**Impact**: Privilege escalation can lead to:
- Unauthorized access to sensitive functions or data.
- Execution of malicious actions (e.g., user management, data deletion).
- Data breaches or non-compliance with standards (e.g., GDPR, PCI DSS).

This guide provides a practical, hands-on methodology for testing privilege escalation vulnerabilities, adhering to OWASP’s WSTG-AUTHZ-03, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as manipulating roles, sessions, or IPs may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing privilege escalation vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and fuzzes requests to test role manipulation and session tampering.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test IP spoofing, path traversal, and session replay.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTHZ-03, focusing on testing role manipulation, profile tampering, condition tampering, IP spoofing, path traversal, weak session IDs, role fuzzing, and session replay.

### 1. Test Role/Privilege Manipulation with Burp Suite

**Objective**: Ensure role or privilege parameters cannot be manipulated to escalate privileges.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a request with role parameters:
   ```bash
   HTTP History -> Select POST /user/viewOrder.jsp -> Send to Repeater
   ```
3. Modify the role parameter to escalate privileges:
   ```bash
   Repeater -> Change groupID=grp001 to groupID=grp002 -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Unauthorized access"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"orderID": "0001", "details": {...}}
```

**Remediation**:
- Validate roles server-side (Node.js):
  ```javascript
  app.post('/user/viewOrder', (req, res) => {
      const { groupID } = req.body;
      if (groupID !== req.session.groupID) {
          return res.status(403).json({ error: 'Unauthorized access' });
      }
      res.json({ order: getOrder(req.body.orderID) });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Manipulating User Profile for Escalation with Burp Suite

**Objective**: Ensure hidden profile fields cannot be modified to escalate privileges.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a form submission with profile fields:
   ```bash
   HTTP History -> Select POST /visual.jsp -> Send to Repeater
   ```
3. Modify the profile field to a higher privilege:
   ```bash
   Repeater -> Change profile=user to profile=SysAdmin -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Permission denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Profile updated", "role": "SysAdmin"}
```

**Remediation**:
- Validate profile server-side (Python/Flask):
  ```python
  @app.post('/visual')
  def update_profile():
      profile = request.form.get('profile')
      if profile != session.get('profile') and session.get('role') != 'admin':
          return jsonify({'error': 'Permission denied'}), 403
      return jsonify({'status': 'Profile updated'})
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Manipulation of Condition Values with cURL

**Objective**: Ensure condition values cannot be manipulated to escalate privileges.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test a request with a condition value:
   ```bash
   curl -i -X POST -H "Cookie: SESSION=User_Session" -d "PVValid=-1" http://example.com/authenticate
   ```
3. Modify the condition to bypass restrictions:
   ```bash
   curl -i -X POST -H "Cookie: SESSION=User_Session" -d "PVValid=0" http://example.com/authenticate
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Authentication failure"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Authenticated", "role": "admin"}
```

**Remediation**:
- Validate conditions (Node.js):
  ```javascript
  app.post('/authenticate', (req, res) => {
      const { PVValid } = req.body;
      if (PVValid !== getExpectedCondition(req.session.user)) {
          return res.status(403).json({ error: 'Authentication failure' });
      }
      res.json({ status: 'Authenticated' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Manipulation of IP Address with cURL

**Objective**: Ensure IP-based restrictions cannot be bypassed via spoofed headers.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test access with a spoofed IP:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" -H "X-Forwarded-For: 127.0.0.1" http://example.com/admin/login
   ```
3. Test with another spoofed IP:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" -H "X-Forwarded-For: 10.0.0.1" http://example.com/admin/login
   ```
4. Analyze responses; expected secure response validates the request origin.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Unauthorized access"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin_data": {...}}
```

**Remediation**:
- Validate IP headers (Python/Flask):
  ```python
  @app.get('/admin/login')
  def admin_login():
      ip = request.headers.get('X-Forwarded-For', request.remote_addr)
      trusted_ips = ['127.0.0.1', '10.0.0.1']
      if ip not in trusted_ips or session.get('role') != 'admin':
          return jsonify({'error': 'Unauthorized access'}), 403
      return jsonify({'admin_data': get_admin_data()})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test URL Traversal (Path Traversal) with cURL

**Objective**: Ensure path traversal cannot access unauthorized resources.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test a valid resource request:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/account/viewProfile
   ```
3. Test path traversal to access restricted resources:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/../../userInfo.html
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
[Content of userInfo.html]
```

**Remediation**:
- Sanitize URLs (Node.js):
  ```javascript
  const path = require('path');
  app.get('/account/*', (req, res) => {
      const requestedPath = path.normalize(req.path).replace(/^(\.\.[\/\\])+/, '');
      if (requestedPath.includes('..') || !isAuthorizedPath(requestedPath, req.session.user)) {
          return res.status(403).json({ error: 'Access denied' });
      }
      res.sendFile(path.join(__dirname, requestedPath));
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Weak Session IDs with Burp Suite Intruder

**Objective**: Ensure session IDs are strong and cannot be guessed to escalate privileges.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Capture a session ID and send a request to Intruder:
   ```bash
   HTTP History -> Select GET /admin -> Send to Intruder
   ```
3. Brute-force session IDs:
   ```bash
   Intruder -> Payloads -> Add sequential IDs (e.g., MD5_1, MD5_2) -> Start Attack -> Check Response
   ```
4. Analyze responses; expected secure response rejects invalid IDs.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Session expired"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin_data": {...}}
```

**Remediation**:
- Use strong session IDs (Python/Flask):
  ```python
  import secrets
  @app.route('/login', methods=['POST'])
  def login():
      session['token'] = secrets.token_hex(32)
      return jsonify({'status': 'Logged in'})
  ```

**Tip**: Save Burp Suite Intruder responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Role Escalation via API Parameters with Burp Suite Intruder

**Objective**: Ensure API parameters cannot be manipulated to escalate privileges.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept an API request with role parameters:
   ```bash
   HTTP History -> Select POST /user/updateProfile -> Send to Intruder
   ```
3. Fuzz role-related parameters:
   ```bash
   Intruder -> Payloads -> Add payloads (e.g., admin, 1, true) -> Start Attack -> Check Response
   ```
4. Analyze responses; expected secure response denies unauthorized role changes.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Unauthorized role modification"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Profile updated", "role": "admin"}
```

**Remediation**:
- Restrict role changes (Node.js):
  ```javascript
  app.post('/user/updateProfile', (req, res) => {
      const { role } = req.body;
      if (role && req.session.role !== 'admin') {
          return res.status(403).json({ error: 'Unauthorized role modification' });
      }
      res.json({ status: 'Profile updated' });
  });
  ```

**Tip**: Save Burp Suite Intruder responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Session Token Replay with cURL

**Objective**: Ensure session tokens are bound to specific contexts and cannot be replayed.

**Steps**:
1. Log in as an admin and capture a session token.
2. Test the token in the original context:
   ```bash
   curl -i -H "Cookie: SESSION=Admin_Session" -H "User-Agent: Mozilla/5.0" http://example.com/admin
   ```
3. Replay the token in a different context:
   ```bash
   curl -i -H "Cookie: SESSION=Admin_Session" -H "User-Agent: CustomAgent" http://example.com/admin
   ```
4. Analyze responses; expected secure response rejects replayed tokens.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Invalid session context"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin_data": {...}}
```

**Remediation**:
- Bind sessions to context (Python/Flask):
  ```python
  from hashlib import sha256
  def generate_session_token(user_id, user_agent, ip):
      return sha256(f"{user_id}:{user_agent}:{ip}".encode()).hexdigest()
  @app.get('/admin')
  def admin_panel():
      expected_token = generate_session_token(session['user_id'], request.headers.get('User-Agent'), request.remote_addr)
      if session.get('token') != expected_token:
          return jsonify({'error': 'Invalid session context'}), 403
      return jsonify({'admin_data': get_admin_data()})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).