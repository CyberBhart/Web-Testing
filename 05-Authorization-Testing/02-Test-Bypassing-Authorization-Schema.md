# Testing for Bypassing Authorization Schema

## Overview

Testing for Bypassing Authorization Schema (WSTG-AUTHZ-02) involves verifying that the application enforces proper authorization controls to prevent users from accessing resources or performing actions beyond their assigned privileges. According to OWASP, vulnerabilities such as missing server-side checks, reliance on client-side controls, or misconfigured roles can allow horizontal access (e.g., accessing another user’s data) or vertical access (e.g., accessing admin functions). This test focuses on evaluating horizontal and vertical access controls, role configurations, direct resource access, header manipulation, parameter tampering, and endpoint protection to ensure robust authorization.

**Impact**: Bypassing authorization can lead to:
- Unauthorized access to sensitive user data or admin functions.
- Privilege escalation, enabling malicious actions (e.g., deleting resources).
- Data breaches or non-compliance with standards (e.g., GDPR, PCI DSS).

This guide provides a practical, hands-on methodology for testing authorization bypass vulnerabilities, adhering to OWASP’s WSTG-AUTHZ-02, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as manipulating sessions or accessing restricted endpoints may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing authorization bypass vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test horizontal/vertical access and parameter tampering.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test direct resource access, header manipulation, and forced browsing.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTHZ-02, focusing on testing horizontal and vertical access controls, role misconfigurations, direct resource access, header manipulation, parameter tampering, and forced browsing.

### 1. Test Horizontal Access Control: Same Role, Different User with Burp Suite

**Objective**: Ensure users cannot access another user’s data within the same role.

**Steps**:
1. Create two users (e.g., UserA, UserB) and log in with both in separate browser sessions.
2. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
3. Intercept UserA’s request to view settings:
   ```bash
   HTTP History -> Select POST /account/viewSettings -> Send to Repeater
   ```
4. Modify the request to target UserB’s data:
   ```bash
   Repeater -> Change username=UserA to username=UserB -> Click Send -> Check Response
   ```
5. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied: Unauthorized resource"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"username": "UserB", "settings": {...}}
```

**Remediation**:
- Enforce ownership (Node.js):
  ```javascript
  app.post('/account/viewSettings', (req, res) => {
      const { username } = req.body;
      if (username !== req.session.user.username) {
          return res.status(403).json({ error: 'Access denied' });
      }
      res.json({ settings: getUserSettings(username) });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Vertical Access Control: Lower Role Accessing Higher Privileges with cURL

**Objective**: Ensure low-privilege users cannot perform admin-only actions.

**Steps**:
1. Log in as a customer and obtain a session cookie.
2. Test access to an admin-only endpoint:
   ```bash
   curl -i -X POST -H "Cookie: SessionID=Customer_Session" -d "EventID=1000002" http://example.com/account/deleteEvent
   ```
3. Test another admin action:
   ```bash
   curl -i -X POST -H "Cookie: SessionID=Customer_Session" -d "EventID=1000003" http://example.com/account/deleteEvent
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Insufficient privileges"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Event deleted"}
```

**Remediation**:
- Implement RBAC (Python/Flask):
  ```python
  from functools import wraps
  def require_role(role):
      def decorator(f):
          @wraps(f)
          def decorated_function(*args, **kwargs):
              if session.get('role') != role:
                  return jsonify({'error': 'Insufficient privileges'}), 403
              return f(*args, **kwargs)
          return decorated_function
      return decorator
  @app.post('/account/deleteEvent')
  @require_role('admin')
  def delete_event():
      return jsonify({'status': 'Event deleted'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Access to Admin Functions from Non-Admin Roles with cURL

**Objective**: Ensure non-admin users cannot access administrative routes.

**Steps**:
1. Log in as a non-admin (e.g., staff) and obtain a session cookie.
2. Test access to an admin route:
   ```bash
   curl -i -X POST -H "Cookie: SessionID=Staff_Session" -d "userID=fakeuser&role=3&group=grp001" http://example.com/admin/addUser
   ```
3. Test another admin route:
   ```bash
   curl -i -X POST -H "Cookie: SessionID=Staff_Session" -d "userID=testuser&role=1" http://example.com/admin/updateUser
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
Content-Type: application/json
{"status": "User added"}
```

**Remediation**:
- Restrict admin routes (Node.js):
  ```javascript
  app.post('/admin/addUser', (req, res) => {
      if (req.session.role !== 'admin') {
          return res.status(403).json({ error: 'Access denied' });
      }
      res.json({ status: 'User added' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Role Misconfigurations with Session Swapping with Burp Suite

**Objective**: Ensure sensitive actions cannot be performed with lower-privilege sessions.

**Steps**:
1. Log in as an admin and a low-privilege user in separate sessions.
2. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
3. Intercept an admin request (e.g., role assignment):
   ```bash
   HTTP History -> Select POST /admin/assignRole -> Send to Repeater
   ```
4. Replay with the low-privilege session:
   ```bash
   Repeater -> Change Cookie: SessionID=Admin_Session to SessionID=User_Session -> Click Send -> Check Response
   ```
5. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Insufficient privileges"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Role assigned"}
```

**Remediation**:
- Validate roles (Python/Flask):
  ```python
  @app.post('/admin/assignRole')
  @require_role('admin')
  def assign_role():
      return jsonify({'status': 'Role assigned'})
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Resource Access via Direct File URLs with cURL

**Objective**: Ensure private resources require proper authorization.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test access to another user’s private file:
   ```bash
   curl -i -H "Cookie: SessionID=AnotherUser_Session" "https://example.com/uploads/cv/johnsmith_resume.pdf"
   ```
3. Test another private resource:
   ```bash
   curl -i -H "Cookie: SessionID=AnotherUser_Session" "https://example.com/uploads/cv/janedoe_resume.pdf"
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
Content-Type: application/pdf
[Binary PDF content]
```

**Remediation**:
- Use signed URLs (Node.js):
  ```javascript
  const crypto = require('crypto');
  app.get('/uploads/cv/:filename', (req, res) => {
      const { filename } = req.params;
      const { token } = req.query;
      const expectedToken = crypto.createHmac('sha256', 'secret').update(filename + req.session.user.id).digest('hex');
      if (token !== expectedToken) {
          return res.status(403).json({ error: 'Access denied' });
      }
      res.sendFile(path.join(__dirname, 'Uploads', filename));
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Bypassing with X-Original-URL or X-Rewrite-URL Headers with Burp Suite

**Objective**: Ensure spoofed headers cannot bypass authorization.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Test baseline access to a restricted endpoint:
   ```bash
   HTTP History -> Select GET /admin -> Send to Repeater
   ```
3. Add a spoofed header to bypass restrictions:
   ```bash
   Repeater -> Add Header: X-Original-URL: /admin -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response ignores the header.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin_data": {...}}
```

**Remediation**:
- Strip spoofed headers (Python/Flask):
  ```python
  @app.before_request
  def block_spoofed_headers():
      if 'X-Original-URL' in request.headers or 'X-Rewrite-URL' in request.headers:
          return jsonify({'error': 'Invalid headers'}), 403
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Internal IP Spoofing via Forwarding Headers with cURL

**Objective**: Ensure IP-based authorization cannot be bypassed via spoofed headers.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test access with a spoofed internal IP:
   ```bash
   curl -i -H "Cookie: SessionID=User_Session" -H "X-Forwarded-For: 127.0.0.1" http://example.com/admin
   ```
3. Test with another internal IP:
   ```bash
   curl -i -H "Cookie: SessionID=User_Session" -H "X-Forwarded-For: 10.0.0.1" http://example.com/admin
   ```
4. Analyze responses; expected secure response validates the request origin.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin_data": {...}}
```

**Remediation**:
- Validate IP headers (Node.js):
  ```javascript
  app.get('/admin', (req, res) => {
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      const trustedIps = ['127.0.0.1', '10.0.0.1'];
      if (!trustedIps.includes(ip) || req.session.role !== 'admin') {
          return res.status(403).json({ error: 'Access denied' });
      }
      res.json({ admin_data: getAdminData() });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Parameter Tampering for ID Manipulation with Burp Suite

**Objective**: Ensure resource IDs cannot be manipulated to access unauthorized data.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a request accessing a resource:
   ```bash
   HTTP History -> Select POST /account/viewOrder -> Send to Repeater
   ```
3. Modify the resource ID to another user’s ID:
   ```bash
   Repeater -> Change orderID=0001 to orderID=0002 -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied: Unauthorized resource"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"orderID": "0002", "details": {...}}
```

**Remediation**:
- Validate ownership (Python/Flask):
  ```python
  @app.post('/account/viewOrder')
  def view_order():
      order_id = request.form.get('orderID')
      if not is_order_owner(order_id, session.get('user_id')):
          return jsonify({'error': 'Access denied'}), 403
      return jsonify({'order': get_order(order_id)})
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 9. Test Forced Browsing with cURL

**Objective**: Ensure hidden or sensitive endpoints are protected by authorization checks.

**Steps**:
1. Log in as a low-privilege user and obtain a session cookie.
2. Attempt access to a sensitive endpoint:
   ```bash
   curl -i -H "Cookie: SessionID=Customer_Session" http://example.com/admin
   ```
3. Test another potential endpoint:
   ```bash
   curl -i -H "Cookie: SessionID=Customer_Session" http://example.com/api/private
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Insufficient privileges"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"private_data": {...}}
```

**Remediation**:
- Secure endpoints (Node.js):
  ```javascript
  app.get('/api/private', (req, res) => {
      if (req.session.role !== 'admin') {
          return res.status(403).json({ error: 'Insufficient privileges' });
      }
      res.json({ private_data: getPrivateData() });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).