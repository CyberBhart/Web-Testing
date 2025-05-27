# Testing for Bypassing Authentication Schema

## Overview

Testing for Bypassing Authentication Schema (WSTG-AUTH-05) involves identifying vulnerabilities that allow attackers to bypass authentication mechanisms, gaining unauthorized access to protected resources or functionalities. According to OWASP, weak authentication controls—such as unprotected endpoints, manipulable parameters, predictable session tokens, or flawed workflows—can enable attackers to access sensitive data, escalate privileges, or impersonate users. This test focuses on verifying authentication enforcement across web pages, APIs, and workflows, including direct access, parameter manipulation, session tampering, multi-step authentication, and resource-level access controls.

**Impact**: Authentication bypass vulnerabilities can lead to:
- Unauthorized access to user accounts or admin functionalities.
- Exposure of sensitive data or system resources.
- Privilege escalation or session hijacking.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide provides a practical, hands-on methodology for testing authentication bypass, adhering to OWASP’s WSTG-AUTH-05, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as sending unauthorized requests or manipulating sessions may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing authentication bypass, with setup and configuration instructions:

- **cURL**: Sends requests to test direct access or API authentication.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test parameter or session tampering.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **OWASP ZAP**: Tests workflow bypassing and multi-step authentication vulnerabilities.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Install and configure browser proxy: 127.0.0.1:8080.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-05, focusing on testing direct access, parameter manipulation, session tampering, workflow bypassing, API authentication, and resource-level access controls.

### 1. Test Direct Page Access with cURL

**Objective**: Verify that protected pages require authentication and cannot be accessed directly.

**Steps**:
1. Identify protected pages (e.g., `/dashboard`, `/admin`) using Burp Suite or OWASP ZAP.
2. Attempt to access a protected page without authentication:
   ```bash
   curl -i https://example.com/dashboard
   ```
3. Repeat for admin pages:
   ```bash
   curl -i https://example.com/admin
   ```
4. Analyze responses; expected secure response is a redirect to the login page or access denial.

**Example Secure Response**:
```
HTTP/1.1 302 Found
Location: https://example.com/login
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<html>Dashboard content</html>
```

**Remediation**:
- Enforce authentication (Node.js):
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.session.user) {
          return res.redirect('/login');
      }
      res.send('Dashboard content');
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Parameter Manipulation with Burp Suite

**Objective**: Ensure authentication parameters cannot be manipulated to bypass access controls.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Log in as a low-privilege user and capture a request to a protected endpoint (e.g., `GET /profile?role=user`):
   ```
   HTTP History -> Select GET /profile?role=user -> Send to Repeater
   ```
3. Modify the `role` parameter to `admin` and resend:
   ```
   Repeater -> Change role=user to role=admin -> Click Send -> Check response
   ```
4. Analyze responses; expected secure response is access denial or unchanged privileges.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Unauthorized role"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"role": "admin", "data": "Admin panel"}
```

**Remediation**:
- Validate parameters (Python/Flask):
  ```python
  @app.get('/profile')
  def profile():
      role = request.args.get('role')
      if role != session.get('role'):
          return jsonify({'error': 'Unauthorized role'}), 403
      return jsonify({'role': role, 'data': 'Profile data'})
  ```

**Tip**: Save Burp Suite requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Session Token Tampering with Burp Suite

**Objective**: Verify that session tokens cannot be tampered with to bypass authentication.

**Steps**:
1. Log in to the application and capture a request with a session token (e.g., `Cookie: session=xyz123`) in Burp Suite:
   ```
   HTTP History -> Select GET /dashboard -> Verify Cookie header contains session token
   ```
2. Modify the session token to another value (e.g., `session=abc456`) and resend:
   ```
   Repeater -> Change Cookie: session=xyz123 to Cookie: session=abc456 -> Click Send -> Check response
   ```
3. Analyze responses; expected secure response is session invalidation or access denial.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid session token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<html>Dashboard content</html>
```

**Remediation**:
- Validate session tokens (Node.js):
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.cookies.session || !validateToken(req.cookies.session)) {
          return res.status(401).json({ error: 'Invalid session token' });
      }
      res.send('Dashboard content');
  });
  ```

**Tip**: Save Burp Suite requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Authentication Workflow Bypassing with OWASP ZAP

**Objective**: Ensure multi-step authentication workflows (e.g., MFA, CAPTCHA) cannot be bypassed.

**Steps**:
1. Configure OWASP ZAP by setting up the browser proxy (127.0.0.1:8080).
2. Identify a multi-step authentication workflow (e.g., login followed by MFA) and capture the final step (e.g., `POST /mfa/verify`):
   ```
   History tab -> Select POST /mfa/verify -> Verify request requires MFA token
   ```
3. Attempt to skip the MFA step by directly accessing the protected resource:
   ```
   Manual Request Editor -> Send GET /dashboard without MFA token -> Check response
   ```
4. Analyze responses; expected secure response is a redirect to the authentication step or access denial.

**Example Secure Response**:
```
HTTP/1.1 302 Found
Location: https://example.com/mfa/verify
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<html>Dashboard content</html>
```

**Remediation**:
- Enforce workflow steps (Python/Flask):
  ```python
  @app.get('/dashboard')
  def dashboard():
      if not session.get('mfa_verified'):
          return redirect('/mfa/verify')
      return 'Dashboard content'
  ```

**Tip**: Save OWASP ZAP requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test API Authentication Bypass with cURL

**Objective**: Ensure API endpoints require valid authentication and prevent bypass.

**Steps**:
1. Use Burp Suite to identify API endpoints (e.g., `GET /api/user/profile`).
2. Attempt to access the endpoint without authentication headers:
   ```bash
   curl -i https://example.com/api/user/profile
   ```
3. Test with an invalid or manipulated token:
   ```bash
   curl -i -H "Authorization: Bearer invalid" https://example.com/api/user/profile
   ```
4. Analyze responses; expected secure response is authentication required or access denial.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Authentication required"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"user": "admin", "role": "administrator"}
```

**Remediation**:
- Enforce API authentication (Node.js):
  ```javascript
  app.get('/api/user/profile', (req, res) => {
      if (!req.headers.authorization || req.headers.authorization === 'Bearer invalid') {
          return res.status(401).json({ error: 'Authentication required' });
      }
      res.json({ user: 'admin' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Insecure Direct Object References (IDOR) in Authentication with Burp Suite

**Objective**: Ensure authenticated users cannot access unauthorized resources by manipulating identifiers.

**Steps**:
1. Log in as a low-privilege user and capture a request to a resource (e.g., `GET /profile?user_id=123`) in Burp Suite:
   ```
   HTTP History -> Select GET /profile?user_id=123 -> Send to Repeater
   ```
2. Modify the `user_id` to another user’s ID (e.g., `user_id=124`) and resend:
   ```
   Repeater -> Change user_id=123 to user_id=124 -> Click Send -> Check response
   ```
3. Analyze responses; expected secure response is access denial.

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
{"user_id": 124, "data": "Sensitive data"}
```

**Remediation**:
- Prevent IDOR (Python/Flask):
  ```python
  @app.get('/profile')
  def profile():
      user_id = request.args.get('user_id')
      if user_id != session.get('user_id'):
          return jsonify({'error': 'Access denied'}), 403
      return jsonify({'user_id': user_id, 'data': 'Profile data'})
  ```

**Tip**: Save Burp Suite requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).