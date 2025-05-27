# Testing for Session Puzzling

## Overview

Testing for Session Puzzling (WSTG-SESS-08), also known as session variable overloading, involves assessing a web application to ensure that session variables are securely managed and cannot be manipulated to bypass authentication or authorization controls. According to OWASP, session puzzling vulnerabilities allow attackers to confuse the application’s session management logic, potentially escalating privileges or accessing unauthorized resources. This test focuses on verifying proper session variable handling, input validation, and access control to mitigate session manipulation risks.

**Impact**: Session puzzling vulnerabilities can lead to:
- Unauthorized access by impersonating other users or roles (e.g., escalating to admin).
- Authentication or authorization bypass through manipulated session variables.
- Application logic errors causing privilege escalation or data exposure.
- Compromise of sensitive functionality controlled by session variables.

This guide provides a practical, hands-on methodology for testing session puzzling, adhering to OWASP’s WSTG-SESS-08, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing session puzzling, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates session variables in requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests API endpoints for session variable tampering.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends crafted requests to test session variable behavior.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side session variables in cookies, forms, or JavaScript.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates session variable manipulation and testing.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-08, focusing on identifying session variables, testing variable overloading, authentication/authorization bypass, variable scope, and input validation.

### 1. Identify and Manipulate Session Variables with Burp Suite

**Objective**: Map session variables and test for manipulation to alter user roles or states.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Identify Session Variables**:
   - Navigate the application (e.g., login, dashboard) and check “HTTP History” for session variables in cookies (e.g., `role=guest`), headers, or parameters.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Request tab -> Look for Cookie: role=guest or user_id=123
     ```
3. **Manipulate Variables**:
   - Intercept a request to a protected resource (e.g., `GET /admin`) and modify session variables (e.g., change `role=guest` to `role=admin`).
   - Command:
     ```
     HTTP History -> Select GET /admin -> Send to Repeater -> Change Cookie: role=guest to role=admin -> Click Send -> Check response
     ```
4. **Analyze Findings**:
   - Vulnerable: Modified variable grants unauthorized access.
   - Expected secure response: HTTP 403 or redirect to login.

**Remediation**:
- Validate session variables server-side:
  ```javascript
  app.get('/admin', (req, res) => {
      if (req.session.role !== 'admin') {
          return res.status(403).json({ error: 'Unauthorized' });
      }
      res.send('Admin Dashboard');
  });
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Authentication Bypass with Postman

**Objective**: Check if session variables can bypass authentication workflows.

**Steps**:
1. **Identify Authentication Endpoint**:
   - Use Burp Suite to find `POST /login` and import into Postman.
2. **Manipulate Session Variables**:
   - Send a request to a protected resource (e.g., `/dashboard`) with a forged session variable (e.g., `isAuthenticated=true`).
   - Command:
     ```
     New Request -> GET http://example.com/dashboard -> Headers: Cookie: isAuthenticated=true -> Send
     ```
3. **Test Login Response**:
   - Send a legitimate login request and check for session variables.
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send -> Check Set-Cookie
     ```
4. **Analyze Findings**:
   - Vulnerable: Access granted with forged variable.
   - Expected secure response: HTTP 401 or 403.

**Remediation**:
- Avoid client-controlled authentication states:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.get('/dashboard')
  def dashboard():
      if not session.get('user_id'):
          return jsonify({'error': 'Unauthorized'}), 401
      return jsonify({'data': 'Dashboard'})
  ```

**Tip**: Capture requests and responses as JSON or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Authorization Bypass with cURL

**Objective**: Verify if session variables can grant access to restricted resources.

**Steps**:
1. **Identify Restricted Endpoint**:
   - Use Burp Suite to find endpoints like `/admin-panel`.
2. **Manipulate Session Variables**:
   - Send a request with a modified session variable (e.g., `user_role=admin`) to the restricted endpoint.
   - Command:
     ```bash
     curl -i -b "user_role=admin" http://example.com/admin-panel
     ```
3. **Test Default Role**:
   - Send the same request with the original role (e.g., `user_role=guest`).
   - Command:
     ```bash
     curl -i -b "user_role=guest" http://example.com/admin-panel
     ```
4. **Analyze Findings**:
   - Vulnerable: HTTP 200 with restricted content.
   - Expected secure response: HTTP 403 or redirect.

**Remediation**:
- Enforce server-side authorization:
  ```javascript
  app.get('/admin-panel', (req, res) => {
      if (!req.session.user || req.session.user.role !== 'admin') {
          return res.status(403).json({ error: 'Forbidden' });
      }
      res.send('Admin Panel');
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Inspect Client-Side Session Variables with Browser Developer Tools

**Objective**: Analyze client-side code for exposed session variables that can be manipulated.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Forms and JavaScript**:
   - Go to “Elements” tab and search for hidden fields (e.g., `<input name="user_id" value="123">`).
   - Command:
     ```
     Elements tab -> Ctrl+F -> Search for "user_id" or "role" -> Check hidden fields
     ```
3. **Manipulate Variables**:
   - Edit hidden fields (e.g., change `user_id=123` to `user_id=456`) and submit a request.
   - Command:
     ```
     Elements tab -> Edit <input name="user_id" value="123"> to value="456" -> Submit form -> Check Network tab response
     ```
4. **Analyze Findings**:
   - Vulnerable: Manipulated variable grants unauthorized access.
   - Expected secure response: Server rejects tampered values.

**Remediation**:
- Avoid client-side session variables:
  ```python
  @app.post('/update-profile')
  def update_profile():
      user_id = session.get('user_id')
      if not user_id or user_id != request.form.get('user_id'):
          return jsonify({'error': 'Invalid user'}), 403
      return jsonify({'status': 'success'})
  ```

**Tip**: Save screenshots of the Elements tab and Network tab responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., screenshots).

### 5. Automate Session Puzzling Testing with Python Requests

**Objective**: Automate testing to detect session variable manipulation vulnerabilities.

**Steps**:
1. **Write Python Script**:
   - Create a script to manipulate session variables:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     admin_url = f'{base_url}/admin-panel'

     # Log in as regular user
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     session_cookie = session.cookies.get_dict()
     print(f"Session cookies: {session_cookie}")

     # Test role manipulation
     manipulated_cookies = session_cookie.copy()
     manipulated_cookies['role'] = 'admin'
     response = session.get(admin_url, cookies=manipulated_cookies)
     print(f"Role manipulation: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'admin' in response.text.lower():
         print("Vulnerable: Role manipulation granted admin access")

     # Test authentication bypass
     bypass_cookies = session_cookie.copy()
     bypass_cookies['isAuthenticated'] = 'true'
     response = session.get(admin_url, cookies=bypass_cookies)
     print(f"Auth bypass: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'admin' in response.text.lower():
         print("Vulnerable: Authentication bypass succeeded")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_session_puzzling.py
     ```
3. **Test Single Manipulation**:
   - Command:
     ```bash
     python3 -c "import requests; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); r=s.get('http://example.com/admin-panel', cookies={'role': 'admin'}); print(r.status_code, r.text[:100])"
     ```
4. **Verify Findings**:
   - Vulnerable: Manipulated variables grant access.
   - Expected secure response: HTTP 403 or 401 for invalid variables.

**Remediation**:
- Secure session management:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.get('/admin-panel')
  def admin_panel():
      if session.get('role') != 'admin' or not validate_session(session):
          return jsonify({'error': 'Unauthorized'}), 403
      return jsonify({'data': 'Admin Panel'})
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_session_puzzling.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).