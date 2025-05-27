# Testing for Logout Functionality

## Overview

Testing for Logout Functionality (WSTG-SESS-06) involves assessing a web application’s logout mechanism to ensure that user sessions are securely terminated, session identifiers are invalidated, and no residual session data remains exploitable. According to OWASP, weak logout functionality can allow attackers to reuse old session IDs, leading to unauthorized access. This test focuses on verifying server-side session invalidation, client-side cookie clearing, and the effectiveness of the logout process to mitigate session reuse risks.

**Impact**: Weak logout functionality can lead to:
- Unauthorized access if old session IDs remain valid post-logout.
- Session hijacking by reusing intercepted session cookies.
- Data exposure from persistent session data in client-side storage.
- Account compromise on shared or public devices due to incomplete session termination.

This guide provides a practical, hands-on methodology for testing logout functionality, adhering to OWASP’s WSTG-SESS-06, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing logout functionality, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts requests to test session invalidation and cookie clearing.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests logout endpoints and session behavior in APIs.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests to verify session ID reuse post-logout.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects cookies, local storage, and logout functionality.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates testing for session invalidation and client-side cleanup.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-06, focusing on testing session invalidation, cookie clearing, access after logout, multiple sessions, and client-side cleanup.

### 1. Test Session Invalidation with Burp Suite

**Objective**: Verify that the server invalidates the session ID upon logout.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Log In and Capture Session**:
   - Log in to the application and note the session cookie (e.g., `session=abc123`) in “HTTP History”.
3. **Log Out**:
   - Click the logout button/link and capture the `POST /logout` or `GET /logout` request/response.
   - Check for `Set-Cookie: session=; Max-Age=0` or similar.
   - Command:
     ```
     HTTP History -> Select POST /logout -> Response tab -> Check for Set-Cookie: session=; Max-Age=0
     ```
4. **Test Old Session ID**:
   - Replay a request to a protected resource (e.g., `GET /dashboard`) using the old session ID.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Click Send -> Check response
     ```
5. **Analyze Findings**:
   - Vulnerable: Old session ID grants access.
   - Expected secure response: HTTP 401, 403, or redirect to login.

**Remediation**:
- Invalidate sessions on logout:
  ```javascript
  app.post('/logout', (req, res) => {
      req.session.destroy((err) => {
          if (err) return res.status(500).json({ error: 'Logout failed' });
          res.clearCookie('session');
          res.json({ status: 'success' });
      });
  });
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Cookie Clearing with Browser Developer Tools

**Objective**: Ensure session cookies are cleared or expired after logout.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Log In and Inspect Cookies**:
   - Go to “Application” tab (Chrome) or “Storage” tab (Firefox) -> Cookies -> Note `session=abc123`.
   - Command:
     ```
     Application tab -> Cookies -> https://example.com -> Verify session=abc123
     ```
3. **Log Out**:
   - Click logout and refresh the Cookies section.
   - Check if the `session` cookie is removed or set to expire.
   - Command:
     ```
     Application tab -> Cookies -> https://example.com -> Log out -> Refresh -> Verify session cookie absent
     ```
4. **Analyze Findings**:
   - Vulnerable: Cookie persists or has a future expiration.
   - Expected secure response: Cookie absent or expired.

**Remediation**:
- Clear cookies on logout:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.post('/logout')
  def logout():
      response = make_response({'status': 'success'})
      response.set_cookie('session', '', expires=0, httponly=True, secure=True)
      return response
  ```

**Tip**: Save screenshots of the Cookies section before and after logout. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., cookie screenshots).

### 3. Test Access After Logout with cURL

**Objective**: Confirm that protected resources are inaccessible using old session IDs post-logout.

**Steps**:
1. **Log In and Capture Session**:
   - Log in and note the session ID (e.g., `session=abc123`) using Burp Suite or cURL.
2. **Log Out**:
   - Send a logout request.
   - Command:
     ```bash
     curl -i -X POST -b "session=abc123" http://example.com/logout
     ```
3. **Test Old Session ID**:
   - Send a request to a protected resource with the old session ID.
   - Command:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
4. **Analyze Findings**:
   - Vulnerable: HTTP 200 with dashboard content.
   - Expected secure response: HTTP 401, 403, or redirect to login.

**Remediation**:
- Reject invalid sessions:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.session.user) {
          return res.status(401).json({ error: 'Unauthorized' });
      }
      res.send('Dashboard');
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Multiple Sessions with Postman

**Objective**: Verify that logout terminates all user sessions across devices or browsers.

**Steps**:
1. **Identify Logout Endpoint**:
   - Use Burp Suite to find `POST /logout`.
   - Import into Postman.
2. **Log In Multiple Sessions**:
   - Log in from two browsers or devices, capturing session cookies (e.g., `session=abc123`, `session=xyz789`).
3. **Log Out from One Session**:
   - Send a logout request from one session.
   - Command:
     ```
     New Request -> POST http://example.com/logout -> Headers: Cookie: session=abc123 -> Send
     ```
4. **Test Other Session**:
   - Use the second session’s cookie to access a protected resource.
   - Command:
     ```
     New Request -> GET http://example.com/dashboard -> Headers: Cookie: session=xyz789 -> Send
     ```
5. **Analyze Findings**:
   - Vulnerable: Second session remains active.
   - Expected secure response: All sessions terminated; HTTP 401 or 403.

**Remediation**:
- Terminate all sessions:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/logout')
  def logout():
      user_id = session.get('user_id')
      invalidate_all_sessions(user_id)  # Custom function to clear all user sessions
      session.clear()
      response = make_response({'status': 'success'})
      response.set_cookie('session', '', expires=0)
      return response
  ```

**Tip**: Capture requests and responses as JSON or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Automate Logout Testing with Python Requests

**Objective**: Automate testing to verify session invalidation and client-side cleanup.

**Steps**:
1. **Write Python Script**:
   - Create a script to test logout functionality:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     logout_url = f'{base_url}/logout'
     dashboard_url = f'{base_url}/dashboard'

     # Log in
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     session.post(login_url, data=login_data)
     session_cookie = session.cookies.get('session')
     print(f"Session cookie: {session_cookie}")

     # Log out
     response = session.post(logout_url)
     logout_cookie = response.headers.get('Set-Cookie', '')
     print(f"Logout Set-Cookie: {logout_cookie}")
     if 'session=; Max-Age=0' in logout_cookie or 'expires=Thu, 01 Jan 1970' in logout_cookie:
         print("Secure: Cookie cleared")
     else:
         print("Vulnerable: Cookie not cleared")

     # Test old session ID
     old_session = requests.Session()
     old_session.cookies.set('session', session_cookie)
     response = old_session.get(dashboard_url)
     print(f"Old session access: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Old session ID accepted")
     else:
         print("Secure: Old session ID rejected")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_logout.py
     ```
3. **Test Single Logout**:
   - Command:
     ```bash
     python3 -c "import requests; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); c=s.cookies.get('session'); r=s.post('http://example.com/logout'); print(r.headers.get('Set-Cookie')); s.cookies.set('session', c); r=s.get('http://example.com/dashboard'); print(r.status_code)"
     ```
4. **Verify Findings**:
   - Vulnerable: Cookie persists or old session ID grants access.
   - Expected secure response: Cookie cleared; old ID rejected.

**Remediation**:
- Secure logout handling:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/logout')
  def logout():
      session.clear()
      response = make_response({'status': 'success'})
      response.set_cookie('session', '', expires=0, httponly=True, secure=True, samesite='Strict')
      return response
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_logout.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).