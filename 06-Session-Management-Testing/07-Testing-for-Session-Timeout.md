# Testing Session Timeout

## Overview

Testing Session Timeout (WSTG-SESS-07) involves assessing a web application’s session timeout mechanisms to ensure that inactive sessions are terminated after an appropriate period, preventing unauthorized access. According to OWASP, inadequate session timeouts can allow attackers to reuse stolen session IDs, especially on shared or public devices. This test focuses on verifying server-side session invalidation, client-side cookie expiration, and effective timeout implementation to mitigate session reuse risks.

**Impact**: Inadequate session timeout mechanisms can lead to:
- Unauthorized access from persistent sessions on shared devices.
- Session hijacking by reusing stolen session IDs from prolonged sessions.
- Data exposure in environments with physical or network access risks.
- Increased attack surface for sensitive sessions (e.g., admin) with extended validity.

This guide provides a practical, hands-on methodology for testing session timeout, adhering to OWASP’s WSTG-SESS-07, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing session timeout, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts requests to test session validity after timeout.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests API endpoints for session timeout behavior.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests to verify session ID reuse post-timeout.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects cookies and client-side timeout behavior.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates testing for session invalidation and timeout.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-07, focusing on testing idle timeout, server-side invalidation, client-side cookie expiration, session reuse, and absolute timeout.

### 1. Test Idle Timeout with Burp Suite

**Objective**: Verify that sessions expire after a period of inactivity.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Log In and Capture Session**:
   - Log in and note the session cookie (e.g., `session=abc123`) in “HTTP History”.
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Note Set-Cookie: session=abc123
     ```
3. **Wait for Timeout**:
   - Leave the session idle for a period exceeding the expected timeout (e.g., 30 minutes). Refer to application documentation or estimate 15–30 minutes if unknown.
4. **Test Session Validity**:
   - Send a request to a protected resource (e.g., `GET /dashboard`) using the session ID.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Wait 30 minutes -> Click Send -> Check response
     ```
5. **Analyze Findings**:
   - Vulnerable: Session remains valid after extended inactivity.
   - Expected secure response: HTTP 401, 403, or redirect to login.

**Remediation**:
- Implement idle timeout:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: { maxAge: 1800000 }, // 30 minutes
      store: new MemoryStore({ checkPeriod: 1800000 }) // Expire sessions server-side
  }));
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Client-Side Cookie Expiration with Browser Developer Tools

**Objective**: Ensure session cookies expire client-side after timeout.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Log In and Inspect Cookies**:
   - Go to “Application” tab (Chrome) or “Storage” tab (Firefox) -> Cookies -> Check `session` cookie for `Max-Age` or `Expires`.
   - Command:
     ```
     Application tab -> Cookies -> https://example.com -> Select session cookie -> Verify Max-Age or Expires
     ```
3. **Wait for Timeout**:
   - Leave the session idle for the timeout period (e.g., 30 minutes).
   - Refresh the Cookies section to verify if the cookie is removed or expired.
   - Command:
     ```
     Application tab -> Cookies -> Wait 30 minutes -> Refresh -> Check if session cookie is absent
     ```
4. **Analyze Findings**:
   - Vulnerable: Cookie persists or lacks `Max-Age`/`Expires`.
   - Expected secure response: Cookie absent or expired (e.g., `Expires=Thu, 01 Jan 1970`).

**Remediation**:
- Set cookie expiration:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.post('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', max_age=1800, httponly=True, secure=True) # 30 minutes
      return response
  ```

**Tip**: Save screenshots of the Cookies section before and after timeout. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., cookie screenshots).

### 3. Test Session Reuse Post-Timeout with cURL

**Objective**: Confirm that expired session IDs cannot access protected resources.

**Steps**:
1. **Log In and Capture Session**:
   - Log in and note the session ID (e.g., `session=abc123`).
   - Command:
     ```bash
     curl -i -X POST -d "username=test&password=Secure123" http://example.com/login | grep Set-Cookie
     ```
2. **Wait for Timeout**:
   - Leave the session idle for the timeout period (e.g., 30 minutes).
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
- Validate session expiration:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.session.user || req.session.expires < Date.now()) {
          return res.status(401).json({ error: 'Session expired' });
      }
      res.send('Dashboard');
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Absolute Timeout with Postman

**Objective**: Verify that sessions have a maximum lifetime, regardless of activity.

**Steps**:
1. **Identify Protected Endpoint**:
   - Use Burp Suite to find `GET /dashboard`.
   - Import into Postman.
2. **Log In and Maintain Activity**:
   - Log in and periodically send requests (e.g., every 5 minutes) to keep the session active for an extended period (e.g., 24 hours).
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send -> Note Cookie: session=abc123
     ```
3. **Test Session Validity**:
   - After the absolute timeout period (e.g., 8 hours), send a request to `/dashboard`.
   - Command:
     ```
     New Request -> GET http://example.com/dashboard -> Headers: Cookie: session=abc123 -> Send
     ```
4. **Analyze Findings**:
   - Vulnerable: Session remains valid after 24 hours.
   - Expected secure response: HTTP 401 or redirect to login after 8 hours.

**Remediation**:
- Implement absolute timeout:
  ```python
  from flask import Flask, session
  import time
  app = Flask(__name__)
  @app.before_request
  def check_absolute_timeout():
      if session.get('created_at') and session['created_at'] + 28800 < time.time(): # 8 hours
          session.clear()
          return jsonify({'error': 'Session expired'}), 401
  ```

**Tip**: Capture requests and responses as JSON or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Automate Timeout Testing with Python Requests

**Objective**: Automate testing to verify idle and absolute timeout behavior.

**Steps**:
1. **Write Python Script**:
   - Create a script to test session timeout:
     ```python
     import requests
     import time

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     dashboard_url = f'{base_url}/dashboard'

     # Log in
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     session_cookie = session.cookies.get('session')
     print(f"Session cookie: {session_cookie}")

     # Test idle timeout
     print("Waiting 30 minutes for idle timeout...")
     time.sleep(1800)  # 30 minutes
     response = session.get(dashboard_url)
     print(f"Idle timeout test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session valid after idle timeout")
     else:
         print("Secure: Session expired after idle timeout")

     # Test absolute timeout (simplified to 1 hour for testing)
     new_session = requests.Session()
     new_session.post(login_url, data=login_data)
     time.sleep(3600)  # 1 hour
     response = new_session.get(dashboard_url)
     print(f"Absolute timeout test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session valid after absolute timeout")
     else:
         print("Secure: Session expired after absolute timeout")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_session_timeout.py
     ```
3. **Test Idle Timeout**:
   - Command:
     ```bash
     python3 -c "import requests, time; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); c=s.cookies.get('session'); time.sleep(1800); r=s.get('http://example.com/dashboard'); print(r.status_code, r.text[:100])"
     ```
4. **Verify Findings**:
   - Vulnerable: Sessions remain valid after timeouts.
   - Expected secure response: Sessions expire with HTTP 401 or redirect.

**Remediation**:
- Combine idle and absolute timeouts:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: { maxAge: 1800000 }, // 30 minutes idle
      store: new MemoryStore({
          checkPeriod: 1800000,
          ttl: 28800 // 8 hours absolute
      })
  }));
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_session_timeout.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).