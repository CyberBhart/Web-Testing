# Testing for Session Fixation

## Overview

Testing for Session Fixation (WSTG-SESS-03) involves assessing a web application to ensure it regenerates session identifiers upon authentication or privilege changes, preventing attackers from forcing users to use a known session ID to hijack their sessions. According to OWASP, session fixation vulnerabilities allow attackers to gain unauthorized access by pre-setting a session ID that remains valid after a user logs in. This test focuses on verifying session ID regeneration, invalidation of old session IDs, and secure handling of session IDs to mitigate session fixation risks.

**Impact**: Session fixation vulnerabilities can lead to:
- Unauthorized access to user accounts by attackers using pre-set session IDs.
- Session hijacking if fixed session IDs remain valid post-authentication.
- Compromise of sensitive accounts (e.g., admin) through targeted fixation attacks.

This guide provides a practical, hands-on methodology for testing session fixation, adhering to OWASP’s WSTG-SESS-03, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing session fixation, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates session IDs to test regeneration and fixation.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests API endpoints for session ID handling during authentication.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests with pre-set session IDs to verify acceptance.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects session cookies and URL parameters for fixation vectors.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates session ID testing and validation.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-03, focusing on testing session ID regeneration, acceptance of pre-set IDs, invalidation, and transmission vectors.

### 1. Test Session ID Regeneration with Burp Suite

**Objective**: Verify that the application regenerates session IDs upon login.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Pre-Login Session**:
   - Access the application (e.g., `GET /`) as an unauthenticated user.
   - Check “HTTP History” for the `Set-Cookie` header (e.g., `session=abc123`).
   - Command:
     ```
     HTTP History -> Select GET / -> Response tab -> Find Set-Cookie: session=abc123
     ```
3. **Log In**:
   - Log in with valid credentials and capture the `POST /login` response.
   - Check for a new `Set-Cookie` header with a different session ID.
   - Command:
     ```
     HTTP History -> Select POST /login -> Send to Repeater -> Submit username=test, password=Secure123 -> Click Send -> Check Set-Cookie for new session ID
     ```
4. **Analyze Findings**:
   - Compare pre-login and post-login session IDs.
   - Vulnerable: Same session ID persists.
   - Expected secure response: New session ID (e.g., `session=xyz789`).

**Remediation**:
- Regenerate session ID on login:
  ```javascript
  app.post('/login', (req, res) => {
      // Authenticate user
      req.session.regenerate((err) => {
          if (err) return res.status(500).json({ error: 'Session error' });
          res.json({ status: 'success' });
      });
  });
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Pre-Set Session ID Acceptance with Postman

**Objective**: Check if the application accepts a forced session ID after authentication.

**Steps**:
1. **Identify Login Endpoint**:
   - Use Burp Suite to find `POST /login`.
   - Import into Postman.
2. **Set Pre-Defined Session ID**:
   - Send an unauthenticated request with a custom session ID (e.g., `session=attacker123`).
   - Command:
     ```
     New Request -> GET http://example.com/ -> Headers: Cookie: session=attacker123 -> Send -> Note Set-Cookie
     ```
3. **Log In with Pre-Set ID**:
   - Log in using the same session ID and check if it is retained.
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Headers: Cookie: session=attacker123 -> Send -> Check Set-Cookie
     ```
4. **Analyze Findings**:
   - Vulnerable: Pre-set session ID is accepted post-login.
   - Expected secure response: New session ID issued; old ID rejected.

**Remediation**:
- Reject untrusted session IDs:
  ```python
  @app.post('/login')
  def login():
      if 'session' in request.cookies and not validate_session(request.cookies['session']):
          response = make_response({'error': 'Invalid session'})
          response.set_cookie('session', '', expires=0)
          return response, 401
      session['user'] = authenticate_user()
      return jsonify({'status': 'success'})
  ```

**Tip**: Capture requests and responses as JSON or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Old Session ID Reuse with cURL

**Objective**: Verify that old session IDs are invalidated after authentication.

**Steps**:
1. **Capture Pre-Login Session**:
   - Access the application and note the session ID (e.g., `session=abc123`).
   - Command:
     ```bash
     curl -i http://example.com/ | grep Set-Cookie
     ```
2. **Log In**:
   - Log in to obtain a new session ID (e.g., `session=xyz789`).
3. **Reuse Old Session ID**:
   - Send a request to a protected resource using the old session ID.
   - Command:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
4. **Analyze Findings**:
   - Vulnerable: Old session ID grants access.
   - Expected secure response: HTTP 401 or 403.

**Remediation**:
- Invalidate old sessions:
  ```javascript
  app.post('/login', (req, res) => {
      req.session.destroy(() => {
          req.session.regenerate(() => {
              res.json({ status: 'success' });
          });
      });
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Session ID in URL with Browser Developer Tools

**Objective**: Check if session IDs can be forced via URL parameters, enabling fixation.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect URLs**:
   - Navigate the application and check “Network” tab for session IDs in URLs (e.g., `?sessionid=abc123`).
   - Command:
     ```
     Network tab -> Select GET / -> Request URL -> Look for ?sessionid=abc123
     ```
3. **Force Session ID**:
   - Modify the URL to include a custom session ID (e.g., `http://example.com/?sessionid=attacker123`).
   - Log in and check if the application uses the provided ID.
   - Command:
     ```
     Network tab -> Edit URL to http://example.com/?sessionid=attacker123 -> Reload -> Log in -> Check Set-Cookie
     ```
4. **Analyze Findings**:
   - Vulnerable: URL-based session ID is accepted.
   - Expected secure response: Session ID ignored; cookie-based ID used.

**Remediation**:
- Use cookies for session IDs:
  ```python
  @app.route('/')
  def home():
      if 'sessionid' in request.args:
          return jsonify({'error': 'Session IDs via URL not supported'}), 400
      response = make_response({'status': 'success'})
      response.set_cookie('session', secrets.token_urlsafe(32))
      return response
  ```

**Tip**: Save screenshots of the Network tab and console outputs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Automate Session Fixation Testing with Python Requests

**Objective**: Automate testing to verify session ID regeneration across multiple login attempts.

**Steps**:
1. **Write Python Script**:
   - Create a script to test session ID changes:
     ```python
     import requests

     url = 'http://example.com'
     login_url = f'{url}/login'
     dashboard_url = f'{url}/dashboard'

     # Get pre-login session
     session = requests.Session()
     response = session.get(url)
     pre_login_session = session.cookies.get('session')
     print(f"Pre-login session: {pre_login_session}")

     # Log in
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     post_login_session = session.cookies.get('session')
     print(f"Post-login session: {post_login_session}")

     # Check regeneration
     if pre_login_session == post_login_session:
         print("Vulnerable: Session ID not regenerated")
     else:
         print("Secure: Session ID regenerated")

     # Test old session ID
     old_session = requests.Session()
     old_session.cookies.set('session', pre_login_session)
     response = old_session.get(dashboard_url)
     print(f"Old session access: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200:
         print("Vulnerable: Old session ID accepted")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_session_fixation.py
     ```
3. **Test Single Login**:
   - Command:
     ```bash
     python3 -c "import requests; s=requests.Session(); s.get('http://example.com'); print(s.cookies.get('session')); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); print(s.cookies.get('session'))"
     ```
4. **Verify Findings**:
   - Vulnerable: Same session ID or old ID grants access.
   - Expected secure response: New ID; old ID rejected.

**Remediation**:
- Regenerate and invalidate sessions:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/login')
  def login():
      session.clear() # Invalidate old session
      session['user'] = authenticate_user()
      return jsonify({'status': 'success'})
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_session_fixation.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).