# Testing for Cross Site Request Forgery

## Overview

Testing for Cross Site Request Forgery (WSTG-SESS-05) involves assessing a web application to ensure that state-changing operations are protected against CSRF attacks, where attackers trick a user’s browser into performing unauthorized actions using their authenticated session. According to OWASP, CSRF vulnerabilities allow attackers to execute actions like updating profiles or transferring funds without user consent. This test focuses on verifying the presence and effectiveness of anti-CSRF mechanisms (e.g., tokens, `SameSite` cookies) to prevent forged requests.

**Impact**: CSRF vulnerabilities can lead to:
- Unauthorized actions performed on behalf of users (e.g., account changes, transactions).
- Financial loss or data compromise in sensitive applications.
- Account takeover or privilege escalation through state-changing exploits.
- Reputational damage from session exploitation.

This guide provides a practical, hands-on methodology for testing CSRF vulnerabilities, adhering to OWASP’s WSTG-SESS-05, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing CSRF vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test CSRF protections.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests API endpoints for CSRF token validation.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends crafted requests to simulate CSRF attacks.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects forms and cookies for anti-CSRF tokens and `SameSite` attributes.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates CSRF testing and token bypass attempts.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-05, focusing on testing state-changing endpoints, anti-CSRF tokens, `SameSite` cookies, request validation, and bypass attempts.

### 1. Identify and Test State-Changing Endpoints with Burp Suite

**Objective**: Analyze state-changing operations and test for CSRF protections.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Identify State-Changing Requests**:
   - Navigate the application (e.g., update profile, transfer funds) and check “HTTP History” for `POST` or `PUT` requests to endpoints like `/update-profile`.
   - Note parameters, headers, and any CSRF tokens (e.g., `_csrf=xyz789`).
   - Command:
     ```
     HTTP History -> Select POST /update-profile -> Request tab -> Note _csrf=xyz789
     ```
3. **Test Without CSRF Token**:
   - Replay the request in Repeater, removing the CSRF token (e.g., delete `_csrf` parameter).
   - Command:
     ```
     HTTP History -> Select POST /update-profile -> Send to Repeater -> Remove _csrf parameter -> Click Send -> Check response
     ```
4. **Analyze Findings**:
   - Vulnerable: Request succeeds without a token.
   - Expected secure response: HTTP 403 or error indicating missing/invalid token.

**Remediation**:
- Implement CSRF tokens:
  ```javascript
  app.post('/update-profile', (req, res) => {
      if (!req.body._csrf || !validateCsrfToken(req.body._csrf)) {
          return res.status(403).json({ error: 'Invalid CSRF token' });
      }
      // Update profile
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test SameSite Cookie Protection with Postman

**Objective**: Verify that `SameSite` attributes prevent cross-site requests.

**Steps**:
1. **Identify State-Changing Endpoint**:
   - Use Burp Suite to find `POST /update-profile`.
   - Import into Postman.
2. **Simulate Cross-Site Request**:
   - Send a `POST` request with the session cookie but from a different origin (e.g., `evil.com`).
   - Command:
     ```
     New Request -> POST http://example.com/update-profile -> Body -> JSON: {"name": "test"} -> Headers: Cookie: session=abc123 -> Send
     ```
3. **Check SameSite Attribute**:
   - Verify the `SameSite` attribute in the session cookie.
   - Command:
     ```
     New Request -> GET http://example.com/login -> Send -> Response Headers -> Check Set-Cookie for SameSite
     ```
4. **Analyze Findings**:
   - Vulnerable: Request succeeds with `SameSite=None` or missing attribute.
   - Expected secure response: Cookie not sent if `SameSite=Strict`; HTTP 401 or 403.

**Remediation**:
- Set `SameSite=Strict`:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.post('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', httponly=True, secure=True, samesite='Strict')
      return response
  ```

**Tip**: Capture requests and responses as JSON or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test GET-Based State Changes with cURL

**Objective**: Check if state-changing actions can be triggered via GET requests.

**Steps**:
1. **Identify State-Changing Endpoints**:
   - Use Burp Suite to find endpoints like `/transfer` or `/update-profile`.
2. **Test GET Request**:
   - Send a GET request to the endpoint with parameters.
   - Command:
     ```bash
     curl -i "http://example.com/transfer?amount=1000&to=attacker"
     ```
3. **Compare POST Request**:
   - Send a POST request to confirm behavior.
   - Command:
     ```bash
     curl -i -X POST -d "amount=1000&to=attacker" http://example.com/transfer
     ```
4. **Analyze Findings**:
   - Vulnerable: GET request succeeds and changes state.
   - Expected secure response: HTTP 405 or error indicating method not allowed.

**Remediation**:
- Restrict state changes to POST:
  ```javascript
  app.get('/transfer', (req, res) => {
      res.status(405).json({ error: 'Method not allowed' });
  });
  app.post('/transfer', (req, res) => {
      // Validate CSRF token and process transfer
      res.json({ status: 'success' });
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Inspect CSRF Tokens with Browser Developer Tools

**Objective**: Analyze forms and API requests for anti-CSRF tokens.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/profile` and press `F12` in Chrome/Firefox.
2. **Inspect Forms**:
   - Go to “Elements” tab and search for `<form>` tags.
   - Check for hidden input fields like `<input name="_csrf" value="xyz789">`.
   - Command:
     ```
     Elements tab -> Ctrl+F -> Search for "_csrf" or "token" -> Verify <input name="_csrf">
     ```
3. **Test Token Absence**:
   - Submit the form after removing the CSRF token (edit HTML or use Burp Suite).
   - Command:
     ```
     Elements tab -> Edit <form> -> Remove <input name="_csrf"> -> Submit form -> Check Network tab response
     ```
4. **Analyze Findings**:
   - Vulnerable: Form submission succeeds without a token.
   - Expected secure response: Server rejects request without valid token.

**Remediation**:
- Add CSRF token to forms:
  ```html
  <form action="/update-profile" method="POST">
      <input type="hidden" name="_csrf" value="<%= generateCsrfToken() %>">
      <input type="text" name="name" value="test">
      <input type="submit">
  </form>
  ```

**Tip**: Save screenshots of the Elements and Network tabs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses, form screenshots).

### 5. Automate CSRF Testing with Python Requests

**Objective**: Automate testing to detect missing or weak CSRF protections.

**Steps**:
1. **Write Python Script**:
   - Create a script to simulate CSRF attacks:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     profile_url = f'{base_url}/update-profile'

     # Log in to get session
     session = requests.Session()
     login_data = {'username': 'test', 'password': 'Secure123'}
     session.post(login_url, data=login_data)
     session_cookie = session.cookies.get('session')
     print(f"Session cookie: {session_cookie}")

     # Test state-changing request without CSRF token
     profile_data = {'name': 'attacker'}
     response = session.post(profile_url, data=profile_data)
     print(f"No CSRF token: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'success' in response.text.lower():
         print("Vulnerable: Request succeeded without CSRF token")

     # Test GET-based state change
     response = session.get(f'{profile_url}?name=attacker')
     print(f"GET request: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'success' in response.text.lower():
         print("Vulnerable: GET-based state change allowed")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_csrf.py
     ```
3. **Test Single CSRF Request**:
   - Command:
     ```bash
     python3 -c "import requests; s=requests.Session(); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); r=s.post('http://example.com/update-profile', data={'name': 'attacker'}); print(r.status_code, r.text[:100])"
     ```
4. **Verify Findings**:
   - Vulnerable: Requests succeed without tokens or via GET.
   - Expected secure response: HTTP 403 or errors for invalid requests.

**Remediation**:
- Validate CSRF tokens:
  ```python
  from flask import Flask, request, session
  app = Flask(__name__)
  @app.post('/update-profile')
  def update_profile():
      if not request.form.get('_csrf') or not validate_csrf_token(request.form['_csrf'], session['user']):
          return jsonify({'error': 'Invalid CSRF token'}), 403
      return jsonify({'status': 'success'})
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_csrf.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).