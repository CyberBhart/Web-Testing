# Testing for Weak or Unenforced Username Policy

## Overview

Testing for Weak or Unenforced Username Policy (WSTG-IDNT-05) involves assessing a web application’s username policy to ensure it enforces strong, unique, and secure usernames, preventing vulnerabilities that could enable account enumeration, impersonation, or unauthorized access. According to OWASP, weak username policies that allow predictable (e.g., `admin`, `user1`), non-unique, sensitive (e.g., emails), or overly long usernames can facilitate attacks like brute-forcing, phishing, or system abuse. This test focuses on validating username format, uniqueness, input sanitization, server-side enforcement, and anti-automation controls during registration and profile updates to identify and mitigate risks.

**Impact**: Weak or unenforced username policies can lead to:
- Predictable usernames enabling account enumeration or targeted attacks.
- Impersonation through usernames mimicking privileged accounts (e.g., `administrator`).
- Privacy breaches by allowing sensitive data (e.g., emails, SSNs) in usernames.
- Account conflicts or hijacking due to non-unique or case-insensitive usernames.
- System errors or abuse from unrestricted username lengths or characters.

This guide provides a practical, hands-on methodology for testing weak or unenforced username policies, adhering to OWASP’s WSTG-IDNT-05, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as registering multiple accounts or probing username policies may trigger security alerts or disrupt live systems.

## Testing Tools

The following tools are recommended for testing username policies, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates registration requests to test username validation.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints for weak username policies and length restrictions.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends crafted requests to analyze username restrictions in registration and updates.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side validation and hidden fields in registration forms.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates tests for username patterns, enumeration risks, and rate limiting.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-IDNT-05, focusing on testing username format, predictability, uniqueness, input validation, server-side enforcement, length restrictions, update policies, and rate limiting during account creation or profile updates.

### 1. Test Username Format with Burp Suite

**Objective**: Submit various usernames to verify format restrictions and input validation.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com/register` to the target scope in the “Target” tab.
2. **Capture Registration Request**:
   - Submit a registration form and check “HTTP History” for `POST /register`.
3. **Test Username Inputs**:
   - Try weak (e.g., `a`, `admin`), sensitive (e.g., `test@email.com`), and malicious (e.g., `<script>`) usernames.
4. **Analyze Responses**:
   - Check if insecure usernames are accepted (HTTP 200).

**Burp Suite Commands**:
- **Command 1**: Test short username:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Change username=test to username=a -> Click Send
  ```
- **Command 2**: Test sensitive username:
  ```
  Repeater -> Change username=test to username=test@email.com -> Click Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Enforce strong formats (Node.js):
  ```javascript
  app.post('/register', (req, res) => {
      const username = req.body.username;
      if (!/^[a-zA-Z0-9]{6,32}$/.test(username) || username.match(/^(admin|user\d+|test)$/i)) {
          return res.status(400).json({ error: 'Invalid username: 6-32 alphanumeric characters required' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Username Uniqueness with Postman

**Objective**: Verify that the application prevents duplicate or case-insensitive usernames.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find `POST /api/register`.
   - Import into Postman.
2. **Test Duplicate Usernames**:
   - Register `testuser`, then try `TestUser`.
3. **Analyze Responses**:
   - Check for duplicate acceptance or conflicts.

**Postman Commands**:
- **Command 1**: Register username:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "testuser", "email": "test1@example.com", "password": "Secure123"} -> Send
  ```
- **Command 2**: Test case-insensitive duplicate:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "TestUser", "email": "test2@example.com", "password": "Secure123"} -> Send
  ```

**Example Vulnerable Response**:
```
[Second attempt]
HTTP/1.1 200 OK
{"status": "Account created"}
```

**Remediation**:
- Ensure uniqueness (Python/Flask):
  ```python
  @app.post('/api/register')
  def register():
      username = request.json['username']
      if db.users.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}}):
          return jsonify({'error': 'Username already exists'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 3. Test Predictable Usernames with cURL

**Objective**: Attempt to register common or sequential usernames to identify predictability.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find `POST /register`.
2. **Test Common Usernames**:
   - Try `admin`, `user1`, etc.
3. **Analyze Responses**:
   - Check if predictable usernames are accepted.

**cURL Commands**:
- **Command 1**: Test common username:
  ```bash
  curl -i -X POST -d "username=admin&email=test1@example.com&password=Secure123" http://example.com/register
  ```
- **Command 2**: Test sequential username:
  ```bash
  curl -i -X POST -d "username=user1&email=test2@example.com&password=Secure123" http://example.com/register
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Block predictable usernames (Python/Flask):
  ```python
  @app.post('/register')
  def register():
      username = request.form['username']
      if re.match(r'^(admin|user\d+|test)$', username, re.I):
          return jsonify({'error': 'Username not allowed'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Bypass Client-Side Validation with Browser Developer Tools

**Objective**: Test if username validation relies on client-side checks that can be bypassed.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/register` and press `F12` in Chrome.
2. **Inspect Form**:
   - Check for JavaScript validation or form constraints (e.g., `minlength`).
3. **Bypass Validation**:
   - Remove `minlength` or disable JavaScript and submit weak usernames.

**Browser Developer Tools Commands**:
- **Command 1**: Modify form validation:
  ```
  Elements tab -> Find <input name="username" minlength="6"> -> Edit as HTML -> Remove minlength -> Submit form with username=a
  ```
- **Command 2**: Disable JavaScript:
  ```
  Network tab -> Submit form with username=admin after disabling JavaScript -> Check response
  ```

**Example Vulnerable Script**:
```html
<input name="username" minlength="6" oninput="validateUsername(this)">
<script>
function validateUsername(input) {
    if (input.value.length < 6) input.setCustomValidity('Username too short');
}
</script>
```

**Remediation**:
- Enforce server-side validation (Node.js):
  ```javascript
  app.post('/register', (req, res) => {
      const username = req.body.username;
      if (username.length < 6 || username.match(/^(admin|user\d+|test)$/i)) {
          return res.status(400).json({ error: 'Invalid username' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save screenshots and network logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., form submissions).

### 5. Test Enumeration Risks with Python Requests

**Objective**: Analyze registration responses for username enumeration risks during policy enforcement.

**Steps**:
1. **Write Python Script**:
   - Test registration with existing and new usernames.
2. **Run Script**:
   - Check for enumeration clues (e.g., “Username already exists”).
3. **Analyze Responses**:
   - Verify generic error usage.

**Python Commands**:
- **Command 1**: Run username policy test:
  ```bash
  python3 test_username_policy.py
  ```
  ```python
  # test_username_policy.py
  import requests
  url = 'http://example.com/register'
  usernames = ['admin', 'testuser', 'newuser123']
  for username in usernames:
      data = {'username': username, 'email': f'{username}@example.com', 'password': 'Secure123'}
      response = requests.post(url, data=data)
      print(f"Username={username}, Status={response.status_code}, Response={response.text[:100]}")
      if 'already exists' in response.text.lower():
          print("Enumeration risk: Username existence disclosed")
  ```
- **Command 2**: Test single registration:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/register', data={'username': 'admin', 'email': 'admin@example.com', 'password': 'Secure123'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Username=admin, Status=400, Response={"error": "Username already exists"}
Enumeration risk: Username existence disclosed
```

**Remediation**:
- Use generic errors (Python/Flask):
  ```python
  @app.post('/register')
  def register():
      username = request.form['username']
      if db.users.find_one({'username': username}):
          return jsonify({'error': 'Registration failed'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save script output to a file (e.g., `python3 test_username_policy.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).

### 6. Test Username Length and Character Restrictions

**Objective**: Test if the application enforces minimum and maximum username lengths and allowed characters.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find `POST /api/register`.
   - Import into Postman.
2. **Test Length and Characters**:
   - Try overly long usernames (e.g., 256 characters) and disallowed characters (e.g., `user@123`).
3. **Analyze Responses**:
   - Check for rejection of invalid usernames.

**Postman Commands**:
- **Command 1**: Test long username:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "a".repeat(256), "email": "test1@example.com", "password": "Secure123"} -> Send
  ```
- **Command 2**: Test disallowed characters:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"username": "user@123", "email": "test2@example.com", "password": "Secure123"} -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Account created"}
```

**Remediation**:
- Restrict length and characters (Python/Flask):
  ```python
  @app.post('/api/register')
  def register():
      username = request.json['username']
      if not re.match(r'^[a-zA-Z0-9]{6,32}$', username):
          return jsonify({'error': 'Invalid username: 6-32 alphanumeric characters required'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 7. Test Username Update Endpoint Policies

**Objective**: Test if username update endpoints enforce strong policies.

**Steps**:
1. **Authenticate**:
   - Log in and capture session token with Burp Suite.
2. **Test Username Updates**:
   - Try weak (e.g., `admin`) or existing usernames.
3. **Analyze Responses**:
   - Check for rejection of invalid changes.

**cURL Commands**:
- **Command 1**: Test weak username:
  ```bash
  curl -i -X POST -b "session=user_token" -d "username=admin" http://example.com/api/update-profile
  ```
- **Command 2**: Test sensitive username:
  ```bash
  curl -i -X POST -b "session=user_token" -d "username=new@email.com" http://example.com/api/update-profile
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
- Validate updates (Python/Flask):
  ```python
  @app.post('/api/update-profile')
  def update_profile():
      username = request.form['username']
      if not re.match(r'^[a-zA-Z0-9]{6,32}$', username) or db.users.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}}):
          return jsonify({'error': 'Invalid username'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Rate Limiting for Username Registration

**Objective**: Test if registration endpoints enforce rate limiting to prevent policy abuse.

**Steps**:
1. **Write Python Script**:
   - Send multiple registration requests.
2. **Run Script**:
   - Check for HTTP 429 or CAPTCHA prompts.
3. **Analyze Responses**:
   - Verify blocking of excessive attempts.

**Python Commands**:
- **Command 1**: Run rate limit test:
  ```bash
  python3 test_rate_limit.py
  ```
  ```python
  # test_rate_limit.py
  import requests
  import time
  url = 'http://example.com/register'
  for i in range(10):
      data = {'username': f'user{i}', 'email': f'test{i}@example.com', 'password': 'Secure123'}
      response = requests.post(url, data=data)
      print(f"Attempt {i+1}: Status={response.status_code}, Response={response.text[:100]}")
      if response.status_code == 429 or 'CAPTCHA required' in response.text:
          print("Rate limiting or CAPTCHA detected")
          break
      time.sleep(1)
  ```
- **Command 2**: Test single registration:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/register', data={'username': 'user0', 'email': 'test0@example.com', 'password': 'Secure123'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status=200, Response={"status": "Account created"}
Attempt 10: Status=200, Response={"status": "Account created"}
```

**Remediation**:
- Implement rate limiting (Python/Flask):
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.remote_addr)
  @app.post('/register')
  @limiter.limit('5 per hour')
  def register():
      return jsonify({'status': 'success'})
  ```

**Tip**: Save script output to a file (e.g., `python3 test_rate_limit.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).