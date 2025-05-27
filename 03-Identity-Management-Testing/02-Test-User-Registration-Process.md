# Test User Registration Process

## Overview

Testing the User Registration Process (WSTG-IDNT-02) involves assessing a web application’s registration functionality to ensure it securely handles user onboarding, enforces strong controls, and prevents vulnerabilities such as unauthorized account creation, privilege escalation, account enumeration, or token misuse. According to OWASP, weaknesses in registration processes can allow attackers to create accounts with elevated privileges, exploit weak password policies, enumerate users, or bypass verification, compromising security and integrity. This test focuses on validating input handling, role assignments, password policies, enumeration risks, anti-automation controls, email verification, client-side validation, and token security to identify and mitigate risks in the registration process.

**Impact**: Weaknesses in the user registration process can lead to:
- Unauthorized account creation with administrative privileges.
- Account enumeration through verbose error messages, aiding targeted attacks.
- Security bypasses due to weak passwords, injection vulnerabilities, or token misuse.
- System overload or abuse from automated account creation.

This guide provides a practical, hands-on methodology for testing the user registration process, adhering to OWASP’s WSTG-IDNT-02, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as automated registration, injection, or token manipulation attempts may disrupt live systems or violate terms of service.

## Testing Tools

The following tools are recommended for testing the user registration process, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates registration requests to test input validation and token security.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API-based registration endpoints for vulnerabilities.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends crafted registration requests to analyze responses and verification processes.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side validation and hidden fields in registration forms.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates tests for enumeration, rate limiting, or injection.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-IDNT-02, focusing on testing input validation, role assignments, password policies, enumeration risks, anti-automation controls, email verification, client-side validation, and token security in the user registration process.

### 1. Test Input Validation with Burp Suite

**Objective**: Submit valid and invalid registration data to identify vulnerabilities in input handling.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com/register` to the target scope in the “Target” tab.
2. **Capture Registration Request**:
   - Fill out the registration form and submit.
   - Check “HTTP History” for the POST request to `/register`.
3. **Test Invalid Inputs**:
   - Modify fields with malicious inputs (e.g., SQL: `email=' OR '1'='1`, XSS: `username=<script>alert(1)</script>`).

**Burp Suite Commands**:
- **Command 1**: Test SQL injection:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Change email=user@example.com to email=' OR '1'='1 -> Click Send
  ```
- **Command 2**: Test weak password:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Change password=SecurePass123 to password=123 -> Click Send
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
  from flask import Flask, request
  import sqlite3
  app = Flask(__name__)
  @app.post('/register')
  def register():
      email = request.form['email']
      conn = sqlite3.connect('users.db')
      conn.execute('INSERT INTO users (email) VALUES (?)', (email,))
      conn.commit()
      return jsonify({'status': 'success'})
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Role Assignment with Postman

**Objective**: Verify that the registration process assigns appropriate roles and prevents privilege escalation.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find POST `/api/register`.
   - Import into Postman.
2. **Test Role Manipulation**:
   - Submit requests with role parameters (e.g., `{"role": "admin"}`).
3. **Analyze Responses**:
   - Check if elevated privileges are granted (e.g., access to `/admin`).

**Postman Commands**:
- **Command 1**: Test role parameter:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"email": "test@example.com", "password": "Secure123", "role": "admin"} -> Send
  ```
- **Command 2**: Test hidden admin flag:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"email": "test@example.com", "password": "Secure123", "is_admin": true} -> Send
  ```

**Example Vulnerable Response**:
```
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
- Enforce default role (Node.js):
  ```javascript
  app.post('/api/register', (req, res) => {
      const { email, password } = req.body;
      if (req.body.role || req.body.is_admin) {
          return res.status(403).json({ error: 'Invalid parameters' });
      }
      res.json({ status: 'success', role: 'user' });
  });
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 3. Test Password Policies with cURL

**Objective**: Check if the registration process enforces strong password requirements.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find POST `/register`.
2. **Submit Weak Passwords**:
   - Test short (e.g., `123`) or repetitive (e.g., `aaaaaa`) passwords.
3. **Analyze Responses**:
   - Check if weak passwords are accepted (HTTP 200).

**cURL Commands**:
- **Command 1**: Test short password:
  ```bash
  curl -i -X POST -d "email=test@example.com&password=123" http://example.com/register
  ```
- **Command 2**: Test repetitive password:
  ```bash
  curl -i -X POST -d "email=test@example.com&password=aaaaaa" http://example.com/register
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Enforce strong passwords (Python/Flask):
  ```python
  @app.post('/register')
  def register():
      password = request.form['password']
      if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$', password):
          return jsonify({'error': 'Password must be 8+ characters with uppercase, lowercase, and numbers'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Enumeration with Browser Developer Tools

**Objective**: Analyze error messages during registration to detect account enumeration risks.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/register` and press `F12` in Chrome.
2. **Submit Registration Data**:
   - Register with an existing email (e.g., `admin@example.com`).
3. **Analyze Error Messages**:
   - Check for messages like “Email already exists” vs. generic errors.

**Browser Developer Tools Commands**:
- **Command 1**: Check registration response:
  ```
  Network tab -> Select POST /register -> Response tab -> Look for "Email already registered"
  ```
- **Command 2**: Test multiple emails:
  ```
  Network tab -> Submit form with email=admin@example.com -> Check response -> Repeat with email=test@example.com
  ```

**Example Vulnerable Response**:
```
{
  "error": "Email already registered"
}
```

**Remediation**:
- Use generic errors (Python/Flask):
  ```python
  @app.post('/register')
  def register():
      email = request.form['email']
      if db.users.find_one({'email': email}):
          return jsonify({'error': 'Registration failed'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save screenshots and network logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., error messages).

### 5. Test Anti-Automation with Python Requests

**Objective**: Attempt automated registrations to verify rate limiting, CAPTCHAs, or email verification.

**Steps**:
1. **Write Python Script**:
   - Create a script to send multiple registration requests.
2. **Run Script**:
   - Execute and analyze responses for HTTP 429 or CAPTCHA prompts.
3. **Verify Findings**:
   - Check if accounts are created without restrictions.

**Python Commands**:
- **Command 1**: Run registration test:
  ```bash
  python3 test_registration.py
  ```
  ```python
  # test_registration.py
  import requests
  import time
  url = 'http://example.com/register'
  for i in range(5):
      data = {'email': f'test{i}@example.com', 'password': 'Secure123', 'username': f'testuser{i}'}
      response = requests.post(url, data=data)
      print(f"Attempt {i+1}: Status={response.status_code}, Response={response.text[:100]}")
      if 'CAPTCHA required' in response.text or response.status_code == 429:
          print("Anti-automation detected")
          break
      time.sleep(1)
  ```
- **Command 2**: Test single registration:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/register', data={'email': 'test@example.com', 'password': '123'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status=200, Response={"status": "Account created"}
Attempt 2: Status=200, Response={"status": "Account created"}
```

**Remediation**:
- Implement rate limiting and CAPTCHA (Node.js):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/register', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5 // 5 requests
  }));
  app.post('/register', (req, res) => {
      if (!req.body.captcha) {
          return res.status(400).json({ error: 'CAPTCHA required' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save script output to a file (e.g., `python3 test_registration.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).

### 6. Test Email Verification Process

**Objective**: Test if the registration process enforces secure email verification.

**Steps**:
1. **Register Account**:
   - Use a temporary email (e.g., from `temp-mail.org`).
2. **Capture Request**:
   - Use cURL to send the registration request.
3. **Analyze Verification**:
   - Check if the account is activated without verification or if tokens are predictable.

**cURL Commands**:
- **Command 1**: Register with temporary email:
  ```bash
  curl -i -X POST -d "email=test@temp-mail.org&password=Secure123" http://example.com/register
  ```
- **Command 2**: Test verification token:
  ```bash
  curl -i http://example.com/verify?token=abc123
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account activated"}
```

**Remediation**:
- Enforce email verification (Python/Flask):
  ```python
  @app.route('/register', methods=['POST'])
  def register():
      email = request.form['email']
      token = generate_unique_token()  # Secure random token
      send_verification_email(email, token)
      return jsonify({'status': 'Verify email'})
  @app.route('/verify')
  def verify():
      token = request.args.get('token')
      if not db.verify_token(token):
          return jsonify({'error': 'Invalid token'}), 403
      return jsonify({'status': 'Account activated'})
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Client-Side Validation Bypass

**Objective**: Test if client-side validation can be bypassed to submit invalid data.

**Steps**:
1. **Inspect Form**:
   - Open the registration form and press `F12` in Chrome.
2. **Modify Form**:
   - Remove `required` attributes or disable JavaScript validation.
3. **Submit Invalid Data**:
   - Submit the form and check server response.

**Browser Developer Tools Commands**:
- **Command 1**: Remove required attribute:
  ```
  Elements tab -> Find <input type="email" required> -> Edit as HTML -> Remove required -> Submit form
  ```
- **Command 2**: Disable validation:
  ```
  Console tab -> Run: document.querySelector('form').noValidate = true -> Submit form
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Server-side validation (Python/Flask):
  ```python
  @app.route('/register', methods=['POST'])
  def register():
      email = request.form['email']
      password = request.form['password']
      if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
          return jsonify({'error': 'Invalid email'}), 400
      if len(password) < 8:
          return jsonify({'error': 'Password too short'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save screenshots and network logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., form submissions).

### 8. Test Registration Token Replay

**Objective**: Test if registration tokens can be replayed or manipulated.

**Steps**:
1. **Capture Registration**:
   - Configure Burp Suite to intercept POST `/register`.
2. **Reuse Token**:
   - Capture and reuse CSRF or session tokens in new requests.
3. **Analyze Response**:
   - Check if the server accepts replayed tokens.

**Burp Suite Commands**:
- **Command 1**: Capture token:
  ```
  HTTP History -> Filter -> Show only: Method=POST, URL contains "register" -> Check for token parameters
  ```
- **Command 2**: Replay token:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Reuse CSRF token -> Change email -> Click Send
  ```

**Example Vulnerable Request**:
```
POST http://example.com/register HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
email=test2@example.com&password=Secure123&csrf_token=abc123
```

**Remediation**:
- Secure CSRF protection (Python/Flask):
  ```python
  from flask_wtf.csrf import CSRFProtect
  csrf = CSRFProtect(app)
  @app.route('/register', methods=['POST'])
  @csrf.required
  def register():
      email = request.form['email']
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Burp Suite requests as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).
