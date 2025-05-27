# Testing for Account Enumeration and Guessable User Account

## Overview

Testing for Account Enumeration and Guessable User Account (WSTG-IDNT-04) involves assessing a web application to identify vulnerabilities that allow attackers to determine valid usernames or accounts or guess usernames due to predictable patterns. According to OWASP, enumeration vulnerabilities, such as verbose error messages, response differences, or timing variations, and guessable usernames (e.g., `admin`, `user1`) can enable attackers to target valid accounts for brute-force attacks, phishing, or unauthorized access. This test focuses on analyzing authentication endpoints (login, registration, password reset, account recovery), error messages, response timing, response lengths, and username patterns to detect enumeration risks and ensure robust account protection.

**Impact**: Vulnerabilities in account enumeration or guessable usernames can lead to:
- Identification of valid accounts, facilitating targeted attacks (e.g., brute-force, phishing).
- Unauthorized access through guessing predictable usernames.
- Privacy breaches by exposing account existence to unauthenticated users.
- Increased risk of account compromise due to weak authentication controls.

This guide provides a practical, hands-on methodology for testing account enumeration and guessable user accounts, adhering to OWASP’s WSTG-IDNT-04, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for enumeration testing, as automated attempts may trigger security alerts or disrupt live systems.

## Testing Tools

The following tools are recommended for testing account enumeration and guessable user accounts, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and analyzes authentication requests for response differences and lengths.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints for enumeration vulnerabilities in password reset and recovery.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends crafted requests to compare responses for valid vs. invalid accounts in registration and login.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side responses and timing for enumeration clues.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates enumeration tests and checks rate limiting.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-IDNT-04, focusing on testing authentication endpoints, error messages, response timing, response lengths, username patterns, and rate limiting to detect enumeration and guessable account vulnerabilities.

### 1. Test Login Enumeration with Burp Suite

**Objective**: Analyze login form responses to detect differences between valid and invalid usernames.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com/login` to the target scope in the “Target” tab.
2. **Capture Login Requests**:
   - Submit login attempts with:
     - Valid username, wrong password (e.g., `admin:wrongpass`).
     - Invalid username, wrong password (e.g., `nonexistent:wrongpass`).
3. **Compare Responses**:
   - Check for differences in error messages, status codes, or lengths.

**Burp Suite Commands**:
- **Command 1**: Test valid username:
  ```
  HTTP History -> Select POST /login -> Send to Repeater -> Set username=admin, password=wrongpass -> Click Send
  ```
- **Command 2**: Test invalid username:
  ```
  Repeater -> Change username=nonexistent, password=wrongpass -> Click Send -> Compare response
  ```

**Example Vulnerable Response**:
```
[Valid username]
HTTP/1.1 401 Unauthorized
{"error": "Incorrect password"}
[Invalid username]
HTTP/1.1 401 Unauthorized
{"error": "Username does not exist"}
```

**Remediation**:
- Use generic errors (Node.js):
  ```javascript
  app.post('/login', (req, res) => {
      const { username, password } = req.body;
      if (!validCredentials(username, password)) {
          return res.status(401).json({ error: 'Invalid credentials' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Password Reset Enumeration with Postman

**Objective**: Check password reset endpoints for enumeration through response differences.

**Steps**:
1. **Identify Reset Endpoint**:
   - Use Burp Suite to find `POST /reset-password`.
   - Import into Postman.
2. **Submit Requests**:
   - Send requests with valid (e.g., `admin@example.com`) and invalid emails (e.g., `nonexistent@example.com`).
3. **Analyze Responses**:
   - Check for differences in messages, status codes, or lengths.

**Postman Commands**:
- **Command 1**: Test valid email:
  ```
  New Request -> POST http://example.com/reset-password -> Body -> JSON: {"email": "admin@example.com"} -> Send
  ```
- **Command 2**: Test invalid email:
  ```
  New Request -> POST http://example.com/reset-password -> Body -> JSON: {"email": "nonexistent@example.com"} -> Send
  ```

**Example Vulnerable Response**:
```
[Valid email]
HTTP/1.1 200 OK
{"message": "Reset link sent"}
[Invalid email]
HTTP/1.1 404 Not Found
{"error": "Email not found"}
```

**Remediation**:
- Use consistent responses (Python/Flask):
  ```python
  @app.post('/reset-password')
  def reset_password():
      email = request.json['email']
      return jsonify({'message': 'If the email exists, a reset link was sent'})
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 3. Test Guessable Usernames with cURL

**Objective**: Attempt to log in or register with common or sequential usernames to identify guessable patterns.

**Steps**:
1. **Identify Authentication Endpoint**:
   - Use Burp Suite to find `POST /login` or `/register`.
2. **Test Common Usernames**:
   - Try `admin`, `user`, `user1`, etc.
3. **Analyze Responses**:
   - Check for valid account indicators (e.g., “Incorrect password”).

**cURL Commands**:
- **Command 1**: Test common username:
  ```bash
  curl -i -X POST -d "username=admin&password=wrongpass" http://example.com/login
  ```
- **Command 2**: Test sequential username:
  ```bash
  curl -i -X POST -d "username=user1&password=wrongpass" http://example.com/login
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Incorrect password"}
```

**Remediation**:
- Restrict usernames (Python/Flask):
  ```python
  @app.post('/register')
  def register():
      username = request.form['username']
      if re.match(r'^(admin|user\d+|test)$', username, re.I):
          return jsonify({'error': 'Username not allowed'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Response Timing with Browser Developer Tools

**Objective**: Analyze response timing differences to detect enumeration vulnerabilities.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/login` and press `F12` in Chrome.
2. **Submit Login Attempts**:
   - Test valid and invalid usernames with wrong passwords.
3. **Analyze Timing**:
   - Compare response times in the “Network” tab.

**Browser Developer Tools Commands**:
- **Command 1**: Check valid username timing:
  ```
  Network tab -> Select POST /login -> Submit username=admin, password=wrongpass -> Note Timing
  ```
- **Command 2**: Check invalid username timing:
  ```
  Network tab -> Submit username=nonexistent, password=wrongpass -> Note Timing -> Compare
  ```

**Example Vulnerable Finding**:
```
Valid username: 500ms
Invalid username: 100ms
```

**Remediation**:
- Normalize timing (Python/Flask):
  ```python
  import time
  @app.post('/login')
  def login():
      start = time.time()
      if not valid_credentials():
          time.sleep(0.5 - (time.time() - start))  # Ensure ~500ms
          return jsonify({'error': 'Invalid credentials'}), 401
      return jsonify({'status': 'success'})
  ```

**Tip**: Save screenshots and network logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., timing data).

### 5. Test Rate Limiting with Python Requests

**Objective**: Attempt automated enumeration to verify rate limiting or anti-automation controls.

**Steps**:
1. **Write Python Script**:
   - Send multiple login attempts.
2. **Run Script**:
   - Analyze for HTTP 429 or CAPTCHA prompts.
3. **Verify Findings**:
   - Check if enumeration succeeds without restrictions.

**Python Commands**:
- **Command 1**: Run enumeration test:
  ```bash
  python3 test_enumeration.py
  ```
  ```python
  # test_enumeration.py
  import requests
  import time
  url = 'http://example.com/login'
  usernames = ['admin', 'user1', 'nonexistent', 'test']
  for i, username in enumerate(usernames):
      data = {'username': username, 'password': 'wrongpass'}
      response = requests.post(url, data=data)
      print(f"Attempt {i+1}: Username={username}, Status={response.status_code}, Response={response.text[:100]}")
      if response.status_code == 429 or 'CAPTCHA required' in response.text:
          print("Rate limiting or CAPTCHA detected")
          break
      time.sleep(1)
  ```
- **Command 2**: Test single login:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/login', data={'username': 'admin', 'password': 'wrongpass'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Username=admin, Status=401, Response={"error": "Incorrect password"}
Attempt 2: Username=user1, Status=401, Response={"error": "Incorrect password"}
```

**Remediation**:
- Implement rate limiting (Node.js):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/login', rateLimit({
      windowMs: 15 * 60 * 1000,  // 15 minutes
      max: 5  // 5 requests
  }));
  app.post('/login', (req, res) => {
      if (!req.body.captcha) {
          return res.status(400).json({ error: 'CAPTCHA required' });
      }
      res.json({ error: 'Invalid credentials' });
  });
  ```

**Tip**: Save script output to a file (e.g., `python3 test_enumeration.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).

### 6. Test Registration Endpoint Enumeration

**Objective**: Test if registration responses reveal existing accounts.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find `POST /register`.
2. **Send Requests**:
   - Test existing (e.g., `admin@example.com`) and non-existing emails.
3. **Analyze Responses**:
   - Check for differences (e.g., “Email already registered”).

**cURL Commands**:
- **Command 1**: Test existing email:
  ```bash
  curl -i -X POST -d "email=admin@example.com&password=Secure123" http://example.com/register
  ```
- **Command 2**: Test non-existing email:
  ```bash
  curl -i -X POST -d "email=nonexistent@example.com&password=Secure123" http://example.com/register
  ```

**Example Vulnerable Response**:
```
[Existing email]
HTTP/1.1 400 Bad Request
{"error": "Email already registered"}
[Non-existing email]
HTTP/1.1 200 OK
{"status": "Account created"}
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

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Account Recovery Endpoint Enumeration

**Objective**: Test if account recovery endpoints reveal valid accounts.

**Steps**:
1. **Identify Recovery Endpoint**:
   - Use Burp Suite to find `POST /recover-account`.
   - Import into Postman.
2. **Submit Requests**:
   - Test valid and invalid emails.
3. **Analyze Responses**:
   - Check for differences (e.g., “Recovery email sent”).

**Postman Commands**:
- **Command 1**: Test valid email:
  ```
  New Request -> POST http://example.com/recover-account -> Body -> JSON: {"email": "admin@example.com"} -> Send
  ```
- **Command 2**: Test invalid email:
  ```
  New Request -> POST http://example.com/recover-account -> Body -> JSON: {"email": "nonexistent@example.com"} -> Send
  ```

**Example Vulnerable Response**:
```
[Valid email]
HTTP/1.1 200 OK
{"message": "Recovery email sent"}
[Invalid email]
HTTP/1.1 404 Not Found
{"error": "Account not found"}
```

**Remediation**:
- Use consistent responses (Node.js):
  ```javascript
  app.post('/recover-account', (req, res) => {
      return res.json({ message: 'If the account exists, a recovery email was sent' });
  });
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 8. Test Response Length Differences

**Objective**: Test if response lengths reveal valid accounts during login attempts.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
2. **Send Login Requests**:
   - Test valid and invalid usernames.
3. **Analyze Lengths**:
   - Compare response lengths in “Response” tab.

**Burp Suite Commands**:
- **Command 1**: Test valid username:
  ```
  HTTP History -> Select POST /login -> Send to Repeater -> Set username=admin, password=wrongpass -> Click Send -> Note length
  ```
- **Command 2**: Test invalid username:
  ```
  Repeater -> Change username=nonexistent -> Click Send -> Compare length
  ```

**Example Vulnerable Finding**:
```
Valid username: Response length = 150 bytes
Invalid username: Response length = 120 bytes
```

**Remediation**:
- Normalize lengths (Python/Flask):
  ```python
  @app.post('/login')
  def login():
      response = {'error': 'Invalid credentials'}
      response_str = json.dumps(response) + ' ' * (150 - len(json.dumps(response)))
      return response_str, 401
  ```

**Tip**: Save Burp Suite requests as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., response lengths).