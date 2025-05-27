# Testing for Weak Lock Out Mechanism

## Overview

Testing for Weak Lock Out Mechanism (WSTG-AUTH-04) involves verifying that a web application enforces effective account lockout mechanisms to prevent brute-force attacks on authentication endpoints. According to OWASP, weak or missing lockout policies—such as no lockout after multiple failed attempts, short lockout durations, or lack of anti-automation controls—can allow attackers to guess credentials or abuse authentication workflows (e.g., login, password reset, security questions). This test focuses on validating lockout policies for login, password reset, security questions, and API authentication, as well as anti-automation measures like CAPTCHA or rate limiting.

**Impact**: Weak lockout mechanisms can lead to:
- Successful brute-force attacks, compromising user accounts.
- Unauthorized access to sensitive data or systems.
- Abuse of password reset or security question workflows.
- Increased risk of automated attacks on APIs or authentication endpoints.

This guide provides a practical, hands-on methodology for testing lockout mechanisms, adhering to OWASP’s WSTG-AUTH-04, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as sending multiple authentication requests may trigger security alerts or disrupt live systems.

## Testing Tools

The following tools are recommended for testing lockout mechanisms, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and automates requests to test lockout and rate limiting.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **OWASP ZAP**: Tests CAPTCHA and lockout mechanisms by simulating failed attempts.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Install and configure browser proxy: 127.0.0.1:8080.

- **cURL**: Sends requests to test lockout for password reset and security questions.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-04, focusing on testing lockout mechanisms for login, password reset, security questions, APIs, and anti-automation controls.

### 1. Test Lockout Mechanism for Login Attempts with Burp Suite

**Objective**: Verify that the application locks out accounts after multiple failed login attempts.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com/login` to the target scope.
2. Capture a login request (e.g., `POST /login`) and send it to Burp Intruder to simulate failed attempts:
   ```
   Intruder -> Set POST /login payload to username=admin&password=§wrong§ -> Run attack with 10 iterations
   ```
3. After 5–10 attempts, test a valid login in Burp Repeater to check for lockout:
   ```
   Repeater -> Send POST /login with username=admin&password=correct -> Check response
   ```
4. Analyze responses; expected secure response is a lockout error after 5–10 failed attempts.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Account locked due to too many failed attempts"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Remediation**:
- Implement login lockout (Node.js):
  ```javascript
  const attempts = {};
  app.post('/login', (req, res) => {
      const { username } = req.body;
      attempts[username] = (attempts[username] || 0) + 1;
      if (attempts[username] > 5) {
          return res.status(403).json({ error: 'Account locked' });
      }
      res.status(401).json({ error: 'Invalid credentials' });
  });
  ```

**Tip**: Save Burp Suite Intruder results and Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Lockout Duration and Reset with OWASP ZAP

**Objective**: Ensure lockout duration is reasonable and accounts reset appropriately.

**Steps**:
1. Configure OWASP ZAP by setting up the browser proxy (127.0.0.1:8080).
2. Trigger a lockout by sending multiple failed login requests:
   ```
   Manual Request Editor -> Send POST /login with username=admin&password=wrong 6 times
   ```
3. Wait 15–30 minutes and test a valid login to check if the account unlocks:
   ```
   Manual Request Editor -> Send POST /login with username=admin&password=correct -> Check response
   ```
4. Analyze responses; expected secure response is a lockout error initially, followed by successful login after the lockout period.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Account locked, try again in 15 minutes"}
[After 15 minutes]
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Login successful"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Remediation**:
- Set lockout duration (Python/Flask):
  ```python
  from datetime import datetime, timedelta
  lockouts = {}
  @app.post('/login')
  def login():
      username = request.form['username']
      if username in lockouts and lockouts[username] > datetime.now():
          return jsonify({'error': 'Account locked'}), 403
      lockouts[username] = datetime.now() + timedelta(minutes=15)
      return jsonify({'error': 'Invalid credentials'}), 401
  ```

**Tip**: Save OWASP ZAP requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of lockout duration issues.

### 3. Test Lockout for Password Reset Attempts with cURL

**Objective**: Verify that password reset functionality locks out after multiple invalid attempts.

**Steps**:
1. Identify the password reset endpoint (e.g., `POST /reset-password`) using Burp Suite.
2. Submit multiple invalid reset requests:
   ```bash
   curl -i -X POST -d "email=invalid@example.com" https://example.com/reset-password
   ```
3. Repeat 5–10 times and test a valid reset request to check for lockout:
   ```bash
   curl -i -X POST -d "email=user@example.com" https://example.com/reset-password
   ```
4. Analyze responses; expected secure response is a lockout error after excessive attempts.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Too many reset attempts, try again later"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent"}
```

**Remediation**:
- Limit reset attempts (Node.js):
  ```javascript
  const resetAttempts = {};
  app.post('/reset-password', (req, res) => {
      const { email } = req.body;
      resetAttempts[email] = (resetAttempts[email] || 0) + 1;
      if (resetAttempts[email] > 5) {
          return res.status(403).json({ error: 'Too many reset attempts' });
      }
      res.json({ status: 'Reset link sent' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test CAPTCHA or Additional Controls with OWASP ZAP

**Objective**: Ensure CAPTCHA or anti-automation controls prevent brute-force attacks.

**Steps**:
1. Configure OWASP ZAP by setting up the browser proxy (127.0.0.1:8080).
2. Attempt a login without solving CAPTCHA (if present):
   ```
   Manual Request Editor -> Send POST /login with username=admin&password=wrong without CAPTCHA token
   ```
3. Send multiple failed login requests to check for rate limiting or CAPTCHA enforcement:
   ```
   Manual Request Editor -> Send POST /login with username=admin&password=wrong 6 times -> Check response
   ```
4. Analyze responses; expected secure response is a CAPTCHA challenge or rate-limiting error.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "CAPTCHA required"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Remediation**:
- Add CAPTCHA (Python/Flask):
  ```python
  from flask import session
  @app.post('/login')
  def login():
      if not session.get('captcha_verified'):
          return jsonify({'error': 'CAPTCHA required'}), 403
      return jsonify({'error': 'Invalid credentials'}), 401
  ```

**Tip**: Save OWASP ZAP requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of missing CAPTCHAs (e.g., HTTP responses).

### 5. Test Lockout for Security Question Attempts with cURL

**Objective**: Ensure security question endpoints enforce lockout after multiple failed attempts.

**Steps**:
1. Identify the security question endpoint (e.g., `POST /security-question`) using Burp Suite.
2. Submit multiple incorrect answers:
   ```bash
   curl -i -X POST -d "question_id=1&answer=wrong1" https://example.com/security-question
   ```
3. Repeat 5–10 times and test a valid answer to check for lockout:
   ```bash
   curl -i -X POST -d "question_id=1&answer=correct" https://example.com/security-question
   ```
4. Analyze responses; expected secure response is a lockout error after excessive attempts.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Too many failed attempts, account locked"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"error": "Incorrect answer"}
```

**Remediation**:
- Implement lockout for security questions (Python/Flask):
  ```python
  from flask import session
  @app.post('/security-question')
  def security_question():
      session['attempts'] = session.get('attempts', 0) + 1
      if session['attempts'] > 5:
          return jsonify({'error': 'Account locked'}), 403
      return jsonify({'error': 'Incorrect answer'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Rate Limiting for API Authentication with Burp Suite

**Objective**: Ensure API login endpoints enforce rate limiting or lockout to prevent automated attacks.

**Steps**:
1. Identify the API login endpoint (e.g., `POST /api/login`) using Burp Suite.
2. Send multiple failed login requests in Burp Intruder:
   ```
   Intruder -> Set POST /api/login payload to username=admin&password=§wrong§ -> Run attack with 10 iterations
   ```
3. Test a valid login after the attack to check for rate limiting or lockout:
   ```
   Repeater -> Send POST /api/login with username=admin&password=correct -> Check for rate-limiting response
   ```
4. Analyze responses; expected secure response is a rate-limiting error or lockout after excessive attempts.

**Example Secure Response**:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json
{"error": "Too many attempts, try again later"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid credentials"}
```

**Remediation**:
- Implement rate limiting for API (Node.js):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5 }));
  ```

**Tip**: Save Burp Suite Intruder results and Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).