# Testing for Weak Password Change or Reset Functionalities

## Overview

Testing for Weak Password Change or Reset Functionalities (WSTG-AUTH-09) involves verifying that password change and reset mechanisms are securely implemented to prevent unauthorized access or account takeover. According to OWASP, vulnerabilities such as weak password policies, insecure reset token generation, lack of rate limiting, improper authentication, or bypassing security controls like MFA can allow attackers to compromise accounts. This test evaluates password policy enforcement, reset token security, authentication requirements, rate limiting, token exposure, MFA enforcement, user enumeration, CSRF protection, brute-force resistance, role-based access, logging, and token expiration consistency.

**Impact**: Weak password change or reset functionalities can lead to:
- Unauthorized password changes or account takeovers.
- Exploitation of predictable or exposed reset tokens.
- Bypassing Multi-Factor Authentication (MFA).
- User enumeration exposing valid accounts.
- Brute-force attacks on reset requests or tokens.
- Non-compliance with security standards (e.g., NIST 800-63B, GDPR).

**Ethical Note**: Obtain explicit permission for testing, as submitting multiple reset requests, manipulating tokens, or testing authentication bypasses may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing weak password change or reset functionalities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test password policies, authentication, token exposure, CSRF, and MFA bypass.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test reset token security, rate limiting, and user enumeration.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Custom Scripts**: Python or Bash scripts for brute-forcing tokens or automating high-volume email testing.
  - Example setup (Python):
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-09, focusing on testing password policy enforcement, reset token security, authentication requirements, rate limiting, token exposure, MFA enforcement, user enumeration, CSRF protection, brute-force resistance, role-based access, logging, and token expiration consistency.

### 1. Test Password Policy in Change/Reset Workflows with Burp Suite

**Objective**: Ensure password change and reset endpoints enforce a strong password policy.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Submit a password change request with a weak password (e.g., "pass"):
   ```
   HTTP History -> Select POST /change-password -> Send to Repeater
   ```
3. Submit a password reset request with a weak password (e.g., "123456"):
   ```
   Repeater -> Change POST /reset-password with password=123456 -> Click Send -> Check response
   ```
4. Analyze responses; expected secure response rejects weak passwords with a clear error.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Password changed successfully"}
```

**Remediation**:
- Enforce strong password policy (Node.js):
  ```javascript
  app.post('/change-password', (req, res) => {
      const { new_password } = req.body;
      if (!/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/.test(new_password)) {
          return res.status(400).json({ error: 'Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Password Reset Token Security with cURL

**Objective**: Verify that password reset tokens are unpredictable, time-limited, one-time use, and properly validated.

**Steps**:
1. Request a password reset to receive a token (e.g., via email or response) and note its format.
2. Test token predictability by requesting another reset and comparing tokens:
   ```bash
   curl -i -X POST -d "email=user@example.com" https://example.com/reset-password-request
   ```
3. Test token lifetime by reusing an old token after expiration (e.g., 24 hours):
   ```bash
   curl -i -X POST -d "token=old_token&password=NewPass123!" https://example.com/reset-password
   ```
4. Test one-time use by attempting to reuse the same token twice:
   ```bash
   curl -i -X POST -d "token=valid_token&password=NewPass123!" https://example.com/reset-password
   curl -i -X POST -d "token=valid_token&password=NewPass123!" https://example.com/reset-password
   ```
5. Analyze responses; expected secure response includes unique, random tokens, rejection of expired tokens, and rejection of reused tokens.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Invalid, expired, or already used token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Password reset successfully"}
[Sequential or predictable tokens: token=123, token=124]
```

**Remediation**:
- Generate secure, time-limited, one-time tokens (Python/Flask):
  ```python
  import secrets
  from datetime import datetime, timedelta
  @app.post('/reset-password')
  def reset_password():
      token = request.form['token']
      if not validate_token(token) or token_expired(token, max_age=timedelta(hours=24)) or token_used(token):
          return jsonify({'error': 'Invalid, expired, or already used token'}), 400
      invalidate_token(token)  # Mark token as used
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., predictable or reusable tokens).

### 3. Test Password Change Authentication with Burp Suite

**Objective**: Ensure password change requires proper authentication (e.g., current password).

**Steps**:
1. Log in and configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Submit a password change request without the current password:
   ```
   HTTP History -> Select POST /change-password -> Send to Repeater
   ```
3. Remove the current password field and resend:
   ```
   Repeater -> Remove current_password field -> Click Send -> Check response
   ```
4. Analyze responses; expected secure response requires authentication.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Current password required"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Password changed successfully"}
```

**Remediation**:
- Require authentication for changes (Node.js):
  ```javascript
  app.post('/change-password', (req, res) => {
      const { current_password, new_password } = req.body;
      if (!current_password || !verifyCurrentPassword(current_password)) {
          return res.status(400).json({ error: 'Current password required' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Rate Limiting for Password Reset Requests with cURL

**Objective**: Ensure the application limits the frequency of password reset requests.

**Steps**:
1. Identify the password reset request endpoint (e.g., `POST /reset-password-request`).
2. Submit multiple reset requests for the same user:
   ```bash
   curl -i -X POST -d "email=user@example.com" https://example.com/reset-password-request
   ```
3. Repeat immediately to test rate limiting:
   ```bash
   curl -i -X POST -d "email=user@example.com" https://example.com/reset-password-request
   ```
4. Analyze responses; expected secure response includes rate limiting or lockout.

**Example Secure Response**:
```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
{"error": "Too many reset requests, please try again later"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent"}
[No rate limiting]
```

**Remediation**:
- Implement rate limiting (Node.js):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/reset-password-request', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5 // 5 requests
  }));
  app.post('/reset-password-request', (req, res) => {
      res.json({ status: 'Reset link sent' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., lack of rate limiting).

### 5. Test Reset Token Exposure in Responses with Burp Suite

**Objective**: Ensure reset tokens are not exposed in HTTP responses, client-side code, URLs, or referrer headers.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Submit a password reset request and inspect the response:
   ```
   HTTP History -> Select POST /reset-password-request -> Check Response for token
   ```
3. Check client-side code or API responses for token leaks:
   ```
   HTTP History -> Select GET /reset-password -> Check HTML/JavaScript for token
   ```
4. Inspect reset links for token exposure in URL parameters (e.g., `/reset-password?token=abc123`):
   ```
   HTTP History -> Select GET /reset-password?token=abc123 -> Check URL
   ```
5. Check referrer headers on pages loading third-party assets:
   ```
   HTTP History -> Select GET requests for third-party assets -> Inspect Referer header
   ```
6. Analyze findings; expected secure response contains no token in responses, URLs, or referrer headers.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent"}
[No token in response, URL, or client-side code]
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent", "token": "xyz123"}
[Or URL: /reset-password?token=xyz123]
```

**Remediation**:
- Avoid token exposure and use POST forms (Python/Flask):
  ```python
  @app.post('/reset-password-request')
  def reset_password_request():
      # Send token via email, not in response or URL
      return jsonify({'status': 'Reset link sent'})
  ```

**Tip**: Save Burp Suite HTTP History responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., exposed tokens in responses or URLs).

### 6. Test MFA/2FA Bypass on Password Reset with Burp Suite

**Objective**: Ensure password reset does not disable or bypass MFA/2FA requirements.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Enable MFA (e.g., TOTP/U2F) on a test account and initiate a password reset:
   ```
   HTTP History -> Select POST /reset-password-request -> Send to Repeater
   ```
3. Complete the reset process and attempt to log in without MFA:
   ```
   Repeater -> Change POST /login with new password -> Click Send -> Check if MFA is prompted
   ```
4. Check if reset clears MFA settings by inspecting account settings post-reset.
5. Analyze responses; expected secure response requires MFA re-prompt after reset.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "MFA verification required"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Login successful"}
[MFA bypassed or disabled]
```

**Remediation**:
- Enforce MFA post-reset (Node.js):
  ```javascript
  app.post('/reset-password', (req, res) => {
      const { token, new_password } = req.body;
      if (!validate_token(token)) {
          return res.status(400).json({ error: 'Invalid token' });
      }
      // Update password but retain MFA settings
      update_password(new_password);
      return res.status(200).json({ status: 'Password reset, MFA re-prompt required' });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., MFA bypass).

### 7. Test User Enumeration via Reset Requests with cURL

**Objective**: Ensure reset request responses do not reveal whether an email is registered.

**Steps**:
1. Submit a password reset request for a registered email:
   ```bash
   curl -i -X POST -d "email=registered@example.com" https://example.com/reset-password-request
   ```
2. Submit a password reset request for an unregistered email:
   ```bash
   curl -i -X POST -d "email=unregistered@example.com" https://example.com/reset-password-request
   ```
3. Compare responses; expected secure response is identical for both cases.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "If this account exists, you will receive an email"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent"} [Registered email]
HTTP/1.1 404 Not Found
Content-Type: application/json
{"error": "Email not found"} [Unregistered email]
```

**Remediation**:
- Return generic responses (Python/Flask):
  ```python
  @app.post('/reset-password-request')
  def reset_password_request():
      email = request.form['email']
      # Always return generic message
      return jsonify({'status': 'If this account exists, you will receive an email'})
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., enumeration via response differences).

### 8. Test CSRF on Password Change with Burp Suite

**Objective**: Ensure password change endpoints are protected against Cross-Site Request Forgery (CSRF).

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Craft a cross-origin form to submit a password change request:
   ```html
   <form action="https://example.com/change-password" method="POST">
       <input type="hidden" name="new_password" value="AttackerPass123!">
       <input type="submit" value="Submit">
   </form>
   ```
3. Host the form on a local server (e.g., `python -m http.server 8000`) and submit it.
4. Check if the request succeeds without a CSRF token:
   ```
   HTTP History -> Select POST /change-password -> Check for CSRF token
   ```
5. Analyze responses; expected secure response rejects requests without valid CSRF tokens.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Invalid CSRF token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Password changed successfully"}
```

**Remediation**:
- Implement CSRF tokens (Node.js):
  ```javascript
  const csrf = require('csurf');
  app.use(csrf());
  app.post('/change-password', (req, res) => {
      if (!req.csrfToken()) {
          return res.status(403).json({ error: 'Invalid CSRF token' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save Burp Suite HTTP History responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., lack of CSRF protection).

### 9. Test Brute-Forcing Token or Email Inputs with Burp Suite and Scripts

**Objective**: Ensure reset tokens and email inputs are resistant to brute-force attacks.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Use Burp Intruder to test token guessing:
   ```
   Intruder -> Select POST /reset-password -> Set token as payload position -> Use wordlist (e.g., 0000-9999) -> Start Attack
   ```
3. Use a Python script to test high-volume email submissions:
   ```python
   import requests
   emails = ['test1@example.com', 'test2@example.com']
   for email in emails:
       response = requests.post('https://example.com/reset-password-request', data={'email': email})
       print(response.json())
   ```
4. Analyze responses; expected secure response includes lockouts or long, random tokens.

**Example Secure Response**:
```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
{"error": "Too many attempts, account locked"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent"}
[Short or predictable tokens]
```

**Remediation**:
- Use long, random tokens and lockouts (Python/Flask):
  ```python
  import secrets
  @app.post('/reset-password')
  def reset_password():
      token = request.form['token']
      if not validate_token(token) or attempts_exceeded(token, max_attempts=5):
          return jsonify({'error': 'Too many attempts, account locked'}), 429
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Burp Intruder results and script outputs as screenshots or logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., brute-force success).

### 10. Test Role-Based Reset Logic Abuse with cURL

**Objective**: Ensure regular users cannot reset admin accounts via ID or email manipulation.

**Steps**:
1. Identify the reset request endpoint (e.g., `POST /reset-password-request`).
2. Submit a reset request using a known admin email or ID:
   ```bash
   curl -i -X POST -d "email=admin@example.com" https://example.com/reset-password-request
   ```
3. Try manipulating user IDs if applicable:
   ```bash
   curl -i -X POST -d "user_id=1" https://example.com/reset-password-request
   ```
4. Analyze responses; expected secure response restricts resets to the authenticated user.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Unauthorized reset attempt"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent"}
```

**Remediation**:
- Restrict resets to authenticated users (Node.js):
  ```javascript
  app.post('/reset-password-request', (req, res) => {
      const { email } = req.body;
      if (email !== req.user.email) {
          return res.status(403).json({ error: 'Unauthorized reset attempt' });
      }
      res.json({ status: 'Reset link sent' });
  });
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., admin reset).

### 11. Test Reset Token Transport Security with Burp Suite

**Objective**: Ensure reset tokens are transmitted securely over HTTPS and pages include proper cache controls.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Submit a password reset request and check if it uses HTTPS:
   ```
   HTTP History -> Select POST /reset-password-request -> Verify protocol is HTTPS
   ```
3. Inspect reset page headers for cache controls:
   ```
   HTTP History -> Select GET /reset-password -> Check for Cache-Control: no-store
   ```
4. Attempt to access the reset endpoint over HTTP:
   ```bash
   curl -i http://example.com/reset-password
   ```
5. Analyze findings; expected secure response uses HTTPS and includes `Cache-Control: no-store`.

**Example Secure Response**:
```
HTTP/1.1 301 Moved Permanently
Location: https://example.com/reset-password
Cache-Control: no-store
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[Over HTTP or missing Cache-Control: no-store]
```

**Remediation**:
- Enforce HTTPS and cache controls (Node.js):
  ```javascript
  app.use((req, res, next) => {
      res.setHeader('Cache-Control', 'no-store');
      if (!req.secure) {
          return res.redirect(301, `https://${req.headers.host}${req.url}`);
      }
      next();
  });
  ```

**Tip**: Save Burp Suite HTTP History responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP usage).

### 12. Test Reset Token Logging, Monitoring, and Alerts

**Objective**: Ensure reset attempts are logged and monitored with alerting for suspicious activity.

**Steps**:
1. Submit multiple reset requests to trigger potential alerts:
   ```bash
   for i in {1..10}; do curl -i -X POST -d "email=user@example.com" https://example.com/reset-password-request; done
   ```
2. Attempt invalid token submissions:
   ```bash
   curl -i -X POST -d "token=invalid_token" https://example.com/reset-password
   ```
3. Request server logs or monitoring setup details from the application owner (if permitted).
4. Analyze findings; expected secure setup logs user ID, IP, timestamp, and result, with alerts for brute-force patterns (e.g., 5 failed resets per minute).

**Example Secure Log**:
```
2025-05-26T16:44:00Z [INFO] Reset attempt: user_id=123, ip=192.168.1.1, result=failed, reason=invalid_token
2025-05-26T16:44:01Z [ALERT] 5 failed resets in 1 minute for user_id=123
```

**Example Vulnerable Log**:
```
[No logs or monitoring]
```

**Remediation**:
- Implement logging and alerting (Python/Flask):
  ```python
  import logging
  logging.basicConfig(filename='reset.log', level=logging.INFO)
  @app.post('/reset-password')
  def reset_password():
      token = request.form['token']
      logging.info(f'Reset attempt: user_id={request.user.id}, ip={request.remote_addr}, result={validate_token(token)}')
      if attempts_exceeded(request.user.id, max_attempts=5):
          send_alert('Brute-force detected', request.user.id)
          return jsonify({'error': 'Too many attempts'}), 429
      return jsonify({'status': 'success'})
  ```

**Tip**: Request log samples from the application owner (if permitted). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., lack of logging).

### 13. Test Expiration Timing Consistency with Burp Suite

**Objective**: Ensure token expiration is enforced server-side and not bypassable via client-side manipulation.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Request a password reset and receive a token.
3. Wait until the token expires (e.g., 24 hours) and attempt to use it:
   ```
   Repeater -> Change POST /reset-password with token=expired_token -> Click Send -> Check response
   ```
4. Manipulate client-side timers (if present in JavaScript) to bypass expiration:
   ```
   HTTP History -> Select GET /reset-password -> Inspect JavaScript for client-side timer -> Modify timer in browser console
   ```
5. Analyze responses; expected secure response enforces expiration server-side.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Expired token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Password reset successfully"}
[Client-side timer bypass]
```

**Remediation**:
- Enforce server-side expiration (Python/Flask):
  ```python
  from datetime import datetime, timedelta
  @app.post('/reset-password')
  def reset_password():
      token = request.form['token']
      if token_expired(token, max_age=timedelta(hours=24)):
          return jsonify({'error': 'Expired token'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., client-side expiration bypass).
