# Testing for Weak Password Change or Reset Functionalities

## Overview

Testing for Weak Password Change or Reset Functionalities (WSTG-AUTH-09) involves verifying that password change and reset mechanisms are securely implemented to prevent unauthorized access or account takeover. According to OWASP, vulnerabilities such as weak password policies, insecure reset token generation, lack of rate limiting, or improper authentication can allow attackers to compromise accounts. This test focuses on evaluating password policy enforcement, reset token security, authentication requirements, rate limiting, and token exposure in password change and reset workflows.

**Impact**: Weak password change or reset functionalities can lead to:
- Unauthorized password changes or account takeovers.
- Exploitation of predictable or exposed reset tokens.
- Brute-force attacks on reset requests or tokens.
- Non-compliance with security standards (e.g., NIST 800-63B, GDPR).

This guide provides a practical, hands-on methodology for testing password change and reset vulnerabilities, adhering to OWASP’s WSTG-AUTH-09, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as submitting multiple reset requests or manipulating tokens may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing weak password change or reset functionalities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test password policies, authentication, and token exposure.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test reset token security and rate limiting.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-09, focusing on testing password policy enforcement, reset token security, authentication requirements, rate limiting, and token exposure in password change and reset workflows.

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

**Objective**: Verify that password reset tokens are unpredictable, time-limited, and properly validated.

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
4. Analyze responses; expected secure response includes unique, random tokens and rejection of expired tokens.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Invalid or expired token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Password reset successfully"}
[Sequential or predictable tokens: token=123, token=124]
```

**Remediation**:
- Generate secure, time-limited tokens (Python/Flask):
  ```python
  import secrets
  from datetime import datetime, timedelta
  @app.post('/reset-password')
  def reset_password():
      token = request.form['token']
      if not validate_token(token) or token_expired(token, max_age=timedelta(hours=24)):
          return jsonify({'error': 'Invalid or expired token'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., predictable tokens).

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

**Objective**: Ensure reset tokens are not exposed in HTTP responses or client-side code.

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
4. Analyze findings; expected secure response contains no token in responses or code.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent"}
[No token in response or client-side code]
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Reset link sent", "token": "xyz123"}
```

**Remediation**:
- Avoid token exposure (Python/Flask):
  ```python
  @app.post('/reset-password-request')
  def reset_password_request():
      # Send token via email, not in response
      return jsonify({'status': 'Reset link sent'})
  ```

**Tip**: Save Burp Suite HTTP History responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., exposed tokens).