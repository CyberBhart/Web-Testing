# Testing for Weak Password Policy

## Overview

Testing for Weak Password Policy (WSTG-AUTH-07) involves verifying that a web application enforces a strong password policy to prevent the use of weak, easily guessable passwords that could be exploited in brute-force or credential-stuffing attacks. According to OWASP, weak password policies—such as accepting short passwords, lacking complexity requirements, or allowing common passwords—can compromise account security. This test focuses on validating password policy enforcement during account creation, password reset, and password change workflows, ensuring rejection of common passwords and providing clear error messages without exposing sensitive information.

**Impact**: Weak password policies can lead to:
- Successful brute-force or credential-stuffing attacks.
- Unauthorized access to user accounts.
- Increased risk of account compromise in data breaches.
- Non-compliance with security standards (e.g., PCI DSS, NIST 800-63B).

This guide provides a practical, hands-on methodology for testing password policy vulnerabilities, adhering to OWASP’s WSTG-AUTH-07, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as submitting multiple registration or password change requests may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing password policy weaknesses, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test password policy enforcement.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test password policies in registration or reset endpoints.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects error messages for policy requirements.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-07, focusing on testing password policy enforcement during account creation, password reset, password change, common password rejection, and error message clarity.

### 1. Test Password Policy During Account Creation with Burp Suite

**Objective**: Ensure account creation enforces a strong password policy.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Submit an account creation request with a weak password (e.g., "pass"):
   ```
   HTTP History -> Select POST /register -> Send to Repeater
   ```
3. Test various weak passwords (e.g., "123456", "abc"):
   ```
   Repeater -> Change password=pass to password=123456 -> Click Send -> Check response
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
{"status": "Account created successfully"}
```

**Remediation**:
- Enforce strong password policy (Node.js):
  ```javascript
  app.post('/register', (req, res) => {
      const { password } = req.body;
      if (!/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/.test(password)) {
          return res.status(400).json({ error: 'Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Password Policy During Password Reset with cURL

**Objective**: Verify that password reset enforces a strong password policy.

**Steps**:
1. Identify the password reset endpoint (e.g., `POST /reset-password`) using Burp Suite.
2. Submit a reset request with a weak password:
   ```bash
   curl -i -X POST -d "password=pass" https://example.com/reset-password
   ```
3. Test another weak password (e.g., "abc"):
   ```bash
   curl -i -X POST -d "password=abc" https://example.com/reset-password
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
{"status": "Password reset successfully"}
```

**Remediation**:
- Enforce password policy for reset (Python/Flask):
  ```python
  @app.post('/reset-password')
  def reset_password():
      password = request.form['password']
      if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$', password):
          return jsonify({'error': 'Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Password Policy Error Messages with Browser Developer Tools

**Objective**: Ensure error messages for weak passwords are clear but not overly verbose.

**Steps**:
1. Access the account creation or password reset page (e.g., `https://example.com/register`) and submit a weak password.
2. Inspect the error message in the browser:
   ```
   Network tab -> Select POST /register -> Check Response for error message
   ```
3. Repeat with another weak password to verify consistency:
   ```
   Network tab -> Select POST /register with password=abc -> Check Response for error message
   ```
4. Analyze responses; expected secure response provides guidance without exposing backend details.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "SQL Error: Password field too short"}
```

**Remediation**:
- Provide clear error messages (Node.js):
  ```javascript
  app.post('/register', (req, res) => {
      const { password } = req.body;
      if (password.length < 8) {
          return res.status(400).json({ error: 'Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save screenshots of Browser Developer Tools Network tab showing error messages. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., verbose errors).

### 4. Test Password Policy During Password Change with Burp Suite

**Objective**: Ensure password change endpoints enforce a strong password policy.

**Steps**:
1. Log in and configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Capture a password change request (e.g., `POST /change-password`):
   ```
   HTTP History -> Select POST /change-password -> Send to Repeater
   ```
3. Submit a weak password (e.g., "pass"):
   ```
   Repeater -> Change new_password=pass -> Click Send -> Check response
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
- Enforce password policy for change (Node.js):
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

### 5. Test Common Password Rejection with cURL

**Objective**: Ensure the application rejects common or dictionary passwords during account creation.

**Steps**:
1. Identify the account creation endpoint (e.g., `POST /register`) using Burp Suite.
2. Submit a registration request with a common password (e.g., "password123"):
   ```bash
   curl -i -X POST -d "username=user123&password=password123" https://example.com/register
   ```
3. Test another common password (e.g., "admin123"):
   ```bash
   curl -i -X POST -d "username=user123&password=admin123" https://example.com/register
   ```
4. Analyze responses; expected secure response rejects common passwords with a clear error.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Password is too common, choose a stronger password"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created successfully"}
```

**Remediation**:
- Reject common passwords (Python/Flask):
  ```python
  common_passwords = {'password123', 'admin123', 'qwerty'}
  @app.post('/register')
  def register():
      password = request.form['password']
      if password in common_passwords:
          return jsonify({'error': 'Password is too common, choose a stronger password'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).