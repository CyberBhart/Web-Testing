# Testing for Vulnerable Remember Password

## Overview

Testing for Vulnerable Remember Password (WSTG-AUTH-05) involves verifying that "Remember Me" or "Remember Password" functionalities in web applications are implemented securely to prevent unauthorized access. According to OWASP, insecure storage of credentials or tokens in cookies, local storage, or predictable formats can allow attackers to hijack accounts if a device is compromised or data is intercepted. This test focuses on checking for plaintext or weakly encrypted credentials, predictable or long-lived tokens, improper server-side validation, and exposure to theft via XSS attacks.

**Impact**: Vulnerable "Remember Me" implementations can lead to:
- Unauthorized account access if cookies or tokens are stolen.
- Session hijacking via intercepted or predictable tokens.
- Exposure of sensitive credentials in client-side storage.
- Compromise of user accounts on shared or compromised devices.

This guide provides a practical, hands-on methodology for testing "Remember Me" vulnerabilities, adhering to OWASP’s WSTG-AUTH-05, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as inspecting cookies or tampering with tokens may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing "Remember Me" vulnerabilities, with setup and configuration instructions:

- **Browser Developer Tools**: Inspects cookies, local storage, and session storage for sensitive data.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Burp Suite Community Edition**: Intercepts and analyzes "Remember Me" tokens for predictability or validation issues.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-05, focusing on testing cookie security, token predictability, client-side storage, server-side validation, and protection against token theft.

### 1. Test Cookies for Plaintext or Weakly Encrypted Credentials with Browser Developer Tools

**Objective**: Ensure "Remember Me" cookies do not store plaintext or weakly encoded credentials.

**Steps**:
1. Access the login page (e.g., `https://example.com/login`), enable "Remember Me," and log in.
2. Open Browser Developer Tools and inspect cookies for plaintext or Base64-encoded credentials:
   ```
   Application tab -> Cookies -> Select https://example.com -> Check for username, password, or Base64 data
   ```
3. Decode any Base64-encoded cookie values to check for credentials:
   ```
   Console tab -> Type atob('encoded_value') -> Check if output contains username or password
   ```
4. Analyze findings; expected secure response is no credentials or strong encryption in cookies.

**Example Secure Response**:
```
Cookie: remember_token=xyz123; HttpOnly; Secure
[No username or password in cookie]
```

**Example Vulnerable Response**:
```
Cookie: credentials=dXNlcm5hbWU6cGFzc3dvcmQ= [Base64: username:password]
```

**Remediation**:
- Avoid storing credentials in cookies (Python/Flask):
  ```python
  @app.post('/login')
  def login():
      response = jsonify({'status': 'success'})
      response.set_cookie('remember_token', generate_secure_token(), httponly=True, secure=True)
      return response
  ```

**Tip**: Save screenshots of Browser Developer Tools cookie and console tabs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., cookie contents).

### 2. Test Token Predictability and Lifetime with Burp Suite

**Objective**: Verify that "Remember Me" tokens are unpredictable and have a reasonable expiration.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Log in with "Remember Me" enabled, capture the cookie (e.g., `remember_token`), and check for predictability:
   ```
   HTTP History -> Select GET /dashboard -> Check Cookie: remember_token for sequential or simple values
   ```
3. Log in again to compare tokens and test lifetime by resending an old token after a week:
   ```
   Repeater -> Use Cookie: remember_token=old_value after 7 days -> Click Send -> Check response
   ```
4. Analyze responses; expected secure response is unique, random tokens and rejection of expired tokens.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Expired or invalid token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<html>Dashboard content</html>
```

**Remediation**:
- Generate secure tokens with expiration (Node.js):
  ```javascript
  const crypto = require('crypto');
  app.post('/login', (req, res) => {
      const token = crypto.randomBytes(32).toString('hex');
      res.cookie('remember_token', token, { maxAge: 604800000, httpOnly: true, secure: true });
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save Burp Suite HTTP History and Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., predictable tokens).

### 3. Test Local Storage for Sensitive Data with Browser Developer Tools

**Objective**: Ensure "Remember Me" credentials or tokens are not stored in local or session storage.

**Steps**:
1. Log in with "Remember Me" enabled and open Browser Developer Tools.
2. Check local storage for sensitive data:
   ```
   Application tab -> Local Storage -> Select https://example.com -> Check for username, password, or token
   ```
3. Check session storage for similar data:
   ```
   Application tab -> Session Storage -> Select https://example.com -> Check for username, password, or token
   ```
4. Analyze findings; expected secure response is no sensitive data in local or session storage.

**Example Secure Response**:
```
[No username, password, or token in Local Storage or Session Storage]
```

**Example Vulnerable Response**:
```
Local Storage: {"username": "user", "token": "xyz123"}
```

**Remediation**:
- Avoid local storage for tokens (Python/Flask):
  ```python
  @app.post('/login')
  def login():
      response = jsonify({'status': 'success'})
      response.set_cookie('remember_token', 'xyz123', httponly=True, secure=True)
      return response
  ```

**Tip**: Save screenshots of Browser Developer Tools storage tabs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., storage contents).

### 4. Test Server-Side Validation of Remember Me Tokens with Burp Suite

**Objective**: Ensure the server rejects invalid or tampered "Remember Me" tokens.

**Steps**:
1. Log in with "Remember Me" enabled and capture a request with the token (e.g., `Cookie: remember_token=xyz123`) in Burp Suite:
   ```
   HTTP History -> Select GET /dashboard with Cookie: remember_token=xyz123 -> Send to Repeater
   ```
2. Tamper with the token (e.g., change to `remember_token=abc123`) and resend:
   ```
   Repeater -> Change remember_token=xyz123 to remember_token=abc123 -> Click Send -> Check response
   ```
3. Analyze responses; expected secure response is rejection of the tampered token.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "Invalid remember token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<html>Dashboard content</html>
```

**Remediation**:
- Validate tokens server-side (Node.js):
  ```javascript
  app.get('/dashboard', (req, res) => {
      const token = req.cookies.remember_token;
      if (!token || !validateToken(token)) {
          return res.status(401).json({ error: 'Invalid remember token' });
      }
      res.send('Dashboard content');
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Remember Me Token Theft via XSS with Browser Developer Tools

**Objective**: Ensure "Remember Me" tokens are protected against theft via XSS.

**Steps**:
1. Log in with "Remember Me" enabled and open Browser Developer Tools.
2. Inspect the "Remember Me" cookie for `HttpOnly` and `Secure` attributes:
   ```
   Application tab -> Cookies -> Select https://example.com -> Verify remember_token has HttpOnly and Secure
   ```
3. Check local storage to ensure tokens are not exposed to JavaScript:
   ```
   Application tab -> Local Storage -> Check for remember_token presence
   ```
4. Analyze findings; expected secure response is `HttpOnly` and `Secure` attributes with no token in local storage.

**Example Secure Response**:
```
Cookie: remember_token=xyz123; HttpOnly; Secure
[No remember_token in Local Storage]
```

**Example Vulnerable Response**:
```
Cookie: remember_token=xyz123
Local Storage: {"remember_token": "xyz123"}
```

**Remediation**:
- Set secure cookie attributes (Python/Flask):
  ```python
  @app.post('/login')
  def login():
      response = jsonify({'status': 'success'})
      response.set_cookie('remember_token', 'xyz123', httponly=True, secure=True, max_age=604800)
      return response
  ```

**Tip**: Save screenshots of Browser Developer Tools cookie and storage tabs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., missing attributes).