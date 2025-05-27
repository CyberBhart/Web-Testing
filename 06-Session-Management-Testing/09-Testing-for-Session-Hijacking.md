# Testing for Session Hijacking

## Overview

Testing for Session Hijacking (WSTG-SESS-09) involves assessing a web application to ensure that session identifiers are securely generated, transmitted, and stored, preventing attackers from stealing or misusing them to impersonate users. According to OWASP, session hijacking vulnerabilities allow attackers to gain unauthorized access to user sessions, potentially compromising sensitive data or functionality. This test focuses on verifying session ID security, transmission encryption, and invalidation mechanisms to mitigate hijacking risks.

**Impact**: Session hijacking vulnerabilities can lead to:
- Unauthorized access to user accounts, enabling actions like data theft or account changes.
- Privilege escalation if admin or privileged sessions are hijacked.
- Data exposure or financial loss in sensitive applications.
- Reputational damage from compromised user sessions.

This guide provides a practical, hands-on methodology for testing session hijacking, adhering to OWASP’s WSTG-SESS-09, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing session hijacking, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts requests and analyzes session ID randomness.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Wireshark**: Captures network traffic to detect unencrypted session IDs.
  - Download from [wireshark.org](https://www.wireshark.org/download.html).
  - Install and configure network interface (e.g., Wi-Fi, Ethernet).

- **Postman**: Tests session ID behavior in API endpoints.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests to verify session ID exposure or reuse.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects cookies and client-side session ID exposure.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates session ID manipulation and hijacking tests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-09, focusing on testing session ID exposure, transmission security, session ID strength, session fixation, session reuse, XSS exploitation, and network sniffing.

### 1. Test Session ID Exposure with Burp Suite

**Objective**: Check if session IDs are exposed in URLs, logs, or client-side code.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Requests**:
   - Log in and navigate the application, checking “HTTP History” for session IDs in URLs (e.g., `?sessionid=abc123`), cookies, or headers.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Request tab -> Look for ?sessionid=abc123
     ```
3. **Test Exposure**:
   - Look for session IDs in referer headers, error messages, or client-side code.
   - Test an exposed session ID in a new session.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc123 -> Click Send -> Check response
     ```
4. **Analyze Findings**:
   - Vulnerable: Session ID exposed and usable.
   - Expected secure response: Session IDs only in secure cookies; URLs clean.

**Remediation**:
- Use cookies for session IDs:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.cookies.session) {
          return res.status(401).json({ error: 'Unauthorized' });
      }
      res.send('Dashboard');
  });
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Transmission Security with Wireshark

**Objective**: Ensure session IDs are transmitted only over encrypted channels.

**Steps**:
1. **Configure Wireshark**:
   - Start Wireshark and select the network interface (e.g., Wi-Fi).
   - Apply filter: `http` to capture HTTP traffic.
2. **Capture Traffic**:
   - Access the application over HTTP (e.g., `http://example.com/login`) and log in.
   - Check Wireshark for session cookies or IDs in HTTP packets.
   - Command:
     ```
     Filter: http -> Apply -> Access http://example.com/login -> Look for Cookie header
     ```
3. **Analyze Findings**:
   - Look for `Cookie: session=abc123` in HTTP packets.
   - Command:
     ```
     Filter: http.request -> Select packet -> Inspect HTTP -> Look for Cookie: session=abc123
     ```
   - Vulnerable: Session ID sent over HTTP.
   - Expected secure response: No session data in HTTP; all traffic over HTTPS.

**Remediation**:
- Enforce HTTPS with HSTS:
  ```javascript
  app.use((req, res, next) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      if (!req.secure) {
          return res.redirect(`https://${req.get('host')}${req.url}`);
      }
      next();
  });
  ```

**Tip**: Save Wireshark packet captures as PCAP files. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., packet captures).

### 3. Test Session ID Strength with Burp Suite Sequencer

**Objective**: Verify that session IDs are random and unpredictable.

**Steps**:
1. **Configure Burp Suite Sequencer**:
   - Log in multiple times to capture session cookies in “HTTP History”.
   - Select a `Set-Cookie: session=abc123` response and send to Sequencer.
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Right-click Set-Cookie -> Send to Sequencer -> Start Capture
     ```
2. **Analyze Randomness**:
   - Run Sequencer to collect 100+ session IDs.
   - Check entropy analysis for predictability (e.g., sequential or timestamp-based IDs).
3. **Test Guessing**:
   - Generate a predicted session ID (e.g., incrementing numbers) and test it.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Set Cookie: session=abc124 -> Click Send -> Check response
     ```
4. **Analyze Findings**:
   - Vulnerable: Low entropy or predictable IDs.
   - Expected secure response: High entropy, random IDs.

**Remediation**:
- Generate random session IDs:
  ```python
  from flask import Flask, session
  import secrets
  app = Flask(__name__)
  @app.post('/login')
  def login():
      session['id'] = secrets.token_urlsafe(32)
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Sequencer reports as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., entropy analysis).

### 4. Test Session Fixation with cURL

**Objective**: Check if attackers can force a known session ID on a user.

**Steps**:
1. **Set Known Session ID**:
   - Access the application with a predefined session ID (e.g., `session=attacker123`).
   - Command:
     ```bash
     curl -i -b "session=attacker123" http://example.com/login
     ```
2. **Authenticate**:
   - Log in using the same session ID and check if the server accepts it.
   - Command:
     ```bash
     curl -i -b "session=attacker123" -d "username=test&password=Secure123" -X POST http://example.com/login
     curl -i -b "session=attacker123" http://example.com/dashboard
     ```
3. **Test Hijacking**:
   - Use the known session ID in another session to access protected resources.
4. **Analyze Findings**:
   - Vulnerable: Known session ID is accepted post-authentication.
   - Expected secure response: New session ID generated on login.

**Remediation**:
- Regenerate session ID on login:
  ```javascript
  app.post('/login', (req, res) => {
      req.session.regenerate((err) => {
          if (err) return res.status(500).json({ error: 'Login failed' });
          req.session.user = 'test';
          res.json({ status: 'success' });
      });
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test XSS-Based Session Theft with Browser Developer Tools

**Objective**: Assess if XSS vulnerabilities can steal session IDs.

**Steps**:
1. **Identify XSS Vulnerability**:
   - Test for XSS (e.g., via input fields) using payloads like `<script>alert(document.cookie)</script>`.
   - Command:
     ```
     Elements tab -> Edit input field -> Set value to <script>alert(document.cookie)</script> -> Submit form -> Check alert
     ```
2. **Steal Session ID**:
   - Inject a payload to send `document.cookie` to an attacker-controlled server.
   - Command:
     ```
     Console tab -> Run: document.cookie -> Check if session=abc123 is returned
     ```
3. **Test Hijacking**:
   - Use the stolen session ID to access protected resources.
4. **Analyze Findings**:
   - Vulnerable: Cookie stolen and usable.
   - Expected secure response: `HttpOnly` prevents cookie access.

**Remediation**:
- Set `HttpOnly` on cookies:
  ```python
  response.set_cookie('session', 'abc123', httponly=True, secure=True, samesite='Strict')
  ```

**Tip**: Save screenshots of the Console and Network tabs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., screenshots).

### 6. Automate Session Hijacking Testing with Python Requests

**Objective**: Automate testing to detect session ID vulnerabilities.

**Steps**:
1. **Write Python Script**:
   - Create a script to test session ID exposure, fixation, and reuse:
     ```python
     import requests

     base_url = 'http://example.com'
     login_url = f'{base_url}/login'
     dashboard_url = f'{base_url}/dashboard'

     # Test session fixation
     session = requests.Session()
     session.cookies.set('session', 'attacker123')
     response = session.post(login_url, data={'username': 'test', 'password': 'Secure123'})
     response = session.get(dashboard_url)
     print(f"Fixation test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session fixation succeeded")

     # Test session ID exposure in URL
     response = session.get(f'{base_url}/dashboard?sessionid=abc123')
     if 'sessionid' in response.url:
         print(f"Vulnerable: Session ID in URL: {response.url}")

     # Test session reuse after logout
     session_cookie = session.cookies.get('session')
     session.post(f'{base_url}/logout')
     response = session.get(dashboard_url, cookies={'session': session_cookie})
     print(f"Reuse test: Status={response.status_code}, Response={response.text[:100]}")
     if response.status_code == 200 and 'dashboard' in response.text.lower():
         print("Vulnerable: Session ID reused after logout")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_session_hijacking.py
     ```
3. **Test Session Fixation**:
   - Command:
     ```bash
     python3 -c "import requests; s=requests.Session(); s.cookies.set('session', 'attacker123'); s.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); r=s.get('http://example.com/dashboard'); print(r.status_code, r.text[:100])"
     ```
4. **Verify Findings**:
   - Vulnerable: Session fixation, exposure, or reuse detected.
   - Expected secure response: HTTP 401 or 403 for invalid sessions.

**Remediation**:
- Secure session handling:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/login')
  def login():
      session.regenerate()  # Prevent fixation
      session['user'] = 'test'
      response = make_response({'status': 'success'})
      response.set_cookie('session', session.sid, httponly=True, secure=True, samesite='Strict')
      return response
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_session_hijacking.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).