# Testing for Session Management Schema

## Overview

Testing for Session Management Schema (WSTG-SESS-01) involves assessing a web application’s session management mechanisms to ensure that sessions are securely created, maintained, and terminated, preventing vulnerabilities like session hijacking, fixation, or prediction. According to OWASP, weak session management can allow attackers to steal or manipulate session identifiers, gaining unauthorized access to user accounts. This test focuses on analyzing session identifier generation, cookie attributes, session lifecycle, and transmission to identify and mitigate risks in the session management schema.

**Impact**: Weak session management can lead to:
- Session hijacking by stealing or predicting session identifiers.
- Session fixation, where attackers force users to use known session IDs.
- Unauthorized access due to improper session termination or insecure attributes.
- Information disclosure through session IDs in URLs or unencrypted channels.

This guide provides a practical, hands-on methodology for testing the session management schema, adhering to OWASP’s WSTG-SESS-01, with detailed tool setups, specific commands integrated into test steps, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing the session management schema, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and analyzes session cookies and requests for secure attributes and fixation.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests API endpoints for session handling and regeneration.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests to inspect session IDs and lifecycle behavior.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects cookies, headers, and client-side session handling.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates session ID collection and analysis for randomness.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-01, focusing on testing session identifier generation, cookie attributes, session lifecycle, fixation, and transmission. The following tests provide practical, hands-on guidance, integrating real-world scenarios for common session management vulnerabilities observed in penetration testing.

### 1. Analyze Session Cookie Attributes with Burp Suite

**Objective**: Inspect session cookies for secure attributes (e.g., `HttpOnly`, `Secure`, `SameSite`) and proper configuration to prevent vulnerabilities like session hijacking or client-side access.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Login Request**:
   - Log in to the application and check “HTTP History” for the `Set-Cookie` header in the response (e.g., `session=abc123`).
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie: session=abc123
     ```
3. **Inspect Attributes**:
   - Verify presence of `HttpOnly`, `Secure`, and `SameSite` attributes.
   - Check cookie expiration (e.g., `Expires` or `Max-Age`).
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Note missing attributes (e.g., HttpOnly, Secure, SameSite)
     ```
4. **Test Insecure Access**:
   - Access the cookie via JavaScript in Browser Developer Tools to confirm `HttpOnly` enforcement.
     ```
     Console tab -> Run: document.cookie -> Check if session=abc123 is accessible
     ```
   - Test cookie transmission over HTTP:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Change https:// to http:// -> Click Send -> Check if cookie is sent
     ```
5. **Analyze Findings**:
   - Missing attributes (e.g., no `HttpOnly`) indicate vulnerabilities.
   - Expected secure response: All attributes set (e.g., `HttpOnly; Secure; SameSite=Strict`).
   - Example vulnerable response:
     ```
     HTTP/1.1 200 OK
     Set-Cookie: session=abc123; Path=/
     ```

**Remediation**:
- Set secure cookie attributes:
  ```javascript
  res.cookie('session', 'abc123', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
  });
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Session Fixation with Postman

**Objective**: Verify that the application regenerates session IDs upon authentication to prevent session fixation, where an attacker forces a user to use a known session ID.

**Steps**:
1. **Identify Login Endpoint**:
   - Use Burp Suite to find `POST /login` and import into Postman.
2. **Test Pre-Authentication Session**:
   - Send an unauthenticated request to get a session ID (e.g., `GET /`).
   - Command:
     ```
     New Request -> GET http://example.com/ -> Send -> Note Cookie: session=abc123
     ```
3. **Log In with Same Session**:
   - Send a login request using the same session ID and check if it changes.
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Headers: Cookie: session=abc123 -> Send -> Check Set-Cookie
     ```
4. **Analyze Responses**:
   - Compare session IDs before and after login.
   - Expected secure response: New session ID after login.
   - Vulnerable response: Same session ID persists (e.g., `Set-Cookie: session=abc123` pre- and post-login).

**Remediation**:
- Regenerate session ID on login:
  ```javascript
  app.post('/login', (req, res) => {
      req.session.regenerate(() => {
          // Set new session ID
          res.json({ status: 'success' });
      });
  });
  ```

**Tip**: Capture requests and responses as JSON or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Session Invalidation with cURL

**Objective**: Check if sessions are invalidated server-side after logout or timeout to prevent reuse of old session IDs.

**Steps**:
1. **Log In and Capture Session**:
   - Log in and note the session ID from the `Set-Cookie` header.
   - Command:
     ```bash
     curl -i -X POST -d "username=test&password=Secure123" http://example.com/login
     ```
2. **Test Logout**:
   - Send a logout request (e.g., `POST /logout`).
   - Reuse the old session ID to access a protected resource (e.g., `/dashboard`).
   - Command:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
3. **Test Timeout**:
   - Wait for the session timeout period (e.g., 30 minutes) and try reusing the session ID.
   - Command:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
4. **Analyze Responses**:
   - Check if the old session ID grants access (HTTP 200).
   - Expected secure response: HTTP 401 or 403 after logout/timeout.
   - Example vulnerable response:
     ```
     HTTP/1.1 200 OK
     Content-Type: text/html
     Dashboard Content
     ```

**Remediation**:
- Invalidate sessions on logout:
  ```javascript
  app.post('/logout', (req, res) => {
      req.session.destroy();
      res.clearCookie('session');
      res.json({ status: 'success' });
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Inspect Session Transmission with Browser Developer Tools

**Objective**: Analyze how session IDs are transmitted to detect insecure practices, such as session IDs in URLs or unencrypted channels.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Requests**:
   - Check the “Network” tab for session IDs in URLs (e.g., `?session=abc123`) or HTTP headers.
   - Verify if requests use HTTPS (lock icon in browser).
   - Command:
     ```
     Network tab -> Select GET /dashboard -> Check for ?session=abc123 in Request URL
     ```
3. **Test Insecure Transmission**:
   - Force an HTTP request (e.g., edit URL to `http://`) and check if the session cookie is sent.
   - Command:
     ```
     Network tab -> Edit GET https://example.com/dashboard to http://example.com/dashboard -> Reload -> Check if Cookie header includes session
     ```
4. **Analyze Responses**:
   - Confirm session ID presence in URLs or HTTP transmission.
   - Expected secure response: Session ID only in cookies over HTTPS.
   - Example vulnerable request:
     ```
     GET /dashboard?session=abc123 HTTP/1.1
     ```

**Remediation**:
- Avoid session IDs in URLs and enforce HTTPS:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.cookies.session) {
          return res.status(401).json({ error: 'Unauthorized' });
      }
      res.send('Dashboard');
  });
  ```

**Tip**: Save screenshots of the Network tab and console outputs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Analyze Session ID Randomness with Python Requests

**Objective**: Collect and analyze session IDs to ensure they are unpredictable and cryptographically secure.

**Steps**:
1. **Write Python Script**:
   - Create a script to collect multiple session IDs:
     ```python
     import requests
     import base64
     import re

     url = 'http://example.com/login'
     session_ids = []
     for i in range(5):
         response = requests.get(url)
         session_id = response.cookies.get('session')
         if session_id:
             session_ids.append(session_id)
             print(f"Session ID {i+1}: {session_id}")
         # Check for patterns (e.g., incremental, timestamp)
         if len(session_ids) > 1:
             if any(s in session_ids[0] for s in session_ids[1:]):
                 print("Potential predictability detected")
     # Basic randomness check
     for sid in session_ids:
         try:
             decoded = base64.b64decode(sid).hex()
             print(f"Decoded {sid}: {decoded[:20]}...")
         except:
             print(f"{sid} not base64-encoded")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_session_ids.py
     ```
3. **Test Single Session ID**:
   - Command:
     ```bash
     python3 -c "import requests; r=requests.get('http://example.com/'); print(r.cookies.get('session'))"
     ```
4. **Verify Findings**:
   - Check if IDs are short, incremental, or timestamp-based.
   - Expected secure response: Long, random IDs with no patterns.
   - Example vulnerable output:
     ```
     Session ID 1: user1_123456
     Session ID 2: user2_123457
     Potential predictability detected
     ```

**Remediation**:
- Use cryptographically secure session IDs:
  ```python
  import secrets
  @app.route('/login')
  def login():
      session_id = secrets.token_urlsafe(32)
      response.set_cookie('session', session_id, httponly=True, secure=True, samesite='Strict')
      return response
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_session_ids.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., session ID patterns).
