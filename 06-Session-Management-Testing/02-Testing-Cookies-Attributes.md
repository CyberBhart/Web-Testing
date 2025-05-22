# Testing for Cookies Attributes

## Overview

Testing for Cookies Attributes (WSTG-SESS-02) involves assessing the security configuration of session cookies in a web application to ensure they are protected against unauthorized access, interception, or manipulation. According to OWASP, misconfigured cookie attributes can lead to vulnerabilities such as session hijacking, cross-site scripting (XSS), or cross-site request forgery (CSRF). This test focuses on verifying the presence and correctness of `HttpOnly`, `Secure`, `SameSite`, expiration, and scope attributes, as well as ensuring cookies do not contain sensitive data, to mitigate risks in session management.

**Impact**: Misconfigured cookie attributes can lead to:
- Session hijacking by intercepting cookies over unencrypted connections.
- Cookie theft through XSS attacks due to missing `HttpOnly` flags.
- CSRF attacks or unintended cookie sharing due to lax `SameSite` settings.
- Persistent sessions from missing or overly long expiration times, increasing exposure.

This guide provides a practical, hands-on methodology for testing cookie attributes, adhering to OWASP’s WSTG-SESS-02, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing cookie attributes, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and analyzes cookies for secure attributes and transmission.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests API responses for cookie settings and behavior.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests to inspect cookie headers and attributes.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects cookies, their attributes, and client-side accessibility.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Automates cookie collection and analysis for attributes and content.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-02, focusing on testing `HttpOnly`, `Secure`, `SameSite`, expiration, scope, and content of session cookies.

### 1. Inspect Cookie Attributes with Burp Suite

**Objective**: Analyze session cookies for `HttpOnly`, `Secure`, and `SameSite` attributes.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Login Response**:
   - Log in to the application and check “HTTP History” for the `Set-Cookie` header in the response.
   - Note the session cookie (e.g., `session=abc123`).
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie: session=abc123
     ```
3. **Inspect Attributes**:
   - Verify presence of `HttpOnly`, `Secure`, and `SameSite` (preferably `Strict` or `Lax`).
   - Check `Expires` or `Max-Age` for reasonable session duration (e.g., 30 minutes).
   - Ensure `Path` and `Domain` are appropriately scoped (e.g., `Path=/`, `Domain=example.com`).
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie -> Verify Path=/ and Domain=example.com
     ```
4. **Analyze Findings**:
   - Missing attributes or overly broad scope indicate vulnerabilities.
   - Expected secure response: `Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Max-Age=1800; Path=/`.

**Remediation**:
- Set secure cookie attributes:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          maxAge: 1800000, // 30 minutes
          path: '/',
          domain: 'example.com'
      }
  }));
  ```

**Tip**: Save requests and responses in the “Logger” or export as XML/JSON. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test HttpOnly Protection with Browser Developer Tools

**Objective**: Verify that session cookies are inaccessible to client-side scripts.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Cookies**:
   - Go to “Application” tab (Chrome) or “Storage” tab (Firefox) -> Cookies -> Check `session` cookie attributes.
   - Verify `HttpOnly` is checked.
   - Command:
     ```
     Application tab -> Cookies -> https://example.com -> Select session cookie -> Verify HttpOnly checkbox
     ```
3. **Test JavaScript Access**:
   - Run `document.cookie` in the “Console” tab to check if the session cookie is accessible.
   - Command:
     ```
     Console tab -> Run: document.cookie -> Check if session=abc123 is returned
     ```
   - Expected secure response: Cookie not visible (empty or missing `session`).
4. **Analyze Findings**:
   - If `session=abc123` appears, the `HttpOnly` flag is missing.

**Remediation**:
- Enable `HttpOnly` flag:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.route('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', httponly=True)
      return response
  ```

**Tip**: Save screenshots of the Network tab and console outputs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., console outputs).

### 3. Test Secure Flag with cURL

**Objective**: Ensure session cookies are only transmitted over HTTPS.

**Steps**:
1. **Log In and Capture Cookie**:
   - Log in to capture the session cookie (e.g., `session=abc123`).
   - Use Burp Suite to note the `Set-Cookie` header.
2. **Test HTTP Transmission**:
   - Send a request over HTTP to a protected resource (e.g., `/dashboard`).
   - Check if the session cookie is included in the request.
   - Command:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
3. **Compare HTTPS Request**:
   - Send the same request over HTTPS to confirm behavior.
   - Command:
     ```bash
     curl -i -b "session=abc123" https://example.com/dashboard
     ```
4. **Analyze Responses**:
   - If the cookie is sent over HTTP, the `Secure` flag is missing.
   - Expected secure response: Cookie not sent over HTTP; HTTP 401 or redirect to HTTPS.

**Remediation**:
- Enable `Secure` flag:
  ```javascript
  res.cookie('session', 'abc123', {
      secure: true,
      httpOnly: true,
      sameSite: 'strict'
  });
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test SameSite Protection with Postman

**Objective**: Verify that the `SameSite` attribute mitigates CSRF and cross-site attacks.

**Steps**:
1. **Identify Protected Endpoint**:
   - Use Burp Suite to find a state-changing endpoint (e.g., `POST /update-profile`).
   - Import into Postman.
2. **Simulate Cross-Site Request**:
   - Send a request from a different origin (e.g., `evil.com`) with the session cookie.
   - Command:
     ```
     New Request -> POST http://example.com/update-profile -> Body -> JSON: {"name": "test"} -> Headers: Cookie: session=abc123 -> Send
     ```
3. **Test Cross-Site GET**:
   - Send a GET request to verify `SameSite=Lax` behavior.
   - Command:
     ```
     New Request -> GET http://example.com/profile -> Headers: Cookie: session=abc123 -> Send
     ```
4. **Analyze Responses**:
   - Check if the POST request succeeds with the cookie.
   - Expected secure response: Cookie not sent if `SameSite=Strict`; HTTP 401 or 403. If `SameSite=Lax`, only safe methods (e.g., GET) may include the cookie.

**Remediation**:
- Set `SameSite=Strict`:
  ```python
  @app.route('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', httponly=True, secure=True, samesite='Strict')
      return response
  ```

**Tip**: Capture requests and responses as JSON or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Analyze Cookie Content and Expiration with Python Requests

**Objective**: Check cookie expiration times and ensure no sensitive data is stored in cookies.

**Steps**:
1. **Write Python Script**:
   - Create a script to collect and analyze cookies:
     ```python
     import requests
     import base64

     session = requests.Session()

     # Optional: Modify headers if needed by the target application
     headers = {
         'User-Agent': 'Mozilla/5.0',
         'Content-Type': 'application/x-www-form-urlencoded'
     }

     # Target login endpoint and credentials
     url = 'https://testing.com'
     data = {
         'username': 'test@gmail.com',
         'password': 'test@12345'
     }

     # Perform login request and follow redirects
     response = session.post(url, headers=headers, data=data, allow_redirects=True)

     print("\nCookie Security Attribute Assessment")
     print("=" * 70)

     if not session.cookies:
         print("No cookies received. Test inconclusive.")
     else:
         for cookie in session.cookies:
             print(f"Cookie Name      : {cookie.name}")
             print(f"Value            : {cookie.value}")
             print(f"Domain           : {cookie.domain or 'Not Set'}")
             print(f"Path             : {cookie.path or 'Not Set'}")

             # Secure
             print(f"Secure           : {cookie.secure}")
             if cookie.secure:
                 print("Test Secure      : PASS – Cookie sent only over HTTPS")
             else:
                 print("Test Secure      : FAIL – Cookie is sent over unencrypted HTTP")

             # HttpOnly
             httponly = cookie._rest.get('HttpOnly', None)
             print(f"HttpOnly         : {httponly}")
             if httponly in [True, 'True', 'true']:
                 print("Test HttpOnly    : PASS – Cookie not accessible via JavaScript")
             else:
                 print("Test HttpOnly    : FAIL – Cookie accessible via JavaScript")

             # SameSite
             samesite = cookie._rest.get('SameSite', None)
             print(f"SameSite         : {samesite}")
             if samesite in ['Lax', 'Strict']:
                 print("Test SameSite    : PASS – Cross-site request protection in place")
             else:
                 print("Test SameSite    : FAIL – No protection against CSRF")

             # Expires / Max-Age
             expires = cookie.expires or cookie._rest.get('Max-Age', None)
             print(f"Expires/Max-Age  : {expires}")
             if expires:
                 print("Test Expiration  : PASS – Cookie has an expiration policy")
             else:
                 print("Test Expiration  : WARNING – Session cookie without explicit expiry")

             # Base64 check for sensitive data
             try:
                 decoded = base64.b64decode(cookie.value).decode()
                 print(f"Base64 Decoded   : {decoded}")
                 if any(keyword in decoded.lower() for keyword in ['token', 'password', 'secret']):
                     print("Test Content     : FAIL – Sensitive data found in cookie value")
                 else:
                     print("Test Content     : PASS – No sensitive data detected")
             except:
                 print("Base64 Decoded   : Not base64 or undecodable")
                 print("Test Content     : PASS – Value not easily reversible or readable")

             # Classification
             if 'session' in cookie.name.lower() or 'auth' in cookie.name.lower():
                 print("Likely Type      : Application-level session/authentication cookie")
             elif 'affinity' in cookie.name.lower():
                 print("Likely Type      : Infrastructure cookie (load balancing)")
             else:
                 print("Likely Type      : Unknown or custom")

             print("-" * 70)
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_cookie_attributes.py
     ```
3. **Test Single Cookie Attributes**:
   - Command:
     ```bash
     python3 -c "import requests; s=requests.Session(); r=s.post('https://testing.com', data={'username': 'test@gmail.com', 'password': 'test@12345'}); c=s.cookies.get_dict(); print('Name:', list(c.keys())[0] if c else 'None', 'Secure:', s.cookies[list(c.keys())[0]].secure if c else 'No cookies', 'HttpOnly:', s.cookies[list(c.keys())[0]]._rest.get('HttpOnly', 'Not Set') if c else 'No cookies')"
     ```
4. **Verify Findings**:
   - Check if `Max-Age` is reasonable (e.g., 1800 seconds).
   - Ensure no sensitive data (e.g., passwords, tokens) is stored.
   - Expected secure response: Random session ID, reasonable expiration, no sensitive data.

**Remediation**:
- Store session data server-side:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: {
          maxAge: 1800000, // 30 minutes
          httpOnly: true,
          secure: true,
          sameSite: 'strict'
      },
      store: new MemoryStore() // Use secure session store
  }));
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_cookie_attributes.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).
