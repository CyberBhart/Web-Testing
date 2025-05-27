# Testing for Exposed Session Variables

## Overview

Testing for Exposed Session Variables (WSTG-SESS-04) involves assessing a web application to ensure that session identifiers (e.g., session IDs, tokens) are not exposed in URLs, unencrypted channels, client-side code, logs, or other insecure locations, preventing attackers from intercepting or accessing them. According to OWASP, exposed session variables can lead to session hijacking or unauthorized access, compromising user accounts. This test focuses on verifying secure transmission, storage, and handling of session variables to mitigate exposure risks.

**Impact**: Exposed session variables can lead to:
- Session hijacking by intercepting session IDs over unencrypted connections.
- Unauthorized access if session IDs are exposed in URLs, logs, or client-side code.
- Information disclosure through referer headers or cached pages.
- Compromise of user sessions via network sniffing or server misconfigurations.

This guide provides a practical, hands-on methodology for testing exposed session variables, adhering to OWASP’s WSTG-SESS-04, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing exposed session variables, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts requests to detect session IDs in URLs or headers.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Postman**: Tests API responses for session variable exposure.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends requests to analyze session transmission and exposure.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side code and cookies for exposed session variables.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Wireshark**: Analyzes network traffic for unencrypted session data.
  - Download from [wireshark.org](https://www.wireshark.org/download.html).
  - Install and configure network interface (e.g., Wi-Fi, Ethernet).

- **Python Requests Library**: Automates testing for session variable exposure.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-SESS-04, focusing on testing for session variable exposure in URLs, unencrypted channels, referer headers, client-side code, logs, and caches.

### 1. Test Session IDs in URLs with Burp Suite

**Objective**: Check if session IDs are exposed in URLs as query parameters or path components.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Requests**:
   - Navigate the application (e.g., login, dashboard) and check “HTTP History” for URLs containing session IDs (e.g., `?sessionid=abc123`).
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Request tab -> Look for ?sessionid=abc123 in URL
     ```
3. **Test Session ID Usage**:
   - Log in and visit a URL with a session ID (e.g., `http://example.com/dashboard?sessionid=abc123`).
   - Check if the session ID in the URL grants access.
   - Command:
     ```
     HTTP History -> Select GET /dashboard -> Send to Repeater -> Edit URL to /dashboard?sessionid=abc123 -> Click Send -> Check if session is valid
     ```
4. **Analyze Findings**:
   - Vulnerable: Session ID in URL is accepted and functional.
   - Expected secure response: Session IDs only in cookies; URL parameters ignored.

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

### 2. Test Unencrypted Transmission with Wireshark

**Objective**: Verify that session variables are only transmitted over HTTPS.

**Steps**:
1. **Configure Wireshark**:
   - Start Wireshark and select the network interface (e.g., Wi-Fi).
   - Apply filter: `http` to capture HTTP traffic.
2. **Capture Traffic**:
   - Access the application over HTTP (e.g., `http://example.com/login`) and log in.
   - Check Wireshark for session cookies or IDs in HTTP requests.
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

### 3. Test Referer Header Leakage with cURL

**Objective**: Check if session IDs in URLs are leaked via referer headers to external sites.

**Steps**:
1. **Identify URL with Session ID**:
   - Use Burp Suite to find a URL with a session ID (e.g., `http://example.com/dashboard?sessionid=abc123`).
2. **Simulate External Navigation**:
   - Use cURL to mimic a request to an external site and check the `Referer` header.
   - Command:
     ```bash
     curl -i -H "Referer: http://example.com/dashboard?sessionid=abc123" http://external.com
     ```
3. **Check Referer Policy**:
   - Verify the application’s `Referrer-Policy` header.
   - Command:
     ```bash
     curl -i http://example.com/dashboard?sessionid=abc123 | grep Referrer-Policy
     ```
4. **Analyze Findings**:
   - Vulnerable: `Referer: http://example.com/dashboard?sessionid=abc123`.
   - Expected secure response: No session ID in referer (session in cookies or `Referrer-Policy` set).

**Remediation**:
- Set `Referrer-Policy` and avoid session IDs in URLs:
  ```python
  @app.route('/')
  def home():
      response = make_response({'status': 'success'})
      response.headers['Referrer-Policy'] = 'no-referrer'
      response.set_cookie('session', 'abc123', httponly=True, secure=True)
      return response
  ```

**Tip**: Log command outputs and responses to a text file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Client-Side Exposure with Browser Developer Tools

**Objective**: Inspect client-side code for exposed session variables.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect JavaScript and HTML**:
   - Go to “Sources” tab and search for `session`, `token`, or `id` in JavaScript files.
   - Command:
     ```
     Sources tab -> Ctrl+F -> Search for "session" or "token" -> Check JavaScript files
     ```
3. **Test Cookie Exposure**:
   - Run `document.cookie` in “Console” tab to verify `HttpOnly` protection.
   - Command:
     ```
     Console tab -> Run: document.cookie -> Verify session=abc123 is not returned
     ```
4. **Analyze Findings**:
   - Vulnerable: Session ID accessible in JavaScript or HTML.
   - Expected secure response: No session data in client-side code.

**Remediation**:
- Store session data server-side:
  ```javascript
  app.get('/dashboard', (req, res) => {
      if (!req.session.user) {
          return res.status(401).json({ error: 'Unauthorized' });
      }
      res.send('Dashboard');
  });
  ```

**Tip**: Save screenshots of the Sources and Console tabs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., code snippets, console outputs).

### 5. Automate Exposure Testing with Python Requests

**Objective**: Automate testing to detect session variable exposure in URLs, headers, or responses.

**Steps**:
1. **Write Python Script**:
   - Create a script to check for session IDs in URLs and responses:
     ```python
     import requests
     import re

     url = 'http://example.com'
     login_url = f'{url}/login'
     dashboard_url = f'{url}/dashboard'

     session = requests.Session()
     # Get initial page
     response = session.get(url)
     initial_url = response.url
     if 'session' in initial_url or 'token' in initial_url.lower():
         print(f"Vulnerable: Session ID in URL: {initial_url}")

     # Log in
     login_data = {'username': 'test', 'password': 'Secure123'}
     response = session.post(login_url, data=login_data)
     # Check response for session exposure
     if re.search(r'session[\w]*=[\w-]+', response.text, re.IGNORECASE):
         print("Vulnerable: Session ID in response body")
     # Check headers
     for header, value in response.headers.items():
         if 'session' in value.lower() or 'token' in value.lower():
             print(f"Vulnerable: Session ID in header: {header}: {value}")

     # Test referer leakage
     response = session.get('http://external.com', headers={'Referer': dashboard_url})
     if 'session' in response.request.headers.get('Referer', '').lower():
         print("Vulnerable: Session ID in Referer header")

     # Test HTTP transmission
     response = session.get(dashboard_url.replace('https://', 'http://'))
     if 'session' in str(response.request.headers.get('Cookie', '')).lower():
         print("Vulnerable: Session ID sent over HTTP")
     ```
2. **Run Script**:
   - Execute:
     ```bash
     python3 test_session_exposure.py
     ```
3. **Test Single Request**:
   - Command:
     ```bash
     python3 -c "import requests; r=requests.get('http://example.com/dashboard?sessionid=abc123'); print('Session in URL' if 'session' in r.url.lower() else 'No session in URL')"
     ```
4. **Verify Findings**:
   - Vulnerable: Session IDs in URLs, responses, or HTTP traffic.
   - Expected secure response: Session IDs only in secure cookies.

**Remediation**:
- Secure session handling:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.route('/login', methods=['POST'])
  def login():
      session['user'] = authenticate_user()
      response = make_response({'status': 'success'})
      response.set_cookie('session', session.sid, httponly=True, secure=True, samesite='Strict')
      return response
  ```

**Tip**: Store script outputs in a text file or log (e.g., `python3 test_session_exposure.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).