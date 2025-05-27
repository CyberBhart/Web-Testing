# Testing for Credentials Transported over an Encrypted Channel

## Overview

Testing for Credentials Transported over an Encrypted Channel (WSTG-AUTH-01) involves verifying that a web application transmits sensitive data, such as credentials and session tokens, exclusively over secure channels (HTTPS) to prevent interception by attackers. According to OWASP, unencrypted transmission (e.g., over HTTP) or weak HTTPS configurations can expose credentials, enabling man-in-the-middle (MITM) attacks, session hijacking, or data breaches. This test focuses on validating HTTPS enforcement for authentication requests (login, account creation, password reset/change), session token handling, HTTP Strict Transport Security (HSTS), and the absence of mixed content during account creation or authentication workflows.

**Impact**: Failure to secure credential transport can lead to:
- Interception of usernames, passwords, or session tokens via MITM attacks.
- Session hijacking due to insecure cookie transmission.
- Exposure of sensitive data through mixed content or HTTP fallback.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide provides a practical, hands-on methodology for testing secure credential transport, adhering to OWASP’s WSTG-AUTH-01, with detailed tool setups, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as intercepting traffic or forcing HTTP may trigger security alerts or disrupt live systems.

## Testing Tools

The following tools are recommended for testing credential transport, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and analyzes HTTP/HTTPS requests to verify transport security.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **OWASP ZAP**: Captures and inspects traffic to detect HTTP usage or mixed content.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Install and configure browser proxy: 127.0.0.1:8080.

- **cURL**: Sends requests to check HTTPS enforcement and response headers.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects network traffic and mixed content warnings on authentication pages.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-01, focusing on testing HTTPS enforcement, session token security, HSTS, and mixed content in authentication and session workflows.

### 1. Test Login Request HTTPS Enforcement with Burp Suite

**Objective**: Verify that login requests use HTTPS and reject HTTP attempts.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com/login` to the target scope in the “Target” tab.
2. Load the login page (e.g., `https://example.com/login`), submit valid credentials, and verify the POST request in “HTTP History” uses HTTPS:
   ```
   HTTP History -> Select POST /login -> Verify Request URL starts with https://
   ```
3. In Burp Repeater, modify the request URL to `http://example.com/login` and resend to check if the server redirects to HTTPS or rejects the request:
   ```
   Repeater -> Change https://example.com/login to http://example.com/login -> Click Send -> Check for redirect or rejection
   ```
4. Analyze responses; expected secure response is an HTTP 301/302 redirect to HTTPS or request failure.

**Example Secure Response**:
```
HTTP/1.1 301 Moved Permanently
Location: https://example.com/login
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Login successful"}
```

**Remediation**:
- Enforce HTTPS redirects (Node.js):
  ```javascript
  app.use((req, res, next) => {
      if (!req.secure) return res.redirect(301, `https://${req.headers.host}${req.url}`);
      next();
  });
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Account Creation HTTPS Enforcement with cURL

**Objective**: Ensure account creation requests use HTTPS and reject HTTP.

**Steps**:
1. Use Burp Suite to identify the account creation endpoint (e.g., `POST /register` or `/createAccount`).
2. Send a valid account creation request over HTTPS to confirm functionality:
   ```bash
   curl -i -X POST -d "username=user456&password=Secure123" https://example.com/register
   ```
3. Attempt the same request over HTTP to check for rejection or redirect:
   ```bash
   curl -i -X POST -d "username=user456&password=Secure123" http://example.com/register
   ```
4. Analyze responses; expected secure response is an HTTP 301/302 redirect to HTTPS or request failure.

**Example Secure Response**:
```
HTTP/1.1 301 Moved Permanently
Location: https://example.com/register
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Redirect HTTP to HTTPS (Python/Flask):
  ```python
  @app.before_request
  def enforce_https():
      if not request.is_secure:
          return redirect(request.url.replace('http://', 'https://'), code=301)
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Password Reset/Change HTTPS Enforcement with OWASP ZAP

**Objective**: Verify that password reset or change requests use HTTPS.

**Steps**:
1. Configure OWASP ZAP by setting up the browser proxy (127.0.0.1:8080) and enabling “Break” to intercept requests.
2. Trigger a password reset or change (e.g., `POST /reset-password`) and verify the request in ZAP’s “History” tab uses HTTPS:
   ```
   History tab -> Select POST /reset-password -> Verify Request URL starts with https://
   ```
3. In ZAP’s “Manual Request Editor”, modify the request URL to HTTP and resend to check for redirect or rejection:
   ```
   Manual Request Editor -> Change https://example.com/reset-password to http://example.com/reset-password -> Send -> Check for redirect or rejection
   ```
4. Analyze responses; expected secure response is an HTTP 301/302 redirect to HTTPS or request failure.

**Example Secure Response**:
```
HTTP/1.1 301 Moved Permanently
Location: https://example.com/reset-password
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Password reset successful"}
```

**Remediation**:
- Enforce HTTPS (Node.js):
  ```javascript
  app.post('/reset-password', (req, res) => {
      if (!req.secure) return res.redirect(301, `https://${req.headers.host}${req.url}`);
      // Process reset
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save OWASP ZAP requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Session Token Handling with Browser Developer Tools

**Objective**: Ensure session tokens are transmitted only over HTTPS with Secure/HttpOnly attributes.

**Steps**:
1. Log in to the application and open Browser Developer Tools (Network tab).
2. Check for cookies (e.g., `JSESSIONID`) and verify `Secure` and `HttpOnly` attributes in the “Application” tab:
   ```
   Application tab -> Cookies -> Select https://example.com -> Verify JSESSIONID has Secure and HttpOnly
   ```
3. Navigate to `http://example.com/` and check if cookies are sent over HTTP:
   ```
   Network tab -> Load http://example.com/ -> Check Request Headers for Cookie presence
   ```
4. Analyze responses; expected secure response is that cookies are not sent over HTTP and HTTPS is required.

**Example Secure Response**:
```
HTTP/1.1 301 Moved Permanently
Location: https://example.com/
[No Cookie header in request]
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Request Headers:
    Cookie: JSESSIONID=c1e7b45b
```

**Remediation**:
- Set secure cookies (Python/Flask):
  ```python
  @app.route('/login', methods=['POST'])
  def login():
      response = jsonify({'status': 'success'})
      response.set_cookie('session', 'token', secure=True, httponly=True)
      return response
  ```

**Tip**: Save screenshots and network logs from Browser Developer Tools. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., cookie headers).

### 5. Test HSTS Enforcement with cURL

**Objective**: Verify that the application enforces HSTS to prevent HTTP fallback.

**Steps**:
1. Send a request to the application’s root (e.g., `https://example.com`) and inspect response headers for `Strict-Transport-Security`:
   ```bash
   curl -I https://example.com
   ```
2. Repeat for a subdomain (e.g., `https://sub.example.com`) to verify `includeSubDomains`:
   ```bash
   curl -I https://sub.example.com
   ```
3. Check for `max-age` (e.g., 31536000 for 1 year) and `includeSubDomains`.
4. Analyze responses; expected secure response is an HSTS header with `max-age>=31536000` and `includeSubDomains`.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[No Strict-Transport-Security header]
```

**Remediation**:
- Add HSTS (Python/Flask):
  ```python
  @app.after_request
  def add_hsts(response):
      response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
      return response
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -I ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP headers).

### 6. Test for Mixed Content with Browser Developer Tools

**Objective**: Ensure all resources on authentication pages are loaded over HTTPS.

**Steps**:
1. Access the login page (e.g., `https://example.com/login`) and open Developer Tools (Network tab).
2. Filter for HTTP-loaded resources (e.g., scripts, images):
   ```
   Network tab -> Load https://example.com/login -> Filter for http:// resources
   ```
3. Check the Console tab for “Mixed Content” warnings:
   ```
   Console tab -> Load https://example.com/login -> Look for "Mixed Content" warnings
   ```
4. Analyze findings; expected secure response is no HTTP resources or mixed content warnings.

**Example Secure Output**:
```
[No Mixed Content warnings in Console tab]
[All resources in Network tab use https://]
```

**Example Vulnerable Output**:
```
Mixed Content: The page was loaded over HTTPS, but requested an insecure resource 'http://example.com/script.js'
```

**Remediation**:
- Use HTTPS resources (HTML):
  ```html
  <script src="https://example.com/script.js"></script>
  ```

**Tip**: Save screenshots and console logs from Browser Developer Tools. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., console warnings).
