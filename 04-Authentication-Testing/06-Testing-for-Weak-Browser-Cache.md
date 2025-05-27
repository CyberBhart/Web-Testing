# Testing for Browser Cache Weaknesses

## Overview

Testing for Browser Cache Weaknesses (WSTG-AUTH-06) involves verifying that sensitive data, such as credentials, session tokens, or protected pages, is not cached by browsers, which could allow unauthorized access on shared or compromised devices. According to OWASP, improper cache-control headers or session management can lead to sensitive data being stored in browser cache or history, accessible via cache files or navigation. This test focuses on checking cache-control headers for authentication pages, protected resources, and APIs, ensuring sensitive data is not stored in cache or accessible after logout, and verifying that authentication forms are not cached.

**Impact**: Browser cache weaknesses can lead to:
- Unauthorized access to sensitive data on shared devices.
- Exposure of credentials or session tokens in cache files.
- Access to protected pages after logout via back/forward navigation.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide provides a practical, hands-on methodology for testing browser cache vulnerabilities, adhering to OWASP’s WSTG-AUTH-06, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as accessing cache files or sending requests may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing browser cache weaknesses, with setup and configuration instructions:

- **Browser Developer Tools**: Inspects HTTP response headers, cache contents, and navigation behavior.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **cURL**: Sends requests to test cache-control headers for API endpoints.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-06, focusing on testing cache-control headers, browser cache contents, navigation security, API responses, and authentication forms.

### 1. Test Cache-Control Headers for Sensitive Pages with Browser Developer Tools

**Objective**: Ensure sensitive pages (e.g., login, dashboard) have proper cache-control headers to prevent caching.

**Steps**:
1. Access the login page (e.g., `https://example.com/login`) and open Browser Developer Tools (Network tab).
2. Inspect response headers for `Cache-Control` and `Pragma`:
   ```
   Network tab -> Select GET /login -> Check Response Headers for Cache-Control, Pragma
   ```
3. Repeat for a protected page (e.g., `https://example.com/dashboard`):
   ```
   Network tab -> Select GET /dashboard -> Check Response Headers for Cache-Control, Pragma
   ```
4. Analyze headers; expected secure response includes `Cache-Control: no-store, no-cache` and `Pragma: no-cache`.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html
<html>Login page</html>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<html>Login page</html>
[No Cache-Control or Pragma headers]
```

**Remediation**:
- Set cache-control headers (Python/Flask):
  ```python
  @app.get('/login')
  def login():
      response = make_response(render_template('login.html'))
      response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
      response.headers['Pragma'] = 'no-cache'
      return response
  ```

**Tip**: Save screenshots of Browser Developer Tools Network tab showing headers. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., missing headers).

### 2. Test Browser Cache for Sensitive Data with Browser Developer Tools

**Objective**: Verify that sensitive data is not stored in browser cache or history.

**Steps**:
1. Log in to the application, access a protected page (e.g., `https://example.com/dashboard`), and log out.
2. Check the browser cache for cached responses:
   ```
   Network tab -> Right-click GET /dashboard -> Copy Response -> Check for sensitive data
   ```
3. Check browser history or cache files for sensitive content:
   ```
   Application tab -> Cache Storage -> Select https://example.com -> Check for cached /dashboard response
   ```
4. Analyze findings; expected secure response is no sensitive data in cache or history.

**Example Secure Response**:
```
[No cached response for /dashboard in Network or Cache Storage]
```

**Example Vulnerable Response**:
```
Cached Response: {"user": "admin", "data": "Sensitive dashboard data"}
```

**Remediation**:
- Prevent caching of sensitive pages (Node.js):
  ```javascript
  app.get('/dashboard', (req, res) => {
      res.set({
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Pragma': 'no-cache'
      });
      res.send('Dashboard content');
  });
  ```

**Tip**: Save screenshots of Browser Developer Tools Network and Cache Storage tabs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., cached data).

### 3. Test Back/Forward Navigation After Logout with Browser Developer Tools

**Objective**: Ensure protected pages are not accessible via back/forward navigation after logout.

**Steps**:
1. Log in, access a protected page (e.g., `https://example.com/dashboard`), and log out.
2. Use the browser’s back button to attempt accessing the protected page:
   ```
   Network tab -> Click browser back button -> Monitor requests for /dashboard
   ```
3. Check if the page is reloaded or redirected:
   ```
   Network tab -> Check if GET /dashboard triggers redirect to /login
   ```
4. Analyze responses; expected secure response is a redirect to the login page or access denial.

**Example Secure Response**:
```
HTTP/1.1 302 Found
Location: https://example.com/login
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<html>Dashboard content</html>
```

**Remediation**:
- Invalidate session on logout (Python/Flask):
  ```python
  @app.post('/logout')
  def logout():
      session.clear()
      response = make_response(redirect('/login'))
      response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
      response.headers['Pragma'] = 'no-cache'
      return response
  ```

**Tip**: Save screenshots of Browser Developer Tools Network tab showing navigation requests. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test API Response Caching with cURL

**Objective**: Ensure API endpoints returning sensitive data have proper cache-control headers.

**Steps**:
1. Authenticate and access an API endpoint (e.g., `GET /api/user/profile`) with a valid token.
2. Inspect response headers for `Cache-Control` and `Pragma`:
   ```bash
   curl -i -H "Authorization: Bearer valid_token" https://example.com/api/user/profile
   ```
3. Attempt to access the endpoint without authentication to check for cached data:
   ```bash
   curl -i https://example.com/api/user/profile
   ```
4. Analyze responses; expected secure response includes cache-control headers and no cached data access.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: application/json
{"user": "admin"}
[Second request]
HTTP/1.1 401 Unauthorized
{"error": "Authentication required"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"user": "admin"}
[Second request returns cached data]
HTTP/1.1 200 OK
{"user": "admin"}
```

**Remediation**:
- Set cache-control for APIs (Node.js):
  ```javascript
  app.get('/api/user/profile', (req, res) => {
      res.set({
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Pragma': 'no-cache'
      });
      res.json({ user: 'admin' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Cacheable Authentication Forms with Browser Developer Tools

**Objective**: Ensure login forms are not cached, preventing pre-filled credentials or form data exposure.

**Steps**:
1. Access the login page (e.g., `https://example.com/login`), submit credentials, and open Browser Developer Tools.
2. Inspect response headers for `Cache-Control` and `Pragma`:
   ```
   Network tab -> Select GET /login -> Check Response Headers for Cache-Control, Pragma
   ```
3. Navigate back to the login page and check if form fields are pre-filled:
   ```
   Network tab -> Navigate back to /login -> Check if form fields are pre-filled
   ```
4. Analyze findings; expected secure response includes cache-control headers and no pre-filled fields.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
[Form fields not pre-filled on back navigation]
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[No Cache-Control or Pragma headers]
[Form fields pre-filled with username/password]
```

**Remediation**:
- Prevent form caching (Python/Flask):
  ```python
  @app.get('/login')
  def login():
      response = make_response(render_template('login.html'))
      response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
      response.headers['Pragma'] = 'no-cache'
      return response
  ```

**Tip**: Save screenshots of Browser Developer Tools Network tab and form fields. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., pre-filled forms).