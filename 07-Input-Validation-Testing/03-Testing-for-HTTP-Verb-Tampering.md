# Testing for HTTP Verb Tampering Vulnerabilities

## Overview

Testing for HTTP Verb Tampering vulnerabilities involves verifying that a web application properly restricts and validates HTTP methods (verbs) such as GET, POST, PUT, DELETE, TRACE, and others to prevent unauthorized actions or bypassing of access controls. According to OWASP (WSTG-INPV-11), HTTP verb tampering occurs when an application fails to enforce method-specific restrictions, allowing attackers to use unexpected or unsupported HTTP methods to manipulate resources or access restricted functionality. This guide provides a hands-on methodology to identify and test HTTP verb tampering vulnerabilities, focusing on method enumeration, access control testing, and specific contexts like API endpoints, method override headers, and the TRACE method, with tools, commands, and remediation strategies.

**Impact**: HTTP verb tampering vulnerabilities can lead to:
- Unauthorized access to sensitive resources (e.g., deleting user data via DELETE).
- Bypassing authentication or authorization controls.
- Exposure of debugging information (e.g., via TRACE).
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-11, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as sending unexpected HTTP methods may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing HTTP verb tampering vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to test different methods.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to change HTTP methods (e.g., GET to DELETE) and Proxy > HTTP History to analyze responses.
  - **Note**: Check Options tab for supported methods.

- **OWASP ZAP 3.0**: A free tool for automated HTTP method testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Use Manual Request Editor to send custom methods and Active Scan to detect misconfigurations.
  - **Tip**: Enable HUD for in-browser testing (Tools > Options > HUD).

- **cURL**: Sends HTTP requests with custom methods.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
  - Example:
    ```bash
    curl -X DELETE "http://example.com/api/user/123"
    ```

- **HTTPie**: Beginner-friendly CLI tool for HTTP requests.
  - Install on Linux/Mac:
    ```bash
    sudo apt install httpie
    ```
  - Install on Windows: `pip install httpie`.
  - Example:
    ```bash
    http DELETE "http://example.com/api/user/123"
    ```

- **Postman**: GUI tool for testing HTTP methods on APIs.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Create a new request, select method (e.g., PUT), and send.
  - **Tip**: Use Collections to automate method testing.

- **Nmap**: Scans for supported HTTP methods.
  - Install on Linux:
    ```bash
    sudo apt install nmap
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).
  - Example:
    ```bash
    nmap --script http-methods -p 80,443 example.com
    ```

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to method requests.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses to custom requests.
  - **Note**: Firefox’s 2025 network analysis improvements enhance method testing.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-11, testing HTTP verb tampering vulnerabilities across method enumeration, access control testing, and specific contexts like unexpected methods, API endpoints, method override headers, and TRACE.

### 1. Enumerate Supported HTTP Methods

**Objective**: Identify which HTTP methods the server accepts.

**Steps**:
1. Send an OPTIONS request:
   - Use Burp Repeater:
     ```http
     OPTIONS / HTTP/1.1
     Host: example.com
     ```
   - Check response for `Allow` header (e.g., `Allow: GET, POST, OPTIONS`).
2. Use cURL:
   ```bash
   curl -i -X OPTIONS "http://example.com"
   ```
3. Use Nmap:
   ```bash
   nmap --script http-methods -p 80,443 example.com
   ```
4. Test common methods manually:
   - Send GET, POST, PUT, DELETE, PATCH, HEAD, TRACE via Burp or cURL.
   - Example:
     ```bash
     curl -X PUT "http://example.com/resource"
     ```
5. Document methods:
   - Note which methods return `200 OK`, `405 Method Not Allowed`, or unexpected responses.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
Allow: GET, POST, PUT, DELETE, TRACE
```
TRACE and DELETE are enabled unnecessarily.

**Example Secure Response**:
```http
HTTP/1.1 405 Method Not Allowed
Allow: GET, POST
```
Only expected methods are allowed.

**Remediation**:
- Disable unused methods in the web server:
  - Apache (`httpd.conf`):
    ```apache
    <LimitExcept GET POST>
        Require all denied
    </LimitExcept>
    ```
  - Nginx (`nginx.conf`):
    ```nginx
    if ($request_method !~ ^(GET|POST)$) {
        return 405;
    }
    ```

**Tip**: Save supported methods in a report.

### 2. Test Access Controls for HTTP Methods

**Objective**: Verify if methods allow unauthorized actions.

**Steps**:
1. Identify sensitive endpoints:
   - Browse the site (e.g., `/api/user/123`, `/admin`).
   - Check Burp’s Site Map for URLs.
2. Test restricted methods:
   - Send PUT, DELETE, or PATCH to endpoints:
     ```bash
     curl -X DELETE "http://example.com/api/user/123"
     ```
   - Use Burp Repeater to modify methods on captured requests.
3. Check responses:
   - Look for `200 OK` or data changes (e.g., user deleted).
   - Compare authenticated vs. unauthenticated responses.
4. Verify impact:
   - Check if resources are modified (e.g., user data updated via PUT).

**Example Vulnerable Code (Node.js)**:
```javascript
app.all('/api/user/:id', (req, res) => {
    if (req.method === 'DELETE') {
        // Delete user
        res.send('User deleted');
    }
});
```
Test: `DELETE /api/user/123`
Result: User deleted without authorization.

**Example Secure Code (Node.js)**:
```javascript
app.delete('/api/user/:id', (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).send('Forbidden');
    }
    // Delete user
    res.send('User deleted');
});
```
Test: `DELETE /api/user/123`
Result: `403 Forbidden` for non-admins.

**Remediation**:
- Enforce authorization per method:
  ```javascript
  if (!user.isAuthorized) return res.status(403).send();
  ```
- Use explicit method routing (e.g., `app.get`, `app.post`).

**Tip**: Save unauthorized access attempts in a report.

### 3. Test for Unexpected HTTP Methods

**Objective**: Check if non-standard or deprecated methods are processed.

**Steps**:
1. Test unusual methods:
   - Send requests with methods like CONNECT, PROPFIND, or custom methods:
     ```bash
     curl -X PROPFIND "http://example.com"
     ```
   - Use Burp Repeater:
     ```http
     PROPFIND / HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for `200 OK` or unexpected behavior.
   - Compare with `405 Method Not Allowed`.
3. Use Nmap:
   ```bash
   nmap --script http-methods --script-args http-methods.test-all=true -p 80,443 example.com
   ```
4. Document findings:
   - Note methods that succeed unexpectedly.

**Example Vulnerable Response**:
```http
PROPFIND / HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
```
PROPFIND is processed.

**Example Secure Response**:
```http
HTTP/1.1 405 Method Not Allowed
```
Method rejected.

**Remediation**:
- Restrict to standard methods:
  - Apache:
    ```apache
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
    ```
- Validate methods server-side:
  ```javascript
  if (!['GET', 'POST'].includes(req.method)) {
      res.status(405).send();
  }
  ```

**Tip**: Save unexpected method responses in a report.

### 4. Test API Endpoints for Method Tampering

**Objective**: Verify if API endpoints enforce method restrictions.

**Steps**:
1. Identify API endpoints:
   - Use Burp’s Site Map or Postman to find `/api/*` routes.
   - Example: `/api/users`, `/api/posts`.
2. Test methods:
   - Send GET, POST, PUT, DELETE, PATCH to each endpoint:
     ```bash
     http PUT "http://example.com/api/users/123" name="Test"
     ```
   - Use Postman to cycle through methods.
3. Check responses:
   - Look for `200 OK` or data changes (e.g., user updated).
   - Test unauthenticated requests.
4. Verify impact:
   - Check if unauthorized actions succeed (e.g., deleting posts).

**Example Vulnerable Code (Python Flask)**:
```python
@app.route('/api/users/<id>', methods=['GET', 'POST', 'PUT'])
def user(id):
    if request.method == 'PUT':
        # Update user
        return 'User updated'
```
Test: `PUT /api/users/123`
Result: User updated without checks.

**Example Secure Code (Python Flask)**:
```python
@app.route('/api/users/<id>', methods=['PUT'])
def user(id):
    if not current_user.is_admin:
        return 'Forbidden', 403
    # Update user
    return 'User updated'
```
Test: `PUT /api/users/123`
Result: `403 Forbidden` for non-admins.

**Remediation**:
- Validate API methods:
  ```python
  if not user.has_permission('edit'): abort(403)
  ```
- Use strict routing for APIs.

**Tip**: Save API responses in a report.

### 5. Test HTTP Method Override Headers

**Objective**: Check if override headers (e.g., `X-HTTP-Method-Override`) allow method tampering.

**Steps**:
1. Identify override usage:
   - Check documentation or responses for headers like `X-HTTP-Method-Override`.
2. Inject headers:
   - Use Burp to add:
     ```http
     POST /api/users HTTP/1.1
     Host: example.com
     X-HTTP-Method-Override: DELETE
     ```
   - Use cURL:
     ```bash
     curl -X POST -H "X-HTTP-Method-Override: DELETE" "http://example.com/api/users/123"
     ```
3. Check responses:
   - Look for DELETE-like behavior (e.g., resource removed).
4. Test other headers:
   - Try `X-Method-Override`, `X-HTTP-Method`.

**Example Vulnerable Code (Node.js)**:
```javascript
app.use((req, res, next) => {
    if (req.headers['x-http-method-override']) {
        req.method = req.headers['x-http-method-override'];
    }
    next();
});
```
Test: POST with `X-HTTP-Method-Override: DELETE`
Result: Deletes resource.

**Example Secure Code (Node.js)**:
```javascript
app.delete('/api/users/:id', (req, res) => {
    if (!req.user.isAdmin) return res.status(403).send();
    // Delete user
});
```
Test: POST with `X-HTTP-Method-Override: DELETE`
Result: Ignored, `405 Method Not Allowed`.

**Remediation**:
- Disable method override middleware.
- Validate methods explicitly:
  ```javascript
  if (req.method !== 'DELETE') return res.status(405).send();
  ```

**Tip**: Save override responses in a report.

### 6. Test TRACE Method for Debugging Exposure

**Objective**: Verify if the TRACE method exposes sensitive data.

**Steps**:
1. Send a TRACE request:
   - Use Burp Repeater:
     ```http
     TRACE / HTTP/1.1
     Host: example.com
     Custom-Header: Test
     ```
   - Use cURL:
     ```bash
     curl -i -X TRACE "http://example.com"
     ```
2. Check response:
   - Look for echoed request data, including headers.
3. Test with cookies:
   - Send TRACE with a session cookie and check if it’s reflected.
4. Use Nmap:
   ```bash
   nmap --script http-trace -p 80,443 example.com
   ```

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
TRACE / HTTP/1.1
Host: example.com
Cookie: session=abc123
```
Cookie exposed.

**Example Secure Response**:
```http
HTTP/1.1 405 Method Not Allowed
```
TRACE disabled.

**Remediation**:
- Disable TRACE:
  - Apache:
    ```apache
    TraceEnable off
    ```
  - Nginx:
    ```nginx
    if ($request_method = TRACE) {
        return 405;
    }
    ```

**Tip**: Save TRACE responses in a report.
