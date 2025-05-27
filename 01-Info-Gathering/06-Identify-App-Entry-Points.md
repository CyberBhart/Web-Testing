# **Identify Application Entry Points**

## **Overview**

Identifying application entry points (WSTG-INFO-06) involves discovering all accessible interfaces of a web application, such as URLs, forms, API endpoints, query parameters, and file uploads, where user input is processed. These entry points represent potential attack vectors for vulnerabilities like SQL injection, XSS, or file inclusion. According to OWASP, mapping entry points is critical during the reconnaissance phase to understand the application’s attack surface and prioritize testing efforts.

**Impact**: Unprotected or undiscovered entry points can lead to:
- Exploitation of input validation flaws (e.g., SQL injection, XSS).
- Unauthorized access to sensitive functionality (e.g., admin APIs).
- Exposure of hidden or deprecated endpoints.
- Increased risk of data breaches or application compromise.

This guide provides a step-by-step methodology for identifying application entry points, adhering to OWASP’s WSTG-INFO-06, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for identifying application entry points, suitable for both novice and experienced testers:

- **Burp Suite Community Edition**: Intercepts and crawls web applications to map URLs, forms, and parameters.
- **OWASP ZAP**: Open-source web proxy for automated discovery of entry points.
- **cURL**: Command-line tool for testing URLs and API endpoints.
- **GoBuster**: Tool for brute-forcing directories, files, and API paths.
- **Postman**: Tool for exploring and testing API endpoints.
- **Wappalyzer**: Browser extension to identify application technologies and potential entry points.
- **Wayback Machine (archive.org)**: Archives historical URLs to uncover old entry points.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **ParamSpider**: Tool for discovering URL parameters in web applications.
- **Arjun**: Tool for finding hidden HTTP parameters in forms and APIs.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
2. **OWASP ZAP**:
   - Download from [owasp.org](https://www.zaproxy.org/download/).
   - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
   - Configure proxy: 127.0.0.1:8080.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **GoBuster**:
   - Install: `sudo apt install gobuster`.
   - Verify: `gobuster --version`.
   - Use wordlist: `/usr/share/wordlists/dirb/common.txt`.
5. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
6. **Wappalyzer**:
   - Install as a browser extension (Chrome/Firefox) from [wappalyzer.com](https://www.wappalyzer.com/).
   - Enable and visit target site to view results.
7. **Wayback Machine**:
   - Access via [archive.org](https://archive.org/web/).
   - No setup required.
8. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
9. **ParamSpider**:
   - Clone from GitHub: `git clone https://github.com/devanshbatham/ParamSpider.git`.
   - Install dependencies: `pip install -r requirements.txt`.
   - Verify: `python3 paramspider.py --help`.
10. **Arjun**:
    - Clone from GitHub: `git clone https://github.com/s0md3v/Arjun.git`.
    - Install dependencies: `pip install -r requirements.txt`.
    - Verify: `python3 arjun.py --help`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-06, focusing on passive and active techniques to identify application entry points while minimizing detection risks.

### **1. Crawl the Application with Burp Suite**

Use Burp Suite’s Spider or Crawler to map URLs, forms, and parameters.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Crawl the Site**:
   - Right-click `example.com` in “Site map” and select “Spider this host” (Community Edition limits apply).
   - Monitor “Site map” for discovered URLs (e.g., `/login`, `/api/v1`).
3. **Analyze Entry Points**:
   - Check “Site map” for:
     - Forms (e.g., `<form action="/submit">`).
     - Query parameters (e.g., `?id=123`).
     - API endpoints (e.g., `/api/users`).
   - Review “Issues” tab for potential hidden parameters.
4. **Document Findings**:
   - Export “Site map” or save screenshots of forms and parameters.

**Example Vulnerable Finding**:
- URL: `http://example.com/submit?user_id=123`
- Form: `<form action="/process" method="POST"><input name="token"></form>`

**Remediation**:
- Restrict access to sensitive endpoints:
  ```
  <Location /process>
      Order deny,allow
      Deny from all
      Allow from 127.0.0.1
  </Location>
  ```
- Validate all parameters server-side.

### **2. Enumerate Paths with GoBuster**

Brute-force directories and files to discover hidden entry points.

**Steps**:
1. **Run GoBuster**:
   - Enumerate paths:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html,js,json
     ```
   - Output: Discovered paths (e.g., `/admin`, `/api`, `/upload.php`).
2. **Target API Endpoints**:
   - Use a specialized wordlist:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/api.txt
     ```
   - Output: API paths (e.g., `/api/v1/users`).
3. **Verify Findings**:
   - Test URLs with cURL:
     ```bash
     curl http://example.com/api/v1/users
     ```
   - Check for accessible endpoints or responses.
4. **Document Results**:
   - Save URLs and response codes in a text file or Burp Suite’s “Logger”.

**Example Vulnerable Finding**:
- URL: `http://example.com/api/v1/users`
- Response: JSON data with user details.

**Remediation**:
- Require authentication for APIs:
  ```
  <Location /api>
      AuthType Bearer
      AuthName "API Access"
      Require valid-user
  </Location>
  ```
- Implement rate limiting.

### **3. Discover Parameters with ParamSpider and Arjun**

Identify query and form parameters that serve as entry points.

**Steps**:
1. **Run ParamSpider**:
   - Enumerate parameters:
     ```bash
     python3 paramspider.py -d example.com
     ```
   - Output: URLs with parameters (e.g., `http://example.com/page?id=123&token=abc`).
2. **Run Arjun**:
   - Find hidden parameters:
     ```bash
     python3 arjun.py -u http://example.com/form
     ```
   - Output: Parameters like `debug`, `admin`.
3. **Test Parameters**:
   - Send requests with cURL:
     ```bash
     curl "http://example.com/page?id=123&debug=true"
     ```
   - Check for unexpected behavior (e.g., debug output).
4. **Document Findings**:
   - List parameters and their impact.

**Example Vulnerable Finding**:
- URL: `http://example.com/page?debug=true`
- Response: Debug information with internal server details.

**Remediation**:
- Disable debug parameters in production:
  ```php
  if (isset($_GET['debug'])) {
      http_response_code(403);
      exit;
  }
  ```
- Validate all input parameters.

### **4. Explore APIs with Postman**

Test API endpoints to identify entry points and their functionality.

**Steps**:
1. **Identify APIs**:
   - Use Burp Suite or GoBuster to find API paths (e.g., `/api/v1`).
   - Check for Swagger/OpenAPI documentation:
     ```bash
     curl http://example.com/swagger.json
     ```
2. **Test with Postman**:
   - Create a new request in Postman for `GET http://example.com/api/v1/users`.
   - Test methods (GET, POST, PUT, DELETE) and parameters.
   - Check responses for data or errors.
3. **Analyze Headers**:
   - Look for authentication requirements (e.g., `Authorization: Bearer`).
   - Note rate limits or versioning (e.g., `/v1`, `/v2`).
4. **Document Findings**:
   - Save API endpoints, methods, and parameters.

**Example Vulnerable Finding**:
- URL: `POST http://example.com/api/v1/users`
- Response: Creates user without authentication.

**Remediation**:
- Enforce authentication in API routes:
  ```javascript
  app.post('/api/v1/users', authenticateToken, (req, res) => {
      // Process request
  });
  ```
- Use role-based access control.

### **5. Check Historical Entry Points with Wayback Machine**

Use the Wayback Machine to find archived URLs and entry points.

**Steps**:
1. **Access Wayback Machine**:
   - Go to [archive.org/web/](https://archive.org/web/).
   - Enter `http://example.com` and browse snapshots.
2. **Extract URLs**:
   - Use `waybackurls`:
     ```bash
     waybackurls example.com > archived_urls.txt
     ```
   - Filter for forms, APIs, or parameters (e.g., `grep "api\|form" archived_urls.txt`).
3. **Test URLs**:
   - Query:
     ```bash
     curl http://example.com/old_api
     ```
   - Check if endpoints are still active.
4. **Document Findings**:
   - Save archived URLs and their content.

**Example Vulnerable Finding**:
- Archived URL: `http://example.com/old_api?key=123`
- Response: Exposed API endpoint.

**Remediation**:
- Deprecate and remove old endpoints:
  ```
  <Location /old_api>
      Order allow,deny
      Deny from all
  </Location>
  ```
- Monitor archives for sensitive data.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-06 with practical scenarios based on common entry point identification patterns observed in penetration testing.

### **Test 1: Exposed API Endpoint**

Test for an unprotected API endpoint.

**Steps**:
1. **Run GoBuster**:
   - Enumerate:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/api.txt
     ```
   - Output: `/api/v1`.
2. **Test with cURL**:
   - Query:
     ```bash
     curl http://example.com/api/v1/data
     ```
   - Check for data exposure.
3. **Use Postman**:
   - Send `GET` and `POST` requests to `/api/v1/data`.

**Example Insecure Finding**:
- URL: `http://example.com/api/v1/data`
- Response: `[{"id": 1, "name": "John"}]`

**Example Secure Configuration**:
- Require API authentication:
  ```javascript
  app.get('/api/v1/data', verifyToken, (req, res) => {
      res.json(secureData);
  });
  ```

**Remediation**:
- Implement JWT or OAuth for API access.
- Restrict API methods to authorized users.

### **Test 2: Hidden Form Parameters**

Test for hidden form parameters that affect functionality.

**Steps**:
1. **Crawl with Burp Suite**:
   - Spider `http://example.com` and check “Site map” for forms.
2. **Run Arjun**:
   - Scan:
     ```bash
     python3 arjun.py -u http://example.com/form
     ```
   - Output: Hidden parameters (e.g., `admin`).
3. **Test with cURL**:
   - Query:
     ```bash
     curl -d "admin=true" http://example.com/form
     ```

**Example Insecure Finding**:
- URL: `http://example.com/form?admin=true`
- Response: Admin dashboard access.

**Example Secure Configuration**:
- Validate parameters server-side:
  ```php
  if ($_POST['admin'] && !isAdmin()) {
      http_response_code(403);
      exit;
  }
  ```

**Remediation**:
- Remove unused parameters.
- Enforce role-based access control.

### **Test 3: File Upload Endpoint**

Test for file upload forms as entry points.

**Steps**:
1. **Crawl with OWASP ZAP**:
   - Spider `http://example.com` and check for `<input type="file">`.
2. **Test with Burp Suite**:
   - Send request:
     ```
     POST /upload HTTP/1.1
     Host: example.com
     Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
     ------WebKitFormBoundary
     Content-Disposition: form-data; name="file"; filename="test.txt"
     Content-Type: text/plain
     Test content
     ------WebKitFormBoundary--
     ```
   - Check response for file handling.
3. **Verify Restrictions**:
   - Test with different file types (e.g., `.php`, `.exe`).

**Example Insecure Finding**:
- URL: `http://example.com/upload`
- Response: `File uploaded to /uploads/test.php`

**Example Secure Configuration**:
- Restrict file types in PHP:
  ```php
  $allowed = ['jpg', 'png'];
  $ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
  if (!in_array($ext, $allowed)) {
      die('Invalid file type');
  }
  ```

**Remediation**:
- Validate file types and sizes.
- Store uploads outside the web root.

### **Test 4: Archived Endpoint**

Test for old entry points in the Wayback Machine.

**Steps**:
1. **Extract URLs**:
   - Run:
     ```bash
     waybackurls example.com | grep "api\|form"
     ```
   - Output: `http://example.com/old_form`.
2. **Test with cURL**:
   - Query:
     ```bash
     curl http://example.com/old_form
     ```
   - Check for active forms or parameters.
3. **Verify with Burp Suite**:
   - Analyze response for entry points.

**Example Insecure Finding**:
- URL: `http://example.com/old_form?id=123`
- Response: Form with sensitive parameters.

**Example Secure Configuration**:
- Block deprecated paths:
  ```
  <Location /old_form>
      Order allow,deny
      Deny from all
  </Location>
  ```

**Remediation**:
- Remove or secure old endpoints.
- Request removal of archived sensitive URLs.

## **Additional Tips**

- **Start Simple**: Use Burp Suite to quickly identify forms and parameters.
- **Combine Tools**: Cross-verify GoBuster results with ParamSpider for comprehensive coverage.
- **Gray-Box Testing**: If documentation is available, check for references to APIs or forms.
- **Document Thoroughly**: Save all URLs, forms, parameters, and responses in a report.
- **Bypass Defenses**: Use parameter fuzzing or alternate methods (e.g., `PUT`, `PATCH`) to uncover hidden entry points.
- **Stay Ethical**: Obtain explicit permission for active crawling or parameter testing.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).