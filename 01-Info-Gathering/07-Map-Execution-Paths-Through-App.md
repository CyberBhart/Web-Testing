# **Map Execution Paths Through Application**

## **Overview**

Mapping execution paths through an application (WSTG-INFO-07) involves tracing the sequence of requests, responses, and interactions within a web application to understand its workflow, business logic, and potential vulnerabilities. This reconnaissance phase identifies how user inputs navigate through pages, forms, APIs, and backend processes, revealing hidden functionality, state transitions, or logic flaws. According to OWASP, this process is critical for uncovering insecure direct object references, missing authorization checks, or predictable workflows that attackers could exploit.

**Impact**: Poorly mapped or unprotected execution paths can lead to:
- Unauthorized access to restricted functionality (e.g., bypassing authentication).
- Exploitation of business logic flaws (e.g., skipping payment steps).
- Exposure of sensitive data through predictable URLs or parameters.
- Increased risk of privilege escalation or data manipulation.

This guide provides a step-by-step methodology for mapping execution paths, adhering to OWASP’s WSTG-INFO-07, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for mapping execution paths, suitable for both novice and experienced testers:

- **Burp Suite Community Edition**: Intercepts and maps HTTP requests/responses to trace application workflows.
- **OWASP ZAP**: Open-source web proxy for automated crawling and path analysis.
- **cURL**: Command-line tool for manually testing request sequences.
- **Postman**: Tool for exploring API workflows and state transitions.
- **Selenium**: Browser automation tool for simulating user interactions.
- **Wappalyzer**: Browser extension to identify application technologies and workflows.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **Graphviz**: Tool for visualizing execution paths as flowcharts (optional).
- **Mitmproxy**: Command-line proxy for intercepting and analyzing request flows.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting requests and DOM changes.

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
4. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
5. **Selenium**:
   - Install Python: `sudo apt install python3`.
   - Install Selenium: `pip install selenium`.
   - Download browser driver (e.g., [ChromeDriver](https://chromedriver.chromium.org/)).
   - Verify: Run a sample script.
6. **Wappalyzer**:
   - Install as a browser extension (Chrome/Firefox) from [wappalyzer.com](https://www.wappalyzer.com/).
   - Enable and visit target site to view results.
7. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
8. **Graphviz**:
   - Install on Linux: `sudo apt install graphviz`.
   - Install on Windows/Mac: Download from [graphviz.org](https://graphviz.org/download/).
   - Verify: `dot -V`.
9. **Mitmproxy**:
   - Install: `pip install mitmproxy`.
   - Run: `mitmproxy`.
   - Configure browser proxy: 127.0.0.1:8080.
10. **Browser Developer Tools**:
    - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
    - No setup required.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-07, focusing on tracing execution paths through manual and automated techniques to map application workflows.

### **1. Crawl the Application with Burp Suite**

Use Burp Suite to map URLs, forms, and request sequences.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Crawl the Site**:
   - Right-click `example.com` in “Site map” and select “Spider this host” (Community Edition limits apply).
   - Interact with the application (e.g., login, submit forms) to capture dynamic paths.
3. **Analyze Request Flow**:
   - Check “HTTP History” for request sequences (e.g., `GET /login` → `POST /auth` → `GET /dashboard`).
   - Note parameters, cookies, and headers that influence paths.
4. **Document Findings**:
   - Export “Site map” and save request sequences in a text file or Burp Suite’s “Logger”.

**Example Execution Path**:
```
GET /login HTTP/1.1 → 200 OK (Login form)
POST /auth HTTP/1.1 (username=admin) → 302 Found (Redirect to /dashboard)
GET /dashboard HTTP/1.1 → 200 OK (User dashboard)
```

**Remediation**:
- Enforce strict session management:
  ```php
  session_start();
  if (!isset($_SESSION['user_id'])) {
      header('Location: /login');
      exit;
  }
  ```
- Validate request sequences server-side.

### **2. Simulate User Interactions with Selenium**

Automate user interactions to trace execution paths through complex workflows.

**Steps**:
1. **Write Selenium Script**:
   - Create a Python script to simulate login and navigation:
     ```python
     from selenium import webdriver
     driver = webdriver.Chrome()
     driver.get('http://example.com/login')
     driver.find_element_by_name('username').send_keys('admin')
     driver.find_element_by_name('password').send_keys('password')
     driver.find_element_by_name('submit').click()
     print(driver.current_url)  # Output: /dashboard
     driver.quit()
     ```
2. **Capture Requests**:
   - Run script with browser proxied through Burp Suite.
   - Monitor “HTTP History” for request sequences.
3. **Analyze Paths**:
   - Note redirects, form submissions, and state changes (e.g., authenticated vs. unauthenticated).
4. **Document Findings**:
   - Save script outputs and Burp Suite logs.

**Example Vulnerable Finding**:
- Path: `POST /auth` → `GET /admin` (Bypasses authorization check).

**Remediation**:
- Implement role-based access control:
  ```javascript
  if (!user.isAdmin) {
      res.status(403).send('Access denied');
      return;
  }
  ```
- Validate user permissions for each path.

### **3. Test API Workflows with Postman**

Map execution paths in APIs by testing endpoints and their dependencies.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1`).
   - Check for documentation:
     ```bash
     curl http://example.com/api/swagger.json
     ```
2. **Test with Postman**:
   - Create a collection for `http://example.com/api/v1`.
   - Send requests (e.g., `GET /api/v1/users`, `POST /api/v1/orders`).
   - Note dependencies (e.g., `POST /auth` required before `GET /profile`).
3. **Analyze Responses**:
   - Check for redirects, tokens, or state changes (e.g., `session_id` in cookies).
   - Test invalid sequences (e.g., skipping `POST /auth`).
4. **Document Findings**:
   - Save API workflows and response details.

**Example Vulnerable Finding**:
- Path: `POST /api/v1/orders` without prior `POST /auth`.
- Response: Order created without authentication.

**Remediation**:
- Enforce authentication in API routes:
  ```javascript
  app.post('/api/v1/orders', verifyToken, (req, res) => {
      // Process order
  });
  ```
- Validate workflow dependencies.

### **4. Analyze Client-Side Logic with Browser Developer Tools**

Inspect JavaScript and DOM changes to understand client-side execution paths.

**Steps**:
1. **Open Developer Tools**:
   - Press `F12` on `http://example.com` and go to “Network” tab.
   - Interact with the application (e.g., click buttons, submit forms).
2. **Trace Requests**:
   - Monitor “Network” for XHR/fetch requests (e.g., `/api/update`).
   - Note parameters and headers.
3. **Inspect JavaScript**:
   - Go to “Sources” tab and search for event listeners (e.g., `onclick`).
   - Look for logic controlling paths (e.g., `if (user.role === 'admin')`).
4. **Document Findings**:
   - Save request sequences and JavaScript snippets.

**Example Vulnerable Finding**:
```javascript
if (getParameter('role') === 'admin') {
    window.location = '/admin';
}
```

**Remediation**:
- Validate roles server-side:
  ```php
  if ($_SESSION['role'] !== 'admin') {
      http_response_code(403);
      exit;
  }
  ```
- Avoid client-side logic for sensitive paths.

### **5. Visualize Execution Paths with Graphviz**

Create a flowchart to visualize complex execution paths (optional).

**Steps**:
1. **Define Paths**:
   - Based on Burp Suite or Postman findings, list paths (e.g., `/login` → `/auth` → `/dashboard`).
2. **Create Graphviz File**:
   - Write a `.dot` file:
     ```dot
     digraph execution_path {
         login -> auth;
         auth -> dashboard;
         dashboard -> profile;
         dashboard -> admin [label="if admin"];
     }
     ```
3. **Generate Flowchart**:
   - Run:
     ```bash
     dot -Tpng execution_path.dot -o flowchart.png
     ```
   - Output: Visual representation of paths.
4. **Document Findings**:
   - Include flowchart in the report.

**Example Vulnerable Path**:
- Flow: `POST /auth` → `GET /admin` without role check.

**Remediation**:
- Add authorization checks for each path:
  ```python
  if not current_user.is_admin:
      return abort(403)
  ```
- Regularly audit workflows.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-07 with practical scenarios based on common execution path mapping patterns observed in penetration testing.

### **Test 1: Bypassing Authentication Workflow**

Test for skipping authentication steps to access restricted paths.

**Steps**:
1. **Map Workflow with Burp Suite**:
   - Capture: `GET /login` → `POST /auth` → `GET /dashboard`.
2. **Test Direct Access**:
   - Query:
     ```bash
     curl http://example.com/dashboard
     ```
   - Check for access without `POST /auth`.
3. **Analyze Cookies**:
   - Inspect cookies in Burp Suite for session tokens.

**Example Insecure Finding**:
- URL: `http://example.com/dashboard`
- Response: `HTTP/1.1 200 OK` without authentication.

**Example Secure Configuration**:
- Validate sessions in PHP:
  ```php
  session_start();
  if (!isset($_SESSION['user_id'])) {
      header('Location: /login');
      exit;
  }
  ```

**Remediation**:
- Enforce session checks for all paths.
- Use secure cookies with `HttpOnly` and `Secure` flags.

### **Test 2: Exploiting Logic Flaw in E-commerce**

Test for skipping payment steps in an e-commerce workflow.

**Steps**:
1. **Simulate Purchase with Selenium**:
   - Script:
     ```python
     driver.get('http://example.com/cart')
     driver.find_element_by_id('checkout').click()
     print(driver.current_url)  # Expected: /payment
     ```
2. **Test Direct Access**:
   - Query:
     ```bash
     curl http://example.com/order/confirm
     ```
   - Check for order confirmation without payment.
3. **Analyze with Postman**:
   - Send `POST /order/confirm` without `POST /payment`.

**Example Insecure Finding**:
- URL: `http://example.com/order/confirm`
- Response: Order confirmed without payment.

**Example Secure Configuration**:
- Validate workflow in Node.js:
  ```javascript
  app.post('/order/confirm', (req, res) => {
      if (!req.session.payment_completed) {
          res.status(403).send('Payment required');
      }
  });
  ```

**Remediation**:
- Implement state tracking for workflows.
- Validate all steps server-side.

### **Test 3: Accessing Admin Path via Parameter**

Test for parameter-based access to restricted paths.

**Steps**:
1. **Crawl with OWASP ZAP**:
   - Spider `http://example.com` and check for parameters (e.g., `role=admin`).
2. **Test with cURL**:
   - Query:
     ```bash
     curl "http://example.com/dashboard?role=admin"
     ```
   - Check for admin access.
3. **Inspect JavaScript**:
   - Use Developer Tools to find client-side logic (e.g., `if (role === 'admin')`).

**Example Insecure Finding**:
- URL: `http://example.com/dashboard?role=admin`
- Response: Admin dashboard.

**Example Secure Configuration**:
- Validate roles in Python:
  ```python
  if request.args.get('role') and not current_user.is_admin:
      return abort(403)
  ```

**Remediation**:
- Avoid client-side role checks.
- Enforce server-side authorization.

### **Test 4: API Workflow Misconfiguration**

Test for API paths allowing unauthorized state changes.

**Steps**:
1. **Map API with Postman**:
   - Test: `POST /api/v1/login` → `GET /api/v1/profile`.
2. **Test Invalid Sequence**:
   - Query:
     ```bash
     curl http://example.com/api/v1/profile
     ```
   - Check for access without login.
3. **Analyze Headers**:
   - Check for missing authentication tokens in Burp Suite.

**Example Insecure Finding**:
- URL: `GET /api/v1/profile`
- Response: User data without token.

**Example Secure Configuration**:
- Require tokens in API:
  ```javascript
  app.get('/api/v1/profile', verifyToken, (req, res) => {
      res.json(userData);
  });
  ```

**Remediation**:
- Use JWT or OAuth for API authentication.
- Validate state transitions.

## **Additional Tips**

- **Start Simple**: Use Burp Suite to capture basic request sequences.
- **Combine Tools**: Cross-verify Selenium scripts with Postman for API workflows.
- **Gray-Box Testing**: If documentation is available, check for workflow diagrams or API specs.
- **Document Thoroughly**: Save all request sequences, scripts, and flowcharts in a report.
- **Bypass Defenses**: Test edge cases (e.g., invalid parameters, missing cookies) to uncover hidden paths.
- **Stay Ethical**: Obtain explicit permission for active interaction or automation.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).