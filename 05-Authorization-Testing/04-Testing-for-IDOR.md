# Testing for Insecure Direct Object References (IDOR)

## Overview

Testing for Insecure Direct Object References (IDOR) (WSTG-AUTHZ-04) involves verifying that the application prevents unauthorized access to resources by manipulating object identifiers (e.g., IDs, filenames) in requests. According to OWASP, IDOR vulnerabilities allow attackers to access data or resources belonging to other users (horizontal access) or restricted resources (vertical access) by modifying parameters, URLs, or form fields. This test focuses on evaluating server-side validation, ownership checks, and access controls for parameters, form fields, URLs, and API endpoints to ensure robust authorization.

**Impact**: IDOR vulnerabilities can lead to:
- Unauthorized access to sensitive user data (e.g., profiles, orders).
- Exposure of restricted resources or actions.
- Data breaches or non-compliance with standards (e.g., GDPR, PCI DSS).

This guide provides a practical, hands-on methodology for testing IDOR vulnerabilities, adhering to OWASP’s WSTG-AUTHZ-04, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as manipulating IDs or accessing resources may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing IDOR vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and fuzzes requests to test parameter and form field manipulation.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test direct URL access and API endpoints.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTHZ-04, focusing on testing parameter manipulation, sequential IDs, form field manipulation, direct URL access, predictable resource names, automated ID fuzzing, and API endpoint access.

### 1. Test Parameter Manipulation with Burp Suite

**Objective**: Ensure users cannot access unauthorized resources by manipulating IDs.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a request with an ID parameter:
   ```bash
   HTTP History -> Select POST /account/viewOrder -> Send to Repeater
   ```
3. Modify the ID to another user’s resource:
   ```bash
   Repeater -> Change orderID=0001 to orderID=0002 -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied: Unauthorized resource"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"orderID": "0002", "details": {...}}
```

**Remediation**:
- Enforce ownership (Node.js):
  ```javascript
  app.post('/account/viewOrder', (req, res) => {
      const { orderID } = req.body;
      if (!isOrderOwner(orderID, req.session.user.id)) {
          return res.status(403).json({ error: 'Access denied' });
      }
      res.json({ order: getOrder(orderID) });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Sequential IDs with cURL

**Objective**: Ensure sequential or predictable IDs cannot be used to access unauthorized resources.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test a valid resource request:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/account/viewProfile?userID=100
   ```
3. Test another user’s resource by incrementing the ID:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/account/viewProfile?userID=101
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Unauthorized access"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"userID": "101", "profile": {...}}
```

**Remediation**:
- Use UUIDs (Python/Flask):
  ```python
  import uuid
  @app.get('/account/viewProfile')
  def view_profile():
      user_id = request.args.get('userID')
      if user_id != session.get('user_id'):
          return jsonify({'error': 'Unauthorized access'}), 403
      return jsonify({'profile': get_profile(user_id)})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Form Field Manipulation with Burp Suite

**Objective**: Ensure hidden form fields cannot be modified to access unauthorized resources.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a form submission with hidden fields:
   ```bash
   HTTP History -> Select POST /account/update -> Send to Repeater
   ```
3. Modify the hidden field to another user’s account:
   ```bash
   Repeater -> Change account=johnsmith to account=janedoe -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Permission denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account updated", "account": "janedoe"}
```

**Remediation**:
- Validate form fields (Node.js):
  ```javascript
  app.post('/account/update', (req, res) => {
      const { account } = req.body;
      if (account !== req.session.user.account) {
          return res.status(403).json({ error: 'Permission denied' });
      }
      res.json({ status: 'Account updated' });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Direct Access to Objects with cURL

**Objective**: Ensure direct URLs require proper authorization.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test access to another user’s resource:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/api/users/100
   ```
3. Test another resource:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/api/users/101
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"userID": "101", "data": {...}}
```

**Remediation**:
- Restrict direct access (Python/Flask):
  ```python
  @app.get('/api/users/<user_id>')
  def get_user(user_id):
      if user_id != session.get('user_id'):
          return jsonify({'error': 'Access denied'}), 403
      return jsonify({'user': get_user_data(user_id)})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Predictable Resource Names with cURL

**Objective**: Ensure predictable resource names cannot be guessed to access private files.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test access to a predictable resource:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/uploads/johnsmith_resume.pdf
   ```
3. Test another predictable resource:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/uploads/janedoe_resume.pdf
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/pdf
[Binary PDF content]
```

**Remediation**:
- Use signed URLs (Node.js):
  ```javascript
  const crypto = require('crypto');
  app.get('/uploads/:filename', (req, res) => {
      const { filename } = req.params;
      const { token } = req.query;
      const expectedToken = crypto.createHmac('sha256', 'secret').update(filename + req.session.user.id).digest('hex');
      if (token !== expectedToken) {
          return res.status(403).json({ error: 'Access denied' });
      }
      res.sendFile(path.join(__dirname, 'uploads', filename));
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test IDOR with Burp Suite Intruder for Automated ID Fuzzing

**Objective**: Ensure resource IDs cannot be systematically manipulated to access unauthorized data.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a request with an ID parameter:
   ```bash
   HTTP History -> Select GET /api/orders?orderID=0001 -> Send to Intruder
   ```
3. Fuzz the ID parameter with a numeric range:
   ```bash
   Intruder -> Payloads -> Add numeric range (1-1000) -> Start Attack -> Check Response
   ```
4. Analyze responses; expected secure response denies unauthorized access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Access denied: Unauthorized resource"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"orderID": "0002", "details": {...}}
```

**Remediation**:
- Validate ownership (Python/Flask):
  ```python
  @app.get('/api/orders')
  def get_order():
      order_id = request.args.get('orderID')
      if not is_order_owner(order_id, session.get('user_id')):
          return jsonify({'error': 'Access denied'}), 403
      return jsonify({'order': get_order(order_id)})
  ```

**Tip**: Save Burp Suite Intruder responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test IDOR in API Endpoints with cURL

**Objective**: Ensure API endpoints enforce ownership checks for resource IDs.

**Steps**:
1. Log in as a user and obtain a session cookie.
2. Test access to another user’s resource via an API endpoint:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/api/v1/users/101
   ```
3. Test another resource:
   ```bash
   curl -i -H "Cookie: SESSION=User_Session" http://example.com/api/v1/users/102
   ```
4. Analyze responses; expected secure response denies access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "Unauthorized access"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"userID": "102", "data": {...}}
```

**Remediation**:
- Secure API endpoints (Node.js):
  ```javascript
  app.get('/api/v1/users/:userID', (req, res) => {
      const { userID } = req.params;
      if (userID !== req.session.user.id) {
          return res.status(403).json({ error: 'Unauthorized access' });
      }
      res.json({ user: getUserData(userID) });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).