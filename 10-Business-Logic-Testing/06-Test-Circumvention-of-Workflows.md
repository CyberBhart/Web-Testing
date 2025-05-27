# Testing for the Circumvention of Work Flows

## Overview

Testing for the circumvention of workflows (WSTG-BUSL-06) involves assessing whether a web application enforces the intended sequence of steps in its business processes, preventing attackers from bypassing critical stages, such as payment or authentication, to achieve unauthorized outcomes. According to OWASP, workflow vulnerabilities arise when applications rely on client-side controls or fail to validate the state of a process server-side, allowing attackers to skip or manipulate steps (e.g., accessing a checkout page without payment). This test focuses on identifying weaknesses that permit workflow circumvention, which can undermine the application's business logic.

**Impact**: Workflow circumvention can lead to:
- Financial fraud (e.g., obtaining goods without payment).
- Unauthorized access (e.g., bypassing approval steps).
- Data integrity violations (e.g., modifying records without validation).
- Operational disruptions due to exploited process flaws.

This guide provides a step-by-step methodology for testing workflow circumvention, adhering to OWASP’s WSTG-BUSL-06, with practical tools, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing workflow circumvention, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to bypass workflow steps.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Command-line tool for crafting requests to access out-of-sequence endpoints.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tool for testing API workflows and skipping steps.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and manipulating workflow requests.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Python library for scripting requests to test workflow bypasses.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-06, focusing on attempting to bypass or manipulate workflow steps to access unauthorized functionality or achieve unintended outcomes.

### 1. Map Workflows with Burp Suite

**Objective**: Identify the intended sequence of steps in critical workflows, such as checkout or user registration.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Perform actions like placing an order or registering a user.
   - Capture requests in Burp Suite’s “HTTP History”.
3. **Map Workflow**:
   - Identify sequential endpoints (e.g., `/cart`, `/payment`, `/confirm`).
   - Note parameters, session tokens, or state indicators (e.g., `order_id`, `step`).

**Burp Suite Commands**:
- **Command 1**: Capture and analyze a checkout workflow:
  ```
  Proxy tab -> HTTP History -> Filter by example.com -> Select requests (e.g., POST /cart, POST /payment, POST /confirm) -> Right-click -> Add to Site Map -> Target tab -> Site Map -> Review request sequence
  ```
- **Command 2**: Test skipping payment step:
  ```
  Right-click POST /confirm in HTTP History -> Send to Repeater -> Ensure order_id=123 and session=abc123 -> Click "Send" -> Check response in "Response" pane
  ```

**Example Workflow**:
```
POST /cart HTTP/1.1
Host: example.com
item_id=456&quantity=1

POST /payment HTTP/1.1
Host: example.com
order_id=123&amount=99.99

POST /confirm HTTP/1.1
Host: example.com
order_id=123
```

**Remediation**:
- Validate workflow state server-side (PHP):
  ```php
  session_start();
  if (!isset($_SESSION['payment_completed']) || $_SESSION['order_id'] !== $_POST['order_id']) {
      die('Invalid workflow state');
  }
  ```

**Tip**: Save workflow requests in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 2. Bypass Steps with cURL

**Objective**: Attempt to access workflow endpoints out of sequence to test for circumvention.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to note workflow URLs (e.g., `/confirm`).
2. **Craft Out-of-Sequence Requests**:
   - Send requests directly to later steps with valid session cookies.
3. **Analyze Response**:
   - Check if the application processes the request (e.g., order confirmed without payment).

**cURL Commands**:
- **Command 1**: Skip payment and confirm order:
  ```bash
  curl -X POST -d "order_id=123" -b "session=abc123" http://example.com/confirm
  ```
- **Command 2**: Access dashboard without registration:
  ```bash
  curl -X GET -b "session=abc123" http://example.com/dashboard
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Order Confirmed: Order #123
```

**Remediation**:
- Enforce step validation (Node.js):
  ```javascript
  if (!req.session.payment_verified) {
      res.redirect('/payment');
  }
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > response.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Workflow Bypasses with Postman

**Objective**: Test API endpoints for workflow circumvention vulnerabilities.

**Steps**:
1. **Identify API Workflow**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/order/confirm`).
   - Import into Postman.
2. **Skip Steps**:
   - Send requests to later endpoints without prior steps.
   - Use valid authentication tokens.
3. **Analyze Response**:
   - Check if the API processes out-of-sequence requests.

**Postman Commands**:
- **Command 1**: Send order confirmation request:
  ```
  New Request -> POST http://example.com/api/v1/order/confirm -> Body: {"order_id": 123} -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Access protected API endpoint:
  ```
  New Request -> GET http://example.com/api/v1/user/profile -> Headers: Authorization: Bearer xyz789 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "message": "Order #123 confirmed"
}
```

**Remediation**:
- Validate API workflow state (Python):
  ```python
  if not session.get('payment_completed'):
      return jsonify({'error': 'Payment required'}), 403
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Manipulate Client-Side Workflow with Browser Developer Tools

**Objective**: Test whether client-side controls can be bypassed to skip workflow steps.

**Steps**:
1. **Inspect Workflow**:
   - Open Developer Tools (`F12`) on a workflow page (e.g., `http://example.com/payment`).
   - Identify redirects or JavaScript controlling navigation.
2. **Manipulate Requests**:
   - Modify form actions to point to later steps.
   - Disable JavaScript to bypass redirects.
3. **Analyze Response**:
   - Check if the server accepts the request.

**Browser Developer Tools Commands**:
- **Command 1**: Change form action:
  ```
  Elements tab -> Find <form action="/payment"> -> Right-click -> Edit as HTML -> Change to action="/confirm" -> Submit form
  ```
- **Command 2**: Disable JavaScript:
  ```
  Chrome: Settings -> Privacy and Security -> Site Settings -> JavaScript -> Don’t allow sites to use JavaScript -> Refresh page -> Navigate to http://example.com/confirm
  ```

**Example Vulnerable Finding**:
- Modified form action -> Response: `Order Confirmed`.

**Remediation**:
- Avoid client-side workflow logic (PHP):
  ```php
  if ($_SERVER['REQUEST_URI'] === '/confirm' && !$_SESSION['payment_completed']) {
      header('Location: /payment');
      exit;
  }
  ```

**Tip**: Save screenshots of modified forms or responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTML changes).

### 5. Script Workflow Bypasses with Python Requests

**Objective**: Automate tests to bypass workflow steps and evaluate server-side validation.

**Steps**:
1. **Write Python Script**:
   - Create a script to access later workflow steps directly.
2. **Run Script**:
   - Execute to test for unauthorized access.
3. **Analyze Responses**:
   - Check for successful bypasses.

**Python Script**:
```python
import requests
import sys

url = 'http://example.com/confirm'
data = {'order_id': '123'}
cookies = {'session': 'abc123'}
headers = {'User-Agent': 'Mozilla/5.0'}

try:
    # Attempt order confirmation bypass
    response = requests.post(url, data=data, cookies=cookies, headers=headers, timeout=5)
    print(f"Confirm Status: {response.status_code}")
    print(f"Confirm Response: {response.text[:100]}")
    
    # Attempt dashboard access
    dashboard_url = 'http://example.com/dashboard'
    response = requests.get(dashboard_url, cookies=cookies, headers=headers, timeout=5)
    print(f"Dashboard Status: {response.status_code}")
    print(f"Dashboard Response: {response.text[:100]}")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the script:
  ```bash
  python3 test_workflow_bypass.py
  ```
- **Command 2**: Test profile access:
  ```bash
  python3 -c "import requests; url='http://example.com/api/v1/user/profile'; cookies={'session': 'abc123'}; r=requests.get(url, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Confirm Status: 200
Confirm Response: {"status": "success", "message": "Order #123 confirmed"}
Dashboard Status: 200
Dashboard Response: Welcome to your dashboard
```

**Remediation**:
- Track workflow state (Node.js):
  ```javascript
  if (!req.session.workflow_step || req.session.workflow_step !== 'payment_completed') {
      res.status(403).send('Invalid workflow state');
  }
  ```

**Tip**: Save script output to a file (e.g., `python3 test_workflow_bypass.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Parameter Manipulation for Workflow Bypass

**Objective**: Test whether modifying workflow parameters allows circumvention of validation checks.

**Steps**:
1. **Identify Parameters**:
   - Use Burp Suite to find parameters (e.g., `step`, `order_id`, `status`).
2. **Manipulate Parameters**:
   - Use Intruder to send requests with altered values (e.g., `step=confirm`).
3. **Analyze Responses**:
   - Check for unauthorized access or successful processing.

**Burp Suite Commands**:
- **Command 1**: Identify parameters:
  ```
  HTTP History -> Select POST /process?step=payment -> Check Request Body/Parameters for step, order_id -> Note values
  ```
- **Command 2**: Test with Intruder:
  ```
  Send to Intruder -> Positions -> Set payload position to step=§payment§ -> Payloads -> Strings (confirm, approved) -> Start Attack -> Check Response Status/Content
  ```

**Example Vulnerable Output**:
```
Request (step=confirm): HTTP/1.1 200 OK, {"message": "Order confirmed"}
```

**Remediation**:
- Validate parameters server-side (PHP):
  ```php
  if ($_POST['step'] !== $_SESSION['expected_step']) {
      die('Invalid workflow step');
  }
  ```

**Tip**: Save Intruder responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Concurrent Workflow Manipulation

**Objective**: Detect workflow bypasses caused by concurrent requests exploiting weak state validation.

**Steps**:
1. **Identify Workflow**:
   - Use Burp Suite to map a multi-step process (e.g., `/payment` -> `/confirm`).
2. **Send Concurrent Requests**:
   - Use Python to send multiple `/confirm` requests simultaneously.
3. **Analyze Responses**:
   - Check for successful bypasses indicating race conditions.

**Python Script**:
```python
import requests
import threading
import sys

url = 'http://example.com/confirm'
data = {'order_id': '123'}
cookies = {'session': 'abc123'}

def send_request():
    try:
        response = requests.post(url, data=data, cookies=cookies, timeout=5)
        print(f"Status: {response.status_code}, Response: {response.text[:100]}")
    except requests.RequestException as e:
        print(f"Error: {e}")

threads = []
for _ in range(10):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()
for t in threads:
    t.join()
```

**Python Commands**:
- **Command 1**: Run the concurrent test:
  ```bash
  python3 test_concurrent_bypass.py
  ```
- **Command 2**: Test single concurrent request for verification:
  ```bash
  python3 -c "import requests; url='http://example.com/confirm'; data={'order_id': '123'}; cookies={'session': 'abc123'}; r=requests.post(url, data=data, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Status: 200, Response: {"message": "Order #123 confirmed"}
```

**Remediation**:
- Prevent concurrent access (Python):
  ```python
  from flask import session
  if not session.get('payment_locked'):
      return jsonify({'error': 'Concurrent access detected'}), 403
  ```

**Tip**: Save script output to a file (e.g., `python3 test_concurrent_bypass.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 8. Test Session State Tampering

**Objective**: Test whether tampering with session cookies or tokens allows circumvention of workflow validation.

**Steps**:
1. **Capture Session Data**:
   - Use Burp Suite to capture cookies (e.g., `session=abc123`).
2. **Modify Session State**:
   - Decode cookies (e.g., base64) and alter state indicators (e.g., `payment_completed=true`).
3. **Test Modified Session**:
   - Send requests with tampered cookies to later steps.

**Burp Suite Commands**:
- **Command 1**: Capture and decode cookie:
  ```
  HTTP History -> Select POST /confirm -> Check Request Headers for Cookie: session=abc123 -> Decoder tab -> Paste cookie value -> Decode as Base64 -> Inspect state
  ```
- **Command 2**: Test tampered cookie:
  ```
  Send to Repeater -> Modify Cookie: session=eyJzdGF0ZSI6InBheW1lbnRfY29tcGxldGVkIn0= -> Send -> Check Response
  ```

**Example Vulnerable Output**:
```
HTTP/1.1 200 OK, {"message": "Order confirmed"}
```

**Remediation**:
- Sign session tokens (Node.js):
  ```javascript
  const jwt = require('jsonwebtoken');
  app.use((req, res, next) => {
      const token = req.cookies.session;
      try {
          jwt.verify(token, process.env.SECRET);
          next();
      } catch (e) {
          res.status(403).send('Invalid session');
      }
  });
  ```

**Tip**: Save tampered requests and responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).