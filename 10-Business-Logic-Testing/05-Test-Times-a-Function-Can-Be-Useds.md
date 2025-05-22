# Test Number of Times a Function Can Be Used Limits

## Overview

Testing the number of times a function can be used limits (WSTG-BUSL-05) involves assessing whether a web application enforces restrictions on how many times a function, such as password resets, coupon redemptions, or form submissions, can be executed within a timeframe or session. According to OWASP, vulnerabilities arise when applications fail to implement rate-limiting or usage caps, allowing attackers to abuse functions through brute-force, resource exhaustion, or unauthorized actions. This test identifies weaknesses in usage limits that could lead to security or operational issues.

**Impact**: Weak function usage limits can lead to:
- Brute-force attacks (e.g., guessing reset tokens).
- Resource exhaustion (e.g., spamming submissions).
- Financial loss (e.g., multiple coupon redemptions).
- Denial-of-service (DoS) by overwhelming functions.

This guide provides a step-by-step methodology for testing function usage limits, adhering to OWASP’s WSTG-BUSL-05, with practical tools, specific commands, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing function usage limits, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and automates repeated requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends rapid or repeated HTTP requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tests API endpoints with repeated calls.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Python Requests Library**: Scripts automated, repeated requests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

- **Browser Developer Tools**: Inspects client-side limit mechanisms in Chrome/Firefox.
  - Access by pressing `F12` or right-clicking and selecting “Inspect”.
  - No setup required.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-05, focusing on repeatedly executing functions to test usage limits or rate-limiting mechanisms.

### 1. Identify Restricted Functions with Burp Suite

**Objective**: Locate functions that should have usage limits (e.g., password resets, coupon redemptions).

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in “Target” tab.
2. **Capture Requests**:
   - Perform actions (e.g., request password reset, redeem coupon).
   - Review “HTTP History” for endpoints (e.g., `/reset-password`, `/coupon/redeem`).
3. **Analyze Functions**:
   - Note parameters (e.g., `email`, `coupon_code`) and session tokens.

**Burp Suite Commands**:
- **Command 1**: Capture request:
  ```
  HTTP History -> Select POST /reset-password -> Check Params: email=user@example.com -> Send to Intruder
  ```
- **Command 2**: Export endpoints:
  ```
  Target -> Site Map -> Right-click example.com -> Copy URLs in Scope -> Paste to file
  ```

**Example Request**:
```
POST /reset-password HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

email=user@example.com
```

**Remediation**:
- Implement rate-limiting (PHP):
  ```php
  $cache = new Cache();
  $key = 'reset_' . md5($email);
  if ($cache->get($key) >= 5) {
      die('Too many attempts');
  }
  $cache->increment($key, 1, 3600); // 1-hour limit
  ```

**Tip**: Save “HTTP History” requests to Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., request details).

### 2. Test Rate Limits with cURL

**Objective**: Send repeated requests to test usage limit enforcement.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to note request structure.
2. **Send Repeated Requests**:
   - Use cURL to send rapid requests.
3. **Analyze Response**:
   - Check for HTTP 429 (Too Many Requests) or continued processing.

**cURL Commands**:
- **Command 1**: Send 10 password reset requests:
  ```bash
  for i in {1..10}; do curl -X POST -d "email=user@example.com" http://example.com/reset-password; sleep 0.1; done
  ```
- **Command 2**: Test 5 coupon redemptions:
  ```bash
  for i in {1..5}; do curl -X POST -d "coupon_code=SAVE10" -b "session=abc123" http://example.com/coupon/redeem; done
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "message": "Reset link sent"}
```

**Remediation**:
- Use throttling (Express):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/reset-password', rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 5 // 5 requests
  }));
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Function Limits with Postman

**Objective**: Test API endpoints for usage limit enforcement.

**Steps**:
1. **Import Endpoints**:
   - Identify APIs from Burp Suite (e.g., `/api/v1/reset-password`).
   - Add to Postman.
2. **Send Repeated Requests**:
   - Use Collection Runner with 10 iterations, 0ms delay.
3. **Analyze Response**:
   - Check for rate-limiting or excessive executions.

**Postman Commands**:
- **Command 1**: Run 10 password reset requests:
  ```
  New Collection -> Add POST http://example.com/api/v1/reset-password -> Body: {"email": "user@example.com"} -> Collection Runner -> Iterations: 10, Delay: 0ms -> Run
  ```
- **Command 2**: Test 5 coupon redemptions:
  ```
  New Request -> POST http://example.com/api/v1/coupon/redeem -> Body: {"coupon_code": "SAVE10"} -> Headers: Cookie: session=abc123 -> Collection Runner -> Iterations: 5 -> Run
  ```

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "message": "Coupon applied"
}
```

**Remediation**:
- Enforce API limits (Flask):
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.json.get('email'))
  @limiter.limit("5/hour")
  @app.route('/api/v1/reset-password', methods=['POST'])
  def reset_password():
      return jsonify({"status": "success"})
  ```

**Tip**: Save Postman collection runs as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Simulate High-Volume Requests with Python Requests

**Objective**: Test function limits under high-frequency requests.

**Steps**:
1. **Write Script**:
   - Use threading for concurrent requests.
2. **Run Script**:
   - Execute and analyze responses.
3. **Verify Findings**:
   - Cross-check with Burp Suite.

**Python Script**:
```python
import requests
import threading
import sys

url = 'http://example.com/reset-password'
data = {'email': 'user@example.com'}
cookies = {'session': 'abc123'}

def send_request():
    try:
        response = requests.post(url, data=data, cookies=cookies, timeout=5)
        print(f"Status: {response.status_code}, Response: {response.text[:100]}")
    except requests.RequestException as e:
        print(f"Error: {e}")

try:
    threads = [threading.Thread(target=send_request) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run script:
  ```bash
  python3 test_high_volume.py
  ```
- **Command 2**: Test single request:
  ```bash
  python3 -c "import requests; url='http://example.com/reset-password'; data={'email': 'user@example.com'}; cookies={'session': 'abc123'}; r=requests.post(url, data=data, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Status: 200, Response: {"status": "success", "message": "Reset link sent"}
```

**Remediation**:
- Use database limits (SQL):
  ```sql
  INSERT INTO rate_limits (user_id, action, count, expiry)
  VALUES (123, 'reset_password', 1, NOW() + INTERVAL 1 HOUR)
  ON DUPLICATE KEY UPDATE count = count + 1;
  IF (SELECT count FROM rate_limits WHERE user_id = 123 AND action = 'reset_password') > 5 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Too many attempts';
  END IF;
  ```

**Tip**: Save script output to a file (e.g., `python3 test_high_volume.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 5. Automate Repeated Requests with Python Requests

**Objective**: Script automated tests for function limits.

**Steps**:
1. **Write Script**:
   - Send sequential requests with controlled timing.
2. **Run Script**:
   - Execute and analyze responses.
3. **Verify Findings**:
   - Cross-check with Postman.

**Python Script**:
```python
import requests
import time
import sys

url = 'http://example.com/coupon/redeem'
data = {'coupon_code': 'SAVE10'}
cookies = {'session': 'abc123'}

try:
    for i in range(10):
        response = requests.post(url, data=data, cookies=cookies, timeout=5)
        print(f"Attempt {i + 1}: Status: {response.status_code}, Response: {response.text[:100]}")
        time.sleep(0.1)
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run script:
  ```bash
  python3 test_repeated.py
  ```
- **Command 2**: Test single coupon redemption:
  ```bash
  python3 -c "import requests; url='http://example.com/coupon/redeem'; data={'coupon_code': 'SAVE10'}; cookies={'session': 'abc123'}; r=requests.post(url, data=data, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status: 200, Response: {"status": "success", "message": "Coupon applied"}
...
Attempt 10: Status: 200, Response: {"status": "success", "message": "Coupon applied"}
```

**Remediation**:
- Use Redis for rate-limiting (Python):
  ```python
  import redis
  r = redis.Redis(host='localhost', port=6379)
  key = f"coupon:{data['coupon_code']}"
  if r.exists(key) and int(r.get(key)) >= 1:
      raise ValueError("Coupon exhausted")
  r.incr(key)
  r.expire(key, 3600)  # 1-hour expiry
  ```

**Tip**: Save script output to a file (e.g., `python3 test_repeated.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Client-Side Limit Bypasses with Browser Developer Tools

**Objective**: Verify if client-side rate-limiting can be bypassed.

**Steps**:
1. **Access Function**:
   - Open `http://example.com/reset-password`, press `F12` to access Developer Tools.
2. **Identify Limits**:
   - Check for JavaScript or local storage (e.g., `localStorage.resetCount`).
3. **Bypass Limits**:
   - Modify or clear counters (e.g., `localStorage.resetCount = 0`).
4. **Test Function**:
   - Submit the function and check server enforcement.

**Browser Developer Tools Commands**:
- **Command 1**: Clear counter:
  ```
  Console -> localStorage.resetCount = 0 -> Submit form at http://example.com/reset-password -> Check Response
  ```
- **Command 2**: Disable JavaScript limit:
  ```
  Console -> window.submitLimit = () => true -> Submit form at http://example.com/reset-password -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "message": "Reset link sent"}
```

**Remediation**:
- Enforce server-side limits (PHP):
  ```php
  $cache = new Cache();
  $key = 'reset_' . md5($email);
  if ($cache->get($key) >= 5) {
      die('Too many attempts');
  }
  $cache->increment($key, 1, 3600);
  ```

**Tip**: Save screenshots of modified scripts and responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Session-Based Limit Evasion with Burp Suite

**Objective**: Check if multiple sessions bypass usage limits.

**Steps**:
1. **Capture Request**:
   - Capture a request (e.g., `POST /coupon/redeem`) with a session cookie.
2. **Send Multiple Sessions**:
   - Use Intruder with different session cookies.
3. **Analyze Response**:
   - Check for excessive executions across sessions.

**Burp Suite Commands**:
- **Command 1**: Send multiple sessions:
  ```
  Intruder -> POST /coupon/redeem -> Payloads -> Simple list -> Add session cookies: abc123, def456, ghi789 -> Start Attack
  ```
- **Command 2**: Test single session:
  ```
  Repeater -> POST /coupon/redeem -> Headers: Cookie: session=abc123 -> Send -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "message": "Coupon applied"}
```

**Remediation**:
- Track usage globally (Express):
  ```javascript
  const redis = require('redis').createClient();
  const key = `coupon:${req.body.coupon_code}`;
  if (await redis.get(key) >= 1) {
      res.status(400).send('Coupon exhausted');
  }
  await redis.incr(key);
  await redis.expire(key, 3600);
  ```

**Tip**: Save Intruder results as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test IP-Based Limit Evasion with cURL

**Objective**: Verify if IP-based rate-limiting can be bypassed.

**Steps**:
1. **Capture Request**:
   - Note request details (e.g., `POST /reset-password`).
2. **Send via Proxies**:
   - Use cURL with different proxy IPs.
3. **Analyze Response**:
   - Check for rate-limiting enforcement.

**cURL Commands**:
- **Command 1**: Send via proxy:
  ```
  curl -X POST -d "email=user@example.com" --proxy http://proxy1.com:8080 http://example.com/reset-password
  ```
- **Command 2**: Send via second proxy:
  ```
  curl -X POST -d "email=user@example.com" --proxy http://proxy2.com:8080 http://example.com/reset-password
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "message": "Reset link sent"}
```

**Remediation**:
- Enforce IP limits (Flask):
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.remote_addr)
  @limiter.limit("5/hour")
  @app.route('/reset-password', methods=['POST'])
  def reset_password():
      return jsonify({"status": "success"})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).