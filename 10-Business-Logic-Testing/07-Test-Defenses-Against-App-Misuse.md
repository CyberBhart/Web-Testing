# Test Defenses Against Application Misuse

## Overview

Testing defenses against application misuse (WSTG-BUSL-07) involves assessing whether a web application has active mechanisms to detect and respond to misuse, such as malicious inputs, abnormal usage patterns, or attempts to exploit legitimate functionality. According to OWASP, misuse can include actions like submitting invalid data, rapid automated requests, or performing unexpected operations, which may indicate an attack. Weak or absent defenses allow attackers to probe for vulnerabilities without detection, leaving the application owner unaware of the threat. This test focuses on verifying whether the application monitors and mitigates misuse, particularly in authenticated areas, though public areas may also be tested for rate-limiting or scraping defenses.

**Impact**: Insufficient defenses against misuse can lead to:
- Undetected brute-force attacks (e.g., credential stuffing).
- Resource exhaustion (e.g., DoS via excessive requests).
- Exploitation of legitimate features (e.g., spamming contact forms).
- Increased attack surface due to unmonitored malicious activity.

This guide provides a step-by-step methodology for testing defenses against application misuse, adhering to OWASP’s WSTG-BUSL-07, with practical tools, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing defenses against application misuse, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and automates requests to simulate misuse patterns.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Command-line tool for sending rapid or malformed requests to test defenses.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tool for testing API endpoints with abusive inputs or patterns.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Apache JMeter**: Load testing tool for simulating high-frequency or malicious requests.
  - Download from [jmeter.apache.org](https://jmeter.apache.org/download_jmeter.cgi).
  - Extract and run: `bin/jmeter.sh` (Linux) or `bin/jmeter.bat` (Windows).

- **Python Requests Library**: Python library for scripting automated misuse scenarios.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-07, focusing on simulating misuse patterns (e.g., excessive requests, malformed inputs, or abnormal actions) to evaluate the application’s detection and response mechanisms.

### 1. Simulate Excessive Requests with Burp Suite

**Objective**: Test whether the application detects and blocks rapid or excessive requests, such as login attempts or form submissions.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Request**:
   - Perform an action like logging in or submitting a form.
   - Capture the request in Burp Suite’s “HTTP History” (e.g., `POST /login`).
3. **Simulate Misuse**:
   - Use Intruder to send multiple requests rapidly.
   - Observe responses for rate-limiting or account lockout.
4. **Analyze Response**:
   - Check for HTTP 429 (Too Many Requests), account lockout, or continued processing.

**Burp Suite Commands**:
- **Command 1**: Send 50 login attempts:
  ```
  Right-click POST /login in HTTP History -> Send to Intruder -> Positions tab -> Clear § -> Select password parameter (e.g., password=pass123) -> Add § -> Payloads tab -> Simple list -> Add "pass123" -> Options tab -> Set Threads to 10 -> Start Attack
  ```
- **Command 2**: Scan for rate-limiting issues:
  ```
  Target tab -> Site Map -> Right-click example.com -> Engagement Tools -> Active Scan -> Select /contact endpoint -> Run Scan -> Check Issues tab for rate-limiting or misuse detection
  ```

**Example Request**:
```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=pass123
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Login failed (50 times, no lockout)
```

**Remediation**:
- Implement account lockout (PHP):
  ```php
  $cache = new Cache();
  $key = 'login_attempts_' . $username;
  if ($cache->get($key, 0) >= 5) {
      die('Account locked for 30 minutes');
  }
  $cache->increment($key, 1, 1800); // 30-minute window
  ```

**Tip**: Save Intruder results and responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test with Malformed Inputs Using cURL

**Objective**: Send malformed or unexpected inputs to test whether the application detects and handles misuse.

**Steps**:
1. **Identify Input Points**:
   - Use Burp Suite to find forms or API endpoints (e.g., `/contact`, `/api/v1/submit`).
2. **Send Malformed Requests**:
   - Submit invalid or malicious data (e.g., oversized strings, SQL injection payloads).
   - Repeat to test detection mechanisms.
3. **Analyze Response**:
   - Check for input validation, error handling, or blocking.

**cURL Commands**:
- **Command 1**: Submit oversized input:
  ```bash
  curl -X POST -d "message=$(printf 'A%.0s' {1..10000})" http://example.com/contact
  ```
- **Command 2**: Test SQL injection detection:
  ```bash
  curl -X POST -d "username=admin' OR '1'='1" -b "session=abc123" http://example.com/login
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
Error: Input too long (no blocking)
```

**Remediation**:
- Validate and sanitize inputs (Node.js):
  ```javascript
  const sanitize = require('sanitize-html');
  if (req.body.message.length > 1000 || !sanitize(req.body.message)) {
      res.status(400).send('Invalid input');
  }
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > response.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Misuse with Postman

**Objective**: Test API endpoints for defenses against rapid or malicious requests.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/login`).
   - Import into Postman.
2. **Simulate Misuse**:
   - Send rapid requests or malformed payloads.
   - Test for rate-limiting or input validation.
3. **Analyze Response**:
   - Check for HTTP 429, error messages, or continued processing.

**Postman Commands**:
- **Command 1**: Send 10 rapid login requests:
  ```
  New Collection -> Add Request (POST http://example.com/api/v1/login) -> Body: {"username": "user@example.com", "password": "pass123"} -> Save -> Collection Runner -> Select Collection -> Set Iterations to 10, Delay to 0ms -> Run
  ```
- **Command 2**: Test malicious JSON payload:
  ```
  New Request -> POST http://example.com/api/v1/submit -> Body: {"data": "<script>alert('xss')</script>"} -> Headers: Cookie: session=abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "message": "Request processed (10 times, no limits)"
}
```

**Remediation**:
- Enforce API rate limits (Python):
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.remote_addr)
  @limiter.limit("10/minute")
  @app.route('/api/v1/login', methods=['POST'])
  def login():
      return jsonify({"status": "failed"})
  ```

**Tip**: Save Postman run results as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Simulate High-Volume Misuse with Apache JMeter

**Objective**: Test defenses against high-frequency or abusive requests using load testing.

**Steps**:
1. **Create JMeter Test Plan**:
   - Add a Thread Group with 20 threads and 1 loop.
   - Add an HTTP Request sampler for a target endpoint (e.g., `POST /contact`).
2. **Simulate Misuse**:
   - Configure rapid or malformed requests.
   - Run the test plan.
3. **Analyze Results**:
   - Check for rate-limiting, blocking, or error responses.

**JMeter Commands**:
- **Command 1**: Send 20 contact form submissions:
  ```
  JMeter GUI -> File -> New -> Add -> Threads (Users) -> Thread Group -> Number of Threads: 20, Ramp-Up Period: 0, Loop Count: 1 -> Add -> Sampler -> HTTP Request -> Server: example.com, Path: /contact, Method: POST, Parameters: message=TestMessage -> Run
  ```
- **Command 2**: Test login with malicious inputs:
  ```
  JMeter GUI -> Thread Group -> Number of Threads: 10, Ramp-Up Period: 0, Loop Count: 1 -> HTTP Request -> Server: example.com, Path: /login, Method: POST, Parameters: username=admin' OR '1'='1, password=pass123 -> Add -> Config Element -> HTTP Cookie Manager -> Cookie: session=abc123 -> Run
  ```

**Example Vulnerable Result**:
- 20 requests -> All return `HTTP 200: Message sent`.

**Remediation**:
- Implement IP-based throttling (SQL):
  ```sql
  INSERT INTO request_limits (ip, count, expiry)
  VALUES ('192.168.1.1', 1, NOW() + INTERVAL 1 MINUTE)
  ON DUPLICATE KEY UPDATE count = count + 1;
  IF (SELECT count FROM request_limits WHERE ip = '192.168.1.1') > 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Too many requests';
  END IF;
  ```

**Tip**: Save JMeter results as CSV or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., test plan results).

### 5. Script Misuse Scenarios with Python Requests

**Objective**: Automate tests to simulate misuse and evaluate detection mechanisms.

**Steps**:
1. **Write Python Script**:
   - Create a script to send rapid or malicious requests.
2. **Run Script**:
   - Execute to test for detection or blocking.
3. **Analyze Responses**:
   - Check for rate-limiting or blocking.

**Python Script**:
```python
import requests
import time
import sys

url = 'http://example.com/login'
payloads = [
    {'username': 'user@example.com', 'password': 'pass123'},
    {'username': 'admin\' OR \'1\'=\'1', 'password': 'pass123'},
    {'username': 'a' * 10000, 'password': 'pass123'}
]
cookies = {'session': 'abc123'}

try:
    for i, payload in enumerate(payloads * 5):  # Repeat each payload 5 times
        response = requests.post(url, data=payload, cookies=cookies, timeout=5)
        print(f"Attempt {i + 1}: Status={response.status_code}, Response={response.text[:100]}")
        time.sleep(0.1)  # Simulate rapid requests
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the login misuse script:
  ```bash
  python3 test_misuse.py
  ```
- **Command 2**: Test form submission with oversized data:
  ```bash
  python3 -c "import requests; url='http://example.com/contact'; data={'message': 'A' * 10000}; cookies={'session': 'abc123'}; for _ in range(5): r=requests.post(url, data=data, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status=200, Response={"status": "failed"}
...
Attempt 15: Status=200, Response={"status": "failed"}
```

**Remediation**:
- Use anomaly detection (Python):
  ```python
  from redis import Redis
  redis = Redis(host='localhost', port=6379)
  key = f"requests:{request.remote_addr}"
  if redis.exists(key) and int(redis.get(key)) >= 10:
      return jsonify({'error': 'Suspicious activity detected'}), 429
  redis.incr(key)
  redis.expire(key, 60)  # 1-minute window
  ```

**Tip**: Save script output to a file (e.g., `python3 test_misuse.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test CAPTCHA or Challenge-Response Mechanisms

**Objective**: Test whether CAPTCHAs or challenge-response mechanisms activate and prevent automated misuse.

**Steps**:
1. **Identify Target**:
   - Use Burp Suite to find forms or endpoints with CAPTCHA (e.g., `/contact`).
2. **Simulate Misuse**:
   - Send multiple requests without solving CAPTCHA.
3. **Analyze Responses**:
   - Check for CAPTCHA prompts, blocking, or continued processing.

**Python Script**:
```python
import requests
import sys

url = 'http://example.com/contact'
data = {'message': 'Test message'}
cookies = {'session': 'abc123'}

try:
    for i in range(5):
        response = requests.post(url, data=data, cookies=cookies, timeout=5)
        print(f"Attempt {i + 1}: Status={response.status_code}, Response={response.text[:100]}")
        if 'captcha' in response.text.lower():
            print("CAPTCHA triggered")
            break
except requests.RequestException as e:
    print(f"Error: Agostador: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the CAPTCHA test:
  ```bash
  python3 test_captcha.py
  ```
- **Command 2**: Test single submission for verification:
  ```bash
  python3 -c "import requests; url='http://example.com/contact'; data={'message': 'Test'}; cookies={'session': 'abc123'}; r=requests.post(url, data=data, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status=200, Response=Message sent successfully
Attempt 5: Status=200, Response=Message sent successfully
```

**Remediation**:
- Implement CAPTCHA (Node.js):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/contact', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5,
      message: 'Too many submissions, please complete CAPTCHA'
  }));
  ```

**Tip**: Save script output to a file (e.g., `python3 test_captcha.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 7. Test Anomaly Detection and Logging

**Objective**: Verify if the application logs or alerts on misuse attempts.

**Steps**:
1. **Simulate Misuse**:
   - Send excessive or malicious requests using Intruder.
2. **Analyze Responses**:
   - Check for logging indicators (e.g., unique request IDs, session termination).
3. **Verify Logging**:
   - In gray-box testing, check server logs (if accessible).

**Burp Suite Commands**:
- **Command 1**: Send excessive login attempts:
  ```
  HTTP History -> Select POST /login -> Send to Intruder -> Positions -> Set payload position to password=§pass123§ -> Payloads -> Simple list -> Add "pass123" -> Options -> Set Threads to 20 -> Start Attack -> Check Response Headers/Content
  ```
- **Command 2**: Test malicious input:
  ```
  HTTP History -> Select POST /login -> Send to Repeater -> Modify username=admin' OR '1'='1 -> Send -> Check Response for logging indicators
  ```

**Example Vulnerable Output**:
```
Attempt 1-20: HTTP/1.1 200 OK, {"message": "Login failed"} (no logging indicators)
```

**Remediation**:
- Log suspicious activity (Python):
  ```python
  import logging
  logging.basicConfig(filename='app.log', level=logging.WARNING)
  def login():
      if request.form['username'] in suspicious_inputs:
          logging.warning(f"Suspicious login attempt: {request.remote_addr}")
          return jsonify({'error': 'Suspicious activity'}), 403
  ```

**Tip**: Save Intruder or Repeater responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Feature Misuse

**Objective**: Test whether the application detects and mitigates abuse of legitimate features (e.g., password reset spam).

**Steps**:
1. **Identify Feature**:
   - Use Burp Suite to find endpoints like `/reset-password`.
2. **Simulate Abuse**:
   - Send multiple requests to the endpoint.
3. **Analyze Responses**:
   - Check for rate-limiting, CAPTCHA, or blocking.

**Postman Commands**:
- **Command 1**: Send 10 password reset requests:
  ```
  New Collection -> Add Request (POST http://example.com/reset-password) -> Body: {"email": "user@example.com"} -> Save -> Collection Runner -> Select Collection -> Set Iterations to 10, Delay to 0ms -> Run
  ```
- **Command 2**: Test single reset request:
  ```
  New Request -> POST http://example.com/reset-password -> Body: {"email": "user@example.com"} -> Headers: Cookie: session=abc123 -> Send
  ```

**Example Vulnerable Output**:
```
Iteration 1-10: HTTP/1.1 200 OK, {"message": "Password reset email sent"}
```

**Remediation**:
- Limit reset requests (PHP):
  ```php
  $redis = new Redis();
  $key = 'reset:' . $email;
  if ($redis->get($key) >= 3) {
      http_response_code(429);
      die('Too many reset requests');
  }
  $redis->incr($key);
  $redis->expire($key, 3600); // 1-hour window
  ```

**Tip**: Save Postman run results as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).