# Test Integrity Checks

## Overview

Testing integrity checks (WSTG-BUSL-03) involves assessing whether a web application enforces mechanisms to prevent unauthorized tampering with critical data, such as transaction details, user inputs, or session parameters. According to OWASP, integrity checks, such as HMACs, digital signatures, or checksums, ensure data remains unaltered during transmission or processing. Weak or absent integrity checks allow attackers to modify data (e.g., prices, quantities, roles) to bypass business logic, leading to unauthorized actions or data corruption.

**Impact**: Weak integrity checks can lead to:
- Unauthorized modifications (e.g., altering order amounts).
- Bypassing business logic (e.g., changing user permissions).
- Data integrity violations (e.g., tampering with balances).
- Financial loss or reputational damage.

This guide provides a step-by-step methodology for testing integrity checks, adhering to OWASP’s WSTG-BUSL-03, with practical tools, specific commands, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing integrity checks, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints with tampered data.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends custom HTTP requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects and modifies form data in Chrome/Firefox.
  - Access by pressing `F12` or right-clicking and selecting “Inspect”.
  - No setup required.

- **Python Requests Library**: Scripts automated tampering tests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-03, focusing on tampering with data, testing integrity mechanisms, and bypassing checks to identify vulnerabilities.

### 1. Identify Critical Data Points with Burp Suite

**Objective**: Map requests containing critical data that should be protected by integrity checks.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in “Target” tab.
2. **Capture Requests**:
   - Perform actions (e.g., submit forms, place orders).
   - Review “HTTP History” for parameters like `price`, `quantity`, or `hash`.
3. **Analyze Data**:
   - Identify integrity fields (e.g., `hash`, `signature`, `checksum`).

**Burp Suite Commands**:
- **Command 1**: Capture request:
  ```
  HTTP History -> Select POST /order/submit -> Check Params: item_id=123, quantity=2, price=99.99, hash=abc123 -> Send to Repeater
  ```
- **Command 2**: Export data:
  ```
  Target -> Site Map -> Right-click example.com -> Copy URLs in Scope -> Paste to file
  ```

**Example Request**:
```
POST /order/submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

item_id=123&quantity=2&price=99.99&hash=abc123
```

**Remediation**:
- Implement HMACs (PHP):
  ```php
  $secret = 'your-secret-key';
  $data = $_POST['item_id'] . $_POST['quantity'] . $_POST['price'];
  $hash = hash_hmac('sha256', $data, $secret);
  if ($_POST['hash'] !== $hash) {
      die('Data tampered');
  }
  ```

**Tip**: Save “HTTP History” requests to Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., request details).

### 2. Tamper with Data Using Burp Suite Repeater

**Objective**: Modify critical data to test integrity check enforcement.

**Steps**:
1. **Send to Repeater**:
   - Right-click a request in “HTTP History” and select “Send to Repeater”.
   - Modify parameters (e.g., `price=99.99` to `price=0.01`, keep `hash`).
2. **Test Edge Cases**:
   - Alter values (e.g., `quantity=-1`, `user_id=admin`).
   - Remove integrity fields (e.g., delete `hash`).
   - Use invalid hashes (e.g., `hash=invalid`).
3. **Analyze Response**:
   - Check if tampered data is accepted (e.g., order total changes).

**Burp Suite Commands**:
- **Command 1**: Tamper price:
  ```
  Repeater -> POST /order/submit -> Params -> Change price=99.99 to price=0.01 -> Send -> Check Response
  ```
- **Command 2**: Remove hash:
  ```
  Repeater -> POST /order/submit -> Params -> Delete hash -> Send -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Order Total: $0.01
```

**Remediation**:
- Validate integrity (Express):
  ```javascript
  const crypto = require('crypto');
  const data = `${req.body.item_id}${req.body.quantity}${req.body.price}`;
  const hash = crypto.createHmac('sha256', 'secret').update(data).digest('hex');
  if (req.body.hash !== hash) {
      res.status(400).send('Invalid data');
  }
  ```

**Tip**: Save Repeater requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Integrity with Postman

**Objective**: Test API endpoints for weak integrity checks.

**Steps**:
1. **Import Endpoints**:
   - Identify APIs from Burp Suite (e.g., `/api/v1/order`).
   - Add to Postman.
2. **Tamper Parameters**:
   - Modify data (e.g., `total=0.01`, keep `hash`).
   - Omit integrity fields (e.g., remove `signature`).
3. **Analyze Response**:
   - Check if tampered data is processed.

**Postman Commands**:
- **Command 1**: Tamper total:
  ```
  New Request -> PUT http://example.com/api/v1/order -> Body -> raw -> JSON: {"total": 0.01, "hash": "abc123"} -> Send
  ```
- **Command 2**: Omit signature:
  ```
  New Request -> PUT http://example.com/api/v1/order -> Body -> raw -> JSON: {"total": 99.99} -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "total": 0.01
}
```

**Remediation**:
- Enforce API integrity (Flask):
  ```python
  import hmac, hashlib
  secret = b'secret'
  data = f"{request.json['item_id']}{request.json['quantity']}{request.json['total']}".encode()
  hash = hmac.new(secret, data, hashlib.sha256).hexdigest()
  if request.json.get('hash') != hash:
      return jsonify({'error': 'Data tampered'}), 400
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Bypass Client-Side Integrity Checks with Browser Developer Tools

**Objective**: Test client-side integrity mechanisms for bypasses.

**Steps**:
1. **Access Form**:
   - Open `http://example.com/order`, press `F12`, go to “Elements” tab.
   - Locate fields (e.g., `<input name="price" value="99.99">`, `<input name="hash" value="abc123">`).
2. **Modify Values**:
   - Change `price=99.99` to `price=0.01`, keep `hash`.
   - Submit the form.
3. **Analyze Response**:
   - Check if tampered data is accepted.

**Browser Developer Tools Commands**:
- **Command 1**: Modify price:
  ```
  Elements -> Find <input name="price" value="99.99"> -> Edit value to 0.01 -> Submit Form -> Check Response
  ```
- **Command 2**: Remove hash:
  ```
  Elements -> Find <input name="hash" value="abc123"> -> Delete input -> Submit Form -> Check Response
  ```

**Example Vulnerable Response**:
```
Order Total: $0.01
```

**Remediation**:
- Server-side validation (PHP):
  ```php
  $data = $_POST['item_id'] . $_POST['quantity'] . $_POST['price'];
  $hash = hash_hmac('sha256', $data, 'secret');
  if (!isset($_POST['hash']) || $_POST['hash'] !== $hash) {
      die('Tampering detected');
  }
  ```

**Tip**: Save screenshots of modified forms and responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Script Tampering Tests with Python Requests

**Objective**: Automate tampering tests for integrity checks.

**Steps**:
1. **Write Script**:
   - Create a script for multiple tampering scenarios.
2. **Run Script**:
   - Execute and analyze responses.
3. **Verify Findings**:
   - Cross-check with Burp Suite.

**Python Script**:
```python
import requests
import sys

url = 'http://example.com/order/submit'
payloads = [
    {'item_id': '123', 'quantity': 2, 'price': 0.01, 'hash': 'abc123'},
    {'item_id': '123', 'quantity': -1, 'price': 99.99, 'hash': 'abc123'},
    {'item_id': '123', 'quantity': 2, 'price': 99.99}  # Missing hash
]

try:
    for payload in payloads:
        response = requests.post(url, data=payload, timeout=5)
        print(f"Payload: {payload}")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:100]}\n")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run script:
  ```bash
  python3 test_tamper.py
  ```
- **Command 2**: Test single payload:
  ```bash
  python3 -c "import requests; url='http://example.com/order/submit'; payload={'item_id': '123', 'quantity': 2, 'price': 0.01, 'hash': 'abc123'}; r=requests.post(url, data=payload, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Payload: {'item_id': '123', 'quantity': 2, 'price': 0.01, 'hash': 'abc123'}
Status: 200
Response: {"status": "success", "total": 0.01}
```

**Remediation**:
- Robust checks (Express):
  ```javascript
  const data = `${payload.item_id}${payload.quantity}${payload.price}`;
  const hash = require('crypto').createHmac('sha256', 'secret').update(data).digest('hex');
  if (!payload.hash || payload.hash !== hash) {
      res.status(400).send('Data tampered');
  }
  ```

**Tip**: Save script output to a file (e.g., `python3 test_tamper.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Weak Hashing Algorithms with Burp Suite and Python

**Objective**: Identify if integrity checks use insecure hashing algorithms (e.g., MD5).

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture a request with a hash (e.g., `hash=abc123`).
2. **Analyze Hash**:
   - Check hash length/format (e.g., 32 chars for MD5).
3. **Generate Weak Hash**:
   - Use Python to create an MD5 hash for tampered data.
4. **Test Acceptance**:
   - Send tampered request with MD5 hash and check response.

**Python Script**:
```python
import hashlib
import requests
import sys

url = 'http://example.com/order/submit'
data = {'item_id': '123', 'quantity': 2, 'price': 0.01}
data_str = f"{data['item_id']}{data['quantity']}{data['price']}"

try:
    md5_hash = hashlib.md5(data_str.encode()).hexdigest()
    data['hash'] = md5_hash
    response = requests.post(url, data=data, timeout=5)
    print(f"MD5 Hash: {md5_hash}")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:100]}")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Commands**:
- **Command 1**: Run script:
  ```bash
  python3 test_md5.py
  ```
- **Command 2**: Generate MD5 hash:
  ```bash
  python3 -c "import hashlib; data='item_id=123quantity=2price=0.01'; print(hashlib.md5(data.encode()).hexdigest())"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "total": 0.01}
```

**Remediation**:
- Use SHA-256 (Flask):
  ```python
  import hmac, hashlib
  secret = b'secret'
  data = f"{request.json['item_id']}{request.json['quantity']}".encode()
  hash = hmac.new(secret, data, hashlib.sha256).hexdigest()
  if request.json.get('hash') != hash:
      return jsonify({'error': 'Invalid hash'}), 400
  ```

**Tip**: Save script output and Burp Suite requests as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Replay Attacks on Integrity Fields with Burp Suite

**Objective**: Verify if reusing a valid hash allows tampered submissions.

**Steps**:
1. **Capture Requests**:
   - Use Burp Suite to capture two requests with valid hashes (e.g., `POST /order/submit`).
2. **Replay Hash**:
   - Use a hash from the first request with tampered data (e.g., `price=0.01`).
3. **Analyze Response**:
   - Check if the tampered request is processed.

**Burp Suite Commands**:
- **Command 1**: Replay hash:
  ```
  Repeater -> POST /order/submit -> Params -> Use hash from previous request -> Change price=99.99 to price=0.01 -> Send
  ```
- **Command 2**: Test without tampering:
  ```
  Repeater -> POST /order/submit -> Params -> Use original hash and data -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "total": 0.01}
```

**Remediation**:
- Use nonces (PHP):
  ```php
  if ($_POST['nonce'] !== $_SESSION['nonce']) {
      die('Invalid or reused nonce');
  }
  $_SESSION['nonce'] = bin2hex(random_bytes(16));
  ```

**Tip**: Save Repeater requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Integrity of Serialized Data with Postman

**Objective**: Check if serialized data tampering bypasses integrity checks.

**Steps**:
1. **Capture Request**:
   - Identify an API request with serialized data (e.g., `data=eyJ...`, `signature=xyz`).
2. **Tamper Data**:
   - Decode data (e.g., base64), modify (e.g., `role=admin`), re-encode.
   - Keep original signature.
3. **Analyze Response**:
   - Check if tampered data is accepted.

**Postman Commands**:
- **Command 1**: Tamper serialized data:
  ```
  New Request -> POST http://example.com/api/v1/update -> Body -> raw -> JSON: {"data": "eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJhZG1pbiJ9", "signature": "xyz789"} -> Send
  ```
- **Command 2**: Verify original:
  ```
  New Request -> POST http://example.com/api/v1/update -> Body -> raw -> JSON: {"data": "eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIn0=", "signature": "xyz789"} -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "role": "admin"}
```

**Remediation**:
- Validate serialized data (Express):
  ```javascript
  const decoded = Buffer.from(req.body.data, 'base64').toString();
  const hash = require('crypto').createHmac('sha256', 'secret').update(decoded).digest('hex');
  if (req.body.signature !== hash) {
      res.status(400).send('Invalid signature');
  }
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).