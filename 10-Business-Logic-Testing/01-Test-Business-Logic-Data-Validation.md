# Test Business Logic Data Validation

## Overview

Testing business logic data validation (WSTG-BUSL-01) involves assessing whether a web application properly validates user inputs and data within its business logic to prevent manipulation, bypass, or exploitation. Business logic flaws occur when an application fails to enforce rules or constraints specific to its functionality, allowing attackers to submit unexpected or malicious data to achieve unauthorized actions (e.g., altering prices, bypassing restrictions). According to OWASP, these vulnerabilities are often missed by automated scanners and require manual testing to identify context-specific issues.

**Impact**: Weak business logic data validation can lead to:
- Unauthorized actions (e.g., purchasing items at manipulated prices).
- Bypassing restrictions (e.g., negative quantities in e-commerce carts).
- Data integrity violations (e.g., tampering with account balances).
- Financial loss or reputational damage due to exploited workflows.

This guide provides a step-by-step methodology for testing business logic data validation, adhering to OWASP’s WSTG-BUSL-01, with practical tools, specific commands, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing business logic data validation, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints with crafted parameters.
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

- **Python Requests Library**: Scripts automated HTTP tests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-01, focusing on manipulating inputs, workflows, and concurrent requests to identify weak data validation in business logic.

### 1. Identify Business Logic Inputs with Burp Suite

**Objective**: Map input points (e.g., forms, API parameters) where business logic validation occurs.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in “Target” tab.
2. **Capture Requests**:
   - Navigate the application (e.g., add items to cart, submit forms).
   - Review “HTTP History” for parameters like `price`, `quantity`, or `discount`.
3. **Analyze Inputs**:
   - Identify hidden fields, cookies, or headers influencing logic (e.g., `POST /cart/add`).

**Burp Suite Commands**:
- **Command 1**: Capture request:
  ```
  HTTP History -> Select POST /cart/add -> Check Params: item_id=123, quantity=1, price=99.99 -> Send to Repeater
  ```
- **Command 2**: Export inputs:
  ```
  Target -> Site Map -> Right-click example.com -> Copy URLs in Scope -> Paste to file
  ```

**Example Request**:
```
POST /cart/add HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

item_id=123&quantity=1&price=99.99
```

**Remediation**:
- Validate inputs server-side (PHP):
  ```php
  if (!is_numeric($_POST['quantity']) || $_POST['quantity'] <= 0) {
      die('Invalid quantity');
  }
  ```

**Tip**: Save “HTTP History” requests to Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., request details).

### 2. Manipulate Inputs with Burp Suite Repeater

**Objective**: Test whether the application enforces proper validation by modifying input values.

**Steps**:
1. **Send to Repeater**:
   - Right-click a request in “HTTP History” and select “Send to Repeater”.
   - Modify parameters (e.g., `price=99.99` to `price=-10.00`).
2. **Test Edge Cases**:
   - Submit negative values (e.g., `quantity=-1`).
   - Use large numbers (e.g., `quantity=999999`).
   - Omit fields (e.g., remove `item_id`).
3. **Analyze Response**:
   - Check if invalid data is accepted (e.g., negative price applied).

**Burp Suite Commands**:
- **Command 1**: Modify price:
  ```
  Repeater -> POST /cart/add -> Params -> Change price=99.99 to price=-10.00 -> Send -> Check Response
  ```
- **Command 2**: Test negative quantity:
  ```
  Repeater -> POST /cart/add -> Params -> Change quantity=1 to quantity=-1 -> Send -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Order Total: -$10.00
```

**Remediation**:
- Enforce validation (Express):
  ```javascript
  if (req.body.price < 0 || req.body.quantity <= 0) {
      res.status(400).send('Invalid input');
  }
  ```

**Tip**: Save Repeater requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Endpoints with Postman

**Objective**: Test API endpoints for weak business logic validation.

**Steps**:
1. **Import Endpoints**:
   - Identify APIs from Burp Suite (e.g., `/api/v1/cart`).
   - Add to Postman.
2. **Manipulate Parameters**:
   - Send requests with invalid data (e.g., `quantity=-5`, `discount_code=SAVE100`).
3. **Analyze Response**:
   - Check if invalid data is processed (e.g., negative totals).

**Postman Commands**:
- **Command 1**: Test negative quantity:
  ```
  New Request -> PUT http://example.com/api/v1/cart -> Body -> raw -> JSON: {"quantity": -5} -> Send
  ```
- **Command 2**: Test invalid discount:
  ```
  New Request -> POST http://example.com/api/v1/checkout -> Body -> raw -> JSON: {"discount_code": "SAVE100", "total": 100.00} -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "total": -50.00
}
```

**Remediation**:
- Validate API inputs (Flask):
  ```python
  from flask import jsonify, request
  if request.json.get('quantity', 0) <= 0:
      return jsonify({'error': 'Invalid quantity'}), 400
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Modify Client-Side Inputs with Browser Developer Tools

**Objective**: Test client-side validation bypasses by modifying form data.

**Steps**:
1. **Access Form**:
   - Open `http://example.com/cart` and press `F12` to access “Elements” tab.
   - Locate fields (e.g., `<input name="price" value="99.99">`).
2. **Modify Values**:
   - Change `value="99.99"` to `value="0.01"`.
   - Submit the form.
3. **Analyze Response**:
   - Check if the server accepts the modified value.

**Browser Developer Tools Commands**:
- **Command 1**: Modify price:
  ```
  Elements -> Find <input name="price" value="99.99"> -> Edit value to 0.01 -> Submit Form -> Check Response
  ```
- **Command 2**: Remove required field:
  ```
  Elements -> Find <input name="item_id" value="123"> -> Delete input -> Submit Form -> Check Response
  ```

**Example Vulnerable Response**:
```
Order Total: $0.01
```

**Remediation**:
- Revalidate server-side (PHP):
  ```php
  $price = floatval($_POST['price']);
  if ($price <= 0 || $price > 1000) {
      die('Invalid price');
  }
  ```

**Tip**: Save screenshots of modified forms and server responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Script Automated Tests with Python Requests

**Objective**: Automate testing of multiple input scenarios for efficiency.

**Steps**:
1. **Write Script**:
   - Create a script to test invalid inputs.
2. **Run Script**:
   - Execute and analyze responses for invalid data acceptance.
3. **Verify Findings**:
   - Cross-check with Burp Suite results.

**Python Script**:
```python
import requests
import sys

url = 'http://example.com/cart/add'
payloads = [
    {'item_id': '123', 'quantity': -1, 'price': 99.99},
    {'item_id': '123', 'quantity': 999999, 'price': 99.99},
    {'item_id': '123', 'quantity': 1, 'price': -10.00}
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
  python3 test_logic.py
  ```
- **Command 2**: Test single payload:
  ```bash
  python3 -c "import requests; url='http://example.com/cart/add'; payload={'item_id': '123', 'quantity': -1, 'price': 99.99}; r=requests.post(url, data=payload, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Payload: {'item_id': '123', 'quantity': -1, 'price': 99.99}
Status: 200
Response: {"status": "success", "total": -99.99}
```

**Remediation**:
- Validate inputs (Express):
  ```javascript
  if (payload.quantity <= 0 || payload.quantity > 100) {
      throw new Error('Invalid quantity');
  }
  ```

**Tip**: Save script output to a file (e.g., `python3 test_logic.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Multi-Step Workflow Bypasses with Burp Suite

**Objective**: Verify if the application enforces proper sequence and validation in multi-step processes.

**Steps**:
1. **Capture Workflow**:
   - Use Burp Suite to capture a multi-step process (e.g., `POST /cart/add`, `POST /checkout/confirm`, `POST /payment`).
2. **Skip Steps**:
   - Send `POST /payment` without `POST /checkout/confirm`.
3. **Analyze Response**:
   - Check for unauthorized actions (e.g., order completion without payment).

**Burp Suite Commands**:
- **Command 1**: Skip checkout step:
  ```
  Repeater -> POST /payment -> Params -> order_id=123 -> Send -> Check Response
  ```
- **Command 2**: Tamper session data:
  ```
  Repeater -> POST /payment -> Params -> Change order_id=123 to order_id=999 -> Send -> Check Response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Order completed"}
```

**Remediation**:
- Enforce workflow (PHP):
  ```php
  if (!isset($_SESSION['checkout_confirmed'])) {
      die('Invalid workflow');
  }
  ```

**Tip**: Save Repeater requests and responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Parameter Tampering for Logic Flaws with Postman

**Objective**: Check if non-numeric parameter manipulation allows unauthorized actions.

**Steps**:
1. **Identify Endpoint**:
   - Find an API endpoint (e.g., `POST /api/v1/profile`) from Burp Suite.
2. **Tamper Parameters**:
   - Modify fields like `user_id` or `role` (e.g., `user_id=999`, `role=admin`).
3. **Analyze Response**:
   - Check if unauthorized actions are performed (e.g., profile updated).

**Postman Commands**:
- **Command 1**: Tamper user ID:
  ```
  New Request -> POST http://example.com/api/v1/profile -> Body -> raw -> JSON: {"user_id": 999, "role": "admin"} -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Verify changes:
  ```
  New Request -> GET http://example.com/api/v1/profile -> Headers: Authorization: Bearer user_token -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
- Restrict parameters (Express):
  ```javascript
  if (req.body.user_id !== req.user.id) {
      res.status(403).send('Unauthorized');
  }
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 8. Test Race Conditions in Business Logic with Python Requests

**Objective**: Verify if concurrent requests bypass validation in transactional endpoints.

**Steps**:
1. **Identify Endpoint**:
   - Find a transactional endpoint (e.g., `POST /account/deposit`).
2. **Send Concurrent Requests**:
   - Use Python to send multiple simultaneous requests.
3. **Analyze Response**:
   - Check if all requests are processed without validation (e.g., inflated balance).

**Python Script**:
```python
import requests
import threading
import sys

url = 'http://example.com/account/deposit'
data = {'amount': 100.00}
headers = {'Authorization': 'Bearer user_token'}

def send_request():
    try:
        response = requests.post(url, data=data, headers=headers, timeout=5)
        print(f"Response: {response.text[:100]}")
    except requests.RequestException as e:
        print(f"Error: {e}")

try:
    threads = []
    for _ in range(10):
        t = threading.Thread(target=send_request)
        threads.append(t)
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
  python3 test_race.py
  ```
- **Command 2**: Test single request:
  ```bash
  python3 -c "import requests; url='http://example.com/account/deposit'; data={'amount': 100.00}; headers={'Authorization': 'Bearer user_token'}; r=requests.post(url, data=data, headers=headers, timeout=5); print(r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Response: {"status": "success", "balance": 1000.00}  # 10x100 instead of 100
```

**Remediation**:
- Use transactions (Django):
  ```python
  from django.db import transaction
  with transaction.atomic():
      user = User.objects.select_for_update().get(id=user_id)
      user.balance += amount
      user.save()
  ```

**Tip**: Save script output to a file (e.g., `python3 test_race.py > race_output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).
