# Testing for Weak Encryption

## Overview

Testing for Weak Encryption (WSTG-CRYP-04) involves assessing web applications for cryptographic implementations that use outdated algorithms, short key lengths, predictable keys, or insecure configurations, which can expose sensitive data (e.g., passwords, session tokens, personal information) to decryption or manipulation. According to OWASP, weak encryption mechanisms, such as MD5, DES, or improper key management, fail to adequately protect data, leading to unauthorized access, data breaches, or regulatory non-compliance. This test focuses on identifying encrypted data, analyzing cryptographic algorithms, and verifying their strength in transit (e.g., API payloads, cookies) and at rest (e.g., database fields, configuration files).

**Impact**: Weak encryption can lead to:
- Decryption of sensitive data, exposing user credentials or personal information.
- Forgery of encrypted data, bypassing authentication or authorization.
- Regulatory violations (e.g., GDPR, PCI-DSS) due to inadequate data protection.
- Increased attack surface by enabling brute-force or cryptanalysis attacks.

This guide provides a practical, hands-on methodology for testing weak encryption vulnerabilities, adhering to OWASP’s WSTG-CRYP-04, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for cryptanalysis, as cracking hashes or decrypting data may expose sensitive information or violate laws.

## Testing Tools

The following tools are recommended for testing weak encryption mechanisms, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and analyzes encrypted data in HTTP traffic.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Browser Developer Tools**: Inspects client-side scripts for hardcoded keys or weak algorithms.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **hashcat**: Cracks weak hashes to identify outdated algorithms (e.g., MD5, SHA-1).
  - Install on Linux:
    ```bash
    sudo apt install hashcat
    ```
  - Install on Windows/Mac: Download from [hashcat.net](https://hashcat.net/hashcat/).

- **John the Ripper**: Tests password hashes for weak encryption.
  - Install on Linux:
    ```bash
    sudo apt install john
    ```
  - Install on Windows/Mac: Download from [openwall.com/john](https://www.openwall.com/john/).

- **Python Cryptography Library**: Analyzes encryption patterns and tests custom cryptographic implementations.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install cryptography:
    ```bash
    pip install cryptography
    ```

- **sslscan**: Analyzes TLS/SSL configurations for weak protocols or ciphers.
  - Install on Linux:
    ```bash
    sudo apt install sslscan
    ```
  - Install on Windows/Mac: Download from [github.com/rbsec/sslscan](https://github.com/rbsec/sslscan).

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CRYP-04, focusing on identifying encrypted data, analyzing cryptographic algorithms, and testing their strength through traffic inspection, client-side analysis, cryptanalysis, and configuration checks.

### 1. Identify Encrypted Data with Burp Suite

**Objective**: Capture and analyze HTTP traffic to locate encrypted or hashed data and assess its cryptographic strength.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Traffic**:
   - Browse the application, log in, or interact with APIs.
   - Check “HTTP History” for encrypted data (e.g., base64-encoded tokens, hashed passwords).
3. **Analyze Data**:
   - Identify hash formats (e.g., 32-character MD5, 40-character SHA-1).
   - Look for encrypted data with predictable patterns (e.g., ECB mode repeating blocks).

**Burp Suite Commands**:
- **Command 1**: Inspect a hashed password:
  ```
  HTTP History -> Select POST /login -> Check for password=5f4dcc3b5aa765d61d8327deb882cf99 -> Send to Repeater -> Note MD5 format
  ```
- **Command 2**: Analyze encrypted token:
  ```
  HTTP History -> Select GET /profile?token=abc123encrypted -> Send to Repeater -> Check token length and encoding
  ```

**Example Vulnerable Request**:
```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=5f4dcc3b5aa765d61d8327deb882cf99
```

**Remediation**:
- Use bcrypt for password hashing (Python):
  ```python
  from bcrypt import hashpw, gensalt
  hashed = hashpw(password.encode('utf-8'), gensalt())
  ```

**Tip**: Save requests and responses in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 2. Inspect Client-Side Code with Browser Developer Tools

**Objective**: Analyze client-side scripts for hardcoded keys, weak algorithms, or insecure encryption practices.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome.
2. **Inspect Scripts**:
   - Check “Sources” tab for JavaScript files or inline scripts.
   - Search for cryptographic functions (e.g., `CryptoJS.MD5`, `DES.encrypt`) or hardcoded keys.
3. **Analyze Findings**:
   - Identify weak algorithms (e.g., MD5, DES) or short keys (e.g., `key=secret123`).

**Browser Developer Tools Commands**:
- **Command 1**: Search for weak algorithms:
  ```
  Sources tab -> Ctrl+F -> Search "MD5" or "DES" -> Inspect script
  ```
- **Command 2**: Find hardcoded keys:
  ```
  Sources tab -> Open main.js -> Ctrl+F -> Search "key =" or "secret" -> Check for constants
  ```

**Example Vulnerable Script**:
```javascript
const key = "secret123";
const encrypted = CryptoJS.DES.encrypt("data", key).toString();
```

**Remediation**:
- Use server-side encryption (Node.js):
  ```javascript
  const crypto = require('crypto');
  const key = crypto.randomBytes(32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  ```

**Tip**: Save screenshots and script excerpts. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., JavaScript code).

### 3. Crack Weak Hashes with hashcat

**Objective**: Test password hashes for weak algorithms by attempting to crack them.

**Steps**:
1. **Extract Hashes**:
   - Use Burp Suite to capture hashes (e.g., `password=5f4dcc3b5aa765d61d8327deb882cf99`).
   - Save to `hashes.txt`.
2. **Run hashcat**:
   - Specify hash type (e.g., MD5) and use a wordlist or brute-force attack.
3. **Analyze Results**:
   - Cracked hashes confirm weak encryption.

**hashcat Commands**:
- **Command 1**: Crack MD5 hashes with a wordlist:
  ```bash
  hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
  ```
- **Command 2**: Brute-force MD5 hashes:
  ```bash
  hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a
  ```

**Example Vulnerable Output**:
```
5f4dcc3b5aa765d61d8327deb882cf99:password
```

**Remediation**:
- Use Argon2 for password hashing (Python):
  ```python
  from argon2 import PasswordHasher
  ph = PasswordHasher()
  hashed = ph.hash("password")
  ```

**Tip**: Save hashcat output to a file (e.g., `hashcat ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., cracked hashes).

### 4. Test Password Hashes with John the Ripper

**Objective**: Analyze captured password hashes for weak encryption mechanisms.

**Steps**:
1. **Extract Hashes**:
   - Use Burp Suite to capture hashes (e.g., SHA-1: `7c4a8d09ca3762af61e59520943dc26494f8941b`).
   - Save to `hashes.txt`.
2. **Run John the Ripper**:
   - Specify hash format (e.g., SHA-1) and use a wordlist.
3. **Analyze Results**:
   - Cracked hashes indicate weak algorithms.

**John the Ripper Commands**:
- **Command 1**: Crack SHA-1 hashes:
  ```bash
  john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  ```
- **Command 2**: Test with incremental mode:
  ```bash
  john --format=Raw-SHA1 --incremental hashes.txt
  ```

**Example Vulnerable Output**:
```
password (7c4a8d09ca3762af61e59520943dc26494f8941b)
```

**Remediation**:
- Use salted bcrypt (PHP):
  ```php
  $password = "secret123";
  $hashed = password_hash($password, PASSWORD_BCRYPT);
  ```

**Tip**: Save John output to a file (e.g., `john ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., cracked hashes).

### 5. Analyze Encryption Patterns with Python Cryptography

**Objective**: Detect weak encryption patterns or test cryptographic implementations.

**Steps**:
1. **Write Python Script**:
   - Create a script to detect ECB mode encryption.
2. **Run Script**:
   - Execute to analyze encrypted data.
3. **Analyze Output**:
   - Check for weak encryption indicators (e.g., ECB mode).

**Python Script**:
```python
import base64
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def detect_ecb(ciphertext):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    return len(blocks) != len(set(blocks))

try:
    token = "5a8b9c0d5a8b9c0d5a8b9c0d5a8b9c0d"  # Repeating blocks indicate ECB
    ciphertext = base64.b64decode(token)
    if detect_ecb(ciphertext):
        print("Weak encryption detected: Possible ECB mode")
    else:
        print("No ECB mode detected")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run ECB detection:
  ```bash
  python3 detect_ecb.py
  ```
- **Command 2**: Check block size:
  ```bash
  python3 -c "import base64; print(len(base64.b64decode('5a8b9c0d5a8b9c0d5a8b9c0d5a8b9c0d')))"
  ```

**Example Vulnerable Output**:
```
Weak encryption detected: Possible ECB mode
```

**Remediation**:
- Use AES-GCM (Python):
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  key = AESGCM.generate_key(bit_length=256)
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, data, None)
  ```

**Tip**: Save script output to a file (e.g., `python3 detect_ecb.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Weak TLS/SSL Configurations

**Objective**: Test the web application’s TLS/SSL setup for weak protocols, ciphers, or configurations.

**Steps**:
1. **Run sslscan**:
   - Scan the target domain for supported protocols and ciphers.
2. **Analyze Output**:
   - Check for outdated protocols (e.g., SSLv3, TLS 1.0) or weak ciphers (e.g., RC4).
3. **Verify Findings**:
   - Use Burp Suite to confirm HTTPS responses.

**sslscan Commands**:
- **Command 1**: Scan TLS/SSL configuration:
  ```bash
  sslscan example.com
  ```
- **Command 2**: Exclude specific tests:
  ```bash
  sslscan --no-heartbleed example.com
  ```

**Example Vulnerable Output**:
```
Supported Server Cipher(s):
  Accepted  TLSv1.0  RC4-MD5      128 bits
  Accepted  SSLv3     DES-CBC-SHA  168 bits
```

**Remediation**:
- Configure strong TLS (Apache):
  ```apache
  SSLEngine on
  SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
  SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!DES
  ```

**Tip**: Save sslscan output to a file (e.g., `sslscan example.com > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., scan results).

### 7. Test Predictable Initialization Vectors (IVs)

**Objective**: Test encrypted data for predictable or reused IVs in CBC mode encryption.

**Steps**:
1. **Capture Encrypted Data**:
   - Use Burp Suite to collect ciphertexts (e.g., API tokens).
2. **Analyze IVs**:
   - Use Python to extract and compare IVs.
3. **Analyze Results**:
   - Repeated IVs indicate weak encryption.

**Python Script**:
```python
import base64
import sys
from collections import Counter

def extract_iv(ciphertext, iv_length=16):
    return ciphertext[:iv_length]

try:
    ciphertexts = [
        "5a8b9c0d5a8b9c0dAAAAAAAAAAAAAAAA",  # IV + ciphertext
        "5a8b9c0d5a8b9c0dBBBBBBBBBBBBBBBB"   # Same IV
    ]
    ivs = [extract_iv(base64.b64decode(ct)) for ct in ciphertexts]
    iv_counts = Counter(ivs)
    for iv, count in iv_counts.items():
        if count > 1:
            print(f"Predictable IV detected: {iv.hex()} used {count} times")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run IV analysis:
  ```bash
  python3 detect_iv.py
  ```
- **Command 2**: Check single ciphertext:
  ```bash
  python3 -c "import base64; print(base64.b64decode('5a8b9c0d5a8b9c0dAAAAAAAAAAAAAAAA')[:16].hex())"
  ```

**Example Vulnerable Output**:
```
Predictable IV detected: 5a8b9c0d5a8b9c0d used 2 times
```

**Remediation**:
- Use random IVs (Python):
  ```python
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  import os
  iv = os.urandom(16)
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  ```

**Tip**: Save script output to a file (e.g., `python3 detect_iv.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 8. Test Weak Key Storage in Configuration Files

**Objective**: Test for weak key storage in exposed configuration files or endpoints.

**Steps**:
1. **Probe Configuration Files**:
   - Use `cURL` to access common paths (e.g., `/config.json`, `/.env`).
2. **Analyze Responses**:
   - Check for plaintext keys or cryptographic settings.
3. **Verify Findings**:
   - Use Burp Suite to check related endpoints.

**cURL Commands**:
- **Command 1**: Probe config file:
  ```bash
  curl http://example.com/config.json
  ```
- **Command 2**: Probe environment file:
  ```bash
  curl http://example.com/.env
  ```

**Example Vulnerable Output**:
```
{"encryption_key": "secret123", "algorithm": "DES"}
```

**Remediation**:
- Secure key storage (Bash):
  ```bash
  export ENCRYPTION_KEY=$(openssl rand -base64 32)
  chmod 600 /var/www/.env
  ```

**Tip**: Save cURL responses to a file (e.g., `curl ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).
