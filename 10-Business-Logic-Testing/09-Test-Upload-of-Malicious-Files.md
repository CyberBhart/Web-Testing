# Test Upload of Malicious Files

## Overview

Testing for the upload of malicious files (WSTG-BUSL-09) involves assessing whether a web application can detect and block files containing malicious content, such as exploits, malware, or code designed to harm the system or its users. According to OWASP, vulnerabilities in file upload mechanisms often stem from inadequate server-side validation, allowing attackers to upload files that could trigger code execution, compromise the server, or infect users accessing the files. Unlike WSTG-BUSL-08, which focuses on unexpected file types, this test targets files with harmful payloads, even if they have allowed extensions or MIME types (e.g., a `.jpg` file containing executable code). The goal is to verify the application’s ability to identify and reject malicious files through content analysis or antivirus integration.

**Impact**: Allowing malicious file uploads can lead to:
- Server-side code execution (e.g., uploading a malicious `.php` file).
- Malware distribution to users (e.g., infected PDFs).
- System compromise through exploits (e.g., buffer overflow in file parsers).
- Data breaches or service disruptions due to malicious payloads.

This guide provides a step-by-step methodology for testing the upload of malicious files, adhering to OWASP’s WSTG-BUSL-09, with practical tools, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Use safe, non-destructive test files (e.g., EICAR test file) in controlled environments with explicit permission to avoid harm.

## Testing Tools

The following tools are recommended for testing malicious file upload vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test malicious file uploads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Command-line tool for crafting and sending malicious file upload requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tool for testing API-based file uploads with malicious content.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and modifying upload forms.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Python library for scripting custom malicious file upload requests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-09, focusing on attempting to upload files with malicious content and verifying whether the application detects and rejects them.

### 1. Identify File Upload Functionality with Burp Suite

**Objective**: Locate file upload mechanisms and assess their validation mechanisms.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Navigate to upload features (e.g., profile picture upload, document submission).
   - Capture upload requests in Burp Suite’s “HTTP History”.
3. **Analyze Upload Requests**:
   - Identify endpoints (e.g., `POST /upload`), parameters (e.g., `file`), and headers (e.g., `Content-Type`).
   - Note validation messages or restrictions (e.g., “Only .jpg, .png allowed”).

**Burp Suite Commands**:
- **Command 1**: Capture and analyze an upload request:
  ```
  Proxy tab -> HTTP History -> Filter by example.com -> Select POST /upload -> Inspect Request tab -> Note Content-Type (e.g., multipart/form-data) and file parameter -> Add to Site Map
  ```
- **Command 2**: Upload the EICAR test file as a `.jpg`:
  ```
  Right-click POST /upload in HTTP History -> Send to Repeater -> Modify file content to "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" -> Change filename to "eicar.jpg" -> Click "Send" -> Check response
  ```

**Example Request**:
```
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123

------WebKitFormBoundary123
Content-Disposition: form-data; name="file"; filename="image.jpg"
Content-Type: image/jpeg

[Binary JPEG Data]
------WebKitFormBoundary123--
```

**Remediation**:
- Scan files for malicious content (PHP):
  ```php
  exec('clamscan ' . escapeshellarg($file['tmp_name']), $output, $return);
  if ($return !== 0) {
      die('Malicious file detected');
  }
  ```

**Tip**: Save request details in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 2. Upload Malicious Test Files with cURL

**Objective**: Test whether the application detects and blocks files with malicious content, such as the EICAR test file.

**Steps**:
1. **Create Test Files**:
   - Create an EICAR test file (`eicar.com`) with: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.
   - Create a mock malicious file (`test.jpg`) with: `<?php echo 'test'; ?>`.
2. **Send Upload Requests**:
   - Upload test files, modifying filenames or MIME types.
3. **Analyze Response**:
   - Check if the file is rejected (e.g., HTTP 400) or accepted (e.g., HTTP 200).

**cURL Commands**:
- **Command 1**: Upload EICAR as a `.txt`:
  ```bash
  curl -X POST -F "file=@eicar.com;filename=eicar.txt" -b "session=abc123" http://example.com/upload
  ```
- **Command 2**: Upload a `.jpg` with PHP code:
  ```bash
  curl -X POST -F "file=@test.jpg;filename=image.jpg" -b "session=abc123" http://example.com/upload
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
File uploaded successfully: /uploads/eicar.txt
```

**Remediation**:
- Validate file content (Python):
  ```python
  import magic
  mime = magic.from_file(file_path, mime=True)
  if mime != 'image/jpeg' or b'<?php' in open(file_path, 'rb').read():
      return jsonify({'error': 'Malicious content detected'}), 400
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > response.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API Malicious File Uploads with Postman

**Objective**: Test API endpoints for detection of malicious file uploads.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find file upload APIs (e.g., `/api/v1/upload`).
   - Import into Postman.
2. **Upload Malicious Files**:
   - Send requests with test files like EICAR or script-embedded files.
3. **Analyze Response**:
   - Check for rejection (e.g., HTTP 400) or acceptance (e.g., HTTP 200).

**Postman Commands**:
- **Command 1**: Upload EICAR:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: eicar.com -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Upload a `.png` with malicious script:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: test.png (with <?php echo 'test'; ?>) -> Headers: Content-Type: image/png, Cookie: session=abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "path": "/uploads/eicar.com"
}
```

**Remediation**:
- Integrate antivirus scanning (Node.js):
  ```javascript
  const { exec } = require('child_process');
  exec(`clamscan ${file.path}`, (err, stdout, stderr) => {
      if (stdout.includes('Infected files: 1')) {
          return res.status(400).send('Malicious file detected');
      }
  });
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Bypass Client-Side Validation with Browser Developer Tools

**Objective**: Test whether client-side checks can be bypassed to upload malicious files.

**Steps**:
1. **Inspect Upload Form**:
   - Open Developer Tools (`F12`) on an upload page (e.g., `http://example.com/upload`).
   - Identify restrictions (e.g., `accept=".jpg,.png"`).
2. **Manipulate Form**:
   - Remove `accept` attributes.
   - Upload a malicious test file (e.g., EICAR).
3. **Analyze Response**:
   - Check if the server accepts the file.

**Browser Developer Tools Commands**:
- **Command 1**: Remove file type restrictions:
  ```
  Elements tab -> Find <input type="file" accept=".jpg,.png"> -> Right-click -> Edit as HTML -> Remove accept attribute -> Upload eicar.com
  ```
- **Command 2**: Modify form submission:
  ```
  Network tab -> Upload a file -> Right-click request -> Copy as cURL -> Modify file content to include "<?php echo 'test'; ?>" -> Replay in terminal
  ```

**Example Vulnerable Finding**:
- Uploaded `eicar.com` -> Response: `File uploaded: /uploads/eicar.com`.

**Remediation**:
- Server-side content validation (PHP):
  ```php
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
  if (!in_array($mime, ['image/jpeg', 'image/png'])) {
      die('Invalid file type');
  }
  ```

**Tip**: Save screenshots of modified forms or responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTML changes).

### 5. Script Malicious File Upload Tests with Python Requests

**Objective**: Automate tests to upload malicious files and evaluate server-side detection.

**Steps**:
1. **Write Python Script**:
   - Create a script to upload test files with malicious content.
2. **Run Script**:
   - Execute to test file acceptance or rejection.
3. **Analyze Responses**:
   - Check if uploaded files are accessible.

**Python Script**:
```python
import requests
import sys

url = 'http://example.com/upload'
cookies = {'session': 'abc123'}
files = [
    ('file', ('eicar.txt', 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'text/plain')),
    ('file', ('image.jpg', '<?php echo "test"; ?>', 'image/jpeg')),
    ('file', ('doc.pdf', '%PDF-1.4\n<script>alert("xss")</script>', 'application/pdf'))
]

try:
    for file_data in files:
        response = requests.post(url, files={'file': file_data}, cookies=cookies, timeout=5)
        print(f"File: {file_data[1]}")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:100]}\n")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the script:
  ```bash
  python3 test_malicious.py
  ```
- **Command 2**: Test a malicious PDF:
  ```bash
  python3 -c "import requests; url='http://example.com/upload'; files={'file': ('doc.pdf', '%PDF-1.4\n<script>alert(\"xss\")</script>', 'application/pdf')}; cookies={'session': 'abc123'}; r=requests.post(url, files=files, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
File: eicar.txt
Status: 200
Response: File uploaded successfully: /uploads/eicar.txt
```

**Remediation**:
- Use antivirus integration (Python):
  ```python
  import subprocess
  result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
  if 'Infected files: 1' in result.stdout:
      return jsonify({'error': 'Malicious file detected'}), 400
  ```

**Tip**: Save script output to a file (e.g., `python3 test_malicious.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Polymorphic or Obfuscated Malicious Content

**Objective**: Test whether the application detects obfuscated or encoded malicious content.

**Steps**:
1. **Create Obfuscated File**:
   - Encode the EICAR test file in base64.
2. **Upload File**:
   - Use Python to upload the obfuscated file.
3. **Analyze Response**:
   - Check for rejection or acceptance.

**Python Script**:
```python
import requests
import base64
import sys

url = 'http://example.com/upload'
cookies = {'session': 'abc123'}
eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
encoded_eicar = base64.b64encode(eicar.encode()).decode()
files = {'file': ('eicar_encoded.txt', encoded_eicar, 'text/plain')}

try:
    response = requests.post(url, files=files, cookies=cookies, timeout=5)
    print(f"File: eicar_encoded.txt")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:100]}")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the obfuscation test:
  ```bash
  python3 test_obfuscated.py
  ```
- **Command 2**: Test a single encoded file:
  ```bash
  python3 -c "import requests, base64; url='http://example.com/upload'; eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'; files={'file': ('eicar_encoded.txt', base64.b64encode(eicar.encode()).decode(), 'text/plain')}; cookies={'session': 'abc123'}; r=requests.post(url, files=files, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
File: eicar_encoded.txt
Status: 200
Response: File uploaded successfully: /uploads/eicar_encoded.txt
```

**Remediation**:
- Decode and scan content (Python):
  ```python
  import subprocess
  import base64
  content = base64.b64decode(file.read()).decode('utf-8', errors='ignore')
  with open('/tmp/tempfile', 'w') as f:
      f.write(content)
  result = subprocess.run(['clamscan', '/tmp/tempfile'], capture_output=True, text=True)
  if 'Infected files: 1' in result.stdout:
      return jsonify({'error': 'Malicious file detected'}), 400
  ```

**Tip**: Save script output to a file (e.g., `python3 test_obfuscated.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 7. Test Malicious File Execution via Alternate Endpoints

**Objective**: Test whether uploaded malicious files can be executed or accessed via alternate endpoints.

**Steps**:
1. **Upload Malicious File**:
   - Upload a test file (e.g., `test.php`) using Test 2’s cURL method.
2. **Identify Alternate Endpoints**:
   - Use Burp Suite to find endpoints (e.g., `/api/execute`).
3. **Attempt Execution**:
   - Send requests to access or execute the file.
4. **Analyze Response**:
   - Check for execution (e.g., `test` output).

**Burp Suite Commands**:
- **Command 1**: Test alternate endpoint execution:
  ```
  HTTP History -> Upload test.php via POST /upload -> Note file path (/uploads/test.php) -> Send to Repeater -> New Request -> GET /api/execute?file=test.php -> Send -> Check Response
  ```
- **Command 2**: Enumerate endpoints:
  ```
  Target -> Site Map -> Right-click example.com -> Engagement Tools -> Discover Content -> Run -> Check for /files/ or /execute/ endpoints -> Send to Repeater -> Test with test.php
  ```

**Example Vulnerable Output**:
```
HTTP/1.1 200 OK, test
```

**Remediation**:
- Restrict execution (Apache):
  ```apache
  <Location "/api/execute">
      Deny from all
  </Location>
  <Directory "/var/www/uploads">
      Options -ExecCGI
      RemoveHandler .php
  </Directory>
  ```

**Tip**: Save Repeater responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Malicious File Upload with File Metadata Exploits

**Objective**: Test whether the application detects malicious content in file metadata.

**Steps**:
1. **Create Malicious Metadata**:
   - Embed a script in an image’s EXIF data using `exiftool`.
2. **Upload File**:
   - Use cURL to upload the modified image.
3. **Analyze Response**:
   - Check for rejection or acceptance.

**cURL Commands**:
- **Command 1**: Create and upload image with malicious EXIF:
  ```bash
  exiftool -Comment='<script>alert("xss")</script>' test.jpg
  curl -X POST -F "file=@test.jpg;filename=image.jpg" -b "session=abc123" http://example.com/upload
  ```
- **Command 2**: Upload another image with different metadata:
  ```bash
  exiftool -Artist='<?php echo "test"; ?>' test2.jpg
  curl -X POST -F "file=@test2.jpg;filename=image2.jpg" -b "session=abc123" http://example.com/upload
  ```

**Example Vulnerable Output**:
```
HTTP/1.1 200 OK, {"message": "File uploaded successfully"}
```

**Remediation**:
- Check metadata (Python):
  ```python
  from exiftool import ExifToolHelper
  with ExifToolHelper() as et:
      metadata = et.get_metadata(file_path)
      for tag in metadata:
          if 'script' in str(tag).lower():
              return jsonify({'error': 'Malicious metadata detected'}), 400
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > response.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).