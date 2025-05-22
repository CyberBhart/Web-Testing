# Test Upload of Unexpected File Types

## Overview

Testing for the upload of unexpected file types (WSTG-BUSL-08) involves assessing whether a web application properly restricts file uploads to only approved file types, preventing attackers from uploading unauthorized files that could bypass business logic or harm the system. According to OWASP, vulnerabilities in file upload mechanisms often arise from weak validation, such as relying solely on file extensions or client-side checks, allowing attackers to upload files like scripts or executables that could be executed or cause damage. This test focuses on verifying the application’s ability to reject unapproved file types that may not be inherently malicious but could disrupt functionality or exploit system weaknesses.

**Impact**: Allowing unexpected file types can lead to:
- Execution of unauthorized scripts (e.g., uploading a `.php` file to a web server).
- System compromise through exploitable file types (e.g., `.exe` files).
- Data corruption or application errors due to incompatible formats.
- Increased attack surface by enabling further exploitation (e.g., uploading configuration files).

This guide provides a step-by-step methodology for testing the upload of unexpected file types, adhering to OWASP’s WSTG-BUSL-08, with practical tools, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing file upload vulnerabilities, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test file uploads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Command-line tool for crafting and sending file upload requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Postman**: Tool for testing API-based file uploads.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and modifying upload forms.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Python Requests Library**: Python library for scripting custom file upload requests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-BUSL-08, focusing on attempting to upload unexpected file types and verifying whether the application rejects them securely.

### 1. Identify File Upload Functionality with Burp Suite

**Objective**: Locate file upload mechanisms and determine their intended file types.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Navigate to upload features (e.g., profile picture upload, document submission).
   - Capture upload requests in Burp Suite’s “HTTP History”.
3. **Analyze Upload Requests**:
   - Identify endpoints (e.g., `POST /upload`), parameters (e.g., `file`), and headers (e.g., `Content-Type`).
   - Note accepted file types (e.g., `.jpg`, `.pdf`) from form restrictions or responses.

**Burp Suite Commands**:
- **Command 1**: Capture and analyze an upload request:
  ```
  Proxy tab -> HTTP History -> Filter by example.com -> Select POST /upload -> Inspect Request tab -> Note Content-Type (e.g., multipart/form-data) and file parameter -> Add to Site Map
  ```
- **Command 2**: Upload a `.php` file disguised as a `.jpg`:
  ```
  Right-click POST /upload in HTTP History -> Send to Repeater -> Modify file content to "<?php echo 'test'; ?>" -> Change filename to "test.php.jpg" -> Click "Send" -> Check response
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
- Validate file types server-side (PHP):
  ```php
  $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!in_array($_FILES['file']['type'], $allowed_types)) {
      die('Invalid file type');
  }
  ```

**Tip**: Save request details in Burp Suite’s “Logger” or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests).

### 2. Upload Unexpected File Types with cURL

**Objective**: Test whether the application accepts unauthorized file types by uploading files with unexpected extensions or MIME types.

**Steps**:
1. **Create Test Files**:
   - Create a `.php` file (e.g., `test.php` with `<?php echo 'test'; ?>`) and a `.txt` file (e.g., `test.txt` with random text).
2. **Send Upload Requests**:
   - Upload unexpected file types, modifying filenames or MIME types.
3. **Analyze Response**:
   - Check if the file is accepted (e.g., HTTP 200) or rejected (e.g., error message).
   - Verify if the uploaded file is accessible (e.g., via a URL).

**cURL Commands**:
- **Command 1**: Upload a `.php` file disguised as a `.jpg`:
  ```bash
  curl -X POST -F "file=@test.php;filename=image.jpg" -b "session=abc123" http://example.com/upload
  ```
- **Command 2**: Upload a `.txt` file:
  ```bash
  curl -X POST -F "file=@test.txt;type=text/plain" -b "session=abc123" http://example.com/upload
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
File uploaded successfully: /uploads/image.jpg
```

**Remediation**:
- Check file content (Python):
  ```python
  from PIL import Image
  try:
      Image.open(file).verify()
  except:
      return jsonify({'error': 'Invalid image'}), 400
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > response.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test API File Uploads with Postman

**Objective**: Test API endpoints for unexpected file type uploads.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find file upload APIs (e.g., `/api/v1/upload`).
   - Import into Postman.
2. **Upload Unexpected Files**:
   - Send requests with unauthorized file types (e.g., `.php`, `.txt`).
   - Modify headers or filenames.
3. **Analyze Response**:
   - Check for acceptance (e.g., HTTP 200) or rejection (e.g., HTTP 400).

**Postman Commands**:
- **Command 1**: Upload a `.php` file:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: test.php -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Upload a `.txt` file with fake MIME type:
  ```
  New Request -> POST http://example.com/api/v1/upload -> Body -> form-data -> Key: file, Type: File, Value: test.txt -> Headers: Content-Type: text/plain, Cookie: session=abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "path": "/uploads/test.php"
}
```

**Remediation**:
- Validate MIME types (Node.js):
  ```javascript
  const allowedTypes = ['image/jpeg', 'image/png'];
  if (!allowedTypes.includes(req.files.file.mimetype)) {
      res.status(400).send('Invalid file type');
  }
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Bypass Client-Side Validation with Browser Developer Tools

**Objective**: Test whether client-side file type restrictions can be bypassed.

**Steps**:
1. **Inspect Upload Form**:
   - Open Developer Tools (`F12`) on an upload page (e.g., `http://example.com/upload`).
   - Identify file input restrictions (e.g., `accept=".jpg,.png"`).
2. **Manipulate Form**:
   - Remove or modify `accept` attributes.
   - Upload an unexpected file type (e.g., `.php`).
3. **Analyze Response**:
   - Check if the server accepts the file.

**Browser Developer Tools Commands**:
- **Command 1**: Remove file type restrictions:
  ```
  Elements tab -> Find <input type="file" accept=".jpg,.png"> -> Right-click -> Edit as HTML -> Remove accept attribute -> Upload test.php
  ```
- **Command 2**: Modify filename in request:
  ```
  Network tab -> Upload a file -> Right-click request -> Copy as cURL -> Modify filename to test.php.jpg -> Replay in terminal
  ```

**Example Vulnerable Finding**:
- Uploaded `test.php` -> Response: `File uploaded: /uploads/test.php`.

**Remediation**:
- Server-side validation (PHP):
  ```php
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
  if (!in_array($mime, ['image/jpeg', 'image/png'])) {
      die('Invalid file type');
  }
  ```

**Tip**: Save screenshots of modified forms or responses. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTML changes).

### 5. Script File Upload Tests with Python Requests

**Objective**: Automate tests to upload unexpected file types and evaluate server-side validation.

**Steps**:
1. **Write Python Script**:
   - Create a script to upload various file types.
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
    ('file', ('image.jpg', '<?php echo "test"; ?>', 'image/jpeg')),
    ('file', ('script.php', '<?php echo "test"; ?>', 'text/php')),
    ('file', ('text.txt', 'Sample text', 'text/plain'))
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
  python3 test_upload.py
  ```
- **Command 2**: Test a double-extension file:
  ```bash
  python3 -c "import requests; url='http://example.com/upload'; files={'file': ('test.php.jpg', '<?php echo \"test\"; ?>', 'image/jpeg')}; cookies={'session': 'abc123'}; r=requests.post(url, files=files, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
File: script.php
Status: 200
Response: File uploaded successfully: /uploads/script.php
```

**Remediation**:
- Verify file extensions and content (Python):
  ```python
  import magic
  allowed_extensions = ['jpg', 'png', 'pdf']
  file_ext = file.filename.rsplit('.', 1)[-1].lower()
  mime = magic.from_buffer(file.read(1024), mime=True)
  if file_ext not in allowed_extensions or mime not in ['image/jpeg', 'image/png', 'application/pdf']:
      return jsonify({'error': 'Invalid file'}), 400
  ```

**Tip**: Save script output to a file (e.g., `python3 test_upload.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).

### 6. Test Null Byte Injection in File Uploads

**Objective**: Test whether null byte injection allows uploading unauthorized file types.

**Steps**:
1. **Capture Upload Request**:
   - Use Burp Suite to capture an upload request (e.g., `POST /upload`).
2. **Inject Null Byte**:
   - Modify the filename to include a null byte (e.g., `test.php%00.jpg`).
3. **Analyze Response**:
   - Check if the file is accepted as `test.php`.

**Burp Suite Commands**:
- **Command 1**: Test null byte injection:
  ```
  HTTP History -> Select POST /upload -> Send to Repeater -> Modify filename=test.php%00.jpg -> Send -> Check Response
  ```
- **Command 2**: Verify with different null byte encoding:
  ```
  Send to Repeater -> Modify filename=test.php\0.jpg -> Send -> Check Response
  ```

**Example Vulnerable Output**:
```
HTTP/1.1 200 OK, {"message": "File uploaded: /uploads/test.php"}
```

**Remediation**:
- Sanitize filenames (PHP):
  ```php
  $filename = str_replace("\0", "", $_FILES['file']['name']);
  $ext = pathinfo($filename, PATHINFO_EXTENSION);
  if (!in_array($ext, ['jpg', 'png'])) {
      die('Invalid file type');
  }
  ```

**Tip**: Save Repeater responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test File Size and Resource Limits

**Objective**: Test whether the application enforces file size limits to prevent resource exhaustion.

**Steps**:
1. **Create Large File**:
   - Generate a 100MB file using `dd`.
2. **Upload File**:
   - Use cURL to upload the oversized file.
3. **Analyze Response**:
   - Check for rejection (e.g., HTTP 413) or acceptance.

**cURL Commands**:
- **Command 1**: Create and upload a 100MB file:
  ```bash
  dd if=/dev/zero of=largefile.bin bs=1M count=100
  curl -X POST -F "file=@largefile.bin;filename=image.jpg" -b "session=abc123" http://example.com/upload
  ```
- **Command 2**: Upload a smaller oversized file (10MB):
  ```bash
  dd if=/dev/zero of=mediumfile.bin bs=1M count=10
  curl -X POST -F "file=@mediumfile.bin;filename=image.jpg" -b "session=abc123" http://example.com/upload
  ```

**Example Vulnerable Output**:
```
HTTP/1.1 200 OK, {"message": "File uploaded successfully"}
```

**Remediation**:
- Enforce size limits (Python):
  ```python
  max_size = 5 * 1024 * 1024  # 5MB
  if request.files['file'].content_length > max_size:
      return jsonify({'error': 'File too large'}), 413
  ```

**Tip**: Save cURL responses to a file (e.g., `curl -i ... > response.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Upload Directory Enumeration and Access

**Objective**: Test whether the upload directory is accessible or enumerable, allowing exploitation of stored files.

**Steps**:
1. **Identify Upload Directory**:
   - Note directory from upload responses (e.g., `/uploads/`).
2. **Enumerate Directory**:
   - Send requests to guess filenames or access the directory.
3. **Analyze Responses**:
   - Check for directory listings or file access (e.g., HTTP 200).

**Python Script**:
```python
import requests
import sys

base_url = 'http://example.com/uploads/'
filenames = ['image.jpg', 'test.php', 'script.php', 'index.php']
cookies = {'session': 'abc123'}

try:
    for filename in filenames:
        url = base_url + filename
        response = requests.get(url, cookies=cookies, timeout=5)
        print(f"File: {filename}, Status: {response.status_code}, Response: {response.text[:100]}")
    # Test directory listing
    response = requests.get(base_url, cookies=cookies, timeout=5)
    print(f"Directory: {base_url}, Status: {response.status_code}, Response: {response.text[:100]}")
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run the enumeration script:
  ```bash
  python3 test_directory.py
  ```
- **Command 2**: Test a single file access:
  ```bash
  python3 -c "import requests; url='http://example.com/uploads/test.php'; cookies={'session': 'abc123'}; r=requests.get(url, cookies=cookies, timeout=5); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
File: test.php, Status: 200, Response: test
Directory: http://example.com/uploads/, Status: 200, Response: <html><body><a href="test.php">test.php</a></body></html>
```

**Remediation**:
- Secure upload directory (Apache):
  ```apache
  <Directory "/var/www/uploads">
      Options -Indexes
      Deny from all
      <FilesMatch "\.(jpg|png|pdf)$">
          Allow from all
      </FilesMatch>
  </Directory>
  ```

**Tip**: Save script output to a file (e.g., `python3 test_directory.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script output).