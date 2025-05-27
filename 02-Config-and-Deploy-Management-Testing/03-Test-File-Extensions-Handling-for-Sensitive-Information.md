# Testing File Extensions Handling for Sensitive Information

## Overview

Testing File Extensions Handling for Sensitive Information (WSTG-CONF-03) involves assessing how a web application handles files with specific extensions to ensure that sensitive information (e.g., configuration files, backups, source code) is not exposed due to misconfigurations. According to OWASP, improper handling of file extensions can lead to the disclosure of sensitive data or application compromise. This test focuses on verifying secure handling of file extensions, access controls, and server configurations to prevent unauthorized access to sensitive files.

**Impact**: Improper file extension handling can lead to:
- Exposure of sensitive data, such as database credentials or API keys.
- Access to source code or backups, enabling further attacks.
- Disclosure of internal application details through logs or temporary files.
- Application compromise if sensitive files reveal vulnerabilities.

This guide provides a practical, hands-on methodology for testing file extension handling, adhering to OWASP’s WSTG-CONF-03, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing file extension handling, with setup and configuration instructions:

- **Gobuster**: Enumerates directories and files with sensitive extensions.
  - Install on Linux:
    ```bash
    sudo apt install gobuster
    ```
  - Alternative: Download from [github.com/OJ/gobuster](https://github.com/OJ/gobuster).

- **Wfuzz**: Brute-forces files and directories for exposed resources.
  - Install:
    ```bash
    pip install wfuzz
    ```

- **Burp Suite Community Edition**: Analyzes responses for file access and misconfigurations.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Curl**: Tests direct access to sensitive files and server responses.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Nikto**: Scans for exposed files and misconfigurations.
  - Install on Linux:
    ```bash
    sudo apt install nikto
    ```

- **Dirb**: Enumerates directories and files with common extensions.
  - Install on Linux:
    ```bash
    sudo apt install dirb
    ```

- **Python (with Requests Library)**: Automates testing for sensitive file extensions and directory indexing.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CONF-03, focusing on testing sensitive file extensions, backup files, source code exposure, configuration files, file extension handling, predictable file names, and directory indexing.

### 1. Enumerate Sensitive File Extensions with Gobuster

**Objective**: Identify accessible files with sensitive extensions (e.g., `.bak`, `.conf`).

**Steps**:
1. **Configure Gobuster**:
   - Use a wordlist (e.g., `/usr/share/wordlists/dirb/common.txt`).
   - Specify sensitive extensions (e.g., `.bak`, `.conf`, `.sql`).
2. **Run File Enumeration**:
   - Brute-force files in the root or common directories (e.g., `/backup`).
3. **Analyze Findings**:
   - Vulnerable: Files like `config.bak` return HTTP 200.
   - Expected secure response: HTTP 403 or 404 for sensitive files.

**Gobuster Commands**:
- **Command 1**: Enumerate files with extensions:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x .bak,.conf,.sql -o gobuster_files.txt
  ```
- **Command 2**: Target backup directory:
  ```bash
  gobuster dir -u http://example.com/backup -w /usr/share/wordlists/dirb/common.txt -x .zip,.tar.gz -o gobuster_backup.txt
  ```

**Example Vulnerable Output**:
```
/config.bak (Status: 200)
/backup/db.sql (Status: 200)
```

**Remediation**:
- Deny access to sensitive extensions (Nginx):
  ```nginx
  location ~* \.(bak|conf|sql|zip|tar\.gz)$ {
      deny all;
  }
  ```

**Tip**: Save Gobuster output to a file (e.g., `gobuster_files.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Gobuster outputs).

### 2. Brute-Force Backup Files with Wfuzz

**Objective**: Check for exposed backup or archive files.

**Steps**:
1. **Configure Wfuzz**:
   - Use a wordlist for filenames and extensions.
2. **Run File Brute-Force**:
   - Target common backup extensions (e.g., `.zip`, `.tar.gz`).
3. **Analyze Findings**:
   - Vulnerable: Backup files accessible (e.g., `backup.zip`).
   - Expected secure response: HTTP 404 or 403.

**Wfuzz Commands**:
- **Command 1**: Brute-force backup files:
  ```bash
  wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z list,bak-zip-tar.gz --sc 200 http://example.com/FUZZ.FUZZ
  ```
- **Command 2**: Target specific directory:
  ```bash
  wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z list,sql-bak --sc 200 http://example.com/backup/FUZZ.FUZZ
  ```

**Example Vulnerable Output**:
```
200  backup.zip
200  db_backup.sql
```

**Remediation**:
- Move backups outside web root:
  ```bash
  mv /var/www/html/backup /var/secure_backups
  ```

**Tip**: Save Wfuzz output to a file (e.g., `wfuzz -c ... > wfuzz_output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Wfuzz outputs).

### 3. Test Source Code Exposure with Curl

**Objective**: Verify that source code files are not served as plain text.

**Steps**:
1. **Test Source Code Files**:
   - Request files like `index.php` or `index.php.bak` to check server handling.
2. **Analyze Responses**:
   - Check Content-Type and content for source code exposure.
3. **Analyze Findings**:
   - Vulnerable: `.php.bak` file served as `text/plain`.
   - Expected secure response: File executed or access denied.

**Curl Commands**:
- **Command 1**: Test PHP file:
  ```bash
  curl -i http://example.com/index.php
  ```
- **Command 2**: Test backup of source file:
  ```bash
  curl -i http://example.com/index.php.bak
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
<?php
// Database connection details
$db = mysqli_connect("localhost", "root", "password", "app");
?>
```

**Remediation**:
- Configure MIME types and deny access to backups (Apache):
  ```apache
  AddType application/x-httpd-php .php
  <FilesMatch "\.(bak|inc|old)$">
      Order Deny,Allow
      Deny from all
  </FilesMatch>
  ```

**Tip**: Save Curl responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Check Directory Indexing with Burp Suite

**Objective**: Ensure directory indexing does not expose sensitive files.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope.
2. **Test Directory Access**:
   - Request directories like `/backup/` or `/config/` to check for indexing.
3. **Analyze Findings**:
   - Vulnerable: Directory listing shows files (e.g., `db.sql`).
   - Expected secure response: HTTP 403 or no listing.

**Burp Suite Commands**:
- **Command 1**: Test directory indexing:
  ```
  HTTP History -> Select GET /backup/ -> Send to Repeater -> Click Send -> Check for directory listing
  ```
- **Command 2**: Check common directories:
  ```
  HTTP History -> Select GET / -> Send to Repeater -> Change to GET /config/ -> Click Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
<!DOCTYPE html>
<html>
<body>
<a href="db_backup.sql">db_backup.sql</a>
</body>
</html>
```

**Remediation**:
- Disable directory indexing (Apache):
  ```apache
  <Directory /var/www/html>
      Options -Indexes
  </Directory>
  ```

**Tip**: Save Burp Suite responses as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Scan for Misconfigurations with Nikto

**Objective**: Identify exposed sensitive files or misconfigurations.

**Steps**:
1. **Configure Nikto**:
   - Ensure permission to scan the target.
2. **Run Nikto Scan**:
   - Scan for exposed files or directories.
3. **Analyze Findings**:
   - Vulnerable: Files like `config.conf` detected.
   - Expected secure response: No sensitive files exposed.

**Nikto Commands**:
- **Command 1**: Basic scan:
  ```bash
  nikto -h example.com -output nikto_scan.txt
  ```
- **Command 2**: Scan with SSL:
  ```bash
  nikto -h https://example.com -ssl -output nikto_ssl.txt
  ```

**Example Vulnerable Output**:
```
+ /config.bak: Backup file found
+ /backup/: Directory indexing enabled
```

**Remediation**:
- Deny access (Nginx):
  ```nginx
  location /backup {
      deny all;
  }
  location ~* \.(bak|conf)$ {
      deny all;
  }
  ```

**Tip**: Save Nikto output to a file (e.g., `nikto_scan.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Nikto outputs).

### 6. Automate Testing with Python Script

**Objective**: Automate testing for sensitive file extensions and directory indexing.

**Steps**:
1. **Write Python Script**:
   - Create a script to test file access and indexing:
     ```python
     import requests

     target = 'http://example.com'
     extensions = ['.bak', '.conf', '.sql', '.zip', '.tar.gz']
     directories = ['/backup', '/config', '/admin']
     files = ['config', 'backup', 'db', 'settings']

     # Test sensitive files
     print("Testing sensitive files:")
     for file in files:
         for ext in extensions:
             url = f"{target}/{file}{ext}"
             response = requests.get(url)
             print(f"{url}: Status={response.status_code}")
             if response.status_code == 200:
                 print(f"Vulnerable: {file}{ext} accessible")

     # Test directory indexing
     print("\nTesting directory indexing:")
     for dir in directories:
         response = requests.get(f"{target}{dir}/")
         print(f"{dir}/: Status={response.status_code}")
         if response.status_code == 200 and '<a href="' in response.text.lower():
             print(f"Vulnerable: Directory indexing enabled for {dir}")
     ```
2. **Run Script**:
   - Install dependencies:
     ```bash
     pip install requests
     ```
   - Execute:
     ```bash
     python3 test_file_extensions.py
     ```
3. **Analyze Findings**:
   - Vulnerable: Accessible sensitive files or directory indexing enabled.
   - Expected secure response: HTTP 403/404 for files and directories; no indexing.

**Python Commands**:
- **Command 1**: Run file extensions test:
  ```bash
  python3 test_file_extensions.py
  ```
- **Command 2**: Test specific file:
  ```bash
  python3 -c "import requests; r=requests.get('http://example.com/config.bak'); print('Status:', r.status_code, 'Vulnerable' if r.status_code==200 else 'Secure')"
  ```

**Example Vulnerable Output**:
```
Testing sensitive files:
http://example.com/config.bak: Status=200
Vulnerable: config.bak accessible

Testing directory indexing:
/backup/: Status=200
Vulnerable: Directory indexing enabled for /backup
```

**Remediation**:
- Secure configuration (Apache):
  ```apache
  <Directory /var/www/html>
      Options -Indexes
  </Directory>
  <FilesMatch "\.(bak|conf|sql|zip|tar\.gz)$">
      Order Deny,Allow
      Deny from all
  </FilesMatch>
  ```

**Tip**: Save script output to a file (e.g., `python3 test_file_extensions.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).
