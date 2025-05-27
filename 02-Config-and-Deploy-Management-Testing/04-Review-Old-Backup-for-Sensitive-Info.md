# Reviewing Old, Backup, and Unreferenced Files for Sensitive Information

## Overview

Reviewing Old, Backup, and Unreferenced Files for Sensitive Information (WSTG-CONF-04) involves testing a web application to identify files that may expose sensitive data due to improper cleanup or misconfiguration. According to OWASP, old, backup, and unreferenced files can reveal credentials, source code, or internal details, enabling attackers to compromise the application. This test focuses on enumerating and reviewing such files to ensure they are not accessible or do not contain sensitive information.

**Impact**: Exposed old, backup, or unreferenced files can lead to:
- Disclosure of sensitive data, such as database credentials or API keys.
- Exposure of source code, revealing vulnerabilities or intellectual property.
- Application compromise through exploitable configurations or scripts.
- Increased attack surface from forgotten or temporary files.

This guide provides a practical, hands-on methodology for testing old, backup, and unreferenced files, adhering to OWASP’s WSTG-CONF-04, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing old, backup, and unreferenced files, with setup and configuration instructions:

- **Gobuster**: Enumerates directories and files with backup or old extensions.
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

- **Burp Suite Community Edition**: Crawls the application and tests file access.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Configure proxy:
    ```bash
    curl -x http://127.0.0.1:8080 http://example.com
    ```

- **Curl**: Tests direct access to suspected files and server responses.
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

- **Dirb**: Enumerates directories and files with common names.
  - Install on Linux:
    ```bash
    sudo apt install dirb
    ```

- **Python (with Requests Library)**: Automates testing for old, backup, and unreferenced files.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CONF-04, focusing on enumerating backup files, old files, unreferenced files, temporary files, configuration files, predictable file names, and checking for directory indexing.

### 1. Enumerate Backup and Old Files with Gobuster

**Objective**: Identify accessible backup or old files (e.g., `.bak`, `.old`).

**Steps**:
1. **Configure Gobuster**:
   - Use a wordlist (e.g., `/usr/share/wordlists/dirb/common.txt`).
   - Specify backup/old extensions (e.g., `.bak`, `.old`, `.backup`).
2. **Run File Enumeration**:
   - Brute-force files in the root or directories like `/backup` or `/old`.
3. **Analyze Findings**:
   - Vulnerable: Files like `index.php.bak` return HTTP 200.
   - Expected secure response: HTTP 403 or 404 for sensitive files.

**Gobuster Commands**:
- **Command 1**: Enumerate backup files:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x .bak,.old,.backup -o gobuster_backup.txt
  ```
- **Command 2**: Target backup directory:
  ```bash
  gobuster dir -u http://example.com/backup -w /usr/share/wordlists/dirb/common.txt -x .zip,.tar.gz,.sql -o gobuster_backup_dir.txt
  ```

**Example Vulnerable Output**:
```
/index.php.bak (Status: 200)
/backup/db_backup.sql (Status: 200)
```

**Remediation**:
- Deny access to backup extensions (Nginx):
  ```nginx
  location ~* \.(bak|old|backup|zip|tar\.gz|sql)$ {
      deny all;
  }
  ```

**Tip**: Save Gobuster output to a file (e.g., `gobuster_backup.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Gobuster outputs).

### 2. Brute-Force Unreferenced Files with Wfuzz

**Objective**: Check for unreferenced or temporary files not linked in the application.

**Steps**:
1. **Configure Wfuzz**:
   - Use a wordlist for filenames and extensions.
2. **Run File Brute-Force**:
   - Target common unreferenced files (e.g., `test.php`, `debug.log`).
3. **Analyze Findings**:
   - Vulnerable: Files like `debug.log` accessible.
   - Expected secure response: HTTP 404 or 403.

**Wfuzz Commands**:
- **Command 1**: Brute-force unreferenced files:
  ```bash
  wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z list,bak-log-inc --sc 200 http://example.com/FUZZ.FUZZ
  ```
- **Command 2**: Target temporary directory:
  ```bash
  wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z list,tmp-log-sql --sc 200 http://example.com/tmp/FUZZ.FUZZ
  ```

**Example Vulnerable Output**:
```
200  debug.log
200  temp.sql
```

**Remediation**:
- Remove unreferenced files:
  ```bash
  rm -f /var/www/html/tmp/debug.log /var/www/html/tmp/temp.sql
  ```

**Tip**: Save Wfuzz output to a file (e.g., `wfuzz -c ... > wfuzz_output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Wfuzz outputs).

### 3. Crawl for Unreferenced Files with Burp Suite

**Objective**: Use web crawling to identify unreferenced files.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope.
2. **Run Crawler**:
   - Crawl the application to map files and directories.
   - Manually test unreferenced files found in crawl results (e.g., `test.php`).
3. **Analyze Findings**:
   - Vulnerable: Unreferenced files like `test.php` accessible.
   - Expected secure response: HTTP 403 or 404.

**Burp Suite Commands**:
- **Command 1**: Start crawl:
  ```
  Target -> Site map -> Right-click example.com -> Crawl -> Start Crawl -> Check Crawl Results for .bak, .log
  ```
- **Command 2**: Test unreferenced file:
  ```
  HTTP History -> Select GET / -> Send to Repeater -> Change to GET /test.php -> Click Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
<?php echo "Test script"; ?>
```

**Remediation**:
- Restrict access (Apache):
  ```apache
  <Files "test.php">
      Order Deny,Allow
      Deny from all
  </Files>
  ```

**Tip**: Save Burp Suite crawl results as screenshots or exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Predictable File Names with Curl

**Objective**: Check for files with predictable names (e.g., date-based backups).

**Steps**:
1. **Test Predictable Files**:
   - Request files like `backup_2025-05-08.sql` or `config.bak`.
2. **Analyze Responses**:
   - Check for HTTP 200 and sensitive content.
3. **Analyze Findings**:
   - Vulnerable: Predictable files accessible.
   - Expected secure response: HTTP 404 or 403.

**Curl Commands**:
- **Command 1**: Test date-based backup:
  ```bash
  curl -i http://example.com/backup/backup_2025-05-08.sql
  ```
- **Command 2**: Test common backup:
  ```bash
  curl -i http://example.com/config.bak
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
CREATE TABLE users (id INT, username VARCHAR(50));
```

**Remediation**:
- Use unpredictable names and secure storage:
  ```bash
  mv /var/www/html/backup/backup_2025-05-08.sql /var/secure_backups/$(uuidgen).sql
  ```

**Tip**: Save Curl responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Scan for Exposed Files with Nikto

**Objective**: Identify exposed old or backup files.

**Steps**:
1. **Configure Nikto**:
   - Ensure permission to scan the target.
2. **Run Nikto Scan**:
   - Scan for backup files or misconfigurations.
3. **Analyze Findings**:
   - Vulnerable: Files like `index.php.old` detected.
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
+ /index.php.bak: Backup file found
+ /old/: Directory with old files
```

**Remediation**:
- Remove old files:
  ```bash
  rm -f /var/www/html/index.php.bak /var/www/html/old/*
  ```

**Tip**: Save Nikto output to a file (e.g., `nikto_scan.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Nikto outputs).

### 6. Check Directory Indexing with Dirb

**Objective**: Ensure directory indexing does not expose backup or old files.

**Steps**:
1. **Configure Dirb**:
   - Use a wordlist (e.g., `/usr/share/dirb/wordlists/common.txt`).
2. **Run Directory Scan**:
   - Test directories like `/backup/` or `/old/` for indexing.
3. **Analyze Findings**:
   - Vulnerable: Directory listing shows files (e.g., `backup.zip`).
   - Expected secure response: HTTP 403 or no listing.

**Dirb Commands**:
- **Command 1**: Scan for directories:
  ```bash
  dirb http://example.com /usr/share/dirb/wordlists/common.txt -o dirb_dirs.txt
  ```
- **Command 2**: Check specific directory:
  ```bash
  dirb http://example.com/backup /usr/share/dirb/wordlists/common.txt -o dirb_backup.txt
  ```

**Example Vulnerable Output**:
```
+ http://example.com/backup/ (CODE:200|SIZE:1234)
----> Directory indexing enabled: backup.zip, db.sql
```

**Remediation**:
- Disable directory indexing (Nginx):
  ```nginx
  autoindex off;
  ```

**Tip**: Save Dirb output to a file (e.g., `dirb_dirs.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., Dirb outputs).

### 7. Automate Testing with Python Script

**Objective**: Automate testing for old, backup, and unreferenced files.

**Steps**:
1. **Write Python Script**:
   - Create a script to test file access and directory indexing:
     ```python
     import requests
     import datetime

     target = 'http://example.com'
     extensions = ['.bak', '.old', '.backup', '.zip', '.sql']
     directories = ['/backup', '/old', '/tmp']
     files = ['config', 'backup', 'index', 'test', 'db']

     # Test backup/old files
     print("Testing backup/old files:")
     for file in files:
         for ext in extensions:
             url = f"{target}/{file}{ext}"
             try:
                 response = requests.get(url, timeout=5)
                 print(f"{url}: Status={response.status_code}")
                 if response.status_code == 200:
                     print(f"Vulnerable: {file}{ext} accessible")
             except requests.RequestException as e:
                 print(f"{url}: Error={e}")

     # Test predictable file names
     print("\nTesting predictable file names:")
     today = datetime.datetime.now().strftime("%Y-%m-%d")
     for dir in directories:
         for file in files:
             url = f"{target}{dir}/{file}_{today}.sql"
             try:
                 response = requests.get(url, timeout=5)
                 print(f"{url}: Status={response.status_code}")
                 if response.status_code == 200:
                     print(f"Vulnerable: Predictable file accessible")
             except requests.RequestException as e:
                 print(f"{url}: Error={e}")

     # Test directory indexing
     print("\nTesting directory indexing:")
     for dir in directories:
         try:
             response = requests.get(f"{target}{dir}/", timeout=5)
             print(f"{dir}/: Status={response.status_code}")
             if response.status_code == 200 and '<a href="' in response.text.lower():
                 print(f"Vulnerable: Directory indexing enabled at {dir}")
         except requests.RequestException as e:
             print(f"{dir}/: Error={e}")
     ```
2. **Run Script**:
   - Install dependencies:
     ```bash
     pip install requests
     ```
   - Execute:
     ```bash
     python3 test_backup_files.py
     ```
3. **Analyze Findings**:
   - Vulnerable: Accessible files or directory indexing detected.
   - Expected secure response: HTTP 403/404 for files; no indexing.

**Python Commands**:
- **Command 1**: Run backup files test:
  ```bash
  python3 test_backup_files.py
  ```
- **Command 2**: Test specific backup file:
  ```bash
  python3 -c "import requests; r=requests.get('http://example.com/index.php.bak', timeout=5); print(r.status_code, 'Vulnerable' if r.status_code==200 else 'Secure')"
  ```

**Example Vulnerable Output**:
```
Testing backup/old files:
http://example.com/index.php.bak: Status=200
Vulnerable: index.php.bak accessible

Testing predictable file names:
http://example.com/backup/db_2025-05-22.sql: Status=200
Vulnerable: Predictable file accessible

Testing directory indexing:
/backup/: Status=200
Vulnerable: Directory indexing enabled at /backup
```

**Remediation**:
- Secure configuration (Apache):
  ```apache
  <FilesMatch "\.(bak|old|backup|zip|sql)$">
      Order Deny,Allow
      Deny from all
  </FilesMatch>
  <Directory /var/www/html>
      Options -Indexes
  </Directory>
  ```

**Tip**: Save script output to a file (e.g., `python3 test_backup_files.py > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., script outputs).
