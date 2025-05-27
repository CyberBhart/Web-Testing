# Test File Permission

## Overview

Testing file permissions involves verifying that files and directories on a web server are configured with secure permissions to prevent unauthorized access, modification, or exposure of sensitive data. According to OWASP (WSTG-CONF-02), improper file permissions can allow attackers to read configuration files, modify application code, or gain unauthorized access to sensitive resources. This guide provides a hands-on methodology to test file permissions, covering world-readable/writable files, sensitive file permissions, directory listing, ownership, access controls, and automated testing, with tools, commands, payloads, and remediation strategies.

**Impact**: Insecure file permissions can lead to:
- Exposure of sensitive data (e.g., database credentials, API keys) in configuration files.
- Unauthorized modification of application code or scripts.
- Directory listing exposing file structures and metadata.
- Privilege escalation through misconfigured ownership.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

This guide aligns with OWASP’s WSTG-CONF-02, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as probing file permissions may trigger security alerts, access sensitive data, or disrupt server functionality, potentially affecting user experience.

## Testing Tools

The following tools are recommended for testing file permissions, with setup instructions optimized for new pentesters:

- **cURL**: Command-line tool for testing file access.
  - Install on Linux:  
    `sudo apt install curl`
  - Install on Windows/Mac: Download from [cURL](https://curl.se/download.html).
  - Example:  
    `curl -I https://example.com/config.php`

- **Wget**: Command-line utility for downloading files.
  - Install on Linux:  
    `sudo apt install wget`
  - Example:  
    `wget https://example.com/.htaccess`

- **Burp Suite Community Edition**: Intercepting proxy for testing file access responses.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Example:  
    Use Repeater to analyze responses.

- **OWASP ZAP 3.2**: Open-source web application security scanner.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD:  
    1. Go to Tools > Options > HUD.  
    2. Enable HUD for real-time browser inspection.
  - Example:  
    `zap-cli quick-scan https://example.com`

- **Nmap**: Network scanning tool for identifying open directories and files.
  - Install on Linux:  
    `sudo apt install nmap`
  - Example:  
    `nmap --script http-enum -p80,443 example.com`

- **Nikto**: Web server scanner for detecting misconfigurations and exposed files.
  - Install on Linux:  
    `sudo apt install nikto`
  - Example:  
    `nikto -h https://example.com --ssl`  
    *Note*: Use `--ssl` for HTTPS targets to reduce false positives.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-02, testing file and directory permissions through access attempts, permission checks, directory listing, ownership validation, access control audits, and automated scripting.

### Common File Permission Checks and Payloads

Below is a list of common files, directories, and commands to test for permission vulnerabilities. Use with caution to avoid disrupting production environments.

- **Sensitive Files**:
  - Configuration files: `config.php`, `web.config`, `.htaccess`, `.htpasswd`.
  - Backup files: `backup.sql`, `site.bak`.
  - Logs: `access.log`, `error.log`.

- **Test Commands**:
  - Check file access:  
    `curl https://example.com/config.php`
  - List directory:  
    `curl https://example.com/uploads/`
  - Check permissions (gray-box):  
    `ls -l /var/www/html/config.php`

- **Expected Permissions**:
  - Files: `rw-r-----` (640) for sensitive files.
  - Directories: `rwxr-x---` (750) for web directories.
  - Ownership: Web server user (e.g., `www-data`). Use `ps aux | egrep '(apache|nginx)'` to verify the actual user (e.g., `apache`, `nginx`, or `www-data`).

**Note**: Permission behavior depends on the server (e.g., Apache, Nginx) and operating system (e.g., Linux, Windows). Test both black-box (external access) and gray-box (server access) scenarios for comprehensive coverage.

### 1. Check World-Readable/Writable Files

**Objective**: Ensure no files or directories are world-readable or world-writable, which could allow unauthorized access or modification.

**Steps**:
1. Use cURL (black-box):
   - Run:  
     `curl -I https://example.com/config.php`
   - **Example Vulnerable Output**:  
     ```text
     HTTP/1.1 200 OK
     ```
   - **Example Secure Output**:  
     ```text
     HTTP/1.1 403 Forbidden
     ```
2. Check permissions (gray-box):
   - Run:  
     `find /var/www/html -perm -o+r -o -perm -o+w`
   - Look for files with `rw-rw-rw-` (666) or `rwxrwxrwx` (777).
3. Use Burp Suite:
   - Test access to sensitive files.
4. Use OWASP ZAP:
   - Run Active Scan.
   - Check for accessible file alerts under **Alerts > File Exposure**.

**Example Vulnerable Configuration**:
```bash
-rw-rw-rw- 1 www-data www-data 123 May 27 2025 config.php
```
Result: World-readable/writable file.

**Example Secure Configuration**:
```bash
-rw-r----- 1 www-data www-data 123 May 27 2025 config.php
```
Result: Restricted permissions.

**Remediation**:
- Set secure permissions:  
  `chmod 640 /var/www/html/config.php`
- Verify Apache configuration:  
  `grep -i config /etc/apache2/sites-enabled/*.conf`
- Verify Nginx configuration:  
  `nginx -T | grep -i location`

**Tip**: Save world-readable/writable file evidence in a report.

### 2. Verify Sensitive File Permissions

**Objective**: Ensure sensitive files (e.g., configuration, backups, .htpasswd) have restrictive permissions.

**Steps**:
1. Use cURL (black-box):
   - Run:  
     `curl -sI https://example.com/.htaccess`
   - Run:  
     `curl -sI https://example.com/.htpasswd`
   - **Example Vulnerable Output**:  
     ```text
     HTTP/1.1 200 OK
     ```
   - **Example Secure Output**:  
     ```text
     HTTP/1.1 403 Forbidden
     ```
2. Check permissions (gray-box):
   - Run:  
     `ls -l /var/www/html/.htaccess`
   - Expect: `rw-r-----` (640).
3. Use Nmap:
   - Run:  
     `nmap --script http-enum -p80,443 example.com`
   - Look for exposed sensitive files.
4. Use OWASP ZAP:
   - Check for sensitive file alerts.

**Example Vulnerable Configuration**:
```bash
-rw-r--r-- 1 www-data www-data 123 May 27 2025 .htpasswd
```
Result: Readable by all users.

**Example Secure Configuration**:
```bash
-rw-r----- 1 www-data www-data 123 May 27 2025 .htpasswd
```
Result: Restricted to owner and group.

**Remediation**:
- Restrict permissions:  
  `chmod 640 /var/www/html/.htpasswd`
- Protect sensitive files (Apache):  
  ```apache
  <Files ".ht*">
      Require all denied
  </Files>
  ```
- Protect in Nginx:  
  ```nginx
  location ~ /\.ht {
      deny all;
  }
  ```
- Verify Apache configuration:  
  `grep -i ht /etc/apache2/sites-enabled/*.conf`
- Verify Nginx configuration:  
  `nginx -T | grep -i \.ht`

**Tip**: Save sensitive file permission evidence in a report.

### 3. Test Directory Listing

**Objective**: Ensure directory listing is disabled to prevent exposure of file structures.

**Steps**:
1. Use cURL (black-box):
   - Run:  
     `curl -s https://example.com/uploads/`
   - **Example Vulnerable Output**:  
     ```html
     <html><body><a href="file1.pdf">file1.pdf</a></body></html>
     ```
   - **Example Secure Output**:  
     ```text
     [403 Forbidden or empty response]
     ```
2. Use Burp Suite:
   - Test directory access.
3. Use OWASP ZAP:
   - Check for directory listing alerts under **Alerts > Directory Browsing**.
4. Check server config (gray-box):
   - Run:  
     `grep -i Options /etc/apache2/sites-enabled/*.conf`

**Example Vulnerable Configuration**:
```apache
Options +Indexes
```
Result: Directory listing enabled.

**Example Secure Configuration**:
```apache
Options -Indexes
```
Result: Directory listing disabled.

**Remediation**:
- Disable directory listing (Apache):  
  ```apache
  Options -Indexes
  ```
- Disable in Nginx:  
  ```nginx
  autoindex off;
  ```
- Verify Apache configuration:  
  `grep -i Indexes /etc/apache2/sites-enabled/*.conf`
- Verify Nginx configuration:  
  `nginx -T | grep -i autoindex`

**Tip**: Save directory listing evidence in a report.

### 4. Ensure Proper Ownership

**Objective**: Ensure files and directories are owned by the appropriate user (e.g., web server user).

**Steps**:
1. Check ownership (gray-box):
   - Run:  
     `stat /var/www/html/config.php`
   - Alternative:  
     `ls -l /var/www/html/`
   - **Example Vulnerable Output (stat)**:  
     ```text
     File: /var/www/html/config.php
     Access: (0644/-rw-r--r--)  Uid: (0/root)   Gid: (0/root)
     ```
   - **Example Secure Output (stat)**:  
     ```text
     File: /var/www/html/config.php
     Access: (0640/-rw-r-----)  Uid: (33/www-data)   Gid: (33/www-data)
     ```
2. Use cURL (black-box):
   - Test access to files owned by incorrect users.
3. Use Burp Suite:
   - Verify access restrictions.
4. Use Nmap:
   - Identify exposed files with incorrect ownership.

**Example Vulnerable Configuration**:
```bash
-rw-r--r-- 1 root root 123 May 27 2025 config.php
```
Result: Owned by root, accessible to others.

**Example Secure Configuration**:
```bash
-rw-r----- 1 www-data www-data 123 May 27 2025 config.php
```
Result: Owned by web server user.

**Remediation**:
- Set correct ownership:  
  `chown www-data:www-data /var/www/html/config.php`
- Verify web server user:  
  `ps aux | egrep '(apache|nginx)'`
- Verify Apache configuration:  
  `ps aux | grep apache`
- Verify Nginx configuration:  
  `ps aux | grep nginx`

**Tip**: Save ownership evidence in a report.

### 5. Validate Access Controls

**Objective**: Ensure server access controls restrict unauthorized file access.

**Steps**:
1. Use cURL (black-box):
   - Run:  
     `curl -I https://example.com/private/secret.txt`
   - **Example Vulnerable Output**:  
     ```text
     HTTP/1.1 200 OK
     ```
   - **Example Secure Output**:  
     ```text
     HTTP/1.1 403 Forbidden
     ```
2. Check access controls (gray-box):
   - Run:  
     `cat /etc/apache2/sites-enabled/000-default.conf`
   - Look for `Require` directives.
3. Use Burp Suite:
   - Test access with unauthorized credentials.
4. Use OWASP ZAP:
   - Check for access control alerts.

**Example Vulnerable Configuration**:
```apache
<Directory /var/www/html/private>
    Require all granted
</Directory>
```
Result: Unrestricted access.

**Example Secure Configuration**:
```apache
<Directory /var/www/html/private>
    Require ip 192.168.1.0/24
</Directory>
```
Result: Restricted to specific IPs.

**Remediation**:
- Restrict access (Apache):  
  ```apache
  <Directory /var/www/html/private>
      Require ip 192.168.1.0/24
  </Directory>
  ```
- Restrict in Nginx:  
  ```nginx
  location /private/ {
      allow 192.168.1.0/24;
      deny all;
  }
  ```
- Verify Apache configuration:  
  `grep -i Require /etc/apache2/sites-enabled/*.conf`
- Verify Nginx configuration:  
  `nginx -T | grep -i allow`

**Tip**: Save access control evidence in a report.

### 6. Automated File Permission and Exposure Testing

**Objective**: Use an automated script to test file permissions, sensitive file exposure, directory listing, and web server misconfigurations.

**Steps**:
1. Save the following script as `file_permission_test.sh`:
   ```bash
   #!/bin/bash

   # Usage: ./file_permission_test.sh https://example.com /var/www/html

   TARGET_URL=$1
   LOCAL_PATH=$2

   if [[ -z "$TARGET_URL" || -z "$LOCAL_PATH" ]]; then
     echo "Usage: $0 <target_url> <local_path_for_graybox_checks>"
     exit 1
   fi

   # Check for required tools
   command -v curl >/dev/null 2>&1 || { echo >&2 "curl not found"; exit 1; }
   command -v nmap >/dev/null 2>&1 || { echo >&2 "nmap not found"; exit 1; }
   command -v nikto >/dev/null 2>&1 || { echo >&2 "nikto not found"; exit 1; }

   LOG_DIR="./scan_results_$(date +%Y%m%d_%H%M%S)"
   mkdir -p "$LOG_DIR"

   echo "[*] Starting automated file permission testing on $TARGET_URL"
   echo "[*] Results will be saved in $LOG_DIR"

   ### 1. Check for world-readable/writable files using gray-box (local) access
   echo "[*] Checking world-readable/writable files on local path $LOCAL_PATH..."
   find "$LOCAL_PATH" -perm -o+r -o -perm -o+w > "$LOG_DIR/world_readable_writable.txt"
   echo "[*] Results saved: $LOG_DIR/world_readable_writable.txt"

   ### 2. Use curl to check access to common sensitive files (black-box)
   SENSITIVE_FILES=("config.php" ".htaccess" ".htpasswd" "backup.sql" "error.log")

   for file in "${SENSITIVE_FILES[@]}"; do
     echo "[*] Checking access to $file via HTTP..."
     curl -s -I "$TARGET_URL/$file" >> "$LOG_DIR/curl_sensitive_files.txt"
   done
   echo "[*] HTTP header responses for sensitive files saved in $LOG_DIR/curl_sensitive_files.txt"

   ### 3. Nmap HTTP enumeration script to find accessible files/directories
   echo "[*] Running nmap http-enum script on $TARGET_URL..."
   nmap --script http-enum -p 80,443 "$(echo "$TARGET_URL" | sed -E 's~https?://([^/]+).*~\1~')" -oN "$LOG_DIR/nmap_http_enum.txt"

   ### 4. Run Nikto scan on the target URL
   echo "[*] Running Nikto scan..."
   nikto -h "$TARGET_URL" --ssl -output "$LOG_DIR/nikto_scan.txt"

   ### 5. Check directory listing for /uploads/ (example directory)
   echo "[*] Testing directory listing on /uploads/ ..."
   curl -s "$TARGET_URL/uploads/" > "$LOG_DIR/uploads_dir_listing.html"

   ### Summary output
   echo "-------------------------------------------"
   echo "Scan completed. Results saved to $LOG_DIR"
   echo "- World-readable/writable files: $LOG_DIR/world_readable_writable.txt"
   echo "- Sensitive files HTTP header check: $LOG_DIR/curl_sensitive_files.txt"
   echo "- Nmap HTTP enum: $LOG_DIR/nmap_http_enum.txt"
   echo "- Nikto scan: $LOG_DIR/nikto_scan.txt"
   echo "- Directory listing HTML for /uploads/: $LOG_DIR/uploads_dir_listing.html"
   echo "-------------------------------------------"
   ```
2. Set executable permissions:  
   `chmod +x file_permission_test.sh`
3. Run the script:
   - Example:  
     `./file_permission_test.sh https://example.com /var/www/html`
   - **Example Vulnerable Output** (in `world_readable_writable.txt`):  
     ```text
     /var/www/html/config.php
     ```
   - **Example Vulnerable Output** (in `curl_sensitive_files.txt`):  
     ```text
     HTTP/1.1 200 OK
     ```
   - **Example Secure Output** (in `curl_sensitive_files.txt`):  
     ```text
     HTTP/1.1 403 Forbidden
     ```
4. Review results in the timestamped directory (e.g., `scan_results_20250527_1137`).
5. Use OWASP ZAP to validate findings:
   - Run:  
     `zap-cli quick-scan https://example.com`
   - For passive/active file exposure detection, run OWASP ZAP with HUD or script mode. Consider using the ZAP Python API for deeper integration.

**How the Script Works**:
- **Inputs**: Takes a target URL (for black-box HTTP tests) and a local path (for gray-box file permission checks).
- **Checks**:
  - Uses `find` to detect world-readable/writable files on the server filesystem (gray-box).
  - Uses `curl` to test HTTP access to common sensitive files, including `.htpasswd` (black-box).
  - Runs `nmap`’s `http-enum` script to detect files/directories.
  - Runs `nikto` scan with `--ssl` for HTTPS targets to reduce false positives.
  - Tests directory listing on `/uploads/` with `curl`.
- **Output**: Saves results in a timestamped directory for reporting.
- **Requirements**:
  - `curl`, `nmap`, `nikto` installed and in PATH.
  - Gray-box access to the web root directory for permission checking.
  - Run as a user with permission to read the target directory (for `find`).

**Example Vulnerable Results**:
- `world_readable_writable.txt`:  
  ```text
  /var/www/html/config.php
  ```
- `curl_sensitive_files.txt`:  
  ```text
  HTTP/1.1 200 OK
  ```

**Example Secure Results**:
- `world_readable_writable.txt`:  
  ```text
  [Empty file]
  ```
- `curl_sensitive_files.txt`:  
  ```text
  HTTP/1.1 403 Forbidden
  ```

**Remediation**:
- Fix permissions:  
  `chmod 640 /var/www/html/config.php`  
  `chmod 640 /var/www/html/.htpasswd`
- Set ownership:  
  `chown www-data:www-data /var/www/html/config.php`
- Disable directory listing (Apache):  
  ```apache
  Options -Indexes
  ```
- Protect sensitive files (Nginx):  
  ```nginx
  location ~ \.(php|sql|log|htpasswd)$ {
      deny all;
  }
  ```
- Verify Apache configuration:  
  `grep -i Indexes /etc/apache2/sites-enabled/*.conf`
- Verify Nginx configuration:  
  `nginx -T | grep -i deny`

**Tip**: Save script output and logs in a report.