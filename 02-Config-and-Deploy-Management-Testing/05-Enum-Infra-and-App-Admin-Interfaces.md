# Enumerate Infrastructure and Application Admin Interfaces

## Overview

Enumerating infrastructure and application admin interfaces involves identifying hidden or unprotected administrative pages and interfaces that are not directly accessible via the normal user interface. According to OWASP (WSTG-CONF-05), unprotected admin interfaces can allow attackers to gain unauthorized access to sensitive functionality, such as user management, configuration settings, or system controls, leading to full system compromise. This guide provides a hands-on methodology to test for admin interface exposure, covering identification, access testing, credential brute-forcing, parameter tampering, and configuration review, with tools, commands, payloads, and remediation strategies.

**Impact**: Exposed admin interfaces can lead to:
- Unauthorized access to sensitive data (e.g., user databases, configuration files).
- Privilege escalation to administrative roles.
- Execution of malicious actions (e.g., adding users, modifying settings).
- System compromise or data breaches.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

This guide aligns with OWASP’s WSTG-CONF-05, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as enumerating admin interfaces may trigger security alerts, access sensitive systems, or disrupt application functionality, potentially causing significant harm.

## Testing Tools

The following tools are recommended for enumerating admin interfaces, with setup instructions optimized for new pentesters:

- **OWASP ZAP 3.2**: Open-source web application scanner for forced browsing and enumeration.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Head-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Spider or Active Scan to discover hidden paths.

- **THC-Hydra**: Brute-forcing tool for HTTP authentication.
  - Install on Linux:
    ```bash
    sudo apt install hydra
    ```
  - Install on Windows/Mac: Download from [THC](https://github.com/vanhauser-thc/thc-hydra).
  - Example:
    ```bash
    hydra -l admin -P passwords.txt http-get-form <target_url>
    ```

- **DirBuster**: Directory and file brute-forcing tool.
  - Download from [OWASP](https://sourceforge.net/projects/dirbuster/).
  - Configure target URL and wordlist (e.g., `/usr/share/dirb/wordlists/common.txt`).
  - Example:
    ```bash
    dirb http://example.com /usr/share/dirb/wordlists/common.txt
    ```

- **Burp Suite Community Edition**: Web application security testing suite.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Use Intruder for fuzzing and Repeater for manual testing.

- **Netsparker Dictionary**: Brute-force tool for authentication pages (assumed as a wordlist for tools like Hydra).
  - Use with Hydra or Burp Intruder.
  - Example wordlist: `/usr/share/wordlists/rockyou.txt`.

- **Google Dorks**: Search engine queries for discovering admin interfaces.
  - Access: [Google](https://www.google.com).
  - Example:
    ```text
    site:example.com inurl:(admin | login | dashboard)
    ```

- **Wget**: Command-line utility for scraping directories.
  - Install on Linux:
    ```bash
    sudo apt install wget
    ```
  - Example:
    ```bash
    wget --spider -r http://example.com
    ```

- **cURL**: Command-line tool for testing file access.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Example:
    ```bash
    curl -I http://example.com/admin/login.php
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-05, testing for admin interface exposure through brute-forcing, source code review, access testing, credential brute-forcing, parameter tampering, and configuration analysis.

### Common Admin Interface Paths and Payloads

Below is a list of common paths and payloads to test for admin interfaces. Start with common paths and escalate based on application behavior. Use with caution in controlled environments to avoid unauthorized access.

- **Common Admin Paths**:
  - `/admin`, `/administrator`, `/admin/login.php`, `/admin-panel`
  - `/wp-admin/` (WordPress), `/phpmyadmin/` (PHP)
  - `/admin-authz.xml`, `/admin.conf` (WebSphere)
  - `/admin.dll`, `/author.exe` (FrontPage)
  - `/AdminMain`, `/AdminJDBC` (WebLogic)

- **Brute-Force Payloads**:
  - Extensions: `.php`, `.asp`, `.aspx`, `.jsp`
  - Files: `login.php`, `dashboard.asp`, `control.aspx`, `settings.jsp`
  - Paths: `/admin/`, `/manage/`, `/controlpanel/`, `/sysadmin/`

- **Parameter Tampering Payloads**:
  - `user=admin`, `role=administrator`, `access=1`
  - `id=1`, `is_admin=true`, `level=admin`

- **Credential Brute-Force Payloads**:
  - Username: `admin`, `administrator`, `root`, `superuser`
  - Password: `admin`, `password`, `123456`, `admin123`

**Note**: Paths and payloads depend on the application framework (e.g., WordPress, WebLogic) and server configuration (e.g., Apache, Nginx). Test paths in URLs, forms, or API endpoints where admin interfaces may reside.

### 1. Identify Hidden Admin Interfaces

**Objective**: Discover potential hidden administrative pages and interfaces.

**Steps**:
1. Brute-force directories and files:
   - Use DirBuster:
     ```bash
     dirb http://example.com /usr/share/dirb/wordlists/common.txt -X .php,.asp,.aspx,.jsp
     ```
   - Test paths: `/admin`, `/wp-admin`, `/phpmyadmin`.
2. Use OWASP ZAP:
   - Run Spider or Active Scan to identify hidden paths.
   - Check for: `/admin/login.php`, `/administrator`.
3. Search source code:
   - Open page: `http://example.com`.
   - Press `Ctrl+U` to view source.
   - Search for: `admin`, `login`, `dashboard`.
   - Example:
     ```html
     <a href="/admin/login.php">Admin Login</a>
     ```
4. Use Google Dorks:
   - Query: `site:example.com inurl:(admin | login | dashboard)`.

**Example Vulnerable Response**:
```text
Found: /admin/login.php
```
Test: `http://example.com/admin/login.php`
Result: Admin login page exposed.

**Example Secure Response**:
```text
HTTP/1.1 404 Not Found
```
Test: No admin paths found.

**Remediation**:
- Restrict access:
  ```apache
  <Location "/admin">
      Order deny,allow
      Deny from all
      Allow from 192.168.1.0/24
  </Location>
  ```
- Remove comments:
  ```html
  <!-- Remove: <a href="/admin/login.php"> -->
  ```

**Tip**: Save discovered paths in a report.

### 2. Check for Exposure of Admin Interfaces

**Objective**: Ensure admin interfaces are not publicly accessible.

**Steps**:
1. Test access with cURL:
   - Use:
     ```bash
     curl -I http://example.com/admin/login.php
     ```
   - Check for: `HTTP/1.1 403 Forbidden`.
2. Test alternative ports:
   - Use:
     ```bash
     curl -I http://example.com:8080/admin/login.php
     ```
   - Check for: `HTTP/1.1 403 Forbidden`.
3. Use Burp Suite:
   - Intercept request to `/admin`.
   - Verify response code.
4. Test subdirectories:
   - Try: `/admin-panel`, `/manage`.

**Example Vulnerable Code (Apache)**:
```apache
<Directory "/admin">
    Allow from all
</Directory>
```
Test: `curl http://example.com/admin`
Result: `HTTP/1.1 200 OK`.

**Example Secure Code (Apache)**:
```apache
<Directory "/admin">
    Deny from all
    Allow from 192.168.1.0/24
</Directory>
```
Test: `HTTP/1.1 403 Forbidden`.

**Remediation**:
- Use IP filtering:
  ```nginx
  location /admin {
      allow 192.168.1.0/24;
      deny all;
  }
  ```
- Require authentication:
  ```apache
  <Location "/admin">
      AuthType Basic
      AuthUserFile /etc/htpasswd
      Require valid-user
  </Location>
  ```

**Tip**: Save exposure evidence in a report.

### 3. Review Default or Unchanged Credentials

**Objective**: Check if admin interfaces use default or weak credentials.

**Steps**:
1. Brute-force with THC-Hydra:
   - Use:
     ```bash
     hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get-form "http://example.com/admin/login.php:username=^USER^&password=^PASS^:F=incorrect"
     ```
   - Test credentials: `admin:admin`, `admin:password`.
2. Use Burp Intruder:
   - Set payload: Username=`admin`, Password=`rockyou.txt`.
   - Check for: `HTTP/1.1 200 OK`.
3. Check documentation:
   - Look for default credentials (e.g., `admin:admin` for phpMyAdmin).

**Example Vulnerable Response**:
```text
[80][http-get-form] host: example.com login: admin password: password123
```
Result: Access granted.

**Example Secure Response**:
```text
No valid credentials found
```
Result: Brute-force fails.

**Remediation**:
- Enforce strong passwords:
  ```bash
  passwd admin
  ```
- Lock accounts:
  ```bash
  usermod -L admin
  ```

**Tip**: Save credential findings in a report.

### 4. Verify Protection Against Parameter Tampering

**Objective**: Ensure admin functionality cannot be accessed via parameter manipulation.

**Steps**:
1. Manipulate parameters with Burp Suite:
   - Original: `http://example.com/dashboard?user=normal`
   - Modify: `user=admin`.
   - Use Repeater to send request.
2. Test POST parameters:
   - Original: `user=normal&role=user`
   - Modify: `role=admin`.
   - Use:
     ```http
     POST /dashboard HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded

     user=normal&role=admin
     ```
3. Check responses:
   - Look for: `HTTP/1.1 403 Forbidden`.
4. Test cookies:
   - Modify: `role=admin` in cookie.

**Example Vulnerable Code (PHP)**:
```php
if ($_GET['user'] === 'admin') {
    grantAdminAccess();
}
```
Test: `?user=admin`
Result: Admin access granted.

**Example Secure Code (PHP)**:
```php
if (checkUserRole($_SESSION['user_id']) === 'admin') {
    grantAdminAccess();
}
```
Test: Ignores `user=admin`.

**Remediation**:
- Validate parameters:
  ```php
  if (!in_array($_GET['role'], ['user', 'guest'])) die("Invalid role");
  ```
- Use session-based checks:
  ```php
  if ($_SESSION['role'] !== 'admin') die("Unauthorized");
  ```

**Tip**: Save tampering evidence in a report.

### 5. Review Server and Application Configuration

**Objective**: Ensure server and application hardening to prevent unauthorized access.

**Steps**:
1. Review documentation:
   - Use Wget:
     ```bash
     wget http://example.com/docs/readme.txt
     ```
   - Check for: `/admin`, `/phpMyAdmin`.
2. Check server configuration:
   - Use Burp Suite to identify headers.
   - Look for: `Server: Apache/2.4.38`.
3. Test IP filtering:
   - Use cURL from unauthorized IP:
     ```bash
     curl -I http://example.com/admin
     ```
   - Check for: `HTTP/1.1 403 Forbidden`.
4. Verify `.htaccess`:
   - Example:
     ```apache
     <Files "/admin/*">
         Order Deny,Allow
         Deny from all
         Allow from 192.168.1.0/24
     </Files>
     ```

**Example Vulnerable Code (Nginx)**:
```nginx
location /admin {
    allow all;
}
```
Test: `curl http://example.com/admin`
Result: `HTTP/1.1 200 OK`.

**Example Secure Code (Nginx)**:
```nginx
location /admin {
    allow 192.168.1.0/24;
    deny all;
}
```
Test: `HTTP/1.1 403 Forbidden`.

**Remediation**:
- Harden server:
  ```bash
  chmod 640 /etc/nginx/nginx.conf
  ```
- Audit configurations:
  ```bash
  find /etc -name "*.conf" -exec grep -i admin {} \;
  ```

**Tip**: Save configuration findings in a report.