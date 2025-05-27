# Test RIA Cross Domain Policy

## Overview

Testing RIA (Rich Internet Application) cross-domain policy files involves verifying that policy files like `crossdomain.xml` (used by Adobe Flash) and `clientaccesspolicy.xml` (used by Microsoft Silverlight) are securely configured to prevent unauthorized cross-origin access. According to OWASP (WSTG-CONF-08), overly permissive policy files can allow attackers to access sensitive data, execute malicious scripts, or bypass security controls across domains. This guide provides a hands-on methodology to test RIA cross-domain policies, covering policy file presence, permissive configurations, domain restrictions, protocol usage, and file permissions, with tools, commands, payloads, and remediation strategies.

**Impact**: Insecure RIA cross-domain policies can lead to:
- Unauthorized access to sensitive data (e.g., user sessions, API responses) from untrusted domains.
- Cross-site scripting (XSS) or data theft via malicious Flash/Silverlight content.
- Bypassing same-origin policy (SOP) restrictions.
- Increased attack surface for cross-origin attacks.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

**Note**: Flash and Silverlight are deprecated in modern browsers, but legacy enterprise systems may still use them. Always validate exposure in older apps and services to ensure no residual risks from outdated RIA technologies.

This guide aligns with OWASP’s WSTG-CONF-08, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as probing policy files may trigger security alerts, access sensitive configurations, or disrupt application functionality, potentially affecting user experience.

## Testing Tools

The following tools are recommended for testing RIA cross-domain policies, with setup instructions optimized for new pentesters:

- **cURL**: Command-line tool for retrieving policy files and headers.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Download from [cURL](https://curl.se/download.html).
  - Example:
    ```bash
    curl https://example.com/crossdomain.xml
    ```

- **Wget**: Command-line utility for downloading policy files.
  - Install on Linux:
    ```bash
    sudo apt install wget
    ```
  - Example:
    ```bash
    wget https://example.com/clientaccesspolicy.xml
    ```

- **Burp Suite Community Edition**: Intercepting proxy for inspecting policy file responses.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Use Repeater to analyze responses.

- **OWASP ZAP 3.2**: Open-source web application security scanner.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD:
    1. Go to Tools > Options > HUD.
    2. Enable HUD for real-time browser inspection.
  - Use Active Scan to detect policy files.

- **SecurityHeaders.com**: Online tool for scanning headers and policy file configurations.
  - Access: [SecurityHeaders.com](https://securityheaders.com/).
  - Enter domain and review policy file presence.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-08, testing RIA cross-domain policy files through file discovery, content analysis, domain validation, protocol checks, and permission audits.

### Common RIA Policy Files and Payloads

Below is a list of common RIA policy files and payloads to test for vulnerabilities. Use with caution to avoid disrupting production environments.

- **Policy Files**:
  - `crossdomain.xml`: Adobe Flash cross-domain policy file.
  - `clientaccesspolicy.xml`: Microsoft Silverlight cross-domain policy file.
  - Common paths: `/crossdomain.xml`, `/clientaccesspolicy.xml`.

- **Test Payloads**:
  - Retrieve policy files:
    ```bash
    curl https://example.com/crossdomain.xml
    ```
  - Check for permissive settings:
    ```xml
    <allow-access-from domain="*" />
    ```
  - Test domain restrictions:
    ```xml
    <allow-access-from domain="trusted.com" />
    ```
  - Verify secure protocols:
    ```xml
    <allow-access-from domain="*" secure="true" />
    ```

**Note**: Policy file behavior depends on the application framework (e.g., Flash, Silverlight) and server configuration (e.g., Apache, Nginx). Test files at the root domain and subdirectories to ensure comprehensive coverage.

### 1. Verify the Presence of Policy Files

**Objective**: Ensure RIA policy files (`crossdomain.xml`, `clientaccesspolicy.xml`) are present only when necessary and check for modern CSP protections.

**Steps**:
1. Use cURL to check policy files:
   - Run:
     ```bash
     curl -s https://example.com/crossdomain.xml
     ```
   - **Example Vulnerable Output**:
     ```xml
     <?xml version="1.0"?>
     <cross-domain-policy>
         <allow-access-from domain="*" />
     </cross-domain-policy>
     ```
   - **Example Secure Output**:
     ```text
     [404 Not Found or empty response]
     ```
2. Use cURL to check CSP headers:
   - Run:
     ```bash
     curl -I https://example.com | grep -i content-security-policy
     ```
   - **Example Vulnerable Output**:
     ```text
     [No Content-Security-Policy header]
     ```
   - **Example Secure Output**:
     ```text
     Content-Security-Policy: object-src 'none'; frame-ancestors 'self'
     ```
3. Use Wget:
   - Run:
     ```bash
     wget https://example.com/clientaccesspolicy.xml
     ```
   - Check for file existence.
4. Use Burp Suite:
   - Intercept requests to `/crossdomain.xml`.
   - Verify response content and CSP headers.
5. Use OWASP ZAP:
   - Run Active Scan.
   - Check for policy file alerts under **Alerts > Cross Domain Policy File**.

**Example Vulnerable Response**:
```xml
<cross-domain-policy>
    <allow-access-from domain="*" />
</cross-domain-policy>
```
Result: Policy file allows unrestricted access, no CSP protection.

**Example Secure Response**:
```text
HTTP/1.1 404 Not Found
Content-Security-Policy: object-src 'none'; frame-ancestors 'self'
```
Result: No policy file, CSP restricts RIA content.

**Remediation**:
- Remove unnecessary policy files:
  ```bash
  rm /var/www/html/crossdomain.xml
  ```
- Implement CSP (Apache):
  ```apache
  Header set Content-Security-Policy "object-src 'none'; frame-ancestors 'self'"
  ```
- Implement CSP in Nginx:
  ```nginx
  add_header Content-Security-Policy "object-src 'none'; frame-ancestors 'self'" always;
  ```
- Restrict policy file access (Apache):
  ```apache
  <Files "crossdomain.xml">
      Require all denied
  </Files>
  ```
- Restrict in Nginx:
  ```nginx
  location /crossdomain.xml {
      deny all;
  }
  ```
- Verify Apache configuration:
  ```bash
  apachectl -t -D DUMP_MODULES | grep access
  grep -i crossdomain /etc/apache2/sites-enabled/*.conf
  grep -i content-security-policy /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i crossdomain
  nginx -T | grep -i content-security-policy
  ```

**Tip**: Save policy file and CSP header evidence in a report.

### 2. Check for Permissive Policies

**Objective**: Ensure policy files do not allow unrestricted access (e.g., `domain="*"`).

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -s https://example.com/crossdomain.xml | grep -i allow-access-from
     ```
   - **Example Vulnerable Output**:
     ```xml
     <allow-access-from domain="*" />
     ```
   - **Example Secure Output**:
     ```xml
     <allow-access-from domain="trusted.com" />
     ```
2. Use Burp Suite:
   - Inspect policy file content.
   - Check for `domain="*"`.
3. Use OWASP ZAP:
   - Run Active Scan.
   - Check for permissive policy alerts.
4. Use SecurityHeaders.com:
   - Scan domain and review policy file restrictions.

**Example Vulnerable Policy**:
```xml
<?xml version="1.0"?>
<cross-domain-policy>
    <allow-access-from domain="*" />
</cross-domain-policy>
```
Result: Allows access from any domain.

**Example Secure Policy**:
```xml
<?xml version="1.0"?>
<cross-domain-policy>
    <allow-access-from domain="api.trusted.com" />
</cross-domain-policy>
```
Result: Restricts access to specific domains.

**Remediation**:
- Restrict domains:
  ```xml
  <cross-domain-policy>
      <allow-access-from domain="api.trusted.com" />
  </cross-domain-policy>
  ```
- Update policy file:
  ```bash
  nano /var/www/html/crossdomain.xml
  ```
- Verify Apache configuration:
  ```bash
  grep -i crossdomain /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i crossdomain
  ```

**Tip**: Save permissive policy evidence in a report.

### 3. Test Domain Restrictions

**Objective**: Ensure policy files restrict access to trusted domains only.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -s https://example.com/crossdomain.xml
     ```
   - **Example Vulnerable Output**:
     ```xml
     <allow-access-from domain="*.example.com" />
     ```
   - **Example Secure Output**:
     ```xml
     <allow-access-from domain="api.example.com" />
     ```
2. Test untrusted domains:
   - Attempt access from an untrusted domain (gray-box):
     ```javascript
     // Flash test script
     Security.allowDomain("malicious.com");
     ```
   - Check for access denial.
3. Use Burp Suite:
   - Modify request to test domain restrictions.
4. Use OWASP ZAP:
   - Check for wildcard domain alerts.

**Example Vulnerable Policy**:
```xml
<allow-access-from domain="*.example.com" />
```
Result: Allows access from all subdomains, increasing risk.

**Example Secure Policy**:
```xml
<allow-access-from domain="api.example.com" />
```
Result: Restricts to specific subdomain.

**Remediation**:
- Specify exact domains:
  ```xml
  <allow-access-from domain="api.example.com" />
  ```
- Avoid wildcards:
  ```xml
  <allow-access-from domain="specific.trusted.com" />
  ```
- Verify Apache configuration:
  ```bash
  grep -i crossdomain /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i crossdomain
  ```

**Tip**: Save domain restriction evidence in a report.

### 4. Ensure Secure Protocol Usage

**Objective**: Ensure policy files enforce secure protocols (HTTPS) for cross-domain access.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -s https://example.com/crossdomain.xml | grep -i secure
     ```
   - **Example Vulnerable Output**:
     ```xml
     <allow-access-from domain="api.example.com" />
     ```
   - **Example Secure Output**:
     ```xml
     <allow-access-from domain="api.example.com" secure="true" />
     ```
2. Test HTTP access:
   - Run:
     ```bash
     curl -s http://example.com/crossdomain.xml
     ```
   - Expect: `403 Forbidden` or redirect to HTTPS.
3. Use Burp Suite:
   - Check for `secure="true"` attribute.
4. Use SecurityHeaders.com:
   - Verify HTTPS enforcement for policy files.

**Example Vulnerable Policy**:
```xml
<allow-access-from domain="api.example.com" />
```
Result: Allows HTTP connections.

**Example Secure Policy**:
```xml
<allow-access-from domain="api.example.com" secure="true" />
```
Result: Enforces HTTPS connections.

**Remediation**:
- Enforce secure attribute:
  ```xml
  <allow-access-from domain="api.example.com" secure="true" />
  ```
- Redirect HTTP to HTTPS (Apache):
  ```apache
  <VirtualHost *:80>
      ServerName example.com
      Redirect permanent / https://example.com/
  </VirtualHost>
  ```
- Redirect in Nginx:
  ```nginx
  server {
      listen 80;
      server_name example.com;
      return 301 https://$host$request_uri;
  }
  ```
- Verify Apache configuration:
  ```bash
  apachectl -t -D DUMP_MODULES | grep headers
  grep -i redirect /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i return.*301
  ```

**Tip**: Save secure protocol evidence in a report.

### 5. Validate Policy File Permissions

**Objective**: Ensure policy files have restrictive permissions to prevent unauthorized access or modification.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -I https://example.com/crossdomain.xml
     ```
   - **Example Vulnerable Output**:
     ```text
     HTTP/1.1 200 OK
     ```
   - **Example Secure Output**:
     ```text
     HTTP/1.1 403 Forbidden
     ```
2. Check file permissions (gray-box):
   - Run:
     ```bash
     ls -l /var/www/html/crossdomain.xml
     ```
   - Expect: `rw-r-----` (640) or stricter.
3. Use Burp Suite:
   - Test access to policy files with unauthorized credentials.
4. Use OWASP ZAP:
   - Check for accessible policy file alerts.

**Example Vulnerable Configuration**:
```bash
-rw-rw-rw- 1 www-data www-data 123 May 27 2025 crossdomain.xml
```
Result: World-readable/writable file.

**Example Secure Configuration**:
```bash
-rw-r----- 1 www-data www-data 123 May 27 2025 crossdomain.xml
```
Result: Restricted permissions.

**Remediation**:
- Set restrictive permissions:
  ```bash
  chmod 640 /var/www/html/crossdomain.xml
  chown www-data:www-data /var/www/html/crossdomain.xml
  ```
- Restrict access (Apache):
  ```apache
  <Files "crossdomain.xml">
      Require all denied
  </Files>
  ```
- Restrict in Nginx:
  ```nginx
  location /crossdomain.xml {
      deny all;
  }
  ```
- Verify Apache configuration:
  ```bash
  grep -i crossdomain /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i crossdomain
  ```

**Tip**: Save permission evidence in a report.