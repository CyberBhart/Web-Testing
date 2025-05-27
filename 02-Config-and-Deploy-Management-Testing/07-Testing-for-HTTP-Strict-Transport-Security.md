# Test HTTP Strict Transport Security (HSTS)

## Overview

Testing HTTP Strict Transport Security (HSTS) involves verifying that a web server correctly implements the HSTS header to enforce HTTPS connections, preventing unencrypted HTTP traffic and mitigating man-in-the-middle (MITM) attacks. According to OWASP (WSTG-CONF-07), improper HSTS configurations can allow attackers to downgrade connections to HTTP, intercept sensitive data, or exploit vulnerabilities like SSL stripping. This guide provides a hands-on methodology to test HSTS, covering header presence, max-age directive, includeSubDomains directive, preload status, and HTTPS redirection, with tools, commands, payloads, and remediation strategies.

**Impact**: Insecure HSTS configurations can lead to:
- Exposure of sensitive data (e.g., passwords, cookies) via HTTP interception.
- Successful MITM attacks through SSL stripping or downgrade attacks.
- Bypassing HTTPS on subdomains if includeSubDomains is missing.
- Increased vulnerability during initial connections if preload is not used.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

This guide aligns with OWASP’s WSTG-CONF-07, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as probing HSTS configurations may trigger security alerts or disrupt application functionality, potentially affecting user experience.

## Testing Tools

The following tools are recommended for testing HSTS, with setup instructions optimized for new pentesters:

- **cURL**: Command-line tool for inspecting HTTP headers.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Download from [cURL](https://curl.se/download.html).
  - Example:
    ```bash
    curl -s -D- https://example.com
    ```

- **Burp Suite Community Edition**: Intercepting proxy for inspecting HTTP responses.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Use Repeater to analyze headers.

- **OWASP ZAP 3.2**: Open-source web application security scanner.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD:
    1. Go to Tools > Options > HUD.
    2. Enable HUD for real-time browser inspection.
  - Use Passive Scan to check headers. HSTS alerts appear under **Alerts > Strict-Transport-Security Header Not Set** in the Passive Scan results.

- **SSL Labs Server Test**: Online tool for analyzing HSTS and TLS configurations.
  - Access: [SSL Labs](https://www.ssllabs.com/ssltest/).
  - Enter domain and review HSTS results.

- **SecurityHeaders.com**: Online tool for quick header scanning, including HSTS.
  - Access: [SecurityHeaders.com](https://securityheaders.com/).
  - Enter domain and review HSTS configuration.
  - Example: Check for `Strict-Transport-Security` presence and directives.

- **testssl.sh**: CLI tool for advanced TLS/SSL analysis, including HSTS (for advanced users).
  - Install on Linux:
    ```bash
    git clone https://github.com/drwetter/testssl.sh.git
    cd testssl.sh
    chmod +x testssl.sh
    ```
  - Example:
    ```bash
    ./testssl.sh --headers example.com
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-07, testing HSTS implementation through header inspection, directive validation, and redirection enforcement.

### Common HSTS Headers and Payloads

Below is a list of HSTS headers and payloads to test for correct configuration. Use with caution to avoid disrupting production environments.

- **HSTS Header**:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - Directives:
    - `max-age`: Duration (in seconds) for HSTS enforcement.
    - `includeSubDomains`: Applies HSTS to all subdomains.
    - `preload`: Opts into browser preload lists.

- **Test Payloads**:
  - `GET / HTTP/1.1` on `https://example.com` to check headers.
  - `GET / HTTP/1.1` on `http://example.com` to verify redirection.
  - Header check: `Strict-Transport-Security` presence and values.

**Note**: HSTS behavior depends on the server (e.g., Apache, Nginx) and browser support. Test on HTTPS endpoints and verify HTTP redirects to ensure comprehensive coverage.

### 1. Verify the Presence of the HSTS Header

**Objective**: Ensure the HSTS header is present to enforce HTTPS connections.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -s -D- https://example.com | grep -i strict
     ```
   - **Example Vulnerable Output**:
     ```text
     [No Strict-Transport-Security header]
     ```
   - **Example Secure Output**:
     ```text
     Strict-Transport-Security: max-age=31536000; includeSubDomains
     ```
2. Use Burp Suite:
   - Intercept HTTPS request.
   - Verify header in response.
3. Use OWASP ZAP:
   - Run Passive Scan.
   - Check for HSTS alerts under **Alerts > Strict-Transport-Security Header Not Set** in the Passive Scan results, or use HUD for real-time inspection.
4. Use SSL Labs:
   - Analyze domain: `https://www.ssllabs.com/ssltest/analyze.html?d=example.com`.
   - Review HSTS status.
5. Use SecurityHeaders.com:
   - Scan domain and check for HSTS header presence.

**Edge Case Note**: Some servers only return HSTS on exact hostnames (e.g., no response on `www.example.com` vs. `example.com`). Ensure test URLs are consistent with production setup to avoid false negatives.

**Example Vulnerable Response**:
```text
[No Strict-Transport-Security header]
```
Result: HTTP connections allowed.

**Example Secure Response**:
```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
Result: HTTPS enforced for one year.

**Remediation**:
- Enable HSTS (Apache):
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  ```
- Enable in Nginx:
  ```nginx
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  ```
- Verify Apache configuration:
  ```bash
  # Check headers module
  apachectl -t -D DUMP_MODULES | grep headers
  # Check HSTS config
  grep -i strict /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i strict
  ```

**Tip**: Save header presence evidence in a report.

### 2. Check for the max-age Directive

**Objective**: Ensure the max-age directive is set to a valid, appropriate value.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -s -D- https://example.com | grep -i strict
     ```
   - **Example Vulnerable Output**:
     ```text
     Strict-Transport-Security: max-age=0
     ```
   - **Example Secure Output**:
     ```text
     Strict-Transport-Security: max-age=31536000
     ```
2. Use Burp Suite:
   - Inspect response headers.
   - Verify `max-age` value.
3. Test low values:
   - Look for: `max-age=0` or `max-age=300` (insecure).
4. Use SSL Labs:
   - Check max-age in HSTS section.
5. Use testssl.sh:
   - Run:
     ```bash
     ./testssl.sh --headers example.com
     ```
   - Check for HSTS max-age value.

**Security Warning**: A `max-age=0` effectively disables HSTS, often misused during debugging. Trainees should flag this as a critical misconfiguration, as it allows HTTP connections and exposes the site to MITM attacks.

**Example Short-Term Value**: For temporary testing, use `max-age=86400` (one day), but note this is not production-level secure and should be increased to at least `31536000` (one year) in production.

**Example Vulnerable Response**:
```text
Strict-Transport-Security: max-age=0
```
Result: HSTS disabled or ineffective.

**Example Secure Response**:
```text
Strict-Transport-Security: max-age=31536000
```
Result: HTTPS enforced for one year.

**Remediation**:
- Set reasonable max-age:
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000"
  ```
- Avoid low values:
  ```nginx
  add_header Strict-Transport-Security "max-age=31536000" always;
  ```
- Verify Apache configuration:
  ```bash
  apachectl -t -D DUMP_MODULES | grep headers
  grep -i strict /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i strict
  ```

**Tip**: Save max-age evidence in a report.

### 3. Verify the includeSubDomains Directive

**Objective**: Ensure the includeSubDomains directive applies HSTS to all subdomains.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -s -D- https://example.com | grep -i strict
     ```
   - **Example Vulnerable Output**:
     ```text
     Strict-Transport-Security: max-age=31536000
     ```
   - **Example Secure Output**:
     ```text
     Strict-Transport-Security: max-age=31536000; includeSubDomains
     ```
2. Test subdomain:
   - Run:
     ```bash
     curl -s -D- https://sub.example.com | grep -i strict
     ```
   - **Example Secure Output**:
     ```text
     Strict-Transport-Security: max-age=31536000; includeSubDomains
     ```
3. Use Burp Suite:
   - Compare headers for main domain and subdomains.
4. Use SSL Labs:
   - Check includeSubDomains status.
5. Use SecurityHeaders.com:
   - Scan domain and verify includeSubDomains directive.

**Clarification**: If `sub.example.com` uses a separate certificate or server, the `includeSubDomains` directive must be manually configured on that server too to ensure consistent HSTS enforcement.

**Reminder**: Browsers enforce HSTS per origin, so testing subdomains is essential to rule out bypass vulnerabilities where an attacker could target an unprotected subdomain.

**Example Vulnerable Response**:
```text
Strict-Transport-Security: max-age=31536000
```
Result: Subdomains not protected.

**Example Secure Response**:
```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
Result: Subdomains enforce HTTPS.

**Remediation**:
- Enable includeSubDomains:
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  ```
- Test subdomains:
  ```nginx
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  ```
- Verify Apache configuration:
  ```bash
  apachectl -t -D DUMP_MODULES | grep headers
  grep -i strict /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i strict
  ```

**Tip**: Save includeSubDomains evidence in a report.

### 4. Check for Preload Status

**Objective**: Ensure the site is included in the HSTS preload list for default HTTPS enforcement.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -s -D- https://example.com | grep -i preload
     ```
   - **Example Vulnerable Output**:
     ```text
     Strict-Transport-Security: max-age=31536000; includeSubDomains
     ```
   - **Example Secure Output**:
     ```text
     Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
     ```
2. Check preload list:
   - Visit: [HSTS Preload](https://hstspreload.org/?domain=example.com).
   - Verify domain inclusion.
3. Use SSL Labs:
   - Check preload eligibility and status.
4. Test first connection:
   - Clear browser cache and access `http://example.com`.
   - Expect HTTPS redirect.
   - **Browser DevTools**:
     1. Open DevTools (F12).
     2. Go to Network tab.
     3. Reload page and trace requests to confirm HTTP-to-HTTPS redirect.
5. Use testssl.sh:
   - Run:
     ```bash
     ./testssl.sh --headers example.com
     ```
   - Check for preload directive.

**Emphasis**: The `preload` flag is ineffective unless the domain is submitted to the HSTS preload list via [hstspreload.org](https://hstspreload.org/). Including the flag without submission provides no additional security.

**Footnote**: Once preloaded, removal from browser preload lists can take weeks, impacting site accessibility if HTTPS is misconfigured. Avoid using `preload` unless confident in long-term HTTPS stability.

**Example Vulnerable Response**:
```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
Result: Not in preload list, vulnerable on first visit.

**Example Secure Response**:
```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
Result: Included in preload list.

**Remediation**:
- Enable preload:
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  ```
- Submit to preload list:
  - Register at [HSTS Preload](https://hstspreload.org/).
- Verify Apache configuration:
  ```bash
  apachectl -t -D DUMP_MODULES | grep headers
  grep -i strict /etc/apache2/sites-enabled/*.conf
  ```
- Verify Nginx configuration:
  ```bash
  nginx -T | grep -i strict
  ```

**Tip**: Save preload evidence in a report.

### 5. Ensure HTTPS Redirection

**Objective**: Ensure HTTP requests are redirected to HTTPS.

**Steps**:
1. Use cURL:
   - Run:
     ```bash
     curl -I http://example.com
     ```
   - **Example Vulnerable Output**:
     ```text
     HTTP/1.1 200 OK
     Server: nginx
     ```
   - **Example Secure Output**:
     ```text
     HTTP/1.1 301 Moved Permanently
     Location: https://example.com
     ```
2. Use Burp Suite:
   - Send HTTP request.
   - Verify redirect response.
3. Test browser behavior:
   - Access `http://example.com` in a browser.
   - Expect automatic HTTPS.
   - **Browser DevTools**:
     1. Open DevTools (F12).
     2. Go to Network tab.
     3. Reload page and trace requests to confirm HTTP-to-HTTPS redirect (301 status).
4. Test subdomains:
   - Run:
     ```bash
     curl -I http://sub.example.com
     ```
   - **Example Secure Output**:
     ```text
     HTTP/1.1 301 Moved Permanently
     Location: https://sub.example.com
     ```
5. Use SecurityHeaders.com:
   - Scan domain and verify HTTPS redirection behavior.

**Note**: Although HSTS only applies after the first secure request, initial HTTP redirection ensures HSTS can be cached by browsers. This is especially critical when the `preload` directive is not used, as it protects users on their first visit.

**Misconfiguration Check**: Look for `HTTP/1.1 302 Found` redirects, as they are cacheable by browsers and can cause issues (e.g., inconsistent HTTPS enforcement). Prefer `301` for permanent redirects.

**Example Vulnerable Response**:
```text
HTTP/1.1 200 OK
```
Result: HTTP connections allowed.

**Example Secure Response**:
```text
HTTP/1.1 301 Moved Permanently
Location: https://example.com
```
Result: Redirects to HTTPS.

**Remediation**:
- Enable redirection (Apache):
  ```apache
  <VirtualHost *:80>
      ServerName example.com
      Redirect permanent / https://example.com/
  </VirtualHost>
  ```
- Enable in Nginx:
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

**Tip**: Save redirection evidence in a report.