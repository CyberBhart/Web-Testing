# Test Content Security Policy

## Overview

Testing the Content Security Policy (CSP) involves evaluating the configuration and effectiveness of CSP headers to mitigate client-side attacks, such as Cross-Site Scripting (XSS) and data injection (WSTG-CONF-12). According to OWASP, a poorly configured or absent CSP can allow malicious scripts to execute, steal data, or manipulate web content, increasing the risk of XSS, clickjacking, or mixed content vulnerabilities. CSP is a critical defense mechanism that restricts the sources from which a browser can load resources (e.g., scripts, styles, images), making it essential to test for proper implementation.

**Impact**: Weak or missing CSP configurations can lead to:
- Execution of unauthorized scripts (e.g., XSS attacks).
- Data theft (e.g., session cookies, form inputs).
- Mixed content issues (HTTP resources on HTTPS pages).
- Increased attack surface for client-side exploits.
- Non-compliance with security standards (e.g., PCI DSS, OWASP Top Ten).

This guide provides a hands-on methodology for black-box and gray-box testing, covering CSP header analysis, directive validation, inline script detection, mixed content testing, reporting mechanism checks, and automated scanning. It includes tools, commands, payloads, and an automated script, aligned with OWASP’s WSTG-CONF-12 and best practices as of May 27, 2025. **Ethical Note**: Obtain explicit written authorization before testing, as probing web applications may trigger security alerts, violate terms of service, or disrupt services, potentially leading to legal consequences or service interruptions.

## Testing Tools

The following tools are recommended for testing CSP vulnerabilities, with setup instructions optimized for new pentesters:

- **curl**: Command-line tool for inspecting HTTP headers.
  - Install on Linux:  
    `sudo apt install curl`
  - Example:  
    `curl -I https://example.com`

- **Burp Suite Community Edition 2025.5**: Web security testing tool.
  - Download: [Burp Suite](https://portswigger.net/burp/communitydownload)
  - Configure browser proxy: `127.0.0.1:8080`
  - Example: Intercept requests to view CSP headers.

- **OWASP ZAP 3.2**: Open-source web application security scanner.
  - Download: [ZAP](https://www.zaproxy.org/download/)
  - Configure proxy: `127.0.0.1:8080`
  - Enable HUD: Tools > Options > HUD
  - Example:  
    `zap-cli quick-scan https://example.com`

- **Browser Developer Tools**: Built-in browser tools (e.g., Chrome DevTools).
  - Access: Right-click > Inspect > Network or Console
  - Example: Check CSP violations in Console.

- **CSP Evaluator**: Online tool for analyzing CSP policies.
  - Access: [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
  - Example: Paste CSP header to evaluate weaknesses.

- **Shodan**: API-based OSINT tool (requires API key).
  - Sign up: [Shodan](https://www.shodan.io/)
  - Example:  
    `shodan search http.html:"Content-Security-Policy" example.com`

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-12, testing for CSP vulnerabilities by analyzing headers, validating directives, detecting inline scripts, checking mixed content, verifying reporting mechanisms, and automating scans.

### Common CSP Checks and Payloads

Below are common CSP directives, misconfigurations, and commands to test for vulnerabilities. Use with caution to avoid disrupting production applications. Refer to the [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) for detailed guidance.

- **Common Directives**:
  - `default-src`: Default policy for resource loading.
  - `script-src`: Restricts script sources.
  - `style-src`: Restricts stylesheet sources.
  - `img-src`: Restricts image sources.
  - `connect-src`: Restricts API/WS connections.
  - `report-uri`/`report-to`: Specifies reporting endpoints for violations.

- **Common Misconfigurations**:
  - Missing CSP headers.
  - Overly permissive directives (e.g., `script-src *`).
  - Use of `unsafe-inline` or `unsafe-eval` in `script-src`/`style-src`.
  - Lack of HTTPS enforcement (mixed content).
  - Missing or misconfigured `report-uri`/`report-to`.

- **Test Commands**:
  - Check CSP headers:  
    `curl -I https://example.com`
  - Scan with OWASP ZAP:  
    `zap-cli quick-scan https://example.com`
  - OSINT with Shodan:  
    `shodan search http.html:"Content-Security-Policy" example.com`
  - Test inline script (browser console):  
    ```javascript
    var s = document.createElement('script'); s.innerHTML = 'alert(1)'; document.body.appendChild(s);
    ```

- **Expected Responses**:
  - Vulnerable: Missing CSP header, HTTP 200 with permissive directives (e.g., `script-src *`), or inline script execution.
  - Secure: HTTP 200 with strict CSP (e.g., `script-src 'self'`), inline script blocked, or violation logged in Console.

⚠️ **Warning**: Testing CSP may involve injecting test scripts or probing endpoints, which could trigger WAFs or security alerts. To avoid detection:
- Throttle requests: Use delays in tools like `curl`.
- Set user-agent headers: `curl -A "Mozilla/5.0 (Compatible; SecurityScan)"`.
- Log scan timing: Record start/end times in a log file (see automation script).
- Avoid persistent changes or malicious payloads without explicit authorization.

**Note**: CSP testing depends on browser enforcement and server configuration. Gray-box testing with access to server configs (e.g., Apache, Nginx) or source code provides deeper insight into CSP implementation. Verify the web server user (e.g., `www-data`) with `ps aux | egrep '(apache|nginx)'` if gray-box access is available.

### 1. CSP Header Analysis

**Objective**: Verify the presence and content of CSP headers.

**Steps**:
1. Use curl (black-box):
   - Run:  
     `curl -I -A "Mozilla/5.0 (Compatible; SecurityScan)" https://example.com > $LOG_DIR/headers.txt`
   - **Vulnerable Example**:  
     ```plaintext
     HTTP/1.1 200 OK
     [No Content-Security-Policy header]
     ```
   - **Secure Example**:  
     ```plaintext
     HTTP/1.1 200 OK
     Content-Security-Policy: default-src 'self'; script-src 'self'
     ```
2. Use Burp Suite (black-box):
   - Intercept requests and check `Content-Security-Policy` or `Content-Security-Policy-Report-Only` headers.
3. Use OWASP ZAP:
   - Run Passive Scan to detect missing CSP headers.
4. Use Browser DevTools:
   - Open Network tab, reload page, and check response headers.

**Remediation**:
- Add CSP header in web server config (e.g., Nginx):
  ```nginx
  add_header Content-Security-Policy "default-src 'self'; script-src 'self';";
  ```
- Verify:  
  `curl -I https://example.com`

**Tip**: Save header output in a report.

### 2. Directive Validation

**Objective**: Analyze CSP directives for permissive or insecure settings.

**Steps**:
1. Use curl (black-box):
   - Run:  
     `curl -I https://example.com | grep Content-Security-Policy`
   - Check for `unsafe-inline`, `unsafe-eval`, or `*`.
   - **Vulnerable Example**:  
     ```plaintext
     Content-Security-Policy: script-src *; style-src 'unsafe-inline'
     ```
   - **Secure Example**:  
     ```plaintext
     Content-Security-Policy: script-src 'self' https://trusted.cdn; style-src 'self'
     ```
2. Use CSP Evaluator (black-box):
   - Paste CSP header into [CSP Evaluator](https://csp-evaluator.withgoogle.com/).
   - Look for warnings (e.g., `unsafe-inline` detected).
3. Use Burp Suite (gray-box):
   - Modify CSP headers to test enforcement (requires proxy access).
4. Use Browser DevTools:
   - Check Console for CSP warnings (e.g., blocked resources).

**Remediation**:
- Update CSP to remove `unsafe-inline`/`unsafe-eval`:
  ```nginx
  add_header Content-Security-Policy "script-src 'self' https://trusted.cdn; style-src 'self';";
  ```
- Use nonces or hashes for inline scripts:
  ```html
  <script nonce="random123">alert(1);</script>
  ```
  CSP: `script-src 'nonce-random123'`
- Verify:  
  `curl -I https://example.com`

**Tip**: Document permissive directives.

### 3. Inline Script Detection

**Objective**: Test for execution of inline or unauthorized scripts.

**Steps**:
1. Use Browser DevTools (black-box):
   - Inject test script in Console:  
     ```javascript
     var s = document.createElement('script'); s.innerHTML = 'alert(1)'; document.body.appendChild(s);
     ```
   - **Vulnerable Example**: Alert executes.
   - **Secure Example**: Console error: `Refused to execute inline script`.
2. Use Burp Suite (black-box):
   - Inject inline script via form inputs or URL parameters.
   - Example payload: `<script>alert(1)</script>`
3. Use OWASP ZAP:
   - Run Active Scan to test for XSS vulnerabilities bypassing CSP.
4. Check source code (gray-box):
   - Run:  
     `grep -r "<script>.*</script>" /path/to/webroot`

**Remediation**:
- Block inline scripts:  
  ```nginx
  add_header Content-Security-Policy "script-src 'self';";
  ```
- Use nonces or SRI for trusted scripts:
  ```html
  <script src="trusted.js" integrity="sha256-abc123"></script>
  ```
- Verify:  
  ```javascript
  var s = document.createElement('script'); s.innerHTML = 'alert(1)'; document.body.appendChild(s);
  ```

**Tip**: Save evidence of script execution.

### 4. Mixed Content Testing

**Objective**: Identify HTTP resources loaded on HTTPS pages.

**Steps**:
1. Use Browser DevTools (black-box):
   - Open Network tab, reload page, filter for HTTP resources.
   - **Vulnerable Example**:  
     ```plaintext
     http://example.com/script.js
     ```
   - **Secure Example**: All resources use `https://`.
2. Use curl (black-box):
   - Run:  
     `curl -s https://example.com | grep -i "http://"`
   - Look for HTTP URLs in HTML.
3. Use OWASP ZAP:
   - Run Passive Scan to detect mixed content warnings.
4. Use Burp Suite:
   - Intercept responses to identify HTTP resource references.

**Remediation**:
- Enforce HTTPS in CSP:  
  ```nginx
  add_header Content-Security-Policy "default-src https:; connect-src https:;";
  ```
- Update resources to HTTPS:
  ```html
  <script src="https://example.com/script.js"></script>
  ```
- Add `upgrade-insecure-requests`:  
  ```nginx
  add_header Content-Security-Policy "upgrade-insecure-requests;";
  ```
- Verify:  
  `curl -s https://example.com | grep -i "http://"`

**Tip**: Document mixed content findings.

### 5. Reporting Mechanism Checks

**Objective**: Verify CSP violation reporting functionality.

**Steps**:
1. Use curl (black-box):
   - Check for `report-uri` or `report-to`:  
     `curl -I https://example.com | grep Content-Security-Policy`
   - **Vulnerable Example**:  
     ```plaintext
     Content-Security-Policy: default-src 'self' [no report-uri]
     ```
   - **Secure Example**:  
     ```plaintext
     Content-Security-Policy: default-src 'self'; report-uri https://example.com/csp-report
     ```
2. Test reporting endpoint (black-box):
   - Trigger a violation (e.g., inline script) and check endpoint logs.
   - Example:  
     ```javascript
     var s = document.createElement('script'); s.src = 'http://malicious.com'; document.body.appendChild(s);
     ```
3. Use Burp Suite (gray-box):
   - Send violation reports to `report-uri` and verify receipt.
4. Check server logs (gray-box):
   - Run:  
     `tail -f /var/log/nginx/access.log | grep csp-report`

**Remediation**:
- Add reporting endpoint:  
  ```nginx
  add_header Content-Security-Policy "default-src 'self'; report-uri /csp-report;";
  ```
- Configure endpoint (e.g., Node.js):
  ```javascript
  app.post('/csp-report', (req, res) => { console.log(req.body); res.status(204).end(); });
  ```
- Verify:  
  `curl -I https://example.com`

**Tip**: Save reporting endpoint details.

### 6. Automated CSP Scanning

**Objective**: Use automated tools to scan for CSP vulnerabilities.

**Steps**:
1. Save the following script as `csp_test.sh`:
   ```bash
   #!/bin/bash

   # Usage: ./csp_test.sh example.com

   TARGET_DOMAIN=$1
   LOG_DIR="logs/$(date +%F)"
   mkdir -p "$LOG_DIR"

   if [[ -z "$TARGET_DOMAIN" ]]; then
     echo "Usage: $0 <target_domain>"
     exit 1
   fi

   # Check for required tools
   command -v curl >/dev/null 2>&1 || { echo >&2 "curl not found"; exit 1; }
   command -v zap-cli >/dev/null 2>&1 || { echo >&2 "zap-cli not found"; exit 1; }

   echo "[*] Starting CSP testing on $TARGET_DOMAIN at $(date)" > "$LOG_DIR/scan_timing.log"
   echo "[*] Starting CSP testing on $TARGET_DOMAIN"

   ### 1. Check CSP headers
   echo "[*] Checking CSP headers..."
   curl -s -I -A "Mozilla/5.0 (Compatible; SecurityScan)" "https://$TARGET_DOMAIN" > "$LOG_DIR/headers.txt"
   grep -i "Content-Security-Policy" "$LOG_DIR/headers.txt" > "$LOG_DIR/csp_headers.txt"

   ### 2. Check for permissive directives
   echo "[*] Checking for permissive directives..."
   if grep -qi "unsafe-inline\|unsafe-eval\|\*" "$LOG_DIR/csp_headers.txt"; then
     echo "Warning: Permissive directives found" >> "$LOG_DIR/csp_warnings.txt"
   fi

   ### 3. Check for mixed content
   echo "[*] Checking for mixed content..."
   curl -s "https://$TARGET_DOMAIN" | grep -i "http://" > "$LOG_DIR/mixed_content.txt"

   ### 4. Run OWASP ZAP scan
   echo "[*] Running OWASP ZAP scan..."
   zap-cli quick-scan "https://$TARGET_DOMAIN" > "$LOG_DIR/zap_scan.txt"

   ### 5. Check for reporting endpoint
   echo "[*] Checking for reporting endpoint..."
   if grep -qi "report-uri\|report-to" "$LOG_DIR/csp_headers.txt"; then
     echo "Reporting endpoint found" >> "$LOG_DIR/csp_report.txt"
   else
     echo "No reporting endpoint found" >> "$LOG_DIR/csp_report.txt"
   fi

   echo "[*] Scan completed at $(date)" >> "$LOG_DIR/scan_timing.log"

   ### Summary output
   echo "-------------------------------------------"
   echo "Scan completed. Results saved to $LOG_DIR"
   echo "- Headers: $LOG_DIR/headers.txt"
   echo "- CSP headers: $LOG_DIR/csp_headers.txt"
   echo "- Permissive warnings: $LOG_DIR/csp_warnings.txt"
   echo "- Mixed content: $LOG_DIR/mixed_content.txt"
   echo "- ZAP scan: $LOG_DIR/zap_scan.txt"
   echo "- Reporting endpoint: $LOG_DIR/csp_report.txt"
   echo "- Scan timing: $LOG_DIR/scan_timing.log"
   echo "-------------------------------------------"
   ```
2. Set executable permissions:  
   `chmod +x csp_test.sh`
3. Run the script:
   - Example:  
     `./csp_test.sh example.com`
   - **Vulnerable Example** (in `csp_headers.txt`):  
     ```plaintext
     Content-Security-Policy: script-src *;
     ```
   - **Secure Example**:  
     ```plaintext
     Content-Security-Policy: script-src 'self';
     ```
4. Use OWASP ZAP:
   - Run:  
     `zap-cli quick-scan https://example.com`

**How the Script Works**:
- **Inputs**: Takes a target domain for black-box testing.
- **Checks**:
  - Extracts CSP headers with `curl`.
  - Flags permissive directives (`unsafe-inline`, `unsafe-eval`, `*`).
  - Detects mixed content in HTML.
  - Runs OWASP ZAP for automated scanning.
  - Verifies reporting endpoints (`report-uri`, `report-to`).
- **Output**: Saves results in `logs/YYYY-MM-DD`, including headers, warnings, and scan logs.
- **Requirements**:
  - `curl`, `zap-cli` installed.
  - Run as a user with network access.

**Remediation**:
- Implement strict CSP:  
  ```nginx
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted.cdn; report-uri /csp-report;";
  ```
- Verify:  
  `curl -I https://example.com`
- Example secure CSP:
  ```plaintext
  Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn; style-src 'self'; connect-src 'self'; report-uri /csp-report;
  ```

**Tip**: Save script output and logs in a report.

## References

- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html): Guidance on CSP implementation.
- [OWASP Web Security Testing Guide - CSP Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/12-Configuration_and_Deployment_Management_Testing/12-Test_Content_Security_Policy): OWASP’s CSP testing methodology.
- [Mozilla CSP Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP): Official CSP specifications.
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/): Tool for analyzing CSP policies.
- [Burp Suite Documentation](https://portswigger.net/burp/documentation): Web security testing guide.
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/): ZAP usage and configuration.