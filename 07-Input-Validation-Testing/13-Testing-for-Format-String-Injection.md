# Testing for Format String Injection Vulnerabilities

## Overview

Testing for Format String Injection vulnerabilities involves verifying that a web application properly sanitizes user input used in format string functions (e.g., `printf`, `sprintf` in C/C++) to prevent attackers from manipulating memory, causing crashes, or executing arbitrary code. According to OWASP (WSTG-INPV-013), Format String Injection occurs when untrusted input is passed directly to format string functions without a format specifier, enabling attackers to read sensitive memory data, overwrite memory addresses, or disrupt application stability. This guide provides a hands-on methodology to test for Format String Injection vulnerabilities, focusing on input vectors, basic format string injection, memory read, denial of service (DoS), and filter bypass, with tools, commands, payloads, and remediation strategies.

**Impact**: Format String Injection vulnerabilities can lead to:
- Unauthorized access to sensitive memory data (e.g., stack values).
- Arbitrary memory writes, potentially leading to code execution.
- Application crashes or denial of service.
- Exposure of application logic or sensitive information.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-013, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as format string attacks may crash applications, corrupt memory, or expose sensitive data.

## Testing Tools

The following tools are recommended for testing Format String Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject format string payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check responses for memory leaks or crashes.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom injection rules; manually verify findings due to limited format string support.

- **cURL and HTTPie**: Send HTTP requests with format string payloads.
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
      curl -i "http://example.com/log?input=%n"
      # HTTPie
      http "http://example.com/log?input==%n"
      ```

- **Postman**: GUI tool for testing format string injection in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to format string payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for unexpected output.
  - **Note**: Firefox’s 2025 network analysis improvements enhance response inspection.

- **GDB (GNU Debugger)**: Analyzes application crashes or memory leaks (gray-box testing).
  - Install on Linux:
    ```bash
    sudo apt install gdb
    ```
  - Install on Windows/Mac: Download from [GNU](https://www.gnu.org/software/gdb/).
  - Example:
    ```bash
    gdb ./vulnerable_app
    run < input.txt
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-013, testing Format String Injection vulnerabilities across input vectors, basic format string injection, memory read, denial of service, and filter bypass.

### Common Format String Injection Payloads

Below is a list of common Format String Injection payloads to test for various vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid unintended crashes or data exposure.

- **Basic Format String Payloads**:
  - `%s` (Attempts to read string from stack)
  - `%x` (Reads hex values from stack)
  - `%p` (Reads pointer addresses)
  - `%n` (Attempts to write to memory address)

- **Memory Read Payloads**:
  - `%08x` (Formatted hex read)
  - `%s%s%s` (Multiple string reads)
  - `%100x` (Reads large offset)
  - `AAAA%08x` (Marker with hex read)

- **Denial of Service Payloads**:
  - `%999999d` (Large integer to cause overflow)
  - `%n%n%n` (Multiple writes to cause crash)
  - `%1000000s` (Large string to overflow buffer)

- **Filter Bypass Payloads**:
  - `%25n` (URL-encoded `%n`)
  - `%%n` (Escaped format specifier)
  - `%x%X` (Mixed case variation)
  - `%p%20p` (Space-separated)

- **Memory Write Payloads**:
  - `%n` (Writes to stack address)
  - `AAAA%n` (Writes to address at AAAA)
  - `%100$n` (Direct parameter access)

**Note**: Payloads are most effective in C/C++ applications using vulnerable functions (e.g., fprintf). Responses may vary in modern languages (e.g., Python, Java). Test payloads in query parameters, form fields, or headers where input is processed by low-level functions.

### 1. Identify Input Vectors

**Objective**: Locate user-controllable inputs that may be used in format string functions.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, URLs, or APIs that display user input (e.g., logging, error messages, output fields).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `input=test`, `msg=hello`).
3. Inspect responses:
   - Check for echoed input, error messages, or unexpected output.
   - Use Developer Tools (`Ctrl+Shift+I`) to search for format-related errors.
4. List input vectors:
   - Document query parameters, form fields, headers, and JSON payloads.

**Example Input Vectors**:
- URL: `http://example.com/log?input=test`
- Form: `<input name="message">`
- API: `POST /api/log` with `{"msg": "test"}`

**Remediation**:
- Validate inputs with allowlists:
  ```c
  if (!isalnum(input)) exit(1);
  ```
- Use format specifiers:
  ```c
  printf("%s", input);
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for Basic Format String Injection

**Objective**: Verify if user input can manipulate format string functions.

**Steps**:
1. Identify input fields:
   - Look for parameters like `?input=test` in logs or outputs.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     GET /log?input=%x HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/log?input=%x"
     ```
3. Check responses:
   - Look for hex values (e.g., `deadbeef`) or unexpected output.
   - Test: `%p`, `%s`.
4. Test variations:
   - Try: `%08x`, `AAAA%x`.

**Example Vulnerable Code (C)**:
```c
char *input = getenv("QUERY_STRING");
printf(input);
```
Test: `?input=%x`
Result: Outputs stack values.

**Example Secure Code (C)**:
```c
char *input = getenv("QUERY_STRING");
printf("%s", input);
```
Test: No output manipulation.

**Remediation**:
- Use explicit format specifiers:
  ```c
  printf("%s", user_input);
  ```
- Sanitize inputs:
  ```c
  if (strchr(input, '%')) exit(1);
  ```

**Tip**: Save unexpected output in a report.

### 3. Test for Memory Read

**Objective**: Check if format strings can leak memory data.

**Steps**:
1. Inject memory read payloads:
   - Test: `?input=%08x%08x%08x`
   - Use Burp:
     ```http
     GET /log?input=%08x%08x%08x HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for sequential hex values or sensitive data (e.g., pointers).
   - Test: `AAAA%08x` to identify stack offsets.
3. Escalate payloads:
   - Try: `%s%s` for string leaks (may crash).
4. Use GDB (gray-box):
   ```bash
   gdb ./app
   run < input.txt
   ```

**Example Vulnerable Code (C)**:
```c
char *input = get_input();
fprintf(stderr, input);
```
Test: `?input=%08x%08x`
Result: Leaks stack memory.

**Example Secure Code (C)**:
```c
char *input = get_input();
fprintf(stderr, "%s", input);
```
Test: No leak.

**Remediation**:
- Avoid direct input in format functions:
  ```c
  fprintf(stderr, "%s", input);
  ```
- Use static analysis tools (e.g., `cppcheck`).

**Tip**: Save memory leaks in a report.

### 4. Test for Denial of Service (DoS)

**Objective**: Verify if format strings can crash the application.

**Steps**:
1. Inject DoS payloads:
   - Test: `?input=%999999d`
   - Use cURL:
     ```bash
     curl -i "http://example.com/log?input=%999999d"
     ```
2. Check responses:
   - Look for crashes, errors (e.g., `Segmentation fault`), or timeouts.
   - Test: `%n%n%n`, `%1000000s`.
3. Monitor server behavior:
   - Use Burp Intruder to repeat payloads.
4. Test with GDB (gray-box):
   ```bash
   gdb ./app
   run < input.txt
   ```

**Example Vulnerable Code (C)**:
```c
char *input = get_input();
printf(input);
```
Test: `?input=%999999d`
Result: Application crash.

**Example Secure Code (C)**:
```c
char *input = get_input();
if (strlen(input) > 1000) exit(1);
printf("%s", input);
```
Test: No crash.

**Remediation**:
- Limit input length:
  ```c
  if (strlen(input) > 256) exit(1);
  ```
- Use safe functions:
  ```c
  snprintf(buffer, sizeof(buffer), "%s", input);
  ```

**Tip**: Save crash evidence in a report.

### 5. Test for Filter Bypass

**Objective**: Check if format string filters can be bypassed.

**Steps**:
1. Inject bypass payloads:
   - Test: `?input=%25n`
   - Use Burp:
     ```http
     GET /log?input=%25n HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for memory manipulation or crashes.
   - Test: `%%n`, `%x%X`.
3. Test obfuscation:
   - Try: `%p%20p`.
4. Use Postman for APIs:
   - Send: `{"input": "%25n"}`.

**Example Vulnerable Code (C)**:
```c
char *input = get_input();
if (strstr(input, "%n")) exit(1);
printf(input);
```
Test: `?input=%25n`
Result: Bypasses filter, writes memory.

**Example Secure Code (C)**:
```c
char *input = get_input();
printf("%s", input);
```
Test: No bypass.

**Remediation**:
- Decode inputs before filtering:
  ```c
  char *decoded = urldecode(input);
  ```
- Reject format specifiers:
  ```c
  if (strchr(input, '%')) exit(1);
  ```

**Tip**: Save bypass payloads and responses in a report.