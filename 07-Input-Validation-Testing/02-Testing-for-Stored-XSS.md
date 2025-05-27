# Testing for Stored Cross-Site Scripting (XSS) Vulnerabilities

## Overview

Testing for Stored Cross-Site Scripting (XSS) vulnerabilities involves verifying that a web application properly sanitizes user input stored in the system (e.g., in a database) and displayed to users, preventing malicious script execution. According to OWASP (WSTG-INPV-02), stored XSS occurs when user input, such as comments or profile data, is saved and later rendered without encoding, allowing attackers to inject JavaScript that executes in victims’ browsers. This guide provides a hands-on methodology to identify and test stored XSS vulnerabilities, focusing on input vectors, payload injection, filter bypasses, and specific contexts like user profiles, search queries, file uploads, and admin inputs, with tools, commands, and remediation strategies.

**Impact**: Stored XSS vulnerabilities can lead to:
- Persistent session hijacking via cookie theft.
- Widespread phishing or redirection to malicious sites.
- Unauthorized actions affecting multiple users.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-02, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting payloads may affect other users or trigger security alerts.

## Testing Tools

The following tools are recommended for testing stored XSS vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests/responses to inject XSS payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check Response tab for stored payload reflection.

- **OWASP ZAP 3.0**: A free tool for automated and manual XSS testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with XSS rules to detect vulnerabilities (verify manually).

- **Browser Developer Tools (Chrome/Firefox)**: Inspects HTML, responses, and network requests.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Elements tab to find stored payloads, Network tab to analyze requests, and Console to test execution.
  - Example command to inspect DOM:
    ```javascript
    document.body.innerHTML.includes('<script>alert(123)</script>')
    ```
  - **Tip**: Firefox’s 2025 DOM inspector enhancements improve payload analysis.

- **cURL and HTTPie**: Send HTTP requests to test endpoints with payloads.
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
      curl -i -X POST -d "comment=<script>alert(123)</script>" "http://example.com/submit"
      # HTTPie
      http POST "http://example.com/submit" comment="<script>alert(123)</script>"
      ```

- **PHP Charset Encoder (PCE)**: Encodes payloads to bypass filters.
  - Access online by searching “PHP Charset Encoder.”
  - Example: Encode `<script>alert(123)</script>` to `%3cscript%3ealert(123)%3c/script%3e`.

- **Hackvertor**: Obfuscates payloads for filter evasion.
  - Access online by searching “Hackvertor XSS.”
  - Example: Convert `<script>` to `<scr<script>ipt>`.

- **XSS Filter Evasion Cheat Sheet**: Provides payloads for testing.
  - Resource: [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html).
  - Sample payloads:
    - `<script>alert(123)</script>`
    - `" onmouseover="alert(123)`
    - `<img src=x onerror=alert(123)>`
  - **Tip**: Combine with PCE or Hackvertor for advanced evasion.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-02, testing stored XSS vulnerabilities across input vectors, payload injection, filter bypasses, and specific contexts like user profiles, search queries, file uploads, and admin inputs.

### 1. Identify Input Vectors for Storage

**Objective**: Locate user-controllable inputs that are stored in the application.

**Steps**:
1. Explore the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify features like comment sections, user profiles, forums, or message boards.
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit a form (e.g., comment) and check HTTP History for parameters (e.g., `comment=Hello`).
3. Inspect HTML with Developer Tools:
   - Open Elements tab (`Ctrl+Shift+I`).
   - Search (`Ctrl+F`) for `<input>`, `<textarea>`, or `<form>` tags.
   - Note fields that submit data for storage.
4. List input vectors:
   - Document fields like `comment`, `bio`, `username`, or hidden fields.

**Example Input Vectors**:
- Form: `<textarea name="comment">`
- Profile: `<input name="bio">`
- Hidden: `<input type="hidden" name="user_id" value="123">`

**Remediation**:
- Validate inputs server-side using allowlists:
  ```php
  if (!preg_match('/^[a-zA-Z0-9 ]+$/', $input)) {
      die("Invalid input");
  }
  ```
- Log suspicious inputs:
  ```php
  error_log("Suspicious input: $input");
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for Stored XSS

**Objective**: Inject payloads to verify if malicious code is stored and executed.

**Steps**:
1. Prepare payloads:
   - Start with `<script>alert(123)</script>`.
   - Use OWASP XSS Filter Evasion Cheat Sheet for advanced payloads.
2. Inject payloads with Burp Suite:
   - Capture a form submission (e.g., `POST /submit-comment`).
   - Modify in Repeater: `comment=<script>alert(123)</script>`.
   - Forward and check storage.
3. Inject manually:
   - Submit payloads in form fields or URL parameters.
   - Navigate to where the input is displayed (e.g., comment section).
4. Use OWASP ZAP:
   - Submit payloads via Manual Request Editor.
   - Run Active Scan and check Alerts (verify manually).
5. Check for execution:
   - Visit the display page (e.g., blog comments).
   - If an alert appears, the payload executed.

**Test Payloads**:
- `<script>alert(123)</script>`
- `" onmouseover="alert(123)`
- `%3cscript%3ealert(123)%3c/script%3e`
- `<scr<script>ipt>alert(123)</script>`
- `<img src=x onerror=alert(123)>`

**Example Vulnerable Code (PHP)**:
```php
<?php
$comment = $_POST['comment'];
mysqli_query($conn, "INSERT INTO comments (text) VALUES ('$comment')");
$result = mysqli_query($conn, "SELECT text FROM comments");
while ($row = mysqli_fetch_assoc($result)) {
    echo $row['text'];
}
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: Alert executes on page load.

**Example Secure Code (PHP)**:
```php
<?php
$comment = htmlspecialchars($_POST['comment'], ENT_QUOTES, 'UTF-8');
mysqli_query($conn, "INSERT INTO comments (text) VALUES ('$comment')");
$result = mysqli_query($conn, "SELECT text FROM comments");
while ($row = mysqli_fetch_assoc($result)) {
    echo htmlspecialchars($row['text'], ENT_QUOTES, 'UTF-8');
}
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: No execution.

**Remediation**:
- Sanitize inputs before storage:
  ```php
  $comment = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
  ```
- Use Content Security Policy (CSP):
  ```html
  <meta http-equiv="Content-Security-Policy" content="script-src 'self';">
  ```

**Tip**: Save payloads and display pages in a report.

### 3. Check Impact of Stored XSS

**Objective**: Assess the payload’s effects on other users.

**Steps**:
1. Verify storage:
   - Revisit the display page in a different browser or incognito mode.
   - Search Elements tab for the payload.
2. Test execution:
   - Check if `<script>alert(123)</script>` triggers an alert.
   - Test `<script>alert(document.cookie)</script>` for cookie access.
3. Check display contexts:
   - Note where the payload appears (e.g., HTML, attributes).
   - Use context-specific payloads (e.g., `" onmouseover="alert(123)`).
4. Document impact:
   - Record effects (e.g., cookie theft).
   - Take screenshots of alerts.

**Example Vulnerable Code (PHP)**:
```php
<?php
$result = mysqli_query($conn, "SELECT text FROM comments");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<p>" . $row['text'] . "</p>";
}
?>
```
Test: Submit `<script>alert(document.cookie)</script>`.
Result: Alert shows cookies.

**Example Secure Code (PHP)**:
```php
<?php
$result = mysqli_query($conn, "SELECT text FROM comments");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<p>" . htmlspecialchars($row['text'], ENT_QUOTES, 'UTF-8') . "</p>";
}
?>
```
Test: Submit `<script>alert(document.cookie)</script>`.
Result: No execution.

**Remediation**:
- Encode outputs:
  ```php
  htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
  ```
- Sanitize inputs before storage.

**Tip**: Save impact evidence in a report.

### 4. Bypass XSS Filters

**Objective**: Test if filters or WAFs can be bypassed to store payloads.

**Steps**:
1. Encode payloads:
   - Use PCE to encode `<script>` to `%3cscript%3e`.
   - Test: `comment=%3cscript%3ealert(123)%3c/script%3e`.
2. Try case variations:
   - Test: `<ScRiPt>alert(123)</ScRiPt>`.
3. Test nested payloads:
   - Test: `<scr<script>ipt>alert(123)</script>`.
4. Test alternative tags:
   - Test: `<img src=x onerror=alert(123)>`.
5. Verify results:
   - Visit the display page; check for alert.

**Example Vulnerable Code (PHP)**:
```php
<?php
$comment = $_POST['comment'];
if (preg_match("/<script/i", $comment)) {
    echo "Filtered";
    return;
}
mysqli_query($conn, "INSERT INTO comments (text) VALUES ('$comment')");
?>
```
Test: Submit `<img src=x onerror=alert(123)>`.
Result: Alert executes.

**Example Secure Code (PHP)**:
```php
<?php
$comment = htmlspecialchars($_POST['comment'], ENT_QUOTES, 'UTF-8');
mysqli_query($conn, "INSERT INTO comments (text) VALUES ('$comment')");
?>
```
Test: Submit `<img src=x onerror=alert(123)>`.
Result: No execution.

**Remediation**:
- Use recursive sanitization (e.g., DOMPurify).
- Decode inputs before validation:
  ```php
  $input = urldecode($_POST['comment']);
  ```

**Tip**: Save bypass payloads in a report.

### 5. XSS in Stored User Profiles

**Objective**: Test profile fields displayed across the application.

**Steps**:
1. Identify profile fields:
   - Locate editable fields (e.g., `bio`, `username`) in user settings.
   - Check display locations (e.g., profile pages, posts).
2. Inject payloads:
   - Submit `<script>alert(123)</script>` in the bio field.
   - Use Burp to modify POST data:
     ```http
     POST /profile HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     bio=<script>alert(123)</script>
     ```
3. Check display pages:
   - Visit profile pages or posts.
   - Search Elements tab for the payload.
4. Verify execution:
   - Test `<script>alert(document.cookie)</script>` in another session.

**Example Vulnerable Code (PHP)**:
```php
<?php
$bio = $_POST['bio'];
mysqli_query($conn, "UPDATE users SET bio='$bio' WHERE id=1");
$result = mysqli_query($conn, "SELECT bio FROM users WHERE id=1");
echo $result['bio'];
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: Alert executes.

**Example Secure Code (PHP)**:
```php
<?php
$bio = htmlspecialchars($_POST['bio'], ENT_QUOTES, 'UTF-8');
mysqli_query($conn, "UPDATE users SET bio='$bio' WHERE id=1");
$result = mysqli_query($conn, "SELECT bio FROM users WHERE id=1");
echo htmlspecialchars($result['bio'], ENT_QUOTES, 'UTF-8');
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: No execution.

**Remediation**:
- Sanitize profile inputs:
  ```php
  htmlspecialchars($bio, ENT_QUOTES, 'UTF-8');
  ```
- Validate fields to reject HTML.

**Tip**: Save profile display pages in a report.

### 6. XSS in Stored Search Queries

**Objective**: Test search queries stored in history and displayed unsanitized.

**Steps**:
1. Identify search features:
   - Locate search bars saving queries (e.g., recent searches).
   - Check history or results pages.
2. Inject payloads:
   - Submit `<script>alert(123)</script>` in the search bar.
   - Use cURL:
     ```bash
     curl -i "http://example.com/search?q=<script>alert(123)</script>"
     ```
3. Check display pages:
   - Visit search history page.
   - Search Elements tab for the payload.
4. Verify execution:
   - Test `<script>alert(document.cookie)</script>`.

**Example Vulnerable Code (PHP)**:
```php
<?php
$query = $_GET['query'];
mysqli_query($conn, "INSERT INTO search_history (query) VALUES ('$query')");
$result = mysqli_query($conn, "SELECT query FROM search_history");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<p>Search: " . $row['query'] . "</p>";
}
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: Alert executes.

**Example Secure Code (PHP)**:
```php
<?php
$query = htmlspecialchars($_GET['query'], ENT_QUOTES, 'UTF-8');
mysqli_query($conn, "INSERT INTO search_history (query) VALUES ('$query')");
$result = mysqli_query($conn, "SELECT query FROM search_history");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<p>Search: " . htmlspecialchars($row['query'], ENT_QUOTES, 'UTF-8') . "</p>";
}
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: No execution.

**Remediation**:
- Encode search outputs:
  ```php
  htmlspecialchars($query, ENT_QUOTES, 'UTF-8');
  ```
- Reject HTML in queries.

**Tip**: Save search history pages in a report.

### 7. XSS in Stored File Uploads

**Objective**: Test file upload features where filenames or metadata are displayed unsanitized.

**Steps**:
1. Identify file upload features:
   - Locate upload fields (e.g., profile picture).
   - Check if filenames are displayed.
2. Inject payloads:
   - Upload a file named `image<script>alert(123)</script>.jpg`.
   - Submit payloads in metadata fields.
3. Check display pages:
   - Visit file list or profile page.
   - Search Elements tab for the payload.
4. Verify execution:
   - Test `<script>alert(document.cookie)</script>` in filename.

**Example Vulnerable Code (PHP)**:
```php
<?php
$filename = $_FILES['file']['name'];
mysqli_query($conn, "INSERT INTO uploads (filename) VALUES ('$filename')");
$result = mysqli_query($conn, "SELECT filename FROM uploads");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<p>File: " . $row['filename'] . "</p>";
}
?>
```
Test: Upload `image<script>alert(123)</script>.jpg`.
Result: Alert executes.

**Example Secure Code (PHP)**:
```php
<?php
$filename = htmlspecialchars($_FILES['file']['name'], ENT_QUOTES, 'UTF-8');
mysqli_query($conn, "INSERT INTO uploads (filename) VALUES ('$filename')");
$result = mysqli_query($conn, "SELECT filename FROM uploads");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<p>File: " . htmlspecialchars($row['filename'], ENT_QUOTES, 'UTF-8') . "</p>";
}
?>
```
Test: Upload `image<script>alert(123)</script>.jpg`.
Result: No execution.

**Remediation**:
- Sanitize filenames:
  ```php
  $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
  ```
- Encode metadata outputs.

**Tip**: Save file display pages in a report.

### 8. XSS in Stored Admin Inputs

**Objective**: Test admin-editable fields displayed to users.

**Steps**:
1. Identify admin inputs:
   - Locate fields like announcements (if admin access is available).
   - Check display locations (e.g., homepage).
2. Inject payloads:
   - Submit `<script>alert(123)</script>` in announcement field.
   - Use Burp to modify POST data.
3. Check display pages:
   - Visit announcement banner.
   - Search Elements tab for the payload.
4. Verify execution:
   - Test `<script>alert(document.cookie)</script>` in a user session.

**Example Vulnerable Code (PHP)**:
```php
<?php
$announcement = $_POST['announcement'];
mysqli_query($conn, "UPDATE settings SET announcement='$announcement'");
$result = mysqli_query($conn, "SELECT announcement FROM settings");
echo $result['announcement'];
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: Alert executes.

**Example Secure Code (PHP)**:
```php
<?php
$announcement = htmlspecialchars($_POST['announcement'], ENT_QUOTES, 'UTF-8');
mysqli_query($conn, "UPDATE settings SET announcement='$announcement'");
$result = mysqli_query($conn, "SELECT announcement FROM settings");
echo htmlspecialchars($result['announcement'], ENT_QUOTES, 'UTF-8');
?>
```
Test: Submit `<script>alert(123)</script>`.
Result: No execution.

**Remediation**:
- Sanitize admin inputs:
  ```php
  htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
  ```
- Use CSP to block inline scripts.

**Tip**: Save admin display pages in a report.
