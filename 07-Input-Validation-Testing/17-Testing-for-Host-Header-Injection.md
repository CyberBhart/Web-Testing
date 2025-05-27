# Testing for Host Header Injection Vulnerabilities

## Overview

Testing for Host Header Injection vulnerabilities involves verifying that a web application properly validates the HTTP `Host` header to prevent attackers from manipulating application behavior, poisoning caches, redirecting users, or facilitating phishing attacks. According to OWASP (WSTG-INPV-017), Host Header Injection occurs when an application trusts the user-supplied `Host` header without validation, allowing attackers to inject malicious domains or IPs, bypass security controls, or trigger unintended server actions. This guide provides a hands-on methodology to test for Host Header Injection vulnerabilities, focusing on identifying Host header usage, basic injection, cache poisoning, redirect manipulation, server-side request forgery (SSRF), and filter bypass, with tools, commands, payloads, and remediation strategies.

**Impact**: Host Header Injection vulnerabilities can lead to:
- Cache poisoning with malicious content (e.g., XSS).
- Unauthorized redirects to phishing or malicious sites.
- Server-side request forgery (SSRF) to internal systems.
- Bypassing authentication or access controls.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-017, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as Host Header Injection attempts may poison caches, redirect users, or access internal systems, potentially disrupting services or affecting other users.

## Testing Tools

The following tools are recommended for testing Host Header Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to manipulate the `Host` header.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify Host header usage.
  - **Note**: Use “Collaborator” for SSRF detection (manual setup in Community Edition).

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with custom rules; manually verify findings due to limited Host header support.

- **cURL and HTTPie**: Send HTTP requests with custom `Host` headers.
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
      curl -i -H "Host: attacker.com" http://example.com
      # HTTPie
      http -h "Host:attacker.com" http://example.com
      ```

- **Postman**: GUI tool for testing Host header manipulation in APIs or requests.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Add custom `Host` header in request headers.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to Host header payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze headers and Elements tab for injected content.
  - **Note**: Firefox’s 2025 header inspection enhancements improve debugging.

- **Netcat (nc)**: Tests raw HTTP requests with custom `Host` headers.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "GET / HTTP/1.1\nHost: attacker.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-017, testing Host Header Injection vulnerabilities across Host header usage, basic injection, cache poisoning, redirect manipulation, server-side request forgery (SSRF), and filter bypass.

### Common Host Header Injection Payloads

Below is a list of common payloads to test for Host Header Injection vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid cache poisoning or unintended redirects.

- **Basic Host Injection Payloads**:
  - `Host: attacker.com` (Malicious domain)
  - `Host: 127.0.0.1` (Localhost)
  - `Host: malicious.example.com` (Subdomain)
  - `Host: 192.168.1.1` (Internal IP)

- **Cache Poisoning Payloads**:
  - `Host: attacker.com<script>alert(1)</script>` (XSS injection)
  - `Host: example.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>` (Combined with splitting)
  - `Host: malicious.com?cache=poison` (Cache manipulation)
  - `Host: attacker.com#poison` (Fragment injection)

- **Redirect Manipulation Payloads**:
  - `Host: phishing.com` (Redirect to phishing site)
  - `Host: example.com.attacker.com` (Fake subdomain)
  - `Host: redirect.attacker.com` (Custom redirect domain)
  - `Host: example.com%23@attacker.com` (Obfuscated redirect)

- **SSRF Payloads**:
  - `Host: localhost:8080` (Internal service)
  - `Host: 10.0.0.1` (Private network)
  - `Host: metadata.google.internal` (Cloud metadata)
  - `Host: burpcollaborator.net` (External callback)

- **Filter Bypass Payloads**:
  - `Host: attacker.com%0d%0aX-Injected: malicious` (Header injection)
  - `Host: @attacker.com` (At-sign obfuscation)
  - `Host: attacker.com:80` (Port specification)
  - `Host: [::1]` (IPv6 localhost)

**Note**: Payloads depend on the application’s Host header handling (e.g., PHP, ASP.NET) and server/proxy configurations (e.g., Apache, Nginx). Test payloads in the `Host` header, query parameters, or POST bodies where the header is processed.

### 1. Identify Host Header Usage

**Objective**: Locate endpoints or features that rely on the `Host` header.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify features like redirects, links, or APIs that may use the `Host` header (e.g., password resets, absolute URLs).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Interact with features to capture requests in HTTP History.
   - Note `Host` header values and responses.
3. Inspect responses:
   - Check for `Host` header reflection in redirects, links, or scripts.
   - Use Developer Tools (`Ctrl+Shift+I`) to analyze headers and content.
4. List endpoints:
   - Document URLs, forms, headers, and APIs using the `Host` header.

**Example Endpoints**:
- URL: `http://example.com/reset?token=abc`
- Form: `<input name="redirect">`
- API: `POST /api/link` with `{"host": "example.com"}`

**Remediation**:
- Hardcode Host values:
  ```php
  $host = "example.com";
  ```
- Validate Host header:
  ```php
  if ($_SERVER['HTTP_HOST'] !== 'example.com') die("Invalid Host");
  ```

**Tip**: Save the endpoint list in a report.

### 2. Test for Basic Host Header Injection

**Objective**: Verify if manipulating the `Host` header alters application behavior.

**Steps**:
1. Identify Host-dependent endpoints:
   - Look for pages like `/reset` or `/link`.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     GET /reset HTTP/1.1
     Host: attacker.com
     ```
   - Use cURL:
     ```bash
     curl -i -H "Host: attacker.com" http://example.com/reset
     ```
3. Check responses:
   - Look for reflected domains (e.g., `attacker.com` in links).
   - Test: `Host: 127.0.0.1`.
4. Test variations:
   - Try: `Host: malicious.example.com`.

**Example Vulnerable Code (PHP)**:
```php
$host = $_SERVER['HTTP_HOST'];
echo "<a href='http://$host/reset'>Reset</a>";
```
Test: `Host: attacker.com`
Result: Link to `http://attacker.com/reset`.

**Example Secure Code (PHP)**:
```php
$host = "example.com";
echo "<a href='http://$host/reset'>Reset</a>";
```
Test: No injection.

**Remediation**:
- Use fixed domains:
  ```php
  $host = "example.com";
  ```
- Sanitize Host:
  ```php
  $host = preg_match('/^example\.com$/', $_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'example.com';
  ```

**Tip**: Save injection evidence in a report.

### 3. Test for Cache Poisoning

**Objective**: Check if Host header injection can poison web or proxy caches.

**Steps**:
1. Inject cache poisoning payloads:
   - Test: `Host: attacker.com<script>alert(1)</script>`
   - Use Burp:
     ```http
     GET /page HTTP/1.1
     Host: attacker.com<script>alert(1)</script>
     ```
2. Check cache behavior:
   - Revisit the page with original `Host` (e.g., `example.com`).
   - Look for injected content or XSS.
   - Test: `Host: example.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>`.
3. Verify cache headers:
   - Check `Cache-Control`, `ETag`.
4. Clear cache (post-test):
   - Request purge if permitted.

**Example Vulnerable Code (Node.js)**:
```javascript
const host = req.headers.host;
res.setHeader('Location', `http://${host}/page`);
```
Test: `Host: attacker.com<script>alert(1)</script>`
Result: Poisons cache with XSS.

**Example Secure Code (Node.js)**:
```javascript
const host = 'example.com';
res.setHeader('Location', `http://${host}/page`);
```
Test: No poisoning.

**Remediation**:
- Avoid Host in redirects:
  ```javascript
  res.setHeader('Location', '/page');
  ```
- Set strict cache headers:
  ```javascript
  res.setHeader('Cache-Control', 'no-store, no-cache');
  ```

**Tip**: Save cache poisoning evidence in a report.

### 4. Test for Redirect Manipulation

**Objective**: Verify if Host header injection can control redirects.

**Steps**:
1. Inject redirect payloads:
   - Test: `Host: phishing.com`
   - Use cURL:
     ```bash
     curl -i -H "Host: phishing.com" http://example.com/reset
     ```
2. Check responses:
   - Look for redirects to `phishing.com`.
   - Test: `Host: example.com.attacker.com`.
3. Test obfuscation:
   - Try: `Host: example.com%23@attacker.com`.
4. Use Burp Repeater:
   - Verify redirect headers (e.g., `Location`).

**Example Vulnerable Code (Python)**:
```python
host = request.headers.get('Host')
return redirect(f"http://{host}/reset")
```
Test: `Host: phishing.com`
Result: Redirects to `phishing.com`.

**Example Secure Code (Python)**:
```python
host = "example.com"
return redirect(f"http://{host}/reset")
```
Test: No redirect.

**Remediation**:
- Use relative redirects:
  ```python
  return redirect("/reset")
  ```
- Validate Host:
  ```python
  if request.headers.get('Host') != 'example.com': abort(403)
  ```

**Tip**: Save redirect evidence in a report.

### 5. Test for Server-Side Request Forgery (SSRF)

**Objective**: Check if Host header injection enables SSRF to internal systems.

**Steps**:
1. Inject SSRF payloads:
   - Test: `Host: localhost:8080`
   - Use Burp:
     ```http
     GET /api HTTP/1.1
     Host: localhost:8080
     ```
2. Check responses:
   - Look for internal service responses or errors.
   - Test: `Host: 10.0.0.1`.
3. Use external callback:
   - Try: `Host: burpcollaborator.net`.
4. Monitor timing:
   - Internal requests may cause delays.

**Example Vulnerable Code (PHP)**:
```php
$host = $_SERVER['HTTP_HOST'];
file_get_contents("http://$host/api");
```
Test: `Host: metadata.google.internal`
Result: Accesses cloud metadata.

**Example Secure Code (PHP)**:
```php
$host = "example.com";
file_get_contents("http://$host/api");
```
Test: No SSRF.

**Remediation**:
- Whitelist domains:
  ```php
  $allowed = ['example.com'];
  if (!in_array($_SERVER['HTTP_HOST'], $allowed)) die("Invalid Host");
  ```
- Disable internal requests:
  ```php
  curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
  ```

**Tip**: Save SSRF evidence in a report.

### 6. Test for Filter Bypass

**Objective**: Verify if Host header filters can be bypassed.

**Steps**:
1. Inject bypass payloads:
   - Test: `Host: attacker.com%0d%0aX-Injected: malicious`
   - Use Burp:
     ```http
     GET /page HTTP/1.1
     Host: attacker.com%0d%0aX-Injected: malicious
     ```
2. Check responses:
   - Look for injected headers or behavior changes.
   - Test: `Host: @attacker.com`.
3. Test obfuscation:
   - Try: `Host: attacker.com:80`, `Host: [::1]`.
4. Use Netcat for raw requests:
   ```bash
   echo -e "GET / HTTP/1.1\nHost: attacker.com:80\n\n" | nc example.com 80
   ```

**Example Vulnerable Code (Node.js)**:
```javascript
if (!req.headers.host.includes('example.com')) throw Error('Invalid Host');
res.redirect(`http://${req.headers.host}/page`);
```
Test: `Host: example.com.attacker.com`
Result: Bypasses filter.

**Example Secure Code (Node.js)**:
```javascript
if (req.headers.host !== 'example.com') throw Error('Invalid Host');
res.redirect(`http://example.com/page`);
```
Test: No bypass.

**Remediation**:
- Strict validation:
  ```javascript
  if (req.headers.host !== 'example.com') throw Error('Invalid Host');
  ```
- Remove special characters:
  ```javascript
  host = host.replace(/[\r\n@]/g, '');
  ```

**Tip**: Save bypass evidence in a report.