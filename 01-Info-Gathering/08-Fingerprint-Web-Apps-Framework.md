# **Fingerprint Web Application Framework**

## **Overview**

Fingerprinting a web application framework (WSTG-INFO-08) involves identifying the framework powering a web application, such as Django, Laravel, Ruby on Rails, or ASP.NET, along with its version and configuration details. This reconnaissance phase helps pentesters understand the application’s technology stack, which can reveal known vulnerabilities, default configurations, or misconfigurations specific to the framework. According to OWASP, fingerprinting frameworks is critical for tailoring subsequent tests to framework-specific attack vectors.

**Impact**: Exposed framework details can lead to:
- Exploitation of known vulnerabilities in outdated framework versions (e.g., CVEs).
- Discovery of default or insecure configurations (e.g., debug modes).
- Identification of framework-specific attack surfaces (e.g., CSRF bypass in Rails).
- Increased risk of targeted attacks based on framework weaknesses.

This guide provides a step-by-step methodology for fingerprinting web application frameworks, adhering to OWASP’s WSTG-INFO-08, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for fingerprinting web application frameworks, suitable for both novice and experienced testers:

- **Wappalyzer**: Browser extension to identify frameworks and technologies.
- **WhatWeb**: Command-line tool for fingerprinting frameworks and applications.
- **Burp Suite Community Edition**: Intercepts HTTP responses to analyze framework-specific headers and content.
- **OWASP ZAP**: Open-source web proxy for automated framework detection.
- **cURL**: Command-line tool for inspecting HTTP headers and responses.
- **Nmap**: Open-source tool for scanning services and identifying framework-related services.
- **Retire.js**: Tool for detecting outdated JavaScript frameworks or libraries.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **Droopescan**: Tool for scanning Drupal and other CMS/framework vulnerabilities.
- **BuiltWith**: Online tool for identifying web technologies and frameworks.

### **Tool Setup Instructions**

1. **Wappalyzer**:
   - Install as a browser extension (Chrome/Firefox) from [wappalyzer.com](https://www.wappalyzer.com/).
   - Enable and visit target site to view results.
2. **WhatWeb**:
   - Install: `sudo apt install whatweb` or `gem install whatweb`.
   - Verify: `whatweb --version`.
3. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
4. **OWASP ZAP**:
   - Download from [owasp.org](https://www.zaproxy.org/download/).
   - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
   - Configure proxy: 127.0.0.1:8080.
5. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
6. **Nmap**:
   - Install on Linux: `sudo apt install nmap`.
   - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).
   - Verify: `nmap --version`.
7. **Retire.js**:
   - Install Node.js: `sudo apt install nodejs npm`.
   - Install Retire.js: `npm install -g retire`.
   - Verify: `retire --version`.
8. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
9. **Droopescan**:
   - Install: `pip install droopescan`.
   - Verify: `droopescan --help`.
10. **BuiltWith**:
    - Access online at [builtwith.com](https://builtwith.com/).
    - No setup required.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-08, focusing on passive and active techniques to fingerprint web application frameworks while minimizing detection risks.

### **1. Analyze HTTP Headers and Responses**

Examine HTTP headers, cookies, and response content for framework-specific indicators.

**Steps**:
1. **Inspect Headers with cURL**:
   - Query the target:
     ```bash
     curl -I http://example.com
     ```
   - Look for headers like:
     - `X-Powered-By: ASP.NET`.
     - `X-Django: 3.2.5` (non-standard, but possible).
2. **Check Cookies**:
   - Use Burp Suite to capture requests:
     - Navigate to `http://example.com` and check “HTTP History”.
     - Look for cookies like `sessionid` (Django), `PHPSESSID` (Laravel/PHP), or `_rails_session` (Ruby on Rails).
3. **Analyze Response Content**:
   - Use cURL to fetch HTML:
     ```bash
     curl http://example.com
     ```
   - Search for framework signatures (e.g., `<meta name="generator" content="Django">`).
4. **Document Findings**:
   - Save headers, cookies, and content snippets in Burp Suite’s “Logger” or a text file.

**Example Insecure Response**:
```
HTTP/1.1 200 OK
X-Powered-By: PHP/7.4.3
Set-Cookie: laravel_session=abc123; Path=/
Content-Type: text/html
```

**Remediation**:
- Remove framework-specific headers in PHP (`php.ini`):
  ```
  expose_php = Off
  ```
- Avoid default cookie names in Laravel:
  ```php
  'session' => [
      'cookie' => 'custom_session',
  ],
  ```

### **2. Use Automated Fingerprinting Tools**

Leverage tools like WhatWeb, Wappalyzer, and Retire.js to identify frameworks and versions.

**Steps**:
1. **Run WhatWeb**:
   - Scan the target:
     ```bash
     whatweb http://example.com
     ```
   - Output: Framework details (e.g., `Django[3.2.5]`, `Laravel[8.0]`).
2. **Use Wappalyzer**:
   - Open browser with Wappalyzer extension.
   - Visit `http://example.com` and note frameworks (e.g., `Ruby on Rails`, `ASP.NET`).
3. **Run Retire.js**:
   - Scan for JavaScript frameworks:
     ```bash
     retire --url http://example.com
     ```
   - Output: Client-side frameworks (e.g., `Angular 1.5.0`).
4. **Cross-Verify**:
   - Compare results across tools to confirm framework and version.

**Example WhatWeb Output**:
```
http://example.com [200 OK] Django[3.2.5], Python[3.8], Apache[2.4.29], Country[UNITED STATES][US]
```

**Remediation**:
- Minimize framework exposure by removing version metadata:
  ```python
  # Django settings.py
  SECURE_REFERRER_POLICY = 'strict-origin'
  ```
- Update frameworks to the latest versions.

### **3. Check Framework-Specific Files and Paths**

Test for default files, directories, or endpoints that indicate a specific framework.

**Steps**:
1. **Test Common Paths with cURL**:
   - Query framework-specific URLs:
     ```bash
     curl http://example.com/admin (Django)
     curl http://example.com/rails/info (Ruby on Rails)
     curl http://example.com/web.config (ASP.NET)
     ```
   - Check for 200 OK or framework-specific errors.
2. **Use GoBuster**:
   - Enumerate framework paths:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,py,rb
     ```
   - Look for paths like `/vendor` (Laravel), `/app` (Rails).
3. **Analyze Responses**:
   - Check for framework error pages (e.g., Django debug page, Laravel stack trace).
   - Note file extensions (e.g., `.php` for Laravel, `.aspx` for ASP.NET).
4. **Document Findings**:
   - Save URLs and response details.

**Example Vulnerable Finding**:
- URL: `http://example.com/admin`
- Response: Django admin login page with version `3.2.5`.

**Remediation**:
- Restrict access to admin panels in Django:
  ```python
  # urls.py
  urlpatterns = [
      path('admin/', admin.site.urls, {'require_login': True}),
  ]
  ```
- Disable debug mode:
  ```python
  DEBUG = False
  ```

### **4. Scan with Framework-Specific Tools**

Use tools like Droopescan or custom scripts to fingerprint specific frameworks.

**Steps**:
1. **Run Droopescan**:
   - Scan for Drupal or other frameworks:
     ```bash
     droopescan scan drupal -u http://example.com
     ```
   - Output: Framework version and modules.
2. **Test Nmap Scripts**:
   - Use framework-specific scripts:
     ```bash
     nmap --script http-drupal-enum http://example.com
     ```
   - Output: Drupal version and themes.
3. **Verify Findings**:
   - Cross-check with WhatWeb or manual inspection.
   - Test identified paths with cURL.
4. **Document Results**:
   - Save framework details and versions.

**Example Droopescan Output**:
```
[+] Drupal version: 8.9.2
[+] Modules: views, user
```

**Remediation**:
- Update Drupal to the latest version.
- Remove version information from responses:
  ```php
  // Drupal settings.php
  $settings['disable_version_headers'] = TRUE;
  ```

### **5. Leverage Search Engines and BuiltWith**

Use search engines and BuiltWith to confirm framework usage.

**Steps**:
1. **Craft Google Dork Queries**:
   - Search for framework signatures:
     ```
     site:example.com intext:"Django" | intext:"Laravel" | intext:"Rails"
     ```
2. **Use BuiltWith**:
   - Visit [builtwith.com](https://builtwith.com/) and enter `example.com`.
   - Check for frameworks (e.g., `ASP.NET`, `Spring`).
3. **Verify Findings**:
   - Test URLs or files identified in search results:
     ```bash
     curl http://example.com/laravel.log
     ```
   - Check for framework-specific content.
4. **Document Results**:
   - Save framework details and sources.

**Example Vulnerable Finding**:
- URL: `http://example.com/laravel.log`
- Content: Stack trace with Laravel version `8.0`.

**Remediation**:
- Block log file access in Nginx:
  ```
  location ~* \.log$ {
      deny all;
      return 403;
  }
  ```
- Regularly audit indexed content.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-08 with practical scenarios based on common framework fingerprinting patterns observed in penetration testing.

### **Test 1: Identify Django via Debug Page**

Test for Django debug pages revealing framework version.

**Steps**:
1. **Trigger Error**:
   - Query an invalid URL:
     ```bash
     curl http://example.com/nonexistent
     ```
   - Check for Django debug page.
2. **Analyze with Burp Suite**:
   - Send request:
     ```
     GET /nonexistent HTTP/1.1
     Host: example.com
     ```
   - Look for `Django Version: 3.2.5` in response.
3. **Verify Vulnerability**:
   - Search [cve.mitre.org](https://cve.mitre.org/) for `Django 3.2.5`.

**Example Insecure Finding**:
```
HTTP/1.1 404 Not Found
Content-Type: text/html
<h1>Page not found</h1>
<p>Django Version: 3.2.5</p>
```

**Example Secure Configuration**:
- Disable debug mode in Django:
  ```python
  # settings.py
  DEBUG = False
  ```

**Remediation**:
- Use custom error pages.
- Update Django to the latest version.

### **Test 2: Detect Laravel via Cookies**

Test for Laravel-specific cookies indicating framework usage.

**Steps**:
1. **Capture Cookies with Burp Suite**:
   - Visit `http://example.com` and check “HTTP History”.
   - Look for `laravel_session` cookie.
2. **Test with cURL**:
   - Query:
     ```bash
     curl -I http://example.com
     ```
   - Check for `Set-Cookie: laravel_session`.
3. **Verify Framework**:
   - Test for Laravel paths:
     ```bash
     curl http://example.com/vendor
     ```

**Example Insecure Finding**:
```
HTTP/1.1 200 OK
Set-Cookie: laravel_session=abc123
```

**Example Secure Configuration**:
- Rename cookies in Laravel:
  ```php
  // config/session.php
  'cookie' => 'custom_session',
  ```

**Remediation**:
- Avoid default cookie names.
- Restrict access to framework directories.

### **Test 3: Fingerprint Rails via Default Routes**

Test for Ruby on Rails default routes exposing framework details.

**Steps**:
1. **Test Rails Routes**:
   - Query:
     ```bash
     curl http://example.com/rails/info
     ```
   - Check for Rails environment details.
2. **Use WhatWeb**:
   - Scan:
     ```bash
     whatweb http://example.com
     ```
   - Output: `Ruby on Rails[6.1.4]`.
3. **Verify Vulnerability**:
   - Search [cve.mitre.org](https://cve.mitre.org/) for `Rails 6.1.4`.

**Example Insecure Finding**:
- URL: `http://example.com/rails/info`
- Response: `Ruby on Rails: 6.1.4`

**Example Secure Configuration**:
- Disable default routes in Rails:
  ```ruby
  # config/routes.rb
  Rails.application.routes.draw do
      # Remove rails/info
  end
  ```

**Remediation**:
- Remove diagnostic routes in production.
- Update Rails to the latest version.

### **Test 4: Detect ASP.NET via Headers**

Test for ASP.NET-specific headers revealing framework version.

**Steps**:
1. **Check Headers with cURL**:
   - Query:
     ```bash
     curl -I http://example.com
     ```
   - Look for `X-AspNet-Version` or `X-Powered-By`.
2. **Analyze with Burp Suite**:
   - Capture response:
     ```
     GET / HTTP/1.1
     Host: example.com
     ```
   - Check for `X-AspNet-Version: 4.0.30319`.
3. **Verify with Nmap**:
   - Scan:
     ```bash
     nmap -sV http://example.com
     ```

**Example Insecure Finding**:
```
HTTP/1.1 200 OK
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
```

**Example Secure Configuration**:
- Remove headers in ASP.NET (`web.config`):
  ```
  <system.webServer>
      <httpProtocol>
          <customHeaders>
              <remove name="X-AspNet-Version" />
              <remove name="X-Powered-By" />
          </customHeaders>
      </httpProtocol>
  </system.webServer>
  ```

**Remediation**:
- Disable version headers.
- Update ASP.NET to the latest version.

## **Additional Tips**

- **Start Passive**: Use Wappalyzer and BuiltWith to minimize active requests.
- **Combine Tools**: Cross-verify WhatWeb results with Burp Suite for accuracy.
- **Gray-Box Testing**: If documentation is available, check for framework references in source code.
- **Document Thoroughly**: Save all headers, cookies, and framework details in a report.
- **Bypass Defenses**: Test non-standard paths or error conditions to uncover hidden framework details.
- **Stay Ethical**: Obtain explicit permission for active scans or path enumeration.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).