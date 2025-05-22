# **Fingerprint Web Application**

## **Overview**

Fingerprinting a web application (WSTG-INFO-09) involves identifying the software or platform powering a web application, such as WordPress, Joomla, Drupal, or a custom-built application, along with its version and configuration details. This reconnaissance phase helps pentesters understand the application’s technology stack, revealing potential vulnerabilities, default settings, or misconfigurations specific to the software. According to OWASP, fingerprinting web applications is critical for tailoring subsequent tests to application-specific attack vectors, such as known exploits or plugin vulnerabilities.

**Impact**: Exposed application details can lead to:
- Exploitation of known vulnerabilities in outdated software versions (e.g., CVEs).
- Discovery of misconfigured or default settings (e.g., exposed admin panels).
- Identification of application-specific attack surfaces (e.g., WordPress plugin exploits).
- Increased risk of targeted attacks based on application weaknesses.

This guide provides a step-by-step methodology for fingerprinting web applications, adhering to OWASP’s WSTG-INFO-09, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for fingerprinting web applications, suitable for both novice and experienced testers:

- **Wappalyzer**: Browser extension to identify web applications and technologies.
- **WhatWeb**: Command-line tool for fingerprinting web applications and versions.
- **Burp Suite Community Edition**: Intercepts HTTP responses to analyze application-specific indicators.
- **OWASP ZAP**: Open-source web proxy for automated application detection.
- **cURL**: Command-line tool for inspecting HTTP responses and files.
- **WPScan**: Tool for fingerprinting and analyzing WordPress applications.
- **Droopescan**: Tool for scanning Drupal and other CMS vulnerabilities.
- **JoomScan**: Tool for fingerprinting Joomla applications.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **BuiltWith**: Online tool for identifying web applications and technologies.

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
6. **WPScan**:
   - Install: `sudo apt install wpscan` or `gem install wpscan`.
   - Verify: `wpscan --version`.
   - Optional: Obtain API token from [wpscan.com](https://wpscan.com/) for vulnerability checks.
7. **Droopescan**:
   - Install: `pip install droopescan`.
   - Verify: `droopescan --help`.
8. **JoomScan**:
   - Clone from GitHub: `git clone https://github.com/OWASP/joomscan.git`.
   - Install dependencies: `cd joomscan && cpan install -fi`.
   - Verify: `perl joomscan.pl --help`.
9. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
10. **BuiltWith**:
    - Access online at [builtwith.com](https://builtwith.com/).
    - No setup required.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-09, focusing on passive and active techniques to fingerprint web applications while minimizing detection risks.

### **1. Analyze HTTP Responses and Metadata**

Examine HTTP headers, HTML metadata, and response content for application-specific indicators.

**Steps**:
1. **Inspect Headers with cURL**:
   - Query the target:
     ```bash
     curl -I http://example.com
     ```
   - Look for headers like `X-Generator` or CMS-specific cookies (e.g., `wordpress_logged_in`).
2. **Check HTML Metadata**:
   - Fetch source code:
     ```bash
     curl http://example.com
     ```
   - Search for tags like:
     - `<meta name="generator" content="WordPress 5.4.2">`.
     - `<meta name="application-name" content="Joomla">`.
3. **Analyze with Burp Suite**:
   - Configure browser to proxy through Burp Suite.
   - Visit `http://example.com` and check “HTTP History” for responses.
   - Look for CMS-specific patterns (e.g., `/wp-content/` for WordPress).
4. **Document Findings**:
   - Save headers, metadata, and content snippets in Burp Suite’s “Logger” or a text file.

**Example Insecure Response**:
```
HTTP/1.1 200 OK
Set-Cookie: wordpress_logged_in_abc123=admin; Path=/
Content-Type: text/html
<meta name="generator" content="WordPress 5.4.2">
```

**Remediation**:
- Remove generator tags in WordPress (`functions.php`):
  ```php
  remove_action('wp_head', 'wp_generator');
  ```
- Avoid default cookie names:
  ```php
  define('COOKIEHASH', md5('custom_cookie'));
  ```

### **2. Use Automated Fingerprinting Tools**

Leverage tools like WhatWeb, Wappalyzer, and BuiltWith to identify applications and versions.

**Steps**:
1. **Run WhatWeb**:
   - Scan the target:
     ```bash
     whatweb http://example.com
     ```
   - Output: Application details (e.g., `WordPress[5.4.2]`, `Joomla[3.9.18]`).
2. **Use Wappalyzer**:
   - Open browser with Wappalyzer extension.
   - Visit `http://example.com` and note applications (e.g., `Drupal`, `Shopify`).
3. **Check BuiltWith**:
   - Visit [builtwith.com](https://builtwith.com/) and enter `example.com`.
   - Look for CMS or application details.
4. **Cross-Verify**:
   - Compare results across tools to confirm application and version.

**Example WhatWeb Output**:
```
http://example.com [200 OK] WordPress[5.4.2], PHP[7.4.3], Apache[2.4.29], Country[UNITED STATES][US]
```

**Remediation**:
- Minimize application exposure by removing version metadata:
  ```php
  // WordPress functions.php
  add_filter('the_generator', '__return_false');
  ```
- Update applications to the latest versions.

### **3. Test Application-Specific Paths and Files**

Test for default files, directories, or endpoints that indicate a specific application.

**Steps**:
1. **Test Common Paths with cURL**:
   - Query application-specific URLs:
     ```bash
     curl http://example.com/wp-admin (WordPress)
     curl http://example.com/administrator (Joomla)
     curl http://example.com/user/login (Drupal)
     ```
   - Check for 200 OK or application-specific responses.
2. **Use GoBuster**:
   - Enumerate application paths:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html
     ```
   - Look for paths like `/wp-content` (WordPress), `/modules` (Drupal).
3. **Analyze Responses**:
   - Check for application error pages (e.g., WordPress login page, Joomla 404).
   - Note file extensions (e.g., `.php` for WordPress, `.asp` for custom apps).
4. **Document Findings**:
   - Save URLs and response details.

**Example Vulnerable Finding**:
- URL: `http://example.com/wp-admin`
- Response: WordPress admin login page with version `5.4.2`.

**Remediation**:
- Restrict access to admin panels in WordPress:
  ```php
  // .htaccess
  <Files wp-login.php>
      Order deny,allow
      Deny from all
      Allow from 192.168.1.0/24
  </Files>
  ```
- Use security plugins (e.g., Wordfence).

### **4. Scan with Application-Specific Tools**

Use tools like WPScan, Droopescan, or JoomScan to fingerprint specific applications.

**Steps**:
1. **Run WPScan**:
   - Scan for WordPress:
     ```bash
     wpscan --url http://example.com
     ```
   - Output: WordPress version, plugins, and themes.
2. **Run Droopescan**:
   - Scan for Drupal:
     ```bash
     droopescan scan drupal -u http://example.com
     ```
   - Output: Drupal version and modules.
3. **Run JoomScan**:
   - Scan for Joomla:
     ```bash
     perl joomscan.pl -u http://example.com
     ```
   - Output: Joomla version and components.
4. **Verify Findings**:
   - Cross-check with WhatWeb or manual inspection.
   - Test identified paths with cURL.

**Example WPScan Output**:
```
[+] WordPress version: 5.4.2
[+] Plugins: yoast-seo (v14.0)
[+] Themes: twentytwenty
```

**Remediation**:
- Update WordPress and plugins to the latest versions.
- Hide version information:
  ```php
  // wp-config.php
  define('DISALLOW_FILE_MODS', true);
  ```

### **5. Leverage Search Engines for Application Discovery**

Use search engines to find indexed application details.

**Steps**:
1. **Craft Google Dork Queries**:
   - Search for application signatures:
     ```
     site:example.com intext:"Powered by WordPress" | intext:"Joomla" | intext:"Drupal"
     ```
2. **Check Cached Pages**:
   - Use Google’s cache:
     ```
     cache:example.com
     ```
   - Look for CMS-specific content.
3. **Verify Findings**:
   - Test URLs with cURL:
     ```bash
     curl http://example.com/readme.html
     ```
   - Check for version details (e.g., WordPress `readme.html`).
4. **Document Results**:
   - Save URLs and content snippets.

**Example Vulnerable Finding**:
- URL: `http://example.com/readme.html`
- Content: `WordPress 5.4.2`.

**Remediation**:
- Block access to readme files in Apache:
  ```
  <Files readme.html>
      Order allow,deny
      Deny from all
  </Files>
  ```
- Remove unnecessary files from the web root.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-09 with practical scenarios based on common web application fingerprinting patterns observed in penetration testing.

### **Test 1: Identify WordPress via Metadata**

Test for WordPress metadata revealing application version.

**Steps**:
1. **Check Metadata**:
   - Query:
     ```bash
     curl http://example.com | grep "generator"
     ```
   - Look for `<meta name="generator" content="WordPress 5.4.2">`.
2. **Run WPScan**:
   - Scan:
     ```bash
     wpscan --url http://example.com
     ```
   - Confirm version and plugins.
3. **Verify Vulnerability**:
   - Search [cve.mitre.org](https://cve.mitre.org/) for `WordPress 5.4.2`.

**Example Insecure Finding**:
```html
<meta name="generator" content="WordPress 5.4.2">
```

**Example Secure Configuration**:
- Remove generator tag in WordPress:
  ```php
  // functions.php
  remove_action('wp_head', 'wp_generator');
  ```

**Remediation**:
- Update WordPress to the latest version.
- Use security plugins to obscure version details.

### **Test 2: Detect Joomla via Admin Panel**

Test for Joomla-specific admin panel exposing application details.

**Steps**:
1. **Test Admin Path**:
   - Query:
     ```bash
     curl http://example.com/administrator
     ```
   - Check for Joomla login page.
2. **Run JoomScan**:
   - Scan:
     ```bash
     perl joomscan.pl -u http://example.com
     ```
   - Output: Joomla version `3.9.18`.
3. **Verify with Burp Suite**:
   - Capture response:
     ```
     GET /administrator HTTP/1.1
     Host: example.com
     ```
   - Look for Joomla-specific content.

**Example Insecure Finding**:
- URL: `http://example.com/administrator`
- Response: Joomla login page with version `3.9.18`.

**Example Secure Configuration**:
- Restrict admin access in Joomla:
  ```php
  // .htaccess
  <Directory administrator>
      Order deny,allow
      Deny from all
      Allow from 192.168.1.0/24
  </Directory>
  ```

**Remediation**:
- Rename admin paths.
- Update Joomla to the latest version.

### **Test 3: Fingerprint Drupal via Changelog**

Test for Drupal’s changelog file revealing version details.

**Steps**:
1. **Check Changelog**:
   - Query:
     ```bash
     curl http://example.com/CHANGELOG.txt
     ```
   - Look for `Drupal 8.9.2`.
2. **Run Droopescan**:
   - Scan:
     ```bash
     droopescan scan drupal -u http://example.com
     ```
   - Confirm version and modules.
3. **Verify Vulnerability**:
   - Search [cve.mitre.org](https://cve.mitre.org/) for `Drupal 8.9.2`.

**Example Insecure Finding**:
- URL: `http://example.com/CHANGELOG.txt`
- Content: `Drupal 8.9.2`.

**Example Secure Configuration**:
- Block changelog access in Nginx:
  ```
  location ~* CHANGELOG.txt {
      deny all;
      return 403;
  }
  ```

**Remediation**:
- Remove changelog files from the web root.
- Update Drupal to the latest version.

### **Test 4: Identify Custom App via Error Pages**

Test for custom application details in error pages.

**Steps**:
1. **Trigger Error**:
   - Query:
     ```bash
     curl http://example.com/nonexistent
     ```
   - Check for custom error pages.
2. **Analyze with OWASP ZAP**:
   - Spider `http://example.com` and check “Alerts” for application details.
3. **Check Headers**:
   - Query:
     ```bash
     curl -I http://example.com
     ```
   - Look for custom headers (e.g., `X-Custom-App`).

**Example Insecure Finding**:
```
HTTP/1.1 404 Not Found
X-Custom-App: MyApp v1.0
```

**Example Secure Configuration**:
- Remove custom headers in Node.js:
  ```javascript
  app.use((req, res, next) => {
      res.removeHeader('X-Custom-App');
      next();
  });
  ```

**Remediation**:
- Use generic error pages.
- Avoid exposing application details in responses.

## **Additional Tips**

- **Start Passive**: Use Wappalyzer and BuiltWith to minimize active requests.
- **Combine Tools**: Cross-verify WPScan results with Burp Suite for accuracy.
- **Gray-Box Testing**: If documentation is available, check for application references in source code.
- **Document Thoroughly**: Save all metadata, paths, and application details in a report.
- **Bypass Defenses**: Test non-standard paths or error conditions to uncover hidden application details.
- **Stay Ethical**: Obtain explicit permission for active scans or path enumeration.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).