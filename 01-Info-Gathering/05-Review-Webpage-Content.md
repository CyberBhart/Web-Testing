# **Review Webpage Content for Information Leakage**

## **Overview**

Reviewing webpage content for information leakage (WSTG-INFO-05) involves analyzing the HTML, JavaScript, CSS, and other client-side components of a web application to identify sensitive information that may be unintentionally exposed. This includes developer comments, hidden form fields, embedded credentials, metadata, or references to internal systems. According to OWASP, this reconnaissance phase is critical for uncovering details that could aid attackers in understanding the application’s structure, technologies, or vulnerabilities without direct server interaction.

**Impact**: Exposed webpage content can lead to:
- Disclosure of internal paths, API keys, or credentials.
- Exposure of development notes or debugging information.
- Identification of application technologies or frameworks.
- Insight into hidden functionality or endpoints, facilitating further attacks.

This guide provides a step-by-step methodology for reviewing webpage content, adhering to OWASP’s WSTG-INFO-05, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for reviewing webpage content, suitable for both novice and experienced testers:

- **Burp Suite Community Edition**: Intercepts and analyzes HTTP responses for webpage content.
- **OWASP ZAP**: Open-source web proxy for automated content discovery and analysis.
- **cURL**: Command-line tool for retrieving webpage source code.
- **Wget**: Tool for downloading webpages and their assets recursively.
- **grep**: Command-line utility for searching content within files.
- **Wappalyzer**: Browser extension to identify technologies used in webpages.
- **View Page Source**: Browser feature (Chrome/Firefox) to inspect HTML and JavaScript.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **JSBeautifier**: Online tool for formatting and analyzing minified JavaScript.
- **ExifTool**: Tool for extracting metadata from embedded files (e.g., images, PDFs).

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
2. **OWASP ZAP**:
   - Download from [owasp.org](https://www.zaproxy.org/download/).
   - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
   - Configure proxy: 127.0.0.1:8080.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Wget**:
   - Install on Linux: `sudo apt install wget`.
   - Install on Windows: Download from [gnu.org](https://www.gnu.org/software/wget/).
   - Verify: `wget --version`.
5. **grep**:
   - Pre-installed on Linux/Mac.
   - Install on Windows: Use Git Bash or WSL.
   - Verify: `grep --version`.
6. **Wappalyzer**:
   - Install as a browser extension (Chrome/Firefox) from [wappalyzer.com](https://www.wappalyzer.com/).
   - Enable and visit target site to view results.
7. **View Page Source**:
   - Access in Chrome/Firefox: Right-click page, select “View Page Source” or press `Ctrl+U`.
   - No setup required.
8. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
9. **JSBeautifier**:
   - Access online at [jsbeautifier.org](http://jsbeautifier.org/).
   - No setup required.
10. **ExifTool**:
    - Install on Linux: `sudo apt install exiftool`.
    - Install on Windows/Mac: Download from [exiftool.org](https://exiftool.org/).
    - Verify: `exiftool -ver`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-05, focusing on passive and minimally interactive techniques to analyze webpage content for information leakage.

### **1. Inspect HTML Source Code**

Analyze the HTML source code of webpages for comments, hidden elements, or sensitive data.

**Steps**:
1. **View Page Source**:
   - Open browser, navigate to `http://example.com`, and press `Ctrl+U`.
   - Search for:
     - HTML comments (e.g., `<!-- Debug: API key -->`).
     - Hidden inputs (e.g., `<input type="hidden" name="api_key">`).
     - References to internal paths (e.g., `/internal/api`).
2. **Use cURL**:
   - Retrieve source code:
     ```bash
     curl http://example.com
     ```
   - Pipe to `grep` for sensitive keywords:
     ```bash
     curl http://example.com | grep -i "key\|password\|todo\|debug"
     ```
3. **Analyze with Burp Suite**:
   - Configure browser to proxy through Burp Suite.
   - Visit `http://example.com` and check “HTTP History” for responses.
   - Inspect “Response” tab for HTML content.
4. **Document Findings**:
   - Save comments, hidden fields, or sensitive data in a text file or Burp Suite’s “Logger”.

**Example Insecure Finding**:
```html
<!-- TODO: Remove test API key -->
<input type="hidden" name="api_key" value="xyz123456789">
```

**Remediation**:
- Remove sensitive comments before deployment.
- Avoid storing credentials in hidden fields:
  ```html
  <!-- Use server-side authentication instead -->
  <input type="hidden" name="session_id" value="secure_token">
  ```

### **2. Analyze JavaScript and CSS Files**

Examine client-side scripts and stylesheets for embedded sensitive information.

**Steps**:
1. **Download JavaScript Files**:
   - Identify scripts in HTML (e.g., `<script src="/js/app.js">`).
   - Use cURL:
     ```bash
     curl http://example.com/js/app.js
     ```
2. **Beautify Minified Code**:
   - Copy minified JavaScript to [jsbeautifier.org](http://jsbeautifier.org/) and format.
   - Search for:
     - Hardcoded credentials (e.g., `const API_KEY = "xyz123";`).
     - Internal endpoints (e.g., `fetch("/api/internal")`).
     - Debug flags (e.g., `debug = true`).
3. **Check CSS Files**:
   - Download:
     ```bash
     curl http://example.com/css/style.css
     ```
   - Look for comments or references to hidden elements (e.g., `/* Admin panel styles */`).
4. **Use grep**:
   - Search for sensitive terms:
     ```bash
     grep -r "key\|password\|endpoint" /path/to/downloaded/files
     ```

**Example Insecure Finding**:
```javascript
// app.js
const API_KEY = "xyz123456789";
fetch("/api/internal", { headers: { "Authorization": API_KEY } });
```

**Remediation**:
- Store credentials server-side:
  ```javascript
  // Use environment variables or secure tokens
  fetch("/api/internal", { headers: { "Authorization": getSecureToken() } });
  ```
- Remove debugging code before deployment.

### **3. Extract Metadata from Embedded Files**

Analyze images, PDFs, or other embedded files for metadata that may leak sensitive information.

**Steps**:
1. **Download Files**:
   - Use Wget to retrieve assets:
     ```bash
     wget -r -A jpg,png,pdf http://example.com
     ```
2. **Run ExifTool**:
   - Extract metadata:
     ```bash
     exiftool /path/to/image.jpg
     ```
   - Look for:
     - Author names or emails.
     - Software versions (e.g., Photoshop).
     - Geolocation data.
3. **Analyze PDFs**:
   - Check for creator or application details:
     ```bash
     exiftool /path/to/document.pdf
     ```
4. **Document Findings**:
   - Save metadata outputs and note sensitive details.

**Example Insecure Finding**:
```
File: image.jpg
Author: John Doe <john.doe@internal.example.com>
Software: Adobe Photoshop CS6
```

**Remediation**:
- Strip metadata before uploading files:
  ```bash
  exiftool -all= image.jpg
  ```
- Use server-side processing to remove metadata.

### **4. Crawl Webpages with OWASP ZAP**

Use OWASP ZAP to automatically discover and analyze webpage content.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `http://example.com` to the context.
2. **Spider the Site**:
   - In “Sites” tab, right-click `example.com` and select “Spider”.
   - Monitor “Spider” tab for discovered pages and assets.
3. **Analyze Content**:
   - Check “Alerts” for potential leaks (e.g., comments with sensitive data).
   - Review “History” for responses containing hidden fields or scripts.
4. **Document Findings**:
   - Export “Sites” or save alerts in a report.

**Example Vulnerable Finding**:
- URL: `http://example.com/about`
- Response: `<!-- Internal server: 10.0.0.1 -->`

**Remediation**:
- Sanitize HTML to remove comments:
  ```html
  <!-- Avoid internal references -->
  ```
- Use automated tools to strip comments in production.

### **5. Leverage Search Engines for Content Discovery**

Use search engines to find indexed webpage content that may leak information.

**Steps**:
1. **Craft Google Dork Queries**:
   - Search for sensitive content:
     ```
     site:example.com intext:"internal" | intext:"debug" | intext:"key"
     ```
2. **Check Cached Pages**:
   - Use Google’s cache:
     ```
     cache:example.com
     ```
   - Look for old comments or metadata.
3. **Verify Findings**:
   - Test URLs with cURL:
     ```bash
     curl http://example.com/debug.html
     ```
   - Check for sensitive data in responses.
4. **Document Results**:
   - Save URLs and content snippets.

**Example Vulnerable Finding**:
- URL: `http://example.com/debug.html`
- Content: `<!-- Test user: admin, password: secret123 -->`

**Remediation**:
- Remove debug pages from production:
  ```
  <Files debug.html>
      Order allow,deny
      Deny from all
  </Files>
  ```
- Use `robots.txt` to block indexing:
  ```
  Disallow: /debug.html
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-05 with practical scenarios based on common webpage content leakage patterns observed in penetration testing.

### **Test 1: Sensitive Developer Comments**

Test for HTML comments revealing internal details.

**Steps**:
1. **View Source**:
   - Open `http://example.com` and press `Ctrl+U`.
   - Search for `<!--`.
2. **Use cURL**:
   - Query:
     ```bash
     curl http://example.com | grep -i "<!--"
     ```
3. **Analyze with Burp Suite**:
   - Check “Response” tab for comments like `<!-- API endpoint: /internal -->`.

**Example Insecure Finding**:
```html
<!-- TODO: Remove internal endpoint /api/v1/test -->
```

**Example Secure Practice**:
- Strip comments in production:
  ```html
  <!-- No sensitive information -->
  ```

**Remediation**:
- Use build tools (e.g., HTMLMinifier) to remove comments.
- Review code before deployment.

### **Test 2: Hardcoded API Key in JavaScript**

Test for JavaScript files containing hardcoded credentials.

**Steps**:
1. **Download Script**:
   - Query:
     ```bash
     curl http://example.com/js/app.js
     ```
2. **Beautify Code**:
   - Paste into [jsbeautifier.org](http://jsbeautifier.org/).
   - Search for `key`, `password`, or `token`.
3. **Verify with grep**:
   - Search:
     ```bash
     grep -i "key" app.js
     ```

**Example Insecure Finding**:
```javascript
const API_KEY = "xyz123456789";
```

**Example Secure Practice**:
- Use environment variables:
  ```javascript
  const API_KEY = process.env.API_KEY;
  ```

**Remediation**:
- Store sensitive data server-side.
- Obfuscate client-side code if necessary.

### **Test 3: Image Metadata Leakage**

Test for metadata in images revealing sensitive information.

**Steps**:
1. **Download Image**:
   - Query:
     ```bash
     wget http://example.com/images/team.jpg
     ```
2. **Run ExifTool**:
   - Extract:
     ```bash
     exiftool team.jpg
     ```
3. **Analyze Output**:
   - Look for author, email, or software details.

**Example Insecure Finding**:
```
File: team.jpg
Author: Jane Smith <jane.smith@internal.example.com>
```

**Example Secure Practice**:
- Strip metadata:
  ```bash
  exiftool -all= team.jpg
  ```

**Remediation**:
- Automate metadata removal in upload pipelines.
- Use anonymous author details.

### **Test 4: Hidden Form Fields**

Test for hidden form fields exposing sensitive data.

**Steps**:
1. **View Source**:
   - Open `http://example.com/login` and search for `<input type="hidden">`.
2. **Use OWASP ZAP**:
   - Spider `http://example.com` and check “Parameters” for hidden fields.
3. **Test with Burp Suite**:
   - Send request:
     ```
     GET /login HTTP/1.1
     Host: example.com
     ```
   - Check response for hidden inputs.

**Example Insecure Finding**:
```html
<input type="hidden" name="admin_token" value="abc123">
```

**Example Secure Practice**:
- Use server-side tokens:
  ```html
  <input type="hidden" name="csrf_token" value="secure_random_token">
  ```

**Remediation**:
- Avoid sensitive data in hidden fields.
- Implement CSRF tokens for form security.

## **Additional Tips**

- **Start Simple**: Use “View Page Source” to quickly spot comments or hidden fields.
- **Combine Tools**: Cross-verify Burp Suite findings with OWASP ZAP for comprehensive coverage.
- **Gray-Box Testing**: If documentation is available, check for references to internal scripts or endpoints.
- **Document Thoroughly**: Save all comments, scripts, and metadata in a report.
- **Bypass Defenses**: Use cached pages or alternate paths to access restricted content.
- **Stay Ethical**: Obtain explicit permission before downloading or analyzing sensitive content.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).