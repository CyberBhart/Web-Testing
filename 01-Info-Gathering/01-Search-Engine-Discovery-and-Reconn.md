# **Conducting Search Engine Discovery and Reconnaissance for Information Leakage**

## **Overview**

Search Engine Discovery and Reconnaissance for Information Leakage (WSTG-INFO-01) involves using search engines and web crawlers to identify sensitive information about a target web application that is publicly accessible but not intended for public exposure. This includes configuration files, source code, error messages, employee details, internal documentation, or other data that could aid an attacker in understanding the application’s structure, technologies, or vulnerabilities. According to OWASP, this reconnaissance phase is critical for gathering intelligence passively without direct interaction with the target, reducing the risk of detection.

**Impact**: Leaked information can reveal:
- Application architecture (e.g., server types, frameworks).
- Sensitive data (e.g., API keys, credentials, internal IPs).
- Misconfigurations (e.g., exposed admin panels, backup files).
- Potential attack vectors (e.g., outdated software versions, debug pages).

This guide provides a step-by-step methodology for conducting search engine reconnaissance, adhering to OWASP’s WSTG-INFO-01, supplemented with real-world test cases and practical techniques for professional penetration testing.

## **Testing Tools**

The following tools are recommended for search engine discovery and reconnaissance, suitable for both beginners and advanced testers:

- **Google Search**: Free, powerful search engine for discovering indexed content using advanced operators.
- **Bing Search**: Alternative search engine with unique indexing, useful for cross-verification.
- **TheHarvester**: Open-source tool for gathering emails, subdomains, hosts, and employee names from search engines.
- **GoBuster**: Tool for enumerating directories and files on web servers, useful for verifying discovered paths.
- **Burp Suite Community Edition**: Intercepts HTTP requests to analyze discovered endpoints.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite for detailed analysis.
- **Wayback Machine (archive.org)**: Archives historical versions of websites to uncover old, sensitive content.
- **Shodan**: Search engine for internet-connected devices, useful for identifying exposed servers.
- **Censys**: Similar to Shodan, provides insights into open ports and services.
- **OSINT Framework**: Web-based collection of open-source intelligence tools for reconnaissance.

### **Tool Setup Instructions**

1. **Google Search**:
   - Access via any browser (e.g., Chrome, Firefox).
   - No setup required; use advanced search operators (see below).
2. **Bing Search**:
   - Access via any browser.
   - Use similar operators to Google for targeted queries.
3. **TheHarvester**:
   - Install on Linux: `sudo apt install theharvester` or `pip install theharvester`.
   - Run: `theharvester -d example.com -b google -l 500`.
4. **GoBuster**:
   - Install: `sudo apt install gobuster`.
   - Example: `gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt`.
5. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab for request analysis.
6. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite (127.0.0.1:8080).
7. **Wayback Machine**:
   - Access via [archive.org](https://archive.org/web/).
   - Enter target URL to view archived versions.
8. **Shodan**:
   - Sign up at [shodan.io](https://www.shodan.io/).
   - Search: `hostname:example.com` or `port:80 apache`.
9. **Censys**:
   - Sign up at [censys.io](https://censys.io/).
   - Search: `http.title:"example.com"`.
10. **OSINT Framework**:
    - Access via [osintframework.com](https://osintframework.com/).
    - Navigate to relevant reconnaissance tools (e.g., search engine queries).

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-01, focusing on passive reconnaissance using search engines and public archives to identify information leakage without interacting with the target application.

### **1. Identify Target Scope**

Define the target organization, domain, and related assets to focus reconnaissance efforts.

**Steps**:
1. **Gather Domain Information**:
   - Obtain the primary domain (e.g., `example.com`) from the client or testing scope.
   - Identify subdomains using TheHarvester:
     ```bash
     theharvester -d example.com -b google,bing -l 500
     ```
   - Output: Lists subdomains (e.g., `app.example.com`, `staging.example.com`), emails, and hosts.
2. **Map Related Domains**:
   - Use Google/Bing to find partner domains or acquisitions:
     ```
     site:*.example.com | related:example.com
     ```
   - Check DNS records with `dig` or `nslookup`:
     ```bash
     dig example.com ANY
     ```
3. **Document Scope**:
   - List all domains, subdomains, and IPs in scope (e.g., `example.com`, `api.example.com`, `192.168.1.1`).
   - Note any restrictions (e.g., avoid production systems).

**Example Output**:
- Domains: `example.com`, `app.example.com`, `staging.example.com`
- IPs: `192.168.1.1`, `10.0.0.1`
- Emails: `admin@example.com`, `support@example.com`

**Remediation**:
- Restrict indexing of sensitive subdomains via `robots.txt` (e.g., `Disallow: /staging/`).
- Use DNS configurations to hide internal IPs.
- Monitor OSINT sources for leaked emails and remove them where possible.

### **2. Use Search Engine Operators**

Leverage advanced search operators to uncover sensitive information indexed by search engines.

**Steps**:
1. **Craft Google Dork Queries**:
   - Use operators to find specific content:
     - `site:example.com`: Restrict results to the target domain.
     - `filetype:pdf`: Find specific file types (e.g., PDFs with sensitive data).
     - `inurl:admin`: Locate admin panels or sensitive URLs.
     - `intitle:"index of"`: Find exposed directories.
     - `intext:"api key"`: Search for exposed credentials.
   - Example query:
     ```
     site:example.com filetype:txt intext:"password"
     ```
2. **Test Bing Queries**:
   - Similar operators to Google, but with unique indexing:
     ```
     site:example.com inurl:login
     ```
3. **Combine Operators**:
   - Find configuration files:
     ```
     site:example.com filetype:conf | filetype:env | filetype:bak
     ```
   - Find error logs:
     ```
     site:example.com intext:"error" filetype:log
     ```
4. **Analyze Results**:
   - Check for:
     - Exposed files (e.g., `.env`, `config.php.bak`).
     - Debug pages (e.g., `phpinfo.php`).
     - Employee details (e.g., LinkedIn profiles, email directories).
   - Save URLs and snippets for further analysis.

**Example Vulnerable Findings**:
- URL: `http://example.com/.env`
  - Content: `DB_PASSWORD=secret123`
- URL: `http://example.com/admin/login.php`
  - Exposed admin panel.
- URL: `http://example.com/backup.sql`
  - Database dump with user data.

**Remediation**:
- Add sensitive files to `robots.txt` (e.g., `Disallow: /.env`).
- Implement HTTP authentication for admin panels.
- Remove or restrict access to backup files and logs.

### **3. Explore Historical Data with Wayback Machine**

Use the Wayback Machine to find archived versions of the target site that may contain outdated or sensitive information.

**Steps**:
1. **Access Wayback Machine**:
   - Go to [archive.org/web/](https://archive.org/web/).
   - Enter the target URL (e.g., `http://example.com`).
2. **Browse Snapshots**:
   - Select different years/months to view historical versions.
   - Look for:
     - Old configuration files (e.g., `config.php`).
     - Exposed directories (e.g., `/admin/`).
     - Deprecated APIs or endpoints.
3. **Extract URLs**:
   - Use the Wayback Machine’s API or tools like `waybackurls`:
     ```bash
     waybackurls example.com > archived_urls.txt
     ```
   - Output: List of archived URLs (e.g., `http://example.com/old_api_key.txt`).
4. **Verify Findings**:
   - Test archived URLs with `curl` or Burp Suite:
     ```bash
     curl http://example.com/old_api_key.txt
     ```
   - Check if sensitive data is still accessible or exploitable.

**Example Vulnerable Finding**:
- Archived URL: `http://example.com/api_key.txt` (from 2023 snapshot).
  - Content: `API_KEY=xyz123456789`.
- Current URL: `http://example.com/admin/` (removed but archived).
  - Reveals old admin panel structure.

**Remediation**:
- Regularly audit archived content on archive.org.
- Request removal of sensitive snapshots via archive.org’s contact form.
- Implement strict access controls to prevent future leaks.

### **4. Leverage Shodan and Censys**

Use Shodan and Censys to identify exposed servers, services, or misconfigurations associated with the target.

**Steps**:
1. **Search with Shodan**:
   - Query for the target domain:
     ```
     hostname:example.com
     ```
   - Look for:
     - Open ports (e.g., 8080, 22).
     - Server banners (e.g., Apache 2.4.29).
     - Exposed services (e.g., SSH, FTP).
   - Example: `port:80 apache hostname:example.com`.
2. **Search with Censys**:
   - Query:
     ```
     http.title:"example.com"
     ```
   - Check for:
     - SSL certificates revealing subdomains.
     - Exposed admin interfaces (e.g., `/admin`).
3. **Analyze Results**:
   - Note IPs, ports, and software versions.
   - Cross-reference with target scope to confirm relevance.
4. **Verify with Burp Suite**:
   - Send requests to discovered endpoints:
     ```
     GET /admin HTTP/1.1
     Host: 192.168.1.1
     ```
   - Check for unauthorized access or sensitive data.

**Example Vulnerable Finding**:
- Shodan: `192.168.1.1:8080` running Tomcat with default admin page.
- Censys: SSL certificate for `internal.example.com`, revealing hidden subdomain.

**Remediation**:
- Close unnecessary ports and services.
- Use firewalls to restrict access to internal IPs.
- Update software to patch known vulnerabilities.

### **5. Verify Findings with Active Testing**

Actively test discovered URLs and endpoints to confirm information leakage, using tools like GoBuster and Burp Suite.

**Steps**:
1. **Enumerate Directories with GoBuster**:
   - Use a wordlist to find hidden files/directories:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
     ```
   - Output: Discovered paths (e.g., `/backup/`, `/config/`).
2. **Test URLs with Burp Suite**:
   - Capture requests to sensitive URLs:
     ```
     GET /.env HTTP/1.1
     Host: example.com
     ```
   - Check response for sensitive data (e.g., `DB_PASSWORD=secret123`).
3. **Check HTTP Headers**:
   - Analyze headers for information leakage:
     ```
     Server: Apache/2.4.29
     X-Powered-By: PHP/7.2.0
     ```
   - Note software versions for potential exploits.
4. **Document Findings**:
   - Save screenshots of exposed files, directories, or error messages.
   - Log URLs, response codes, and content in Burp Suite’s “Logger”.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=secret123
```

**Remediation**:
- Restrict directory listing in web server configurations (e.g., `Options -Indexes` in Apache).
- Remove or secure sensitive files (e.g., `.env`, `.bak`).
- Disable verbose headers (e.g., `ServerTokens Prod` in Apache).

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-01 with practical scenarios based on common information leakage patterns observed in penetration testing.

### **Test 1: Exposed Configuration Files**

Test for configuration files (e.g., `.env`, `config.php`) indexed by search engines.

**Steps**:
1. **Search for Files**:
   - Query:
     ```
     site:example.com filetype:env | filetype:conf | filetype:bak
     ```
   - Alternative: `inurl:(.env | config | backup) site:example.com`.
2. **Check Results**:
   - Look for files like `.env`, `wp-config.php.bak`, or `settings.conf`.
3. **Verify with cURL**:
   - Test accessibility:
     ```bash
     curl http://example.com/.env
     ```
4. **Analyze Impact**:
   - Check for credentials, API keys, or database details.

**Example Insecure Finding**:
- URL: `http://example.com/.env`
- Response:
  ```
  DB_HOST=localhost
  DB_USER=root
  DB_PASSWORD=admin123
  API_KEY=xyz123456789
  ```

**Example Secure Practice**:
- File `.env` protected via `.htaccess`:
  ```
  <Files .env>
      Order allow,deny
      Deny from all
  </Files>
  ```
- `robots.txt`:
  ```
  Disallow: /.env
  ```

**Remediation**:
- Store sensitive files outside the web root.
- Use environment variables for credentials.
- Implement access controls to block unauthorized access.

### **Test 2: Leaked Source Code or Backups**

Test for source code or backup files exposed via search engines or archives.

**Steps**:
1. **Search for Backups**:
   - Query:
     ```
     site:example.com filetype:sql | filetype:tar | filetype:zip inurl:(backup | dump)
     ```
2. **Check Wayback Machine**:
   - Enter `example.com/backup` in [archive.org](https://archive.org/web/).
   - Look for old backups (e.g., `backup.sql`).
3. **Verify with Burp Suite**:
   - Send request:
     ```
     GET /backup.sql HTTP/1.1
     Host: example.com
     ```
4. **Analyze Impact**:
   - Check for database schemas, user data, or source code.

**Example Insecure Finding**:
- URL: `http://example.com/backup.sql`
- Content: SQL dump with user table:
  ```
  INSERT INTO users (username, password) VALUES ('admin', 'hashed_password');
  ```

**Example Secure Practice**:
- Web server configuration (Nginx):
  ```
  location ~* \.(sql|zip|tar|bak)$ {
      deny all;
      return 403;
  }
  ```

**Remediation**:
- Remove or restrict access to backup files.
- Encrypt sensitive backups.
- Audit public archives for leaked data.

### **Test 3: Exposed Admin or Debug Pages**

Test for admin panels or debug pages indexed by search engines.

**Steps**:
1. **Search for Admin Pages**:
   - Query:
     ```
     site:example.com inurl:(admin | login | dashboard | phpinfo)
     ```
2. **Check Shodan/Censys**:
   - Query: `http.title:"admin" hostname:example.com`.
3. **Test Access with Burp Suite**:
   - Send request:
     ```
     GET /admin/login.php HTTP/1.1
     Host: example.com
     ```
4. **Analyze Impact**:
   - Check for default credentials or exposed functionality.

**Example Insecure Finding**:
- URL: `http://example.com/phpinfo.php`
- Response: PHP configuration details (e.g., `display_errors=On`).

**Example Secure Practice**:
- Apache configuration:
  ```
  <Location /admin>
      AuthType Basic
      AuthName "Restricted Area"
      AuthUserFile /etc/apache2/.htpasswd
      Require valid-user
  </Location>
  ```

**Remediation**:
- Require authentication for admin pages.
- Remove debug scripts (e.g., `phpinfo.php`).
- Use `robots.txt` to block indexing of sensitive paths.

### **Test 4: Employee or Internal Data Leakage**

Test for employee details or internal documentation exposed via search engines.

**Steps**:
1. **Search for Employee Data**:
   - Query:
     ```
     site:example.com filetype:pdf intext:(employee | directory | contact)
     ```
   - Use TheHarvester:
     ```bash
     theharvester -d example.com -b linkedin
     ```
2. **Check Public Profiles**:
   - Search: `site:linkedin.com "example.com"`.
3. **Verify with cURL**:
   - Test PDFs or directories:
     ```bash
     curl http://example.com/employee_directory.pdf
     ```
4. **Analyze Impact**:
   - Check for names, emails, or internal roles.

**Example Insecure Finding**:
- URL: `http://example.com/staff.pdf`
- Content: List of employee names and emails.

**Example Secure Practice**:
- Restrict access to internal documents:
  ```
  <Files *.pdf>
      Order allow,deny
      Deny from all
  </Files>
  ```

**Remediation**:
- Restrict internal documents to authenticated users.
- Train employees on OSINT risks.
- Monitor public platforms for leaked data.

## **Additional Tips**

- **Start Simple**: Begin with basic Google Dorks (e.g., `site:example.com`) to understand the target’s footprint.
- **Combine Tools**: Use TheHarvester for initial reconnaissance, then verify with GoBuster and Burp Suite.
- **Gray-Box Testing**: If documentation is available, check for references to internal systems or file structures.
- **Document Thoroughly**: Save all search queries, URLs, and responses in Burp Suite’s “Logger” or a text file.
- **Bypass Defenses**: Use alternate search engines (e.g., DuckDuckGo) or encoded queries to evade restrictions.
- **Stay Ethical**: Obtain explicit permission before testing and avoid accessing or sharing sensitive data.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat chronique for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).
