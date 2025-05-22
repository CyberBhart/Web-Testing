# **Review Webserver Metafiles for Information Leakage**

## **Overview**

Reviewing webserver metafiles for information leakage (WSTG-INFO-03) involves identifying and analyzing files created by web servers, development tools, or content management systems that may inadvertently expose sensitive information. These metafiles, such as `robots.txt`, `.git`, `.DS_Store`, or `sitemap.xml`, can reveal directory structures, hidden endpoints, sensitive files, or application details that aid attackers in reconnaissance. According to OWASP, analyzing these files is critical during the information-gathering phase to uncover misconfigurations or unintended disclosures without direct interaction with the application.

**Impact**: Exposed metafiles can lead to:
- Disclosure of hidden directories or sensitive files (e.g., `/admin`, `backup.sql`).
- Exposure of source code or configuration details (e.g., `.git` repositories).
- Insight into application structure or technologies, aiding further attacks.
- Identification of development or backup files that may contain credentials.

This guide provides a step-by-step methodology for reviewing webserver metafiles, adhering to OWASP’s WSTG-INFO-03, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for identifying and analyzing webserver metafiles, suitable for both novice and experienced testers:

- **cURL**: Command-line tool for retrieving metafiles and analyzing responses.
- **Burp Suite Community Edition**: Intercepts HTTP requests to inspect metafile content.
- **GoBuster**: Tool for enumerating directories and files, including metafiles.
- **DirBuster**: Alternative to GoBuster for brute-forcing file and directory names.
- **Wget**: Tool for recursively downloading metafiles or entire directories.
- **GitTools**: Suite for extracting and analyzing exposed `.git` repositories.
- **TheHarvester**: Open-source tool for gathering related metadata from search engines.
- **Wayback Machine (archive.org)**: Archives historical versions of metafiles.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite.
- **OWASP ZAP**: Open-source web proxy for automated metafile discovery.

### **Tool Setup Instructions**

1. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
2. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
3. **GoBuster**:
   - Install: `sudo apt install gobuster`.
   - Verify: `gobuster --version`.
   - Use wordlist: `/usr/share/wordlists/dirb/common.txt`.
4. **DirBuster**:
   - Download from [OWASP](https://sourceforge.net/projects/dirbuster/).
   - Run: `java -jar DirBuster.jar`.
   - Configure with wordlists (e.g., `directory-list-2.3-medium.txt`).
5. **Wget**:
   - Install on Linux: `sudo apt install wget`.
   - Install on Windows: Download from [gnu.org](https://www.gnu.org/software/wget/).
   - Verify: `wget --version`.
6. **GitTools**:
   - Clone from GitHub: `git clone https://github.com/internetwache/GitTools.git`.
   - Install dependencies: `pip install -r requirements.txt`.
   - Verify: `./gitdumper.sh --help`.
7. **TheHarvester**:
   - Install: `sudo apt install theharvester` or `pip install theharvester`.
   - Verify: `theharvester --help`.
8. **Wayback Machine**:
   - Access via [archive.org](https://archive.org/web/).
   - No setup required.
9. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite (127.0.0.1:8080).
10. **OWASP ZAP**:
    - Download from [owasp.org](https://www.zaproxy.org/download/).
    - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
    - Configure proxy: 127.0.0.1:8080.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-INFO-03, focusing on identifying and analyzing webserver metafiles to uncover information leakage using passive and active techniques.

### **1. Identify Common Metafiles**

Check for well-known metafiles that may reveal sensitive information.

**Steps**:
1. **Test Standard Metafiles with cURL**:
   - Query common metafiles:
     ```bash
     curl http://example.com/robots.txt
     curl http://example.com/sitemap.xml
     curl http://example.com/.DS_Store
     curl http://example.com/.git/HEAD
     ```
   - Check for 200 OK responses indicating file presence.
2. **Use Burp Suite**:
   - Configure browser to proxy through Burp Suite.
   - Visit `http://example.com/robots.txt` and check “HTTP History” for content.
   - Look for:
     - Disallowed directories (e.g., `/admin`).
     - Sitemap URLs (e.g., `/hidden_endpoint`).
     - Source control files (e.g., `.git/config`).
3. **Document Findings**:
   - Save file content, URLs, and response codes.
   - Note sensitive paths or references (e.g., `/backup` in `robots.txt`).

**Example Insecure Response**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
User-agent: *
Disallow: /admin
Disallow: /backup
```

**Remediation**:
- Minimize `robots.txt` entries to avoid disclosing sensitive paths:
  ```
  User-agent: *
  Disallow: /
  ```
- Remove or secure referenced directories.

### **2. Enumerate Metafiles with GoBuster**

Use brute-forcing tools to discover hidden or non-standard metafiles.

**Steps**:
1. **Run GoBuster**:
   - Enumerate files with a wordlist:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x txt,xml,git,DS_Store
     ```
   - Output: Discovered files (e.g., `/robots.txt`, `/.git/HEAD`).
2. **Use DirBuster**:
   - Launch DirBuster and set target: `http://example.com`.
   - Select wordlist and extensions (e.g., `.txt`, `.xml`).
   - Analyze results for metafiles.
3. **Verify Findings**:
   - Test discovered URLs with cURL:
     ```bash
     curl http://example.com/.git/config
     ```
   - Check for sensitive data (e.g., repository details).
4. **Document Results**:
   - Save URLs and file content in Burp Suite or a text file.

**Example Vulnerable Finding**:
- URL: `http://example.com/.git/config`
- Content:
  ```
  [core]
      repositoryformatversion = 0
      filemode = true
      bare = false
      logallrefupdates = true
  [remote "origin"]
      url = https://github.com/example/repo.git
  ```

**Remediation**:
- Block access to `.git` directories in Apache:
  ```
  <Directory ~ "\.git">
      Order allow,deny
      Deny from all
  </Directory>
  ```
- Remove exposed repositories from the web root.

### **3. Explore Historical Metafiles with Wayback Machine**

Use the Wayback Machine to find archived versions of metafiles that may contain sensitive information.

**Steps**:
1. **Access Wayback Machine**:
   - Go to [archive.org/web/](https://archive.org/web/).
   - Enter target URL (e.g., `http://example.com/robots.txt`).
2. **Browse Snapshots**:
   - Select different years/months to view historical metafiles.
   - Look for:
     - Old `robots.txt` with sensitive paths.
     - Archived `.git` or `.DS_Store` files.
3. **Extract URLs**:
   - Use `waybackurls`:
     ```bash
     waybackurls example.com > archived_urls.txt
     ```
   - Filter for metafiles (e.g., `robots.txt`, `sitemap.xml`).
4. **Verify Findings**:
   - Test archived URLs with cURL:
     ```bash
     curl http://example.com/old_sitemap.xml
     ```
   - Check if paths are still accessible.

**Example Vulnerable Finding**:
- Archived URL: `http://example.com/robots.txt` (2023 snapshot).
- Content:
  ```
  User-agent: *
  Disallow: /internal_api
  ```

**Remediation**:
- Audit archived content on archive.org.
- Request removal of sensitive snapshots via archive.org’s contact form.
- Secure current metafiles to prevent future leaks.

### **4. Analyze Exposed Git Repositories**

Investigate exposed `.git` directories to extract source code or configuration details.

**Steps**:
1. **Check for `.git` Directory**:
   - Query:
     ```bash
     curl http://example.com/.git/HEAD
     ```
   - Confirm response: `ref: refs/heads/main`.
2. **Use GitTools**:
   - Dump repository with GitDumper:
     ```bash
     ./gitdumper.sh http://example.com/.git/ /tmp/repo
     ```
   - Extract commit history:
     ```bash
     ./extractor.sh /tmp/repo /tmp/extracted
     ```
   - Output: Source code, configuration files, or credentials.
3. **Analyze Content**:
   - Search for sensitive data (e.g., API keys, passwords).
   - Example: `grep -r "password" /tmp/extracted`.
4. **Document Findings**:
   - Save extracted files and sensitive data (with permission).

**Example Vulnerable Finding**:
- File: `/tmp/extracted/config.php`
- Content:
  ```
  <?php
  define('DB_PASSWORD', 'secret123');
  ?>
  ```

**Remediation**:
- Restrict `.git` access in Nginx:
  ```
  location ~* \.git {
      deny all;
      return 403;
  }
  ```
- Move repositories outside the web root.

### **5. Leverage Search Engines for Metafile Discovery**

Use search engines to find indexed metafiles.

**Steps**:
1. **Craft Google Dork Queries**:
   - Search for metafiles:
     ```
     site:example.com filetype:txt inurl:(robots | sitemap)
     site:example.com inurl:(.git | .DS_Store)
     ```
2. **Use TheHarvester**:
   - Gather related metadata:
     ```bash
     theharvester -d example.com -b google
     ```
   - Look for references to metafiles.
3. **Verify Findings**:
   - Test URLs with Burp Suite:
     ```
     GET /.DS_Store HTTP/1.1
     Host: example.com
     ```
   - Check for directory listings or file metadata.
4. **Document Results**:
   - Save URLs and file content.

**Example Vulnerable Finding**:
- URL: `http://example.com/.DS_Store`
- Content: Directory structure with sensitive files (e.g., `backup.sql`).

**Remediation**:
- Block `.DS_Store` access in Apache:
  ```
  <Files .DS_Store>
      Order allow,deny
      Deny from all
  </Files>
  ```
- Use `.gitignore` to prevent metafile uploads.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-INFO-03 with practical scenarios based on common metafile leakage patterns observed in penetration testing.

### **Test 1: Sensitive Paths in robots.txt**

Test for `robots.txt` revealing hidden directories or files.

**Steps**:
1. **Access robots.txt**:
   - Query:
     ```bash
     curl http://example.com/robots.txt
     ```
   - Check for `Disallow` entries.
2. **Test Disallowed Paths**:
   - Query:
     ```bash
     curl http://example.com/admin
     ```
   - Verify if path is accessible.
3. **Use Burp Suite**:
   - Send requests to identified paths and analyze responses.

**Example Insecure Finding**:
- URL: `http://example.com/robots.txt`
- Content:
  ```
  User-agent: *
  Disallow: /admin
  Disallow: /config
  ```

**Example Secure Configuration**:
- Minimal `robots.txt`:
  ```
  User-agent: *
  Disallow: /
  ```

**Remediation**:
- Avoid listing sensitive paths in `robots.txt`.
- Secure referenced directories with authentication.

### **Test 2: Exposed .git Repository**

Test for an accessible `.git` directory exposing source code.

**Steps**:
1. **Check .git Access**:
   - Query:
     ```bash
     curl http://example.com/.git/config
     ```
   - Confirm 200 OK response.
2. **Extract Repository**:
   - Use GitTools:
     ```bash
     ./gitdumper.sh http://example.com/.git/ /tmp/repo
     ```
3. **Analyze Content**:
   - Search for credentials:
     ```bash
     grep -r "password" /tmp/repo
     ```

**Example Insecure Finding**:
- File: `/tmp/repo/api_key.txt`
- Content: `API_KEY=xyz123456789`

**Example Secure Configuration**:
- Nginx `nginx.conf`:
  ```
  location ~* \.git {
      deny all;
      return 403;
  }
  ```

**Remediation**:
- Remove `.git` directories from the web root.
- Use `.htaccess` or server rules to block access.

### **Test 3: .DS_Store File Exposure**

Test for `.DS_Store` files revealing directory structures.

**Steps**:
1. **Check for .DS_Store**:
   - Query:
     ```bash
     curl http://example.com/.DS_Store
     ```
   - Confirm file presence.
2. **Analyze with Wget**:
   - Download:
     ```bash
     wget http://example.com/.DS_Store
     ```
   - Parse with a hex editor or `strings`:
     ```bash
     strings .DS_Store
     ```
3. **Test Listed Paths**:
   - Query identified files (e.g., `/backup.zip`).

**Example Insecure Finding**:
- File: `.DS_Store`
- Content: References to `/internal_docs/`.

**Example Secure Configuration**:
- Apache `.htaccess`:
  ```
  <Files .DS_Store>
      Order allow,deny
      Deny from all
  </Files>
  ```

**Remediation**:
- Add `.DS_Store` to `.gitignore`.
- Configure server to block metafile access.

### **Test 4: Archived Sitemap.xml**

Test for historical `sitemap.xml` files exposing hidden endpoints.

**Steps**:
1. **Check Wayback Machine**:
   - Enter `http://example.com/sitemap.xml` in [archive.org](https://archive.org/web/).
   - Look for old sitemaps.
2. **Extract URLs**:
   - Use `waybackurls`:
     ```bash
     waybackurls example.com | grep sitemap.xml
     ```
3. **Test URLs**:
   - Query:
     ```bash
     curl http://example.com/hidden_endpoint
     ```

**Example Insecure Finding**:
- Archived URL: `http://example.com/sitemap.xml`
- Content: `<url><loc>/api/v1/test</loc></url>`

**Example Secure Configuration**:
- Restrict sitemap access:
  ```
  <Files sitemap.xml>
      Order allow,deny
      Deny from all
  </Files>
  ```

**Remediation**:
- Limit sitemap content to public pages.
- Monitor archives for sensitive data.

## **Additional Tips**

- **Start Simple**: Check standard metafiles (`robots.txt`, `sitemap.xml`) before brute-forcing.
- **Combine Tools**: Use GoBuster for discovery and GitTools for `.git` analysis.
- **Gray-Box Testing**: If documentation is available, look for references to metafiles in source code.
- **Document Thoroughly**: Save all metafile content, URLs, and responses in Burp Suite or a report.
- **Bypass Defenses**: Use case variations (e.g., `ROBOTS.TXT`) to evade WAFs.
- **Stay Ethical**: Obtain explicit permission before accessing or extracting sensitive files.
- **Follow Best Practices**: Refer to OWASP’s Information Gathering Cheat Sheet for additional techniques: [OWASP Cheat Sheet](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering).