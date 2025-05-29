# 🌐 Web Testing Guides

Welcome to the **Web Testing Guides** repository — a curated collection of hands-on, practical walkthroughs focused on real-world web application security testing.

This resource is built upon the **OWASP Web Security Testing Guide (WSTG)** methodology and is ideal for learners, bug bounty hunters, and cybersecurity professionals looking to practice, test, and refine their skills with structured and scenario-based approaches.

---

## 🧠 Why This Repo?

Starting out in web app testing can be overwhelming — especially with scattered resources and unclear testing sequences. This repository bridges that gap by providing:

- A structured, OWASP-aligned roadmap  
- Actionable testing steps and examples  
- Personal notes from real testing experiences  
- A growing knowledge base you can reference and expand  

Whether you're prepping for certifications like **CEH**, **OSCP**, **eJPT**, or diving into **bug bounty** programs — these guides are made to accelerate your learning.

---

## 📑 Table of Contents

### 1. Information Gathering
- [WSTG-INFO-01: Search Engine Discovery and Reconnaissance](./01-Info-Gathering/01-Search-Engine-Discovery-and-Reconn.md)
- [WSTG-INFO-02: Fingerprint Web Server](./01-Info-Gathering/02-Fingerprint-WebServer.md)
- [WSTG-INFO-03: Review Webserver Metafiles](./01-Info-Gathering/03-Review-Webserver-Metafiles.md)
- [WSTG-INFO-04: Enumerate Applications on Webserver](./01-Info-Gathering/04-Enum-Apps-on-Webserver.md)
- [WSTG-INFO-05: Review Webpage Content](./01-Info-Gathering/05-Review-Webpage-Content.md)
- [WSTG-INFO-06: Identify Application Entry Points](./01-Info-Gathering/06-Identify-App-Entry-Points.md)
- [WSTG-INFO-07: Map Execution Paths Through Application](./01-Info-Gathering/07-Map-Execution-Paths-Through-App.md)
- [WSTG-INFO-08: Fingerprint Web Application Framework](./01-Info-Gathering/08-Fingerprint-Web-Apps-Framework.md)
- [WSTG-INFO-09: Fingerprint Web Application](./01-Info-Gathering/09-Fingerprint-Web-Application.md)
- [WSTG-INFO-10: Map Application Architecture](./01-Info-Gathering/10-Map-App-Architecture.md)

### 2. Configuration and Deployment Management Testing
- [WSTG-CONF-01: Test Network Infrastructure Configuration](./02-Config-and-Deploy-Management-Testing/01-Test-Network-Infra-Configuration.md)
- [WSTG-CONF-02: Test Application Platform Configuration](./02-Config-and-Deploy-Management-Testing/02-Test-Application-Platform-Config.md)
- [WSTG-CONF-03: Test File Extensions Handling for Sensitive Information](./02-Config-and-Deploy-Management-Testing/03-Test-File-Extensions-Handling-for-Sensitive-Information.md)
- [WSTG-CONF-04: Review Old Backup for Sensitive Information](./02-Config-and-Deploy-Management-Testing/04-Review-Old-Backup-for-Sensitive-Info.md)
- [WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces](./02-Config-and-Deploy-Management-Testing/05-Enum-Infra-and-App-Admin-Interfaces.md)
- [WSTG-CONF-06: Testing for Insecure HTTP Methods](./02-Config-and-Deploy-Management-Testing/06-Testing-for-Insecure-HTTP-Methods.md)
- [WSTG-CONF-07: Testing for HTTP Strict Transport Security](./02-Config-and-Deploy-Management-Testing/07-Testing-for-HTTP-Strict-Transport-Security.md)
- [WSTG-CONF-08: Testing for RIA Cross Domain Policy](./02-Config-and-Deploy-Management-Testing/08-Testing-for-RIA-Cross-Domain-Policy.md)
- [WSTG-CONF-09: Testing for File Permission](./02-Config-and-Deploy-Management-Testing/09-Testing-for-File-Permission.md)
- [WSTG-CONF-10: Testing for Subdomain Takeover](./02-Config-and-Deploy-Management-Testing/10-Testing-for-Subdomain-Takeover.md)
- [WSTG-CONF-11: Testing Cloud Storage](./02-Config-and-Deploy-Management-Testing/11-Testing-Cloud-Storage.md)
- [WSTG-CONF-12: Testing for Content Security Policy](./02-Config-and-Deploy-Management-Testing/12-Testing-for-Content-Security-Policy.md)

### 3. Identity Management Testing
- [WSTG-IDNT-01: Test Role Definitions](./03-Identity-Management-Testing/01-Test-Role-Definitions.md)
- [WSTG-IDNT-02: Test User Registration Process](./03-Identity-Management-Testing/02-Test-User-Registration-Process.md)
- [WSTG-IDNT-03: Test Account Provisioning Process](./03-Identity-Management-Testing/03-Test-Account-Provisioning-Process.md)
- [WSTG-IDNT-04: Testing Account Enumeration and Guessable User Account](./03-Identity-Management-Testing/04-Testing-Account-Enum-and-Guessable-User-Account.md)
- [WSTG-IDNT-05: Testing Weak or Unenforced Username Policy](./03-Identity-Management-Testing/05-Testing-Weak-Unenforced-Username-Policy.md)

### 4. Authentication Testing
- [WSTG-ATHN-01: Testing for Credentials Transported via Encrypted Channel](./04-Authentication-Testing/01-Testing-for-Creds-Transported-via-Encrypted-Channel.md)
- [WSTG-ATHN-02: Testing for Default Credentials](./04-Authentication-Testing/02-Testing-for-Default-Creds.md)
- [WSTG-ATHN-03: Testing for Weak Lockout Mechanism](./04-Authentication-Testing/03-Testing-for-Weak-Lockout-Mechanism.md)
- [WSTG-ATHN-04: Testing for Bypassing Authentication Schema](./04-Authentication-Testing/04-Testing-for-Bypassing-Authentication-Schema.md)
- [WSTG-ATHN-05: Testing for Vulnerable Remember Password](./04-Authentication-Testing/05-Testing-for-Vulnerable-Remember-Password.md)
- [WSTG-ATHN-06: Testing for Weak Browser Cache](./04-Authentication-Testing/06-Testing-for-Weak-Browser-Cache.md)
- [WSTG-ATHN-07: Testing for Weak Password Policy](./04-Authentication-Testing/07-Testing-for-Weak-Password-Policy.md)
- [WSTG-ATHN-08: Testing for Weak Security Question/Answer](./04-Authentication-Testing/08-Testing-for-Weak-Security-QA.md)
- [WSTG-ATHN-09: Testing for Weak Password Change or Reset Function](./04-Authentication-Testing/09-Testing-for-Weak-Password-Change-Reset-Function.md)
- [WSTG-ATHN-10: Testing for Weaker Authentication in Alternative Channel](./04-Authentication-Testing/10-Testing-for-Weaker-Auth-in-Alternative-Channel.md)

### 5. Authorization Testing
- [WSTG-AUTH-01: Test Directory Traversal and File Include](./05-Authorization-Testing/01-Test-Directory-Traversal-and-File-Include.md)
- [WSTG-AUTH-02: Test Bypassing Authorization Schema](./05-Authorization-Testing/02-Test-Bypassing-Authorization-Schema.md)
- [WSTG-AUTH-03: Testing for Privilege Escalation](./05-Authorization-Testing/03-Testing-for-Privilege-Escalation.md)
- [WSTG-AUTH-04: Testing for Insecure Direct Object References (IDOR)](./05-Authorization-Testing/04-Testing-for-IDOR.md)
- [WSTG-AUTH-05: Testing for OAuth Weakness](./05-Authorization-Testing/05-Testing-for-OAuth-Weakness.md)
- [WSTG-AUTH-06: Testing for OAuth Authorization Server Weaknesses](./05-Authorization-Testing/06-Testing-for-OAuth-Authorization-Server-Weaknesses.md)
- [WSTG-AUTH-07: Testing for OAuth Client Weakness](./05-Authorization-Testing/07-Testing-for-OAuth-Client-Weakness.md)

### 6. Session Management Testing
- [WSTG-SESS-01: Test Session Management Schema](./06-Session-Management-Testing/01-Test-Session-Management-Schema.md)
- [WSTG-SESS-02: Testing for Cookies Attributes](./06-Session-Management-Testing/02-Testing-for-Cookies-Attributes.md)
- [WSTG-SESS-03: Testing for Session Fixation](./06-Session-Management-Testing/03-Testing-for-Session-Fixation.md)
- [WSTG-SESS-04: Testing for Exposed Session Variables](./06-Session-Management-Testing/04-Testing-for-Exposed-Session-Variables.md)
- [WSTG-SESS-05: Testing for Cross-Site Request Forgery (CSRF)](./06-Session-Management-Testing/05-Testing-for-CSRF.md)
- [WSTG-SESS-06: Testing for Logout Functionality](./06-Session-Management-Testing/06-Testing-for-Logout-Functionality.md)
- [WSTG-SESS-07: Testing for Session Timeout](./06-Session-Management-Testing/07-Testing-for-Session-Timeout.md)
- [WSTG-SESS-08: Testing for Session Puzzling](./06-Session-Management-Testing/08-Testing-for-Session-Puzzling.md)
- [WSTG-SESS-09: Testing for Session Hijacking](./06-Session-Management-Testing/09-Testing-for-Session-Hijacking.md)

### 7. Input Validation Testing
- [WSTG-INPV-01: Testing for Reflected XSS](./07-Input-Validation-Testing/01-Testing-for-Reflected-XSS.md)
- [WSTG-INPV-02: Testing for Stored XSS](./07-Input-Validation-Testing/02-Testing-for-Stored-XSS.md)
- [WSTG-INPV-03: Testing for HTTP Verb Tampering](./07-Input-Validation-Testing/03-Testing-for-HTTP-Verb-Tampering.md)
- [WSTG-INPV-04: Testing for HTTP Parameter Pollution (HPP) Vulnerabilities](./07-Input-Validation-Testing/04-Testing-for-HPP-Vulnerabilities.md)
- [WSTG-INPV-05: Testing for SQL Injection](./07-Input-Validation-Testing/05-Testing-for-SQL-Injection.md)
- [WSTG-INPV-06: Testing for LDAP Injection](./07-Input-Validation-Testing/06-Testing-for-LDAP-Injection.md)
- [WSTG-INPV-07: Testing for XML Injection](./07-Input-Validation-Testing/07-Testing-for-XML-Injection.md)
- [WSTG-INPV-08: Testing for SSI Injection](./07-Input-Validation-Testing/08-Testing-for-SSI-Injection.md)
- [WSTG-INPV-09: Testing for XPath Injection](./07-Input-Validation-Testing/09-Testing-for-XPath-Injection.md)
- [WSTG-INPV-10: Testing for IMAP/SMTP Injection](./07-Input-Validation-Testing/10-Testing-for-IMAP-SMTP-Injection.md)
- [WSTG-INPV-11: Testing for Code Injection (LFI/RFI)](./07-Input-Validation-Testing/11-Testing-for-Code-Injection-LFI-RFI.md)
- [WSTG-INPV-12: Testing for Command Injection](./07-Input-Validation-Testing/12-Testing-for-Command-Injection.md)
- [WSTG-INPV-13: Testing for Format String Injection](./07-Input-Validation-Testing/13-Testing-for-Format-String-Injection.md)
- [WSTG-INPV-14: Testing for Incubated Vulnerabilities](./07-Input-Validation-Testing/14-Testing-for-Incubated-Vulnerabilities.md)
- [WSTG-INPV-15: Testing for HTTP Splitting and Smuggling](./07-Input-Validation-Testing/15-Testing-for-HTTP-Splitting-and-Smuggling.md)
- [WSTG-INPV-16: Testing for HTTP Incoming Requests](./07-Input-Validation-Testing/16-Testing-for-HTTP-Incoming-Requests.md)
- [WSTG-INPV-17: Testing for Host Header Injection](./07-Input-Validation-Testing/17-Testing-for-Host-Header-Injection.md)
- [WSTG-INPV-18: Testing for Server-Side Template Injection (SSTI)](./07-Input-Validation-Testing/18-Testing-for-SSTI.md)
- [WSTG-INPV-20: Testing for Server-Side Request Forgery (SSRF)](./07-Input-Validation-Testing/20-Testing-for-SSRF.md)
- [WSTG-INPV-21: Testing for Mass Assignment Vulnerabilities](./07-Input-Validation-Testing/21-Testing-for-Mass-Assignment-Vulnerabilities.md)

### 8. Testing for Error Handling
- [WSTG-ERRH-01: Test Improper Error Handling](./08-Testing-for-Error-Handling/01-Test-Improper-Error-Handling.md)
- [WSTG-ERRH-02: Testing for Stack Traces](./08-Testing-for-Error-Handling/02-Testing-for-Stack-Traces.md)

### 9. Testing Weak Cryptography
- [WSTG-CRYP-01: Testing for Weak TLS](./09-Testing-Weak-Cryptography/01-Testing-for-Weak-TLS.md)
- [WSTG-CRYP-02: Testing for Padding Oracle](./09-Testing-Weak-Cryptography/02-Testing-for-Padding-Oracle.md)
- [WSTG-CRYP-03: Test Information Sent via Unencrypted Channels](./09-Testing-Weak-Cryptography/03-Test-Info-Sent-via-Unencrypted-Channels.md)
- [WSTG-CRYP-04: Testing for Weak Encryption](./09-Testing-Weak-Cryptography/04-Testing-for-Weak-Encryption.md)

### 10. Business Logic Testing
- [WSTG-BUSL-01: Test Business Logic Data Validation](./10-Business-Logic-Testing/01-Test-Business-Logic-Data-Validation.md)
- [WSTG-BUSL-02: Test Ability to Forge Requests](./10-Business-Logic-Testing/02-Test-Ability-to-Forge-Requests.md)
- [WSTG-BUSL-03: Test Integrity Checks](./10-Business-Logic-Testing/03-Test-Integrity-Checks.md)
- [WSTG-BUSL-04: Test Process Timing](./10-Business-Logic-Testing/04-Test-Process-Timing.md)
- [WSTG-BUSL-05: Test Number of Times a Function Can Be Used](./10-Business-Logic-Testing/05-Test-Times-a-Function-Can-Be-Useds.md)
- [WSTG-BUSL-06: Test Circumvention of Workflows](./10-Business-Logic-Testing/06-Test-Circumvention-of-Workflows.md)
- [WSTG-BUSL-07: Test Defenses Against Application Misuse](./10-Business-Logic-Testing/07-Test-Defenses-Against-App-Misuse.md)
- [WSTG-BUSL-08: Test Unexpected File Upload Types](./10-Business-Logic-Testing/08-Test-Unexpected-File-Upload-Types.md)
- [WSTG-BUSL-09: Test Upload of Malicious Files](./10-Business-Logic-Testing/09-Test-Upload-of-Malicious-Files.md)

### 11. Client-Side Testing
- [WSTG-CLNT-01: Test DOM-Based XSS](./11-Client-Side-Testing/01-Test-DOM-Based-XSS.md)
- [WSTG-CLNT-02: Test JavaScript Execution](./11-Client-Side-Testing/02-Test-JavaScript-Execution.md)
- [WSTG-CLNT-03: Test HTML Injection](./11-Client-Side-Testing/03-Test-HTML-Injection.md)
- [WSTG-CLNT-04: Test Client-Side URL Redirect Vulnerabilities](./11-Client-Side-Testing/04-Test-Client-Side-URL-Redirect-Vulnerabilities.md)
- [WSTG-CLNT-05: Test CSS Injection Vulnerabilities](./11-Client-Side-Testing/05-Test-CSS-Injection-Vulnerabilities.md)
- [WSTG-CLNT-06: Test Client-Side Resource Manipulation](./11-Client-Side-Testing/06-Test-Client-Side-Resource-Manipulation.md)
- [WSTG-CLNT-07: Test CORS Vulnerabilities](./11-Client-Side-Testing/07-Tes-CORS-Vulnerabilities.md)
- [WSTG-CLNT-08: Test Cross-Site Flash Vulnerabilities](./11-Client-Side-Testing/08-Test-Cross-Site-Flash-Vulnerabilities.md)
- [WSTG-CLNT-09: Testing for Clickjacking](./11-Client-Side-Testing/09-Testing-for-Clickjacking.md)
- [WSTG-CLNT-10: Test WebSockets Vulnerabilities](./11-Client-Side-Testing/10-Test-WebSockets-Vulnerabilities.md)
- [WSTG-CLNT-11: Test Web Messaging Vulnerabilities](./11-Client-Side-Testing/11-Test-Web-Messaging-Vulnerabilities.md)
- [WSTG-CLNT-12: Test Browser Storage Vulnerabilities](./11-Client-Side-Testing/12-Test-Browser-Storage-Vulnerabilities.md)
- [WSTG-CLNT-13: Testing for Cross-Site Script Inclusion (XSSI)](./11-Client-Side-Testing/13-Testing-for-XSSI.md)
- [WSTG-CLNT-14: Testing for Reverse Tabnabbing](./11-Client-Side-Testing/14-Testing-for-Reverse-Tabnabbing.md)

### 12. API Testing
- [WSTG-APIT-01: API Security Testing](./12-API-Testing/01-API-Security-Testing.md)

---

## ⚠️ Responsible Usage Notice

These guides are intended for use **only in authorized, legal, and controlled environments** such as personal labs or explicitly permitted test systems.  
Improper or unauthorized use of these testing techniques can have serious legal and ethical consequences. Please see [`SECURITY.md`](./SECURITY.md) for detailed responsible usage guidelines.

---

## 📄 License

This project is licensed under the **MIT License**. See [`LICENSE`](./LICENSE) for full details.

---

## 📬 About the Author

This repository and its resources are created and maintained by Bhart Verma, a passionate Cybersecurity Analyst dedicated to building practical learning projects and sharing knowledge.

Check out my portfolio for more about my skills and projects: [https://CyberBhart.github.io/portfolio/](https://CyberBhart.github.io/portfolio/)

---

*Happy testing and keep learning! 🚀*
