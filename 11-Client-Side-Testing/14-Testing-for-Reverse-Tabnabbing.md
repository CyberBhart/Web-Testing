# Testing for Reverse Tabnabbing Vulnerabilities

## Overview

Testing for Reverse Tabnabbing vulnerabilities involves verifying that a web application prevents attackers from manipulating the parent window or tab when a user navigates to an external link. According to OWASP (WSTG-CLNT-14), reverse tabnabbing occurs when an external link opened in a new tab (via `target="_blank"`) allows the new page to control the original page using `window.opener`, potentially redirecting it to a malicious site. This guide provides a hands-on methodology to identify and test reverse tabnabbing vulnerabilities, focusing on insecure link attributes, `window.opener` manipulation, and weak protections, with tools, commands, and remediation strategies.

**Impact**: Reverse tabnabbing vulnerabilities can lead to:
- Phishing attacks by redirecting the original page to a malicious site.
- Session hijacking or data theft via unauthorized navigation.
- User trust erosion due to deceptive redirects.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-14, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as creating malicious pages to test `window.opener` manipulation may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing reverse tabnabbing vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP responses to analyze link attributes and JavaScript.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use DOM Invader to detect `target="_blank"` usage:
    1. Go to Extensions tab.
    2. Add DOM Invader and enable it in the browser.
  - **Note**: Check HTML in Response tab for link attributes.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for analyzing HTML and JavaScript for insecure links.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Passive Scan to flag links with `target="_blank"` without `rel="noopener"`.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects link attributes and `window.opener` behavior.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Elements tab to find `<a>` tags with `target="_blank"` and Console to test `window.opener`.
  - Example command to check `window.opener`:
    ```javascript
    console.log('window.opener exists:', !!window.opener);
    ```
  - **Tip**: Firefox’s 2025 DOM inspector enhancements improve link attribute analysis.

- **cURL and HTTPie**: Send HTTP requests to retrieve pages with external links.
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
      curl -i http://example.com/page
      # HTTPie
      http http://example.com/page
      ```

- **Reverse Tabnabbing PoC Generator**: A custom HTML page to test `window.opener` manipulation.
  - Example PoC (see Testing Methodology).
  - **Note**: Host PoCs on a controlled server for ethical testing.

- **Test Payloads**: Curated payloads for testing.
  - Sample payloads:
    - `window.opener.location='http://malicious.com'`
    - `window.opener.document.body.innerHTML='Phishing page'`
  - Resource: [OWASP Reverse Tabnabbing Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#tabnabbing).
  - **Tip**: Test payloads in a malicious page to verify `window.opener` control.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-14, testing reverse tabnabbing vulnerabilities across insecure link attributes, `window.opener` manipulation, protection bypasses, parameter-based attacks, and external link behavior.

### 1. Test Insecure Link Attributes

**Objective**: Ensure external links with `target="_blank"` include `rel="noopener"` or `rel="noreferrer"`.

**Steps**:
1. Identify external links:
   - Use Elements tab to find `<a>` tags with `target="_blank"`.
   - Console command:
     ```javascript
     document.querySelectorAll('a[target="_blank"]').forEach(a => console.log(a.outerHTML));
     ```
2. Check for `rel` attributes:
   - Look for missing `rel="noopener"` or `rel="noreferrer"`.
3. Test a link manually:
   - Click an external link and run in the new tab:
     ```javascript
     console.log('window.opener:', window.opener);
     ```

**Example Secure Response**:
```html
<a href="http://external.com" target="_blank" rel="noopener">Link</a>
```
`window.opener` is `null`.

**Example Vulnerable Response**:
```html
<a href="http://external.com" target="_blank">Link</a>
```
`window.opener` references the parent window.

**Remediation**:
- Add `rel="noopener"`:
  ```html
  <a href="http://external.com" target="_blank" rel="noopener noreferrer">Link</a>
  ```
- Server-side rendering (e.g., in Node.js):
  ```javascript
  res.send('<a href="http://external.com" target="_blank" rel="noopener">Link</a>');
  ```

**Tip**: Save link attributes and `window.opener` logs in a report.

### 2. Test `window.opener` Manipulation

**Objective**: Ensure a malicious page cannot manipulate the parent window via `window.opener`.

**Steps**:
1. Create a malicious page:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
     <script>
       if (window.opener) {
         window.opener.location = 'http://malicious.com/phishing';
       }
     </script>
   </body>
   </html>
   ```
2. Host the page (e.g., `python3 -m http.server 8000`).
3. Open a target page with a vulnerable link:
   ```html
   <a href="http://localhost:8000/malicious.html" target="_blank">External Link</a>
   ```
4. Click the link and check if the original page redirects to `malicious.com`.

**Example Secure Response**:
```html
<a href="http://external.com" target="_blank" rel="noopener">Link</a>
```
No redirect; `window.opener` is `null`.

**Example Vulnerable Response**:
```html
<a href="http://external.com" target="_blank">Link</a>
```
Original page redirects to `malicious.com`.

**Remediation**:
- Use `rel="noopener"`:
  ```html
  <a href="http://external.com" target="_blank" rel="noopener">Link</a>
  ```
- JavaScript fallback:
  ```javascript
  document.querySelectorAll('a[target="_blank"]').forEach(a => {
    a.rel = 'noopener';
  });
  ```

**Tip**: Save PoC code and redirect screenshots in a report.

### 3. Test Protection Bypasses

**Objective**: Ensure protections against reverse tabnabbing cannot be bypassed.

**Steps**:
1. Identify protections:
   - Search for `rel="noopener"` or JavaScript handling `window.opener`.
2. Test bypass with dynamic links:
   ```html
   <script>
     const a = document.createElement('a');
     a.href = 'http://malicious.com';
     a.target = '_blank';
     document.body.appendChild(a);
     a.click();
   </script>
   ```
3. Check `window.opener` in the malicious page:
   ```javascript
   console.log(window.opener);
   ```
4. Test with `window.open`:
   ```javascript
   window.open('http://malicious.com', '_blank');
   ```

**Example Secure Response**:
```javascript
// Modern browsers default to noopener
window.open('http://external.com', '_blank'); // window.opener is null
```
No manipulation possible.

**Example Vulnerable Response**:
```javascript
// Older or misconfigured code
window.open('http://external.com', '_blank'); // window.opener exists
```
Parent window manipulated.

**Remediation**:
- Ensure modern browser behavior:
  ```html
  <a href="http://external.com" target="_blank" rel="noopener">Link</a>
  ```
- Explicitly nullify `window.opener`:
  ```javascript
  const win = window.open('http://external.com', '_blank');
  if (win) win.opener = null;
  ```

**Tip**: Save bypass attempts and `window.opener` logs in a report.

### 4. Test Parameter-Based Attacks

**Objective**: Ensure URL parameters do not introduce reverse tabnabbing vulnerabilities.

**Steps**:
1. Identify dynamic links:
   - Look for `<a>` tags using URL parameters (e.g., `?url=`).
2. Inject a malicious URL:
   ```bash
   http "http://example.com/page?url=http://malicious.com"
   ```
3. Check link attributes:
   - Verify if the generated link lacks `rel="noopener"`.
   - Example vulnerable link:
     ```html
     <a href="http://malicious.com" target="_blank">Link</a>
     ```
4. Test `window.opener` manipulation as in Step 2.

**Example Secure Response**:
```html
<a href="http://malicious.com" target="_blank" rel="noopener">Link</a>
```
No manipulation possible.

**Example Vulnerable Response**:
```html
<a href="http://malicious.com" target="_blank">Link</a>
```
Parent window redirected.

**Remediation**:
- Sanitize URL parameters:
  ```javascript
  const safeUrl = encodeURIComponent(url);
  document.write(`<a href="${safeUrl}" target="_blank" rel="noopener">Link</a>`);
  ```
- Always include `rel="noopener"`:
  ```javascript
  a.setAttribute('rel', 'noopener');
  ```

**Tip**: Save parameter payloads and link attributes in a report.

### 5. Test External Link Behavior

**Objective**: Ensure all external links are safe against reverse tabnabbing.

**Steps**:
1. Crawl the site for external links:
   - Use ZAP’s Spider or Burp’s Crawler to find `<a>` tags.
   - Console command:
     ```javascript
     document.querySelectorAll('a[href^="http"]').forEach(a => console.log(a.outerHTML));
     ```
2. Check for `target="_blank"` without `rel="noopener"`:
   - Manually inspect or use ZAP’s Passive Scan.
3. Test a sample link with the PoC from Step 2:
   - Verify if `window.opener` allows manipulation.

**Example Secure Response**:
```html
<a href="http://external.com" target="_blank" rel="noopener noreferrer">Link</a>
```
No vulnerability.

**Example Vulnerable Response**:
```html
<a href="http://external.com" target="_blank">Link</a>
```
Parent window at risk.

**Remediation**:
- Enforce `rel="noopener"` globally:
  ```javascript
  document.querySelectorAll('a[target="_blank"]').forEach(a => a.rel = 'noopener');
  ```
- Use Content Security Policy (CSP):
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self';">
  ```

**Tip**: Save external link list and test results in a report.
