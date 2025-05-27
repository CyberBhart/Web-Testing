# Testing for OAuth Authorization Server Weaknesses

## Overview

Testing for OAuth Authorization Server Weaknesses involves verifying that the OAuth authorization server securely handles token issuance, client authentication, and authorization flows to prevent unauthorized access or token misuse. According to OWASP and OAuth 2.0/2.1 best practices, vulnerabilities such as weak client authentication, misconfigured token endpoints, insufficient token validation, insecure token lifetimes, or server misconfigurations can compromise the authorization server. This test focuses on evaluating client authentication, token endpoint security, token validation, token lifetimes, CORS policies, and token revocation to ensure robust server-side protection.

**Impact**: Authorization server weaknesses can lead to:
- Unauthorized token issuance, enabling access to protected resources.
- Token misuse or session disruption.
- Non-compliance with security standards (e.g., GDPR, PCI DSS).

This guide provides a practical, hands-on methodology for testing OAuth authorization server vulnerabilities, adhering to OAuth 2.0/2.1 security best practices and OWASP guidelines, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as manipulating OAuth endpoints or tokens may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing OAuth authorization server weaknesses, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates requests to test client authentication, token validation, and revocation.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test token endpoints, CORS policies, and token lifetimes.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for testing OAuth authorization server vulnerabilities, focusing on client authentication, token endpoint misconfigurations, token validation, token lifetimes, server misconfigurations, CORS policies, and token revocation.

### 1. Test Weak Client Authentication with Burp Suite

**Objective**: Ensure client authentication cannot be bypassed by omitting or forging credentials.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a token request:
   ```bash
   HTTP History -> Select POST /oauth/token -> Send to Repeater
   ```
3. Remove or forge client credentials:
   ```bash
   Repeater -> Remove client_secret -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects invalid credentials.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "invalid_client", "error_description": "Missing or invalid client credentials"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"access_token": "xyz", "token_type": "Bearer"}
```

**Remediation**:
- Validate client credentials (Node.js):
  ```javascript
  app.post('/oauth/token', (req, res) => {
      const { client_id, client_secret } = req.body;
      if (!isValidClient(client_id, client_secret)) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'Missing or invalid client credentials' });
      }
      res.json({ access_token: generateToken() });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Token Endpoint Misconfiguration with cURL

**Objective**: Ensure the token endpoint rejects invalid or missing parameters.

**Steps**:
1. Test a token request with valid parameters:
   ```bash
   curl -i -X POST -d "client_id=public_client&client_secret=secret&grant_type=authorization_code&code=auth_code" http://example.com/oauth/token
   ```
2. Test with missing or invalid parameters:
   ```bash
   curl -i -X POST -d "client_id=public_client&grant_type=authorization_code" http://example.com/oauth/token
   ```
3. Analyze responses; expected secure response rejects invalid requests.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "invalid_request", "error_description": "Missing required parameters"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"access_token": "xyz", "token_type": "Bearer"}
```

**Remediation**:
- Validate endpoint parameters (Python/Flask):
  ```python
  @app.post('/oauth/token')
  def token():
      required = ['client_id', 'client_secret', 'grant_type', 'code']
      if not all(k in request.form for k in required):
          return jsonify({'error': 'invalid_request', 'error_description': 'Missing required parameters'}), 400
      return jsonify({'access_token': generate_token()})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Insufficient Token Validation with cURL

**Objective**: Ensure invalid or expired tokens are rejected.

**Steps**:
1. Capture a valid access token and test a protected resource:
   ```bash
   curl -i -H "Authorization: Bearer xyz" http://example.com/api/user
   ```
2. Test with an invalid or expired token:
   ```bash
   curl -i -H "Authorization: Bearer invalid_token" http://example.com/api/user
   ```
3. Analyze responses; expected secure response rejects invalid tokens.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "invalid_token", "error_description": "Token is invalid or expired"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"user_data": {...}}
```

**Remediation**:
- Validate tokens (Node.js):
  ```javascript
  app.get('/api/user', (req, res) => {
      const token = req.headers.authorization?.split(' ')[1];
      if (!isValidToken(token)) {
          return res.status(401).json({ error: 'invalid_token', error_description: 'Token is invalid or expired' });
      }
      res.json({ user_data: getUserData() });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Insecure Token Lifetimes with Burp Suite

**Objective**: Ensure access tokens have short lifetimes to minimize misuse.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Capture a token request and note the token’s expiry:
   ```bash
   HTTP History -> Select POST /oauth/token -> Send to Repeater
   ```
3. Test the token after its supposed expiry:
   ```bash
   Repeater -> Use token after expiry (e.g., 1 hour) -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects expired tokens.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "invalid_token", "error_description": "Token has expired"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"user_data": {...}}
```

**Remediation**:
- Set short token lifetimes (Python/Flask):
  ```python
  @app.post('/oauth/token')
  def token():
      token = generate_token(expires_in=3600)  # 1 hour
      return jsonify({'access_token': token, 'expires_in': 3600})
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Authorization Server Misconfiguration with Burp Suite

**Objective**: Ensure token requests cannot exploit server misconfigurations.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a token request:
   ```bash
   HTTP History -> Select POST /oauth/token -> Send to Repeater
   ```
3. Manipulate the grant type:
   ```bash
   Repeater -> Change grant_type=authorization_code to grant_type=implicit -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects invalid grant types.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "unsupported_grant_type", "error_description": "Grant type not supported"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"access_token": "xyz", "token_type": "Bearer"}
```

**Remediation**:
- Restrict grant types (Node.js):
  ```javascript
  app.post('/oauth/token', (req, res) => {
      const { grant_type } = req.body;
      const allowedGrants = ['authorization_code', 'client_credentials'];
      if (!allowedGrants.includes(grant_type)) {
          return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Grant type not supported' });
      }
      res.json({ access_token: generateToken() });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test Token Endpoint CORS Misconfiguration with cURL

**Objective**: Ensure the token endpoint restricts CORS to trusted origins.

**Steps**:
1. Test a token request with a valid origin:
   ```bash
   curl -i -H "Origin: https://example.com" -X POST -d "client_id=public_client&client_secret=secret&grant_type=client_credentials" http://example.com/oauth/token
   ```
2. Test with an untrusted origin:
   ```bash
   curl -i -H "Origin: https://evil.com" -X POST -d "client_id=public_client&client_secret=secret&grant_type=client_credentials" http://example.com/oauth/token
   ```
3. Analyze responses; expected secure response rejects untrusted origins.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "invalid_request", "error_description": "Unauthorized origin"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Content-Type: application/json
{"access_token": "xyz", "token_type": "Bearer"}
```

**Remediation**:
- Restrict CORS (Python/Flask):
  ```python
  from flask_cors import CORS
  app = Flask(__name__)
  CORS(app, resources={r"/oauth/token": {"origins": ["https://example.com"]}})
  @app.post('/oauth/token')
  def token():
      return jsonify({'access_token': generate_token()})
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Token Revocation Weaknesses with Burp Suite

**Objective**: Ensure the token revocation endpoint validates requests.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a token revocation request:
   ```bash
   HTTP History -> Select POST /oauth/revoke -> Send to Repeater
   ```
3. Modify the token or client credentials:
   ```bash
   Repeater -> Change token=valid_token to token=invalid_token -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects invalid requests.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "invalid_request", "error_description": "Invalid token"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Token revoked"}
```

**Remediation**:
- Secure revocation (Node.js):
  ```javascript
  app.post('/oauth/revoke', (req, res) => {
      const { token, client_id, client_secret } = req.body;
      if (!isValidToken(token) || !isValidClient(client_id, client_secret)) {
          return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid token or client' });
      }
      revokeToken(token);
      res.json({ status: 'Token revoked' });
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).