# Testing for OAuth Weaknesses

## Overview

Testing for OAuth Weaknesses involves verifying that the application’s OAuth implementation securely handles authorization flows to prevent unauthorized access, token leakage, or misuse. According to OWASP, vulnerabilities such as weak redirect URI validation, missing state parameters, insufficient scope validation, token theft, insecure token storage, or token replay can compromise OAuth flows. This test focuses on evaluating redirect URIs, state parameters, scopes, token handling, PKCE enforcement, and client secret security to ensure compliance with OAuth 2.0/2.1 best practices.

**Impact**: OAuth weaknesses can lead to:
- Unauthorized access to user accounts or resources.
- Token theft, enabling impersonation or data breaches.
- Non-compliance with security standards (e.g., GDPR, PCI DSS).

This guide provides a practical, hands-on methodology for testing OAuth vulnerabilities, adhering to OAuth 2.0/2.1 security best practices and OWASP guidelines, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as manipulating OAuth flows or tokens may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing OAuth weaknesses, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates OAuth requests to test redirect URIs, state parameters, and PKCE.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test scope validation, token replay, and client secret leakage.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

## Testing Methodology

This methodology follows OWASP’s black-box approach for testing OAuth vulnerabilities, focusing on redirect URI manipulation, state parameter absence, scope abuse, token leakage, insecure storage, token replay, PKCE enforcement, and client secret leakage.

### 1. Test Weak Redirect URI Validation with Burp Suite

**Objective**: Ensure redirect URIs cannot be manipulated to redirect authorization codes to attacker-controlled endpoints.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept an OAuth authorization request:
   ```bash
   HTTP History -> Select GET /oauth/authorize -> Send to Repeater
   ```
3. Modify the redirect URI to an attacker-controlled endpoint:
   ```bash
   Repeater -> Change redirect_uri=https://example.com/callback to redirect_uri=https://evil.com -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects invalid URIs.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "invalid_request", "error_description": "Invalid redirect_uri"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 302 Found
Location: https://evil.com?code=auth_code
```

**Remediation**:
- Validate redirect URIs (Node.js):
  ```javascript
  app.get('/oauth/authorize', (req, res) => {
      const { redirect_uri } = req.query;
      const allowedUris = ['https://example.com/callback'];
      if (!allowedUris.includes(redirect_uri)) {
          return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
      }
      res.redirect(`${redirect_uri}?code=auth_code`);
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 2. Test Lack of State Parameter with cURL

**Objective**: Ensure the OAuth flow enforces a state parameter to prevent CSRF attacks.

**Steps**:
1. Initiate an OAuth flow and capture the authorization request.
2. Test the flow without a state parameter:
   ```bash
   curl -i "http://example.com/oauth/authorize?client_id=public_client&redirect_uri=https://example.com/callback&response_type=code"
   ```
3. Test with a tampered state parameter:
   ```bash
   curl -i "http://example.com/oauth/authorize?client_id=public_client&redirect_uri=https://example.com/callback&response_type=code&state=wrong_state"
   ```
4. Analyze responses; expected secure response rejects missing or invalid state parameters.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "invalid_request", "error_description": "Missing or invalid state parameter"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 302 Found
Location: https://example.com/callback?code=auth_code
```

**Remediation**:
- Enforce state parameter (Python/Flask):
  ```python
  @app.get('/oauth/authorize')
  def authorize():
      state = request.args.get('state')
      if not state or not validate_state(state, session.get('state')):
          return jsonify({'error': 'invalid_request', 'error_description': 'Missing or invalid state parameter'}), 400
      return redirect(f"{request.args.get('redirect_uri')}?code=auth_code")
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Insufficient Scope Validation with cURL

**Objective**: Ensure excessive or unauthorized scopes cannot be requested.

**Steps**:
1. Log in and initiate an OAuth flow with valid scopes.
2. Test requesting excessive scopes:
   ```bash
   curl -i "http://example.com/oauth/authorize?client_id=public_client&redirect_uri=https://example.com/callback&response_type=code&scope=profile+email+admin"
   ```
3. Test another unauthorized scope:
   ```bash
   curl -i "http://example.com/oauth/authorize?client_id=public_client&redirect_uri=https://example.com/callback&response_type=code&scope=profile+superuser"
   ```
4. Analyze responses; expected secure response restricts unauthorized scopes.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "invalid_scope", "error_description": "Requested scope is not allowed"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 302 Found
Location: https://example.com/callback?code=auth_code&scope=profile+email+admin
```

**Remediation**:
- Validate scopes (Node.js):
  ```javascript
  app.get('/oauth/authorize', (req, res) => {
      const { scope } = req.query;
      const allowedScopes = ['profile', 'email'];
      const requestedScopes = scope.split('+');
      if (requestedScopes.some(s => !allowedScopes.includes(s))) {
          return res.status(400).json({ error: 'invalid_scope', error_description: 'Requested scope is not allowed' });
      }
      res.redirect(`${req.query.redirect_uri}?code=auth_code`);
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Token Theft via Referer Header with Burp Suite

**Objective**: Ensure access tokens are not leaked in Referer headers.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept the OAuth callback request:
   ```bash
   HTTP History -> Select GET /callback?code=auth_code -> Send to Repeater
   ```
3. Simulate a redirect to an external site and check Referer:
   ```bash
   Repeater -> Add Referer: https://example.com/callback?access_token=xyz -> Click Send -> Check Response
   ```
4. Analyze headers; expected secure response avoids token leakage.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
(No access_token in Referer header)
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Referer: https://example.com/callback?access_token=xyz
```

**Remediation**:
- Prevent token leakage (Python/Flask):
  ```python
  @app.get('/callback')
  def callback():
      access_token = request.args.get('access_token')
      response = make_response(redirect('/dashboard'))
      response.headers['Referrer-Policy'] = 'no-referrer'
      return response
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP headers).

### 5. Test Insecure Token Storage with Browser Developer Tools

**Objective**: Ensure OAuth tokens are not stored insecurely in client-side storage.

**Steps**:
1. Log in via OAuth and open Browser Developer Tools (F12).
2. Check localStorage for tokens:
   ```bash
   Application -> Storage -> Local Storage -> http://example.com
   ```
3. Check cookies for tokens:
   ```bash
   Application -> Storage -> Cookies -> http://example.com
   ```
4. Analyze storage; expected secure response avoids storing tokens in localStorage or non-secure cookies.

**Example Secure Response**:
```
(No access_token in localStorage or cookies)
```

**Example Vulnerable Response**:
```
localStorage: {"access_token": "xyz"}
```

**Remediation**:
- Store tokens securely (JavaScript):
  ```javascript
  // Avoid localStorage; use HTTP-only cookies
  document.cookie = 'access_token=xyz; HttpOnly; Secure; SameSite=Strict';
  ```

**Tip**: Save screenshots of Developer Tools storage inspection. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., storage contents).

### 6. Test Token Replay Attacks with cURL

**Objective**: Ensure access tokens cannot be reused to perform unauthorized actions.

**Steps**:
1. Capture an access token from an OAuth flow.
2. Test the token with a valid request:
   ```bash
   curl -i -H "Authorization: Bearer xyz" http://example.com/api/user
   ```
3. Replay the token in a different context (e.g., different endpoint):
   ```bash
   curl -i -H "Authorization: Bearer xyz" http://example.com/api/admin
   ```
4. Analyze responses; expected secure response rejects replayed tokens.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "invalid_token", "error_description": "Token is not valid for this resource"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin_data": {...}}
```

**Remediation**:
- Bind tokens to scopes (Node.js):
  ```javascript
  app.get('/api/admin', (req, res) => {
      const token = req.headers.authorization?.split(' ')[1];
      if (!isValidToken(token, 'admin_scope')) {
          return res.status(401).json({ error: 'invalid_token', error_description: 'Token is not valid for this resource' });
      }
      res.json({ admin_data: getAdminData() });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test PKCE Misconfiguration with Burp Suite

**Objective**: Ensure the OAuth server enforces PKCE for public clients.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a token request with PKCE parameters:
   ```bash
   HTTP History -> Select POST /oauth/token -> Send to Repeater
   ```
3. Remove or tamper with the code_verifier:
   ```bash
   Repeater -> Remove code_verifier -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects invalid PKCE requests.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "invalid_request", "error_description": "Missing or invalid code_verifier"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"access_token": "xyz", "token_type": "Bearer"}
```

**Remediation**:
- Enforce PKCE (Python/Flask):
  ```python
  @app.post('/oauth/token')
  def token():
      code_verifier = request.form.get('code_verifier')
      code_challenge = session.get('code_challenge')
      if not code_verifier or not verify_pkce(code_verifier, code_challenge):
          return jsonify({'error': 'invalid_request', 'error_description': 'Invalid PKCE'}), 400
      return jsonify({'access_token': generate_token()})
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Client Secret Leakage with cURL

**Objective**: Ensure client secrets are not exposed or mishandled in OAuth flows.

**Steps**:
1. Inspect client-side code for hardcoded client secrets (e.g., JavaScript).
2. Test a token request with a suspected client secret:
   ```bash
   curl -i -X POST -d "client_id=public_client&client_secret=leaked_secret&grant_type=client_credentials" http://example.com/oauth/token
   ```
3. Test with an incorrect secret:
   ```bash
   curl -i -X POST -d "client_id=public_client&client_secret=wrong_secret&grant_type=client_credentials" http://example.com/oauth/token
   ```
4. Analyze responses; expected secure response rejects invalid secrets.

**Example Secure Response**:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
{"error": "invalid_client", "error_description": "Invalid client secret"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"access_token": "xyz", "token_type": "Bearer"}
```

**Remediation**:
- Secure client secrets (Node.js):
  ```javascript
  app.post('/oauth/token', (req, res) => {
      const { client_id, client_secret } = req.body;
      if (!isValidClient(client_id, client_secret)) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client secret' });
      }
      res.json({ access_token: generateToken() });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).