# Testing for OAuth Client Weaknesses

## Overview

Testing for OAuth Client Weaknesses involves verifying that the OAuth client (e.g., web or mobile application) securely handles OAuth flows, tokens, and user interactions to prevent unauthorized access or token compromise. According to OWASP and OAuth 2.0/2.1 best practices, vulnerabilities such as insecure token storage, missing PKCE (Proof Key for Code Exchange), client-side CSRF, improper redirect URI handling, client secret exposure, token leakage in redirects, or insufficient scope handling can compromise the client. This test focuses on evaluating client-side token management, PKCE enforcement, CSRF protection, redirect URI validation, client secret security, redirect safety, and scope handling to ensure robust client-side security.

**Impact**: OAuth client weaknesses can lead to:
- Token theft, enabling unauthorized access to user data.
- CSRF attacks, compromising user sessions.
- Non-compliance with security standards (e.g., GDPR, PCI DSS).

This guide provides a practical, hands-on methodology for testing OAuth client vulnerabilities, adhering to OAuth 2.0/2.1 security best practices and OWASP guidelines, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. **Ethical Note**: Obtain explicit permission for testing, as manipulating OAuth flows or inspecting client-side code may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing OAuth client weaknesses, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates OAuth requests to test PKCE, CSRF, redirect URIs, and token leakage.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **cURL**: Sends requests to test scope handling and client secret exposure.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Browser Developer Tools**: Inspects client-side storage and JavaScript for token storage and client secrets.
  - Available in browsers (e.g., Firefox, Chrome) via F12.

## Testing Methodology

This methodology follows OWASP’s black-box approach for testing OAuth client vulnerabilities, focusing on insecure token storage, missing PKCE, client-side CSRF, improper redirect URI handling, client secret exposure, token leakage in redirects, and insufficient scope handling.

### 1. Test Insecure Token Storage on Client with Browser Developer Tools

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
(No access_token in localStorage; cookies are HttpOnly, Secure, SameSite=Strict)
```

**Example Vulnerable Response**:
```
localStorage: {"access_token": "xyz"}
```

**Remediation**:
- Store tokens securely (JavaScript):
  ```javascript
  // Use HttpOnly cookies instead of localStorage
  document.cookie = 'access_token=xyz; HttpOnly; Secure; SameSite=Strict';
  ```

**Tip**: Save screenshots of Developer Tools storage inspection. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., storage contents).

### 2. Test Missing PKCE in Public Clients with Burp Suite

**Objective**: Ensure public clients enforce PKCE to prevent authorization code interception.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept a token request with PKCE parameters:
   ```bash
   HTTP History -> Select POST /oauth/token -> Send to Repeater
   ```
3. Remove or tamper with the `code_verifier`:
   ```bash
   Repeater -> Remove code_verifier -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects missing PKCE.

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
- Implement PKCE (JavaScript):
  ```javascript
  const codeVerifier = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const codeChallenge = btoa(sha256(codeVerifier)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  fetch('/oauth/authorize?code_challenge=' + codeChallenge + '&code_challenge_method=S256');
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Client-Side CSRF in OAuth Flow with Burp Suite

**Objective**: Ensure the client validates the `state` parameter to prevent CSRF attacks.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept an OAuth authorization request:
   ```bash
   HTTP History -> Select GET /oauth/authorize -> Send to Repeater
   ```
3. Remove or tamper with the `state` parameter:
   ```bash
   Repeater -> Remove state parameter -> Click Send -> Check Response
   ```
4. Analyze responses; expected secure response rejects missing or invalid state.

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
- Validate state (JavaScript):
  ```javascript
  const state = crypto.randomUUID();
  sessionStorage.setItem('oauth_state', state);
  fetch(`/oauth/authorize?state=${state}`).then(() => {
      const returnedState = new URL(window.location).searchParams.get('state');
      if (returnedState !== sessionStorage.getItem('oauth_state')) {
          throw new Error('Invalid state parameter');
      }
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 4. Test Improper Redirect URI Handling with Burp Suite

**Objective**: Ensure the client rejects untrusted redirect URIs.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept an OAuth callback request:
   ```bash
   HTTP History -> Select GET /callback?code=auth_code -> Send to Repeater
   ```
3. Modify the redirect URI to an untrusted endpoint:
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
- Validate redirect URIs (JavaScript):
  ```javascript
  const allowedUris = ['https://example.com/callback'];
  const redirectUri = new URLSearchParams(window.location.search).get('redirect_uri');
  if (!allowedUris.includes(redirectUri)) {
      throw new Error('Invalid redirect_uri');
  }
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Client Secret Exposure in Client-Side Code with Browser Developer Tools

**Objective**: Ensure client secrets are not hardcoded or exposed in client-side code.

**Steps**:
1. Open Browser Developer Tools (F12) and inspect JavaScript files:
   ```bash
   Sources -> Search for "client_secret" or "secret"
   ```
2. Check network requests for exposed secrets:
   ```bash
   Network -> Filter for /oauth/token -> Inspect request payloads
   ```
3. Analyze code and requests; expected secure response avoids exposing secrets.

**Example Secure Response**:
```
(No client_secret in JavaScript or network requests; handled server-side)
```

**Example Vulnerable Response**:
```
JavaScript: const clientSecret = 'leaked_secret';
```

**Remediation**:
- Handle secrets server-side (Node.js):
  ```javascript
  app.post('/oauth/token', async (req, res) => {
      const response = await fetch('http://auth-server/oauth/token', {
          method: 'POST',
          body: JSON.stringify({ client_id: 'public_client', client_secret: process.env.CLIENT_SECRET })
      });
      res.json(await response.json());
  });
  ```

**Tip**: Save screenshots of Developer Tools code inspection. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., JavaScript code).

### 6. Test Token Leakage via Client-Side Redirects with Burp Suite

**Objective**: Ensure tokens are not exposed in URL fragments or query parameters during redirects.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Intercept the OAuth callback response:
   ```bash
   HTTP History -> Select GET /callback#access_token=xyz -> Send to Repeater
   ```
3. Simulate a client-side redirect and check the URL:
   ```bash
   Repeater -> Simulate redirect to /dashboard -> Check URL for token leakage
   ```
4. Analyze responses; expected secure response avoids token exposure.

**Example Secure Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
(No access_token in URL; token handled via postMessage or secure storage)
```

**Example Vulnerable Response**:
```
HTTP/1.1 302 Found
Location: /dashboard?access_token=xyz
```

**Remediation**:
- Handle tokens securely (JavaScript):
  ```javascript
  window.addEventListener('message', (event) => {
      if (event.origin !== 'https://example.com') return;
      const { access_token } = event.data;
      document.cookie = `access_token=${access_token}; HttpOnly; Secure; SameSite=Strict`;
  });
  ```

**Tip**: Save Burp Suite Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Insufficient Token Scope Handling with cURL

**Objective**: Ensure the client restricts tokens with unauthorized scopes.

**Steps**:
1. Obtain a token with an excessive scope (e.g., `admin`).
2. Test the token with a restricted endpoint:
   ```bash
   curl -i -H "Authorization: Bearer xyz" -H "Scope: profile+admin" http://example.com/api/admin
   ```
3. Test with a valid scope:
   ```bash
   curl -i -H "Authorization: Bearer xyz" -H "Scope: profile" http://example.com/api/admin
   ```
4. Analyze responses; expected secure response rejects unauthorized scopes.

**Example Secure Response**:
```
HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error": "insufficient_scope", "error_description": "Token scope not authorized for this action"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"admin_data": {...}}
```

**Remediation**:
- Validate scopes (JavaScript):
  ```javascript
  async function fetchAdminData(token) {
      const scopes = await getTokenScopes(token);
      if (!scopes.includes('admin')) {
          throw new Error('Insufficient scope');
      }
      return fetch('/api/admin', { headers: { Authorization: `Bearer ${token}` } });
  }
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).