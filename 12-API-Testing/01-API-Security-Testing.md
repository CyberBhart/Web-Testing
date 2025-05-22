# Comprehensive API Security Testing Guide

## Overview

API security testing evaluates the security of Application Programming Interfaces (APIs), including GraphQL, REST, and SOAP, which are critical for modern web applications. APIs are vulnerable to attacks due to their exposure and access to sensitive data. The OWASP Web Security Testing Guide (WSTG) v4.2 includes **WSTG-APIT-01: Testing GraphQL**, which focuses on GraphQL-specific vulnerabilities like introspection abuse, broken access control, deep query abuse, and injection attacks. This guide extends beyond GraphQL to cover all API testing scenarios, incorporating the OWASP API Security Top 10 2023 and additional vulnerabilities (e.g., SSRF, misconfigurations) to ensure comprehensive testing.

**Impact**: API vulnerabilities can lead to:
- Unauthorized data access or manipulation.
- Server compromise via injections or malicious queries.
- Denial of Service (DoS) through resource exhaustion.
- Financial or operational damage due to exploited logic flaws.

This guide provides a practical, hands-on methodology for API security testing, including detailed steps for GraphQL testing (WSTG-APIT-01), REST/SOAP testing, and generic API vulnerabilities, with tool setups, specific commands, remediation strategies, and ethical considerations.

## Testing Tools

The following tools are recommended for API security testing, with setup and configuration instructions:

- **Burp Suite Community Edition**: Intercepts and manipulates API requests.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

- **Postman**: Tests API endpoints with crafted queries.
  - Download from [postman.com](https://www.postman.com/downloads/).
  - Install and create a free account.

- **GraphQL Playground**: Interacts with GraphQL APIs for query testing.
  - Download from [GitHub](https://github.com/graphql/graphql-playground).
  - Configure endpoint (e.g., `http://example.com/graphql`).

- **cURL**: Sends custom API requests.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **OWASP ZAP**: Automated scanner for API vulnerabilities.
  - Download from [zaproxy.org](https://www.zaproxy.org/download/).
  - Run: `zap.sh` (Linux) or `zap.bat` (Windows).

- **Python Requests Library**: Scripts automated API tests.
  - Install Python:
    ```bash
    sudo apt install python3
    ```
  - Install Requests:
    ```bash
    pip install requests
    ```

## Testing Methodology

This methodology combines WSTG-APIT-01 for GraphQL with comprehensive REST/SOAP and generic API testing, ensuring all vulnerabilities are tested.

### 1. Discover API Endpoints with Burp Suite

**Objective**: Map all API endpoints to understand the attack surface.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in “Target” tab.
2. **Crawl for Endpoints**:
   - Browse the application or use API documentation to capture requests in “HTTP History”.
   - Identify endpoints (e.g., `/graphql`, `/api/v1/users`, `/soap/service`).
3. **Analyze Findings**:
   - Review “Site Map” for undocumented or sensitive endpoints.

**Burp Suite Commands**:
- **Command 1**: Crawl for endpoints:
  ```
  Target tab -> Site Map -> Right-click example.com -> Engagement Tools -> Crawl -> Include /graphql, /api/* -> Start Crawl
  ```
- **Command 2**: Export endpoints:
  ```
  Target tab -> Site Map -> Right-click example.com -> Copy URLs in Scope -> Paste to file
  ```

**Remediation**:
- Restrict endpoint exposure (Nginx):
  ```nginx
  location ~ ^/(graphql|api) {
      allow 127.0.0.1;
      deny all;
  }
  ```

**Tip**: Save “Site Map” URLs to a file (e.g., `urls.txt`) or as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., endpoint lists).

### 2. Test GraphQL Introspection with GraphQL Playground

**Objective**: Test if introspection queries expose the GraphQL schema (WSTG-APIT-01).

**Steps**:
1. **Configure GraphQL Playground**:
   - Set endpoint to `http://example.com/graphql`.
   - Add headers (e.g., `Authorization: Bearer abc123`).
2. **Run Introspection Query**:
   - Query the schema to retrieve types and fields.
3. **Test Unauthorized Access**:
   - Remove `Authorization` header and rerun query.

**GraphQL Playground Commands**:
- **Command 1**: Run introspection query:
  ```
  Schema tab -> Endpoint: http://example.com/graphql -> Headers: {"Authorization": "Bearer abc123"} -> Query: {__schema {types {name fields {name}}}} -> Run
  ```
- **Command 2**: Test unauthorized introspection:
  ```
  Schema tab -> Remove Authorization header -> Query: {__schema {types {name}}} -> Run
  ```

**Example Vulnerable Response**:
```json
{
  "data": {
    "__schema": {
      "types": [
        {"name": "User", "fields": [{"name": "email"}]}
      ]
    }
  }
}
```

**Remediation**:
- Disable introspection (Apollo Server):
  ```javascript
  const { ApolloServer } = require('apollo-server');
  const server = new ApolloServer({ schema, introspection: false });
  ```

**Tip**: Save query and response as JSON (e.g., `introspection.json`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., schema details).

### 3. Test Access Controls with Postman

**Objective**: Test for broken object-level or function-level authorization (WSTG-APIT-01, API Top 10 A01:2023).

**Steps**:
1. **Import Endpoints**:
   - Add GraphQL/REST endpoints to Postman.
2. **Test Unauthorized Access**:
   - Send queries/requests with unauthorized IDs or roles (e.g., admin endpoints).
3. **Analyze Response**:
   - Check for data exposure or HTTP 403.

**Postman Commands**:
- **Command 1**: Test GraphQL unauthorized access:
  ```
  New Request -> POST http://example.com/graphql -> GraphQL -> Query: query { user(id: 999) { email } } -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Test REST unauthorized access:
  ```
  New Request -> GET http://example.com/api/users/999 -> Headers: Authorization: Bearer user_token -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "data": {
    "user": {
      "email": "admin@example.com"
    }
  }
}
```

**Remediation**:
- Enforce authorization (GraphQL):
  ```javascript
  const resolvers = {
    Query: {
      user: (parent, { id }, { user }) => {
        if (user.id !== id && !user.isAdmin) throw new Error('Unauthorized');
        return db.getUser(id);
      }
    }
  };
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 4. Test Deep Queries and DoS with cURL

**Objective**: Test GraphQL for resource exhaustion via deep queries (WSTG-APIT-01).

**Steps**:
1. **Craft Deep Query**:
   - Create a nested GraphQL query.
2. **Send Queries**:
   - Use cURL to send the query repeatedly.
3. **Analyze Response**:
   - Monitor response time, HTTP 429, or server errors.

**cURL Commands**:
- **Command 1**: Send deep query:
  ```bash
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"query": "query { users { posts { comments { author { posts { comments { id } } } } } } }"}' http://example.com/graphql
  ```
- **Command 2**: Flood with queries:
  ```bash
  for i in {1..10}; do curl -X POST -H "Content-Type: application/json" --data '{"query": "query { users { posts { comments { author { posts { id } } } } } }"}' http://example.com/graphql; done
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[Large JSON response]
```

**Remediation**:
- Limit query depth (Apollo Server):
  ```javascript
  const depthLimit = require('graphql-depth-limit');
  const server = new ApolloServer({ schema, validationRules: [depthLimit(5)] });
  ```

**Tip**: Save cURL responses to a file (e.g., `curl ... > deep_query.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 5. Test Broken Authentication with Burp Suite

**Objective**: Test if API endpoints are accessible without authentication (API Top 10 A02:2023).

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture a request to a sensitive endpoint (e.g., `POST /api/secure`).
2. **Test Without Token**:
   - Remove `Authorization` header and resend.
3. **Analyze Response**:
   - Check for HTTP 401 or data exposure.

**Burp Suite Commands**:
- **Command 1**: Test without token:
  ```
  Intruder -> Select POST /api/secure -> Clear § -> Select Authorization header -> Payloads: None -> Start Attack
  ```
- **Command 2**: Manual test in Repeater:
  ```
  Repeater -> POST /api/secure -> Remove Authorization header -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"data": "sensitive"}
```

**Remediation**:
- Enforce JWT authentication (Express):
  ```javascript
  const jwt = require('jsonwebtoken');
  app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    jwt.verify(token, 'secret', (err) => {
      if (err) res.status(401).send('Invalid token');
      else next();
    });
  });
  ```

**Tip**: Save Burp Intruder results or Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 6. Test SSRF with cURL

**Objective**: Test for Server-Side Request Forgery (API Top 10 A10:2023).

**Steps**:
1. **Identify Endpoint**:
   - Find endpoints accepting URLs (e.g., `POST /api/fetch`).
2. **Test SSRF**:
   - Send a request with an internal URL.
3. **Analyze Response**:
   - Check for internal data exposure or HTTP 400.

**cURL Commands**:
- **Command 1**: Test SSRF:
  ```bash
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"url": "http://internal.example.com/secret"}' http://example.com/api/fetch
  ```
- **Command 2**: Test local resource:
  ```bash
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"url": "http://localhost:8080/admin"}' http://example.com/api/fetch
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"data": "Internal secret"}
```

**Remediation**:
- Validate URLs (PHP):
  ```php
  $allowed = ['example.com'];
  if (!in_array(parse_url($url, PHP_URL_HOST), $allowed)) {
    die('Invalid URL');
  }
  ```

**Tip**: Save cURL responses to a file (e.g., `curl ... > ssrf.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test GraphQL Batch Query Abuse with cURL

**Objective**: Test for resource exhaustion via batched GraphQL queries (WSTG-APIT-01).

**Steps**:
1. **Craft Batch Query**:
   - Create multiple queries in a single request.
2. **Send Batch**:
   - Use cURL to send the batch query.
3. **Analyze Response**:
   - Check for HTTP 429, delays, or full data return.

**cURL Commands**:
- **Command 1**: Send batch query:
  ```bash
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '[{"query": "query { users { id } }"}, {"query": "query { posts { id } }"}, {"query": "query { comments { id } }"}]' http://example.com/graphql
  ```
- **Command 2**: Flood with batches:
  ```bash
  for i in {1..10}; do curl -X POST -H "Content-Type: application/json" --data '[{"query": "query { users { id } }"}]' http://example.com/graphql; done
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[{"data": {"users": [...]}}, {"data": {"posts": [...]}}, ...]
```

**Remediation**:
- Limit batch queries (Apollo Server):
  ```javascript
  const { ApolloServer } = require('apollo-server');
  const server = new ApolloServer({ schema, validationRules: [batchLimit(10)] });
  ```

**Tip**: Save cURL responses to a file (e.g., `curl ... > batch.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 8. Test Excessive Data Exposure and Injections with OWASP ZAP

**Objective**: Test for excessive data exposure and injection vulnerabilities (API Top 10 A03:2023, A08:2023).

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy (127.0.0.1:8080).
   - Import API endpoints.
2. **Run Scans**:
   - Perform active scan for injections and check responses for sensitive data.
3. **Analyze Alerts**:
   - Look for SQL/NoSQL errors or exposed fields (e.g., `password`).

**OWASP ZAP Commands**:
- **Command 1**: Scan for injections:
  ```
  Sites tab -> Right-click http://example.com/graphql -> Attack -> Active Scan -> Select SQL Injection -> Start Scan
  ```
- **Command 2**: Fuzz for data exposure:
  ```
  Sites tab -> Right-click GET http://example.com/api/users -> Attack -> Fuzzer -> Add Payloads: test, ' OR 1=1 -- -> Start Fuzzer
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[{"id": 1, "email": "user@example.com", "password": "hashed"}]
```

**Remediation**:
- Sanitize inputs and filter outputs (Python):
  ```python
  from flask import jsonify
  from re import match
  def get_users(name):
      if not match(r'^[a-zA-Z0-9]+$', name):
          return jsonify({'error': 'Invalid input'}), 400
      users = db.query('SELECT id, email FROM users WHERE name = %s', (name,))
      return jsonify(users)
  ```

**Tip**: Save ZAP scan reports or alerts as exports. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., scan results).

### 9. Test Mass Assignment with Postman

**Objective**: Verify if APIs allow unauthorized modification of object properties (API Top 10 A06:2023).

**Steps**:
1. **Identify Mutation Endpoint**:
   - Find endpoints like `POST /api/users/update`.
2. **Test Unauthorized Fields**:
   - Include restricted fields (e.g., `isAdmin`) in the request.
3. **Analyze Response**:
   - Check if the server accepts unauthorized updates.

**Postman Commands**:
- **Command 1**: Test mass assignment:
  ```
  New Request -> POST http://example.com/api/users/update -> Body -> raw -> JSON: {"id": 123, "name": "test", "isAdmin": true} -> Headers: Authorization: Bearer user_token -> Send
  ```
- **Command 2**: Verify update:
  ```
  New Request -> GET http://example.com/api/users/123 -> Headers: Authorization: Bearer user_token -> Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "updated"}
```

**Remediation**:
- Restrict fields (Express):
  ```javascript
  const _ = require('lodash');
  app.post('/api/users/update', (req, res) => {
    const allowed = ['name', 'email'];
    const updates = _.pick(req.body, allowed);
    db.updateUser(req.body.id, updates);
    res.send('Updated');
  });
  ```

**Tip**: Save Postman requests and responses as exports or screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., API responses).

### 10. Test CORS Misconfigurations with Burp Suite

**Objective**: Check for permissive CORS policies allowing untrusted origins (API Top 10 A07:2023).

**Steps**:
1. **Send Preflight Request**:
   - Use Burp Suite to send an `OPTIONS` request with a malicious `Origin`.
2. **Test Regular Request**:
   - Send a request from an untrusted origin to confirm access.
3. **Analyze Response**:
   - Check for `Access-Control-Allow-Origin: *` or reflected origins.

**Burp Suite Commands**:
- **Command 1**: Test preflight:
  ```
  Repeater -> OPTIONS http://example.com/api/users -> Headers -> Add: Origin: http://evil.com, Access-Control-Request-Method: POST -> Send -> Check Response Headers
  ```
- **Command 2**: Test data access:
  ```
  Repeater -> GET http://example.com/api/users -> Headers -> Add: Origin: http://evil.com -> Send -> Check Response Data
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://evil.com
```

**Remediation**:
- Restrict CORS (Express):
  ```javascript
  app.use((req, res, next) => {
    res.set('Access-Control-Allow-Origin', 'https://example.com');
    next();
  });
  ```

**Tip**: Save Burp Repeater responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., CORS headers).

### 11. Test Rate-Limiting and Throttling with Python Requests

**Objective**: Verify rate-limiting mechanisms to prevent abuse (API Top 10 A04:2023).

**Steps**:
1. **Send Rapid Requests**:
   - Use Python to send multiple requests to an endpoint.
2. **Analyze Response**:
   - Check for HTTP 429 or rate-limit headers (e.g., `X-RateLimit-Remaining`).
3. **Test Per-User Limits**:
   - Repeat with different tokens.

**Python Script**:
```python
import requests
import time
import sys

url = 'http://example.com/api/users'
headers = {'Authorization': 'Bearer abc123'}

try:
    for i in range(100):
        response = requests.get(url, headers=headers, timeout=5)
        remaining = response.headers.get('X-RateLimit-Remaining', 'Not set')
        print(f"Request {i+1}: Status={response.status_code}, Remaining={remaining}")
        if response.status_code == 429:
            print("Rate limit hit!")
            break
        time.sleep(0.1)
except requests.RequestException as e:
    print(f"Error: {e}")
    sys.exit(1)
```

**Python Commands**:
- **Command 1**: Run rate-limiting test:
  ```bash
  python3 test_rate_limit.py
  ```
- **Command 2**: Test with cURL:
  ```bash
  for i in {1..50}; do curl -H "Authorization: Bearer abc123" http://example.com/api/users -i | grep -E "HTTP|X-RateLimit"; done
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
X-RateLimit-Remaining: Not set
```

**Remediation**:
- Implement rate-limiting (Express):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
  ```

**Tip**: Save script or cURL output to a file (e.g., `python3 test_rate_limit.py > rate_limit.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).
