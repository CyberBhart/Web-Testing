# Testing for Weak Transport Layer Security

## Overview

Testing for Weak Transport Layer Security (TLS) (WSTG-CRYP-01) involves assessing the security of a web application’s TLS/SSL configuration to ensure data transmitted between clients and servers is protected against interception, decryption, or manipulation. According to OWASP, weak TLS configurations—such as outdated protocols (e.g., SSLv3, TLS 1.0), weak cipher suites (e.g., RC4, DES), or misconfigured certificates—can expose sensitive data (e.g., credentials, session tokens) to man-in-the-middle (MITM) attacks, session hijacking, or data breaches. This test evaluates protocol versions, cipher suites, certificate validity, security headers, redirects, session handling, and related configurations to identify vulnerabilities.

**Impact**: Weak TLS configurations can lead to:
- Interception of sensitive data via MITM attacks.
- Exposure of user credentials or session tokens due to decryptable traffic.
- Loss of trust from invalid or expired certificates.
- Exploitation of misconfigurations (e.g., CRIME, insecure redirects) for data manipulation.

This guide provides a practical, hands-on methodology for testing weak TLS configurations, adhering to OWASP’s WSTG-CRYP-01, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing.

## Testing Tools

The following tools are recommended for testing weak TLS configurations, with setup and configuration instructions:

- **sslscan**: Enumerates supported TLS protocols and cipher suites.
  - Install on Linux:
    ```bash
    sudo apt install sslscan
    ```
  - Install on Windows/Mac: Download from [GitHub](https://github.com/rbsec/sslscan).

- **testssl.sh**: Comprehensive script for testing TLS/SSL configurations.
  - Download from [testssl.sh](https://testssl.sh/).
  - Extract and run:
    ```bash
    chmod +x testssl.sh
    ```

- **OpenSSL**: Analyzes certificates and tests protocol support.
  - Install on Linux:
    ```bash
    sudo apt install openssl
    ```
  - Install on Windows/Mac: Pre-installed or download from [openssl.org](https://www.openssl.org/).

- **Nmap**: Scans for TLS protocol and cipher details.
  - Install on Linux:
    ```bash
    sudo apt install nmap
    ```
  - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/).

- **Browser Developer Tools**: Inspects certificates, security headers, and mixed content.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **Burp Suite Community Edition**: Intercepts requests to verify session token transmission.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-CRYP-01, focusing on analyzing TLS protocols, cipher suites, certificates, security headers, redirects, and session handling to identify weaknesses.

### 1. Enumerate TLS Protocols and Ciphers with sslscan

**Objective**: Identify supported TLS/SSL protocols and cipher suites to detect outdated or weak configurations.

**Steps**:
1. **Run sslscan**:
   - Scan the target domain to list protocols and ciphers.
   - Check for deprecated protocols (e.g., SSLv2, SSLv3, TLS 1.0, TLS 1.1) and weak ciphers (e.g., RC4, DES).
2. **Analyze Output**:
   - Verify that only secure protocols (TLS 1.2, TLS 1.3) and strong ciphers (e.g., AES-GCM, CHACHA20) are supported.
   - Note any weak or anonymous ciphers (e.g., NULL, EXPORT).

**sslscan Commands**:
- **Command 1**: Scan for all protocols and ciphers:
  ```bash
  sslscan example.com > sslscan_results.txt
  ```
- **Command 2**: Check for specific protocol support:
  ```bash
  sslscan --tlsall example.com
  ```

**Example Vulnerable Output**:
```
Testing SSL server example.com on port 443
  Supported Server Cipher(s):
    Accepted  SSLv3  RC4-MD5
    Accepted  TLSv1.0  DES-CBC-SHA
```

**Remediation**:
- Disable weak protocols and ciphers (Apache):
  ```apache
  SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
  SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!DES
  ServerTokens Prod
  ```

**Tip**: Save scan output to a file (e.g., `sslscan_results.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., scan results).

### 2. Comprehensive TLS Testing with testssl.sh

**Objective**: Perform an in-depth analysis of TLS configurations, including protocols, ciphers, key exchange, and vulnerabilities.

**Steps**:
1. **Run testssl.sh**:
   - Scan the target for protocol support, cipher strength, key exchange (e.g., ECDHE, forward secrecy), and vulnerabilities (e.g., Heartbleed, CRIME, Logjam).
   - Include checks for TLS fallback and downgrade attacks.
2. **Analyze Output**:
   - Check for deprecated protocols, weak ciphers, compression, or weak key exchange (e.g., RSA, DHE with <2048-bit parameters).
   - Verify forward secrecy and absence of downgrade vulnerabilities (e.g., Logjam).
   - Confirm certificate details and HSTS enforcement.

**testssl.sh Commands**:
- **Command 1**: Run a full TLS scan with forward secrecy and vulnerability checks:
  ```bash
  ./testssl.sh --full --forward-secrecy --logjam example.com > testssl_results.html
  ```
- **Command 2**: Test for specific vulnerabilities and key exchange:
  ```bash
  ./testssl.sh --vulnerable --forward-secrecy example.com
  ```

**Example Vulnerable Output**:
```
SSLv3: enabled (WEAK)
Cipher: RC4-SHA (WEAK)
Compression: enabled (CRIME vulnerable)
Forward Secrecy: Not supported
Logjam: Vulnerable (DHE 512-bit parameters)
```

**Remediation**:
- Disable compression, weak protocols, and ensure forward secrecy (Nginx):
  ```nginx
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers on;
  ssl_dhparam /etc/nginx/dhparam.pem; # 2048-bit or higher
  ssl_comp off;
  ```

**Tip**: Save HTML or text output (e.g., `testssl_results.html`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., scan results).

### 3. Analyze Certificates with OpenSSL

**Objective**: Verify certificate validity, trust, and configuration.

**Steps**:
1. **Connect to Server**:
   - Retrieve the server’s certificate.
   - Check for expiration, hostname mismatch, or untrusted issuers.
2. **Test Protocol Support**:
   - Attempt connections with deprecated protocols (e.g., SSLv3).
3. **Analyze Output**:
   - Verify certificate details (e.g., CN, SAN, validity period).
   - Check for self-signed or expired certificates.

**OpenSSL Commands**:
- **Command 1**: Retrieve and inspect certificate:
  ```bash
  openssl s_client -connect example.com:443 -servername example.com < /dev/null | openssl x509 -text -noout
  ```
- **Command 2**: Test for SSLv3 support:
  ```bash
  openssl s_client -connect example.com:443 -ssl3
  ```

**Example Vulnerable Output**:
```
Certificate:
  Subject: CN=wrong.example.com
  Not After: Jan 01 2024 (expired)
connect: SSLv3 handshake successful
```

**Remediation**:
- Use valid certificates from a trusted CA:
  ```bash
  certbot certonly --apache -d example.com
  ```

**Tip**: Save certificate details to a file (e.g., `openssl ... > cert.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., certificate output).

### 4. Scan TLS Configurations with Nmap

**Objective**: Enumerate TLS protocols and ciphers using Nmap scripts.

**Steps**:
1. **Run Nmap Scan**:
   - Use `ssl-enum-ciphers` to list protocols and ciphers.
   - Check for weak or deprecated configurations.
2. **Analyze Output**:
   - Identify SSLv3, TLS 1.0, or weak ciphers (e.g., RC4).
   - Note certificate issues or misconfigurations.

**Nmap Commands**:
- **Command 1**: Enumerate TLS ciphers:
  ```bash
  nmap --script ssl-enum-ciphers -p 443 example.com > nmap_tls_results.txt
  ```
- **Command 2**: Check certificate details:
  ```bash
  nmap --script ssl-cert -p 443 example.com
  ```

**Example Vulnerable Output**:
```
443/tcp open  https
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       DES-CBC-SHA (weak)
```

**Remediation**:
- Restrict protocols (Apache):
  ```apache
  SSLProtocol TLSv1.2 TLSv1.3
  ServerTokens Prod
  ```

**Tip**: Save scan output to a file (e.g., `nmap_tls_results.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., scan results).

### 5. Inspect Security Headers and Content with Browser Developer Tools

**Objective**: Verify HSTS, secure cookies, and mixed content issues.

**Steps**:
1. **Open Browser Developer Tools**:
   - Access `F12` on `https://example.com`.
2. **Check Security Headers**:
   - Inspect `Network` tab for `Strict-Transport-Security` header.
   - Verify cookie attributes (e.g., Secure, HttpOnly).
3. **Test for Mixed Content**:
   - Check for HTTP resources (e.g., images, scripts) on HTTPS pages.
4. **Analyze Certificate**:
   - View certificate details in the `Security` tab.

**Browser Developer Tools Commands**:
- **Command 1**: Check HSTS header:
  ```
  Network tab -> Select GET https://example.com -> Headers -> Response Headers -> Look for Strict-Transport-Security
  ```
- **Command 2**: Inspect certificate:
  ```
  Security tab -> View Certificate -> Check Subject, Validity, and Issuer
  ```

**Example Vulnerable Finding**:
- Missing `Strict-Transport-Security` header.
- Certificate expired or hostname mismatch.

**Remediation**:
- Enable HSTS and set secure cookies (Apache):
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  ```
  ```php
  setcookie('session', 'abc123', ['secure' => true, 'httponly' => true]);
  ```

**Tip**: Save screenshots and network logs from Developer Tools. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., header or certificate details).

### 6. Test HTTP-to-HTTPS Redirects

**Objective**: Ensure all HTTP requests are redirected to HTTPS to prevent unencrypted connections.

**Steps**:
1. **Send HTTP Request**:
   - Use `curl` to access the target over HTTP (port 80).
   - Check for a redirect to HTTPS (status 301/302).
2. **Analyze Response**:
   - Verify the redirect URL is HTTPS and no sensitive data (e.g., cookies) is sent over HTTP.
   - Check for redirect loops or misconfigurations.
3. **Verify in Browser**:
   - Access `http://example.com` and confirm redirection to HTTPS.

**curl Commands**:
- **Command 1**: Check for HTTP-to-HTTPS redirect:
  ```bash
  curl -I http://example.com
  ```
- **Command 2**: Verify no sensitive data in HTTP response:
  ```bash
  curl -i -b "session=abc123" http://example.com
  ```

**Example Vulnerable Output**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: session=abc123; path=/
```

**Remediation**:
- Configure HTTP-to-HTTPS redirects (Apache):
  ```apache
  <VirtualHost *:80>
      ServerName example.com
      Redirect permanent / https://example.com/
      ServerTokens Prod
  </VirtualHost>
  ```

**Tip**: Save curl output to a file (e.g., `curl -I ... > redirect.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 7. Test Session Token Transmission Security

**Objective**: Ensure session tokens are not transmitted over insecure channels (e.g., HTTP or non-TLS endpoints).

**Steps**:
1. **Intercept Requests**:
   - Use Burp Suite to capture requests or monitor the Network tab in Developer Tools.
   - Access the application over HTTP or non-TLS APIs.
2. **Analyze Token Transmission**:
   - Check if session cookies or Authorization headers are sent over HTTP.
   - Verify the `Secure` flag on cookies and TLS enforcement for API tokens.
3. **Test Non-TLS Endpoints**:
   - Identify non-HTTPS endpoints (e.g., APIs on HTTP) and test token inclusion.

**Burp Suite Commands**:
- **Command 1**: Check for tokens in HTTP requests:
  ```
  Proxy -> HTTP History -> Filter for http://example.com -> Check for Cookie or Authorization headers
  ```
- **Command 2**: Test non-TLS API endpoint:
  ```
  Proxy -> HTTP History -> Select POST http://example.com/api/login -> Send to Repeater -> Check for Authorization header
  ```

**Example Vulnerable Output**:
```
GET /login HTTP/1.1
Host: example.com
Cookie: session=abc123
```

**Remediation**:
- Enforce secure session tokens (PHP):
  ```php
  session_set_cookie_params(['secure' => true, 'httponly' => true]);
  session_start();
  ```

**Tip**: Save Burp Suite requests or Developer Tools network logs as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP requests with tokens).
