# Test for Subdomain Takeover

## Overview

Testing for subdomain takeover involves identifying subdomains with DNS records pointing to unclaimed or inactive external services, allowing an attacker to claim control (WSTG-CONF-10). According to OWASP, subdomain takeover occurs when a DNS record (e.g., CNAME, A, NS, MX) references a non-existent or unverified resource on a third-party service (e.g., GitHub Pages, AWS S3), enabling an attacker to host malicious content, conduct phishing, steal cookies, or escalate to full domain control (NS takeover). This vulnerability is critical due to the proliferation of XaaS (Anything as a Service) and cloud services, which often lack robust ownership verification.

**Impact**: Successful subdomain takeover can lead to:
- Hosting malicious content or phishing pages.
- Stealing user session cookies or credentials.
- Reputational damage or malware distribution.
- Full DNS zone control (NS takeover), compromising the entire domain.
- Non-compliance with security standards (e.g., PCI DSS, GSSOC-4).

This guide provides a hands-on methodology for black-box and gray-box testing, covering DNS enumeration, record analysis, service fingerprinting, manual verification, automated scanning, and continuous monitoring. It includes tools, commands, payloads, and an automated script, aligned with OWASP’s WSTG-CONF-10 and best practices.

**Ethical Note**: Obtain explicit written authorization before testing, as probing DNS records or claiming subdomains may disrupt services, trigger alerts, or violate terms of service, potentially affecting user experience or legal compliance.

## Testing Tools

The following tools are recommended for testing subdomain takeover, with setup instructions optimized for new pentesters:

- **dig**: Command-line tool for DNS queries.
  - Install on Linux:  
    `sudo apt install dnsutils`
  - Example:  
    `dig CNAME subdomain.example.com`

- **dnsrecon**: DNS enumeration tool.
  - Install on Linux:  
    `sudo apt install dnsrecon`
  - Example:  
    `dnsrecon -d example.com`

- **OWASP Amass**: Advanced DNS enumeration and OSINT tool.
  - Install on Linux:  
    `sudo snap install amass`
  - Example:  
    `amass enum -d example.com`

- **Subjack**: Subdomain takeover scanner.
  - Install on Linux:  
    `go install github.com/haccer/subjack@latest`
  - Example:  
    `subjack -w subdomains.txt -a -t 100`

- **Nikto**: Web server scanner for detecting misconfigurations.
  - Install on Linux:  
    `sudo apt install nikto`
  - Example:  
    `nikto -h https://subdomain.example.com --ssl -useragent "Mozilla/5.0 (Compatible; SecurityScan)"`  
    *Note*: Use `--ssl` for HTTPS targets to reduce false positives.

- **OWASP ZAP 3.2**: Open-source web application security scanner.
  - Download from [ZAP](https://www.zaproxy.org/download/).
  - Configure browser proxy: `127.0.0.1:8080`.
  - Enable HUD:  
    1. Go to Tools > Options > HUD.  
    2. Enable HUD for real-time browser inspection.
  - Example:  
    `zap-cli quick-scan https://subdomain.example.com`

- **crt.sh**: Passive OSINT tool for certificate transparency logs.
  - Access: [crt.sh](https://crt.sh/).
  - Example:  
    `curl -s https://crt.sh/?q=%.example.com&output=json`

- **SecurityTrails/Shodan**: API-based OSINT tools (requires API key).
  - Sign up: [SecurityTrails](https://securitytrails.com/) or [Shodan](https://www.shodan.io/).
  - Example: Use API to query subdomains.

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-10, testing for subdomain takeover by enumerating DNS records, analyzing responses, fingerprinting services, verifying vulnerabilities, automating scans, and setting up monitoring.

### Common Subdomain Takeover Checks and Payloads

Below is a list of common DNS records, services, and commands to test for subdomain takeover vulnerabilities. Use with caution to avoid disrupting production environments. Refer to [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz) and the [OWASP Subdomain Takeover Cheat Sheet](https://owasp.org/www-community/attacks/Subdomain_Takeover) for detailed fingerprints and methodologies.

- **DNS Records**:
  - `CNAME`: Points to external services (e.g., `github.io`, `s3.amazonaws.com`).
  - `A`: Points to IP addresses of unclaimed resources (e.g., `NXDOMAIN` or decommissioned IPs).
  - `NS`: Delegates to unverified name servers, risking full domain control (high impact).
  - `MX`: Points to unclaimed mail servers, potentially exploitable.

- **Service Risk Prioritization**:
  - 🔥 **High-Risk**: GitHub Pages (`*.github.io`), Heroku (`*.herokudns.com`), AWS S3 (`*.s3.amazonaws.com`).
  - ⚠️ **Moderate**: Microsoft Azure (`*.azurewebsites.net`), Bitbucket (`*.bitbucket.io`), Shopify (`*.myshopify.com`).
  - **Subjack Fingerprint Mapping**:
    - AWS S3: `HTTP/1.1 404 Not Found` + `Server: AmazonS3`.
    - GitHub Pages: `HTTP/1.1 404 Not Found` + `Server: GitHub.com`.
    - Heroku: `HTTP/1.1 404 No such app` + `Server: Cowboy`.

- **Test Commands**:
  - Enumerate subdomains:  
    `dnsrecon -d example.com`
  - Check CNAME:  
    `dig CNAME subdomain.example.com`
  - Check A:  
    `dig A subdomain.example.com`
  - Check NS:  
    `dig NS example.com`
  - Check MX:  
    `dig MX example.com`
  - Check TTL and records:  
    `dig +nocmd subdomain.example.com ANY +multiline +noall +answer`
  - Passive OSINT:  
    `curl -s https://crt.sh/?q=%.example.com&output=json`
  - Scan for takeover:  
    `subjack -w subdomains.txt -a -t 100`

- **Expected DNS Responses**:
  - Vulnerable: `NXDOMAIN`, `SERVFAIL`, `REFUSED`, unclaimed NS, low TTL (< 300s).
  - Secure: Valid, claimed resource, registered NS, stable TTL.

🚨 **NS Takeover Note**: Name server misconfigurations can allow full domain control. Test only in gray-box scenarios with registrar access.

⚠️ **Warning**: Some cloud providers (e.g., AWS, Azure) auto-blacklist repeated probes. To avoid detection:
- Throttle scans: Use `subjack -t 100` for delays.
- Set user-agent headers: `curl -A "Mozilla/5.0 (Compatible; SecurityScan)"`.
- Log scan timing: Record start/end times in a log file (see automation script).

**Note**: Subdomain takeover depends on the external service’s verification process and DNS record state. NS takeover requires DNS misconfiguration and registrar access, making it a high-bar gray-box finding. Test both black-box (external queries) and gray-box (DNS zone access) scenarios. Verify the web server user (e.g., `www-data`, `apache`) with `ps aux | egrep '(apache|nginx)'` if gray-box access is available.

### 1. DNS Enumeration

**Objective**: Identify subdomains and their DNS records (CNAME, A, NS, MX) to find potential takeover targets.

**Steps**:
1. Use dnsrecon (black-box):
   - Run:  
     `dnsrecon -d example.com -t std`
   - **Vulnerable Example**:  
     ```text
     [*] CNAME subdomain.example.com fictitioussubdomain.example.com
     [*] A subdomain2.example.com 192.0.2.1 [NXDOMAIN]
     [*] NS example.com unclaimed.ns1.example.com
     [*] MX example.com unclaimed.mx.example.com
     ```
   - **Secure Example**:  
     ```text
     [*] CNAME subdomain.example.com active.github.io
     [*] A subdomain2.example.com 93.184.216.34
     [*] NS example.com ns1.google.com
     [*] MX example.com mx.google.com
     ```
2. Use OWASP Amass:
   - Run:  
     `amass enum -d example.com -o subdomains.txt`
   - Look for subdomains pointing to external services.
3. Use dig for multiple records:
   - Run:  
     `dig +nocmd subdomain.example.com ANY +multiline +noall +answer`
   - Check NS registration:  
     `whois ns1.example.com`
   - **Vulnerable Example**:  
     ```text
     ns1.unclaimed.example.com [No whois record]
     ```
   - **Secure Example**:  
     ```text
     ns1.google.com [Registered]
     ```
4. Use crt.sh for passive OSINT:
   - Run:  
     `curl -s https://crt.sh/?q=%.example.com&output=json | jq '.[] | .name_value'`
   - Look for untracked subdomains.
5. Use SecurityTrails/Shodan (if API access):
   - Query subdomains via API.
6. Use OWASP ZAP:
   - Run Active Scan to enumerate subdomains via spidering.

**Remediation**:
- **GitHub Pages**: Remove CNAME from DNS or claim the repository by creating `username.github.io` with a matching CNAME file.
- **AWS S3**: Remove the bucket name from CNAME or create a bucket named `subdomain.example.com` in AWS S3.
- **NS Takeover**: Update the domain registrar (e.g., GoDaddy, Namecheap) to point to verified nameservers (e.g., `ns1.google.com`).  
  🚨 **Warning**: NS changes impact the entire domain; verify with registrar access.
- Verify DNS zone:  
  `cat /etc/bind/zones/example.com`

**Tip**: Save enumerated subdomains and records in a report.

### 2. CNAME Record Analysis

**Objective**: Analyze CNAME records for unclaimed or inactive external services, including TTL for false positive reduction.

**Steps**:
1. Use dig (black-box):
   - Run:  
     `dig +nocmd subdomain.example.com CNAME +multiline +noall +answer`
   - **Vulnerable Example**:  
     ```text
     subdomain.example.com. 300 IN CNAME fictitioussubdomain.s3.amazonaws.com.
     ```
   - **Secure Example**:  
     ```text
     subdomain.example.com. 3600 IN CNAME active.github.io.
     ```
   - **Note**: Low TTL (< 300s) or `NXDOMAIN` may indicate a dangling record.
2. Check service status:
   - Visit `http://subdomain.example.com` or query the service (e.g., AWS S3 console).
3. Use Nikto:
   - Run:  
     `nikto -h https://subdomain.example.com --ssl -useragent "Mozilla/5.0 (Compatible; SecurityScan)"`
   - Look for HTTP responses indicating unclaimed resources (e.g., 404, service error).
4. Use OWASP ZAP:
   - Check for external service alerts under **Alerts > External Redirect**.

**Remediation**:
- **GitHub Pages**: Remove CNAME or claim the repository by creating `username.github.io`.
- **AWS S3**: Remove CNAME or create the bucket `subdomain.example.com` in AWS S3.
- Verify DNS:  
  `dig +short CNAME subdomain.example.com`

**Tip**: Save CNAME and TTL analysis results.

### 3. Service Detection

**Objective**: Identify third-party services and their susceptibility to takeover based on HTTP responses, prioritizing high-risk services.

**Steps**:
1. Use cURL (black-box):
   - Run:  
     `curl -I https://subdomain.example.com -A "Mozilla/5.0 (Compatible; SecurityScan)"`
   - **Vulnerable Example (AWS S3)**:  
     ```plaintext
     HTTP/1.1 404 Not Found
     Server: AmazonS3
     ```
   - **Secure Example (GitHub)**:  
     ```plaintext
     HTTP/1.1 200 OK
     Server: GitHub.com
     ```
2. Use Nikto:
   - Run:  
     `nikto -h https://subdomain.example.com --ssl -useragent "Mozilla/5.0 (Compatible; SecurityScan)"`
   - Match responses to fingerprints (see [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)):
     - AWS S3: `404` + `Server: AmazonS3` (🔥 High-Risk).
     - Heroku: `404 No such app` + `Server: Cowboy` (🔥 High-Risk).
     - Azure: `404` + `Server: Microsoft-IIS` (⚠️ Moderate).
3. Check service documentation:
   - Reference [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz) for fingerprints.
4. Use OWASP ZAP:
   - Analyze HTTP responses for service indicators.

**Remediation**:
- **GitHub Pages**: Remove CNAME from DNS or claim the repository.
- **AWS S3**: Create the bucket or remove the bucket name from DNS.
- **Heroku**: Remove CNAME or link the subdomain to an active Heroku app.
- Verify:  
  `curl -I https://subdomain.example.com -A "Mozilla/5.0 (Compatible; SecurityScan)"`

**Tip**: Save service fingerprint evidence.

### 4. Manual Takeover Verification

**Objective**: Verify if a subdomain can be claimed on the external service.

> ⚠️ **Do Not Claim In Production**: Attempting to claim subdomains without authorization can disrupt live services, violate terms of service, or lead to legal consequences. Always obtain explicit written permission and test in a controlled environment.

**Steps**:
1. ⚠️ Only attempt to claim subdomains with **explicit written authorization**:
   - Identify the service (from Test 3).
2. Attempt to claim the subdomain (if authorized):
   - **GitHub Pages**:  
     - Create a repository named `username.github.io`.  
     - Add a CNAME file with `subdomain.example.com`.
   - **AWS S3**:  
     - Create a bucket named `subdomain.example.com`.
3. Check DNS propagation:
   - Run:  
     `dig +short A subdomain.example.com`
   - **Vulnerable Example**:  
     Points to attacker-controlled IP.
   - **Secure Example**:  
     Points to original or no IP.
4. Use OWASP ZAP:
   - Verify if malicious content can be hosted.

**Remediation**:
- **GitHub Pages**: Remove CNAME or claim the repository.
- **AWS S3**: Claim the bucket or remove the DNS record.
- Verify DNS:  
  Update DNS zone.
- Verify ownership:  
  `whois subdomain.example.com`

**Tip**: Document verification attempts ethically.

### 5. Automated Takeover Scanning

**Objective**: Use automated tools to scan for subdomain takeover vulnerabilities across multiple record types.

**Steps**:
1. Generate a subdomain wordlist:
   - Run:  
     `amass enum -d example.com -o subdomains.txt`
   - This creates `subdomains.txt` for use with Subjack.
2. Save the following script as `subdomain_takeover_test.sh`:
   ```bash
   #!/bin/bash

   # Usage: ./subdomain_takeover_test.sh example.com

   TARGET_DOMAIN=$1

   if [[ -z "$TARGET_DOMAIN" ]]; then
     echo "Usage: $0 <target_domain>"
     exit 1
   fi

   # Check for required tools
   command -v dig >/dev/null 2>&1 || { echo >&2 "dig not found"; exit 1; }
   command -v dnsrecon >/dev/null 2>&1 || { echo >&2 "dnsrecon not found"; exit 1; }
   command -v amass >/dev/null 2>&1 || { echo >&2 "amass not found"; exit 1; }
   command -v subjack >/dev/null 2>&1 || { echo >&2 "subjack not found"; exit 1; }
   command -v nikto >/dev/null 2>&1 || { echo >&2 "nikto not found"; exit 1; }
   command -v jq >/dev/null 2>&1 || { echo >&2 "jq not found"; exit 1; }

   LOG_DIR="./takeover_results_$(date +%Y%m%d_%H%M%S)"
   mkdir -p "$LOG_DIR"

   echo "[*] Starting subdomain takeover testing on $TARGET_DOMAIN at $(date)" > "$LOG_DIR/scan_timing.txt"
   echo "[*] Starting subdomain takeover testing on $TARGET_DOMAIN"

   # Function to check takeover fingerprints
   fingerprint_check() {
     local nikto_output="$1"
     echo "[*] Checking for vulnerable service fingerprints..." >> "$LOG_DIR/fingerprint_check.txt"
     if grep -q "Server: AmazonS3" "$nikto_output"; then
       echo "[!] Vulnerable: AWS S3 detected (404 + Server: AmazonS3)" >> "$LOG_DIR/fingerprint_check.txt"
     fi
     if grep -q "Server: GitHub.com" "$nikto_output"; then
       echo "[!] Vulnerable: GitHub Pages detected (404 + Server: GitHub.com)" >> "$LOG_DIR/fingerprint_check.txt"
     fi
     if grep -q "Server: Cowboy" "$nikto_output"; then
       echo "[!] Vulnerable: Heroku detected (404 No such app + Server: Cowboy)" >> "$LOG_DIR/fingerprint_check.txt"
     fi
   }

   ### 1. Enumerate subdomains
   echo "[*] Enumerating subdomains with dnsrecon..."
   dnsrecon -d "$TARGET_DOMAIN" -t std >> "$LOG_DIR/dnsrecon.txt"

   ### 2. Enumerate with Amass
   echo "[*] Enumerating subdomains with Amass..."
   amass enum -d "$TARGET_DOMAIN" -o "$LOG_DIR/subdomains.txt"

   ### 3. Passive OSINT with crt.sh
   echo "[*] Enumerating subdomains with crt.sh..."
   curl -s "https://crt.sh/?q=%.${TARGET_DOMAIN}&output=json" | jq -r '.[] | .name_value' | sort -u >> "$LOG_DIR/subdomains.txt"

   ### 4. Check multiple DNS records
   echo "[*] Checking DNS records (CNAME, A, NS, MX)..."
   while read -r subdomain; do
     dig +nocmd "$subdomain" ANY +multiline +noall +answer >> "$LOG_DIR/dns_records.txt"
     dig CNAME "$subdomain" | grep -E 'IN[[:space:]]*CNAME' >> "$LOG_DIR/cname_records.txt"
     dig A "$subdomain" | grep -E 'IN[[:space:]]*A' >> "$LOG_DIR/a_records.txt"
     dig NS "$subdomain" | grep -E 'IN[[:space:]]*NS' >> "$LOG_DIR/ns_records.txt"
     dig MX "$subdomain" | grep -E 'IN[[:space:]]*MX' >> "$LOG_DIR/mx_records.txt"
   done < "$LOG_DIR/subdomains.txt"

   ### 5. Run Subjack for takeover scan
   echo "[*] Running Subjack scan..."
   subjack -w "$LOG_DIR/subdomains.txt" -a -t 100 -o "$LOG_DIR/subjack_results.txt"
   grep -i 'Vulnerable' "$LOG_DIR/subjack_results.txt" > "$LOG_DIR/vulnerable_only.txt"
   if grep -q 'Vulnerable' "$LOG_DIR/subjack_results.txt"; then
     echo "[!] Subdomain Takeover Risks Detected. Review $LOG_DIR/vulnerable_only.txt"
   fi

   ### 6. Run Nikto on subdomains
   echo "[*] Running Nikto scan on subdomains..."
   while read -r subdomain; do
     nikto -h "https://$subdomain" --ssl -useragent "Mozilla/5.0 (Compatible; SecurityScan)" >> "$LOG_DIR/nikto_scan.txt"
   done < "$LOG_DIR/subdomains.txt"

   # Check fingerprints in Nikto output
   fingerprint_check "$LOG_DIR/nikto_scan.txt"

   echo "[*] Scan completed at $(date)" >> "$LOG_DIR/scan_timing.txt"

   ### Summary output
   echo "-------------------------------------------"
   echo "Scan completed. Results saved to $LOG_DIR"
   echo "- DNSrecon results: $LOG_DIR/dnsrecon.txt"
   echo "- Amass subdomains: $LOG_DIR/subdomains.txt"
   echo "- DNS records (ANY): $LOG_DIR/dns_records.txt"
   echo "- CNAME records: $LOG_DIR/cname_records.txt"
   echo "- A records: $LOG_DIR/a_records.txt"
   echo "- NS records: $LOG_DIR/ns_records.txt"
   echo "- MX records: $LOG_DIR/mx_records.txt"
   echo "- Subjack results: $LOG_DIR/subjack_results.txt"
   echo "- Vulnerable subdomains: $LOG_DIR/vulnerable_only.txt"
   echo "- Nikto scan: $LOG_DIR/nikto_scan.txt"
   echo "- Fingerprint check: $LOG_DIR/fingerprint_check.txt"
   echo "- Scan timing: $LOG_DIR/scan_timing.txt"
   echo "-------------------------------------------"
   ```
3. Set executable permissions:  
   `chmod +x subdomain_takeover_test.sh`
4. Run the script:
   - Example:  
     `./subdomain_takeover_test.sh example.com`
   - **Vulnerable Example** (in `vulnerable_only.txt`):  
     ```text
     [Vulnerable] subdomain.example.com -> fictitioussubdomain.s3.amazonaws.com
     ```
   - **Vulnerable Example** (in `fingerprint_check.txt`):  
     ```text
     [!] Vulnerable: AWS S3 detected (404 + Server: AmazonS3)
     ```
   - **Secure Example**:  
     ```text
     [Empty file]
     ```
5. Use OWASP ZAP:
   - Run:  
     `zap-cli quick-scan https://subdomain.example.com`
   - For passive/active detection, use ZAP’s Python API for deeper integration.

**How the Script Works**:
- **Inputs**: Takes a target domain for black-box DNS tests.
- **Steps**:
  - Generates `subdomains.txt` using `amass` and `crt.sh`.
  - Checks CNAME, A, NS, and MX records with `dig`, logging TTLs and responses.
  - Runs `dnsrecon` for additional enumeration.
  - Uses `subjack` with throttling (`-t 100`) for takeover scanning.
  - Runs `nikto` with `--ssl` and custom user-agent.
  - Parses `subjack` output for vulnerable findings and `nikto` logs for fingerprints.
- **Output**: Saves results in a timestamped directory, including record-specific logs, `vulnerable_only.txt`, and `fingerprint_check.txt`.
- **Requirements**:
  - `dig`, `dnsrecon`, `amass`, `subjack`, `nikto`, `jq` installed.
  - Run as a user with network access.

**Remediation**:
- **GitHub Pages**:  
  Create a repository named `username.github.io` with a CNAME file containing `subdomain.example.com` or remove the CNAME record from DNS.
- **AWS S3**:  
  Create a bucket named `subdomain.example.com` or remove the CNAME/subdomain record from DNS.
- **NS Takeover**:  
  Update the registrar (e.g., GoDaddy, Namecheap) to point to verified nameservers (e.g., `ns1.google.com`).  
  🚨 **Warning**: NS changes impact the entire domain; verify with registrar access.
- Use the following BIND DNS zone patching script (⚠️ **Warning**: Test in a non-production environment first. Back up DNS zone files before modifying. Incorrect changes can disrupt production environments.):
  ```bash
  # Remove vulnerable subdomain record
  sudo sed -i '/subdomain\.example\.com/d' /etc/bind/zones/example.com
  # Reload DNS
  sudo rndc reload
  ```
- Verify:  
  `dig +short CNAME subdomain.example.com`
- Check zone file permissions:  
  `stat /etc/bind/zones/example.com`

**Tip**: Save script output and logs in a report.

### 6. Continuous Monitoring Setup

**Objective**: Implement monitoring to prevent future subdomain takeover vulnerabilities.

**Steps**:
1. Use OWASP Domain Protect:
   - Deploy via AWS/GCP:  
     `terraform apply -var 'domain=example.com'`
   - Configure Slack/email alerts.
2. Schedule periodic scans:
   - Run:  
     `crontab -e`  
     Add: `0 0 * * * /path/to/subdomain_takeover_test.sh example.com`
3. Check DNS zone (gray-box):
   - Run:  
     `stat /etc/bind/zones/example.com`
   - Verify ownership with `ps aux | egrep '(apache|nginx)'`.
4. Use OWASP ZAP:
   - Schedule automated scans via CLI.

**Remediation**:
- Deploy monitoring:  
  Use OWASP Domain Protect.
- Verify:  
  `tail -f /var/log/domain-protect.log`

**Example Vulnerable Results**:
- `vulnerable_only.txt`:  
  ```text
  [Vulnerable] subdomain.example.com -> fictitioussubdomain.example.com
  ```
- `fingerprint_check.txt`:  
  ```
  text
  [!] Vulnerable: AWS S3 detected (404 + Server: AmazonS3)
  ```
- `a_records.txt`:  
  ```text
  subdomain2.example.com. 300 IN A 192.0.2.1 [NXDOMAIN]
  ```

**Example Secure Results**:
- `vulnerable_only.txt`:  
  ```text
  [Empty file]
  ```
- `fingerprint_check.txt`:  
  ```text
  [Empty file]
  ```

**Tip**: Document monitoring setup in a log file.

## References

- [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz): Comprehensive list of service fingerprints for subdomain takeover.
- [OWASP Subdomain Takeover Cheat Sheet](https://owasp.org/www-community/attacks/Subdomain_Takeover): OWASP’s guidance on subdomain takeover testing and mitigation.