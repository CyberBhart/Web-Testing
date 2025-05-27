# Test for Cloud Storage

## Overview

Testing for cloud storage vulnerabilities involves identifying misconfigured cloud storage services (e.g., AWS S3, Google Cloud Storage, Azure Blob Storage) that expose sensitive data, allow unauthorized access, or enable resource abuse (WSTG-CONF-11). According to OWASP, misconfigurations like public buckets, weak access controls, exposed credentials, or abuse scenarios (e.g., cryptomining, ransomware) can lead to data breaches, tampering, or financial loss. These issues stem from complex permission models and widespread cloud adoption, making cloud storage a prime target for attackers.

**Impact**: Misconfigured cloud storage can result in:
- Exposure of sensitive data (e.g., customer records, intellectual property).
- Data tampering or deletion.
- Unauthorized access to cloud resources.
- Financial loss from resource abuse (e.g., cryptomining, billing spikes).
- Non-compliance with regulations (e.g., GDPR, HIPAA, PCI DSS).

This guide provides a hands-on methodology for black-box and gray-box testing, covering bucket enumeration, permission analysis, object access testing, credential exposure checks, automated scanning, and continuous monitoring. It includes tools, commands, payloads, and an automated script, aligned with OWASP’s WSTG-CONF-11 and best practices. 

**Ethical Note**: Obtain explicit written authorization before testing, as probing cloud storage may trigger security alerts, violate terms of service, or disrupt services, potentially leading to legal consequences or service interruptions.

## Testing Tools

The following tools are recommended for testing cloud storage vulnerabilities, with setup instructions optimized for new pentesters:

- **awscli**: Command-line tool for AWS services.
  - Install on Linux:  
    `sudo apt install awscli`
  - Configure:  
    `aws configure` (use test credentials with permission)
  - Example:  
    `aws s3 ls s3://example-bucket`

- **gsutil**: Command-line tool for Google Cloud Storage.
  - Install on Linux:  
    `pip install gsutil`
  - Configure:  
    `gcloud auth login`
  - Example:  
    `gsutil ls gs://example-bucket`

- **az**: Azure CLI for Azure Blob Storage.
  - Install on Linux:  
    `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`
  - Configure:  
    `az login`
  - Example:  
    `az storage blob list --container-name example-container`

- **curl**: Command-line tool for HTTP requests.
  - Install on Linux:  
    `sudo apt install curl`
  - Example:  
    `curl -I https://example-bucket.s3.amazonaws.com`

- **nmap**: Network scanning tool for service enumeration.
  - Install on Linux:  
    `sudo apt install nmap`
  - Example:  
    `nmap -sV example.com`

- **CloudBrute**: Tool for enumerating cloud storage buckets.
  - Install on Linux:  
    `go install github.com/0xsha/CloudBrute@latest`
  - Example:  
    `cloudbrute -d example.com`

- **S3Scanner**: Tool for scanning AWS S3 buckets.
  - Install on Linux:  
    `pip install s3scanner`
  - Example:  
    `s3scanner scan --bucket example-bucket`

- **ScoutSuite**: Multi-cloud security auditing tool.
  - Install on Linux:  
    `pip install scoutsuite`
  - Example:  
    `scout aws`

- **Prowler**: AWS security assessment tool.
  - Install on Linux:  
    `pip install prowler`
  - Example:  
    `prowler aws`

- **TruffleHog**: Credential leak detection tool.
  - Install on Linux:  
    `pip install trufflehog`
  - Example:  
    `trufflehog filesystem /path/to/repo`

- **GitLeaks**: Tool for detecting secrets in Git repositories.
  - Install on Linux:  
    `go install github.com/zricethezav/gitleaks@latest`
  - Example:  
    `gitleaks detect -s /path/to/repo`

- **OWASP ZAP 3.2**: Web application security scanner.
  - Download: [ZAP](https://www.zaproxy.org/download/)
  - Configure proxy: `127.0.0.1:8080`
  - Enable HUD: Tools > Options > HUD
  - Example:  
    `zap-cli quick-scan https://example-bucket.s3.amazonaws.com`

- **Shodan**: API-based OSINT tool (requires API key).
  - Sign up: [Shodan](https://www.shodan.io/)
  - Example:  
    `shodan search org:example.com s3`

## Testing Methodology

This methodology follows OWASP’s black-box and gray-box approaches for WSTG-CONF-11, testing for cloud storage vulnerabilities by enumerating buckets, analyzing permissions, testing object access, checking for credentials and abuse, automating scans, and setting up monitoring.

### Common Cloud Storage Checks and Payloads

Below are common cloud storage services, misconfigurations, and commands to test for vulnerabilities. Use with caution to avoid disrupting production environments. Refer to the [OWASP Cloud Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Cloud_Storage_Testing/) for detailed methodologies.

- **Common Services**:
  - AWS S3: `*.s3.amazonaws.com`
  - Google Cloud Storage: `*.storage.googleapis.com`
  - Azure Blob Storage: `*.blob.core.windows.net`

- **Common Misconfigurations**:
  - Public buckets (readable/writable by all users).
  - Missing authentication for object access.
  - Exposed access keys or credentials in public files.
  - Overly permissive IAM/bucket policies.
  - Resource abuse (e.g., cryptomining, illegal content, ransomware, billing spikes).

- **Gray-Box Credential Scope**:
  - Create least-privilege test accounts for gray-box testing:  
    ```bash
    aws iam create-user --user-name pentest-user
    aws iam attach-user-policy --user-name pentest-user --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
    ```
  - Use temporary credentials with minimal permissions (e.g., read-only) to avoid production risks.

- **Example Vulnerable Bucket Policy (AWS S3)**:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example-bucket/*"
      }
    ]
  }
  ```
- **Example Secure Bucket Policy (AWS S3)**:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:user/secure-user"},
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": "arn:aws:s3:::example-bucket/*",
        "Condition": {"Bool": {"aws:SecureTransport": "true"}}
      }
    ]
  }
  ```

- **Test Commands**:
  - Enumerate AWS S3 buckets:  
    `aws s3 ls s3://example-bucket`
  - Check bucket policy:  
    `aws s3api get-bucket-policy --bucket example-bucket`
  - Check public access:  
    `curl -I https://example-bucket.s3.amazonaws.com`
  - Enumerate Google Cloud Storage:  
    `gsutil ls gs://example-bucket`
  - Enumerate Azure Blob Storage:  
    `az storage blob list --container-name example-container`
  - Scan for open buckets:  
    `s3scanner scan --bucket example-bucket`
  - Check for credentials:  
    `trufflehog filesystem /path/to/repo`
  - OSINT with Shodan:  
    `shodan search org:example.com s3`

- **Expected Responses**:
  - Vulnerable: HTTP 200/403 with bucket listing, `ListBucketResult` XML, public file access, or exposed credentials.
  - Secure: HTTP 404/403 with no bucket listing or access denied.

⚠️ **Warning**: Cloud providers (e.g., AWS, Google, Azure) may blacklist repeated unauthorized probes or flag accounts for abuse. To avoid detection:
- Throttle scans: Use delays in tools like `s3scanner` or `cloudbrute`.
- Set user-agent headers: `curl -A "Mozilla/5.0 (Compatible; SecurityScan)"`.
- Log scan timing: Record start/end times in a log file (see automation script).
- Avoid modifying bucket contents or uploading files without explicit authorization.

**Note**: Cloud storage testing depends on provider-specific APIs and access controls. Gray-box testing with least-privilege credentials (e.g., `AmazonS3ReadOnlyAccess`) provides deeper insight into IAM misconfigurations. Verify the cloud service user (e.g., `www-data`, `apache`) with `ps aux | egrep '(apache|nginx)'` if gray-box access is available.

### 1. Bucket Enumeration

**Objective**: Identify cloud storage buckets associated with the target domain.

**Steps**:
1. Use CloudBrute (black-box):
   - Run:  
     `cloudbrute -d example.com -o $LOG_DIR/cloudbrute_results.txt`
   - **Vulnerable Example**:  
     ```text
     [+] Found: s3://public-example-bucket (AWS S3)
     ```
   - **Secure Example**:  
     ```text
     [+] No buckets found
     ```
2. Use S3Scanner (black-box):
   - Run:  
     `s3scanner scan --bucket example-bucket --out-file $LOG_DIR/s3scanner_results.txt`
   - Look for public or misconfigured buckets.
3. Use Shodan (black-box, requires API key):
   - Run:  
     `shodan search org:example.com s3`
   - Look for exposed S3 endpoints.
4. Manual enumeration (black-box):
   - Test common bucket names:  
     `curl -I -A "Mozilla/5.0 (Compatible; SecurityScan)" https://example-bucket.s3.amazonaws.com`  
     `curl -I -A "Mozilla/5.0 (Compatible; SecurityScan)" https://example-storage.storage.googleapis.com`
   - **Vulnerable Example**:  
     ```plaintext
     HTTP/1.1 200 OK
     Server: AmazonS3
     ```
   - **Secure Example**:  
     ```plaintext
     HTTP/1.1 403 Forbidden
     Server: AmazonS3
     ```
5. Use OWASP ZAP:
   - Run Active Scan to spider cloud storage URLs.

**Remediation**:
- **AWS S3**: Delete or secure public buckets:  
  `aws s3api put-bucket-acl --bucket example-bucket --acl private`
- **Google Cloud Storage**: Restrict bucket permissions:  
  `gsutil iam ch allUsers:-r gs://example-bucket`
- **Azure Blob Storage**: Set container to private:  
  `az storage container set-permission --name example-container --public-access off`
- Verify:  
  `curl -I https://example-bucket.s3.amazonaws.com`

**Tip**: Save enumerated bucket names in a report.

### 2. Permission Analysis

**Objective**: Analyze bucket and IAM permissions to identify public or overly permissive access.

**Steps**:
1. Use awscli (gray-box, requires least-privilege credentials):
   - Create test user:  
     ```bash
     aws iam create-user --user-name pentest-user
     aws iam attach-user-policy --user-name pentest-user --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
     ```
   - Check bucket policy:  
     `aws s3api get-bucket-policy --bucket example-bucket`
   - **Vulnerable Example**:  
     ```json
     {
       "Statement": [
         {
           "Effect": "Allow",
           "Principal": "*",
           "Action": "s3:GetObject",
           "Resource": "arn:aws:s3:::example-bucket/*"
         }
       ]
     }
     ```
   - **Secure Example**:  
     ```json
     {
       "Statement": [
         {
           "Effect": "Allow",
           "Principal": {"AWS": "arn:aws:iam::123456789012:user/secure-user"},
           "Action": ["s3:GetObject"],
           "Resource": "arn:aws:s3:::example-bucket/*"
         }
       ]
     }
     ```
   - Check IAM policy:  
     `aws iam get-policy --policy-arn arn:aws:iam::123456789012:policy/example-policy`
2. Use gsutil (gray-box):
   - Run:  
     `gsutil iam get gs://example-bucket`
   - Look for `allUsers` or `allAuthenticatedUsers`.
3. Use az (gray-box):
   - Run:  
     `az storage container show-permission --name example-container`
   - Check for `publicAccess: blob` or `container`.
4. Use curl (black-box):
   - Run:  
     `curl -A "Mozilla/5.0 (Compatible; SecurityScan)" https://example-bucket.s3.amazonaws.com?list-type=2`
   - **Vulnerable Example**:  
     ```xml
     <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
     ```
   - **Secure Example**:  
     ```xml
     <Error><Code>AccessDenied</Code></Error>
     ```

**Remediation**:
- **AWS S3**: Restrict public access:  
  `aws s3api put-public-access-block --bucket example-bucket --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`
  Update bucket policy:  
  ```bash
  aws s3api put-bucket-policy --bucket example-bucket --policy file://secure-policy.json
  ```
  Example `secure-policy.json`:  
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:user/secure-user"},
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::example-bucket/*"
      }
    ]
  }
  ```
- **Google Cloud Storage**: Remove public access:  
  `gsutil iam ch -d allUsers gs://example-bucket`
- **Azure Blob Storage**: Disable public access:  
  `az storage account update --name example-account --default-action Deny`
- Verify:  
  `curl https://example-bucket.s3.amazonaws.com?list-type=2`

**Tip**: Document permission findings.

### 3. Object Access Testing

**Objective**: Test for unauthorized access to objects and detect resource abuse (e.g., cryptomining, illegal content, ransomware, billing spikes).

**Steps**:
1. Use curl (black-box):
   - Run:  
     `curl -A "Mozilla/5.0 (Compatible; SecurityScan)" https://example-bucket.s3.amazonaws.com/test.txt`
   - **Vulnerable Example**:  
     ```plaintext
     Sensitive data exposed
     ```
   - **Secure Example**:  
     ```xml
     <Error><Code>AccessDenied</Code></Error>
     ```
2. Use awscli (gray-box):
   - Run:  
     `aws s3 ls s3://example-bucket`
   - Look for sensitive files (e.g., `config.json`, `backup.sql`).
3. Check for resource abuse (gray-box):
   - Run:  
     `aws s3 ls s3://example-bucket --recursive | grep -E '\.bin|\.js|\.zip|\.exe'`
   - **Vulnerable Example**:  
     ```text
     2025-05-01 10:00:00 123456789 miner.bin
     2025-05-01 10:00:00 50000 cryptominer.js
     2025-05-01 10:00:00 1000000 backup.zip
     2025-05-01 10:00:00 5000000 warez.exe
     ```
   - **Secure Example**:  
     ```text
     [No matching files]
     ```
   - **Abuse Scenarios**:
     - **Cryptomining**: Large `.bin` or `.js` files (e.g., `miner.bin`, `cryptominer.js`).
     - **Illegal Content**: Executables or media files (e.g., `warez.exe`) in open buckets.
     - **Ransomware**: Encrypted backups (e.g., `backup.zip`) with ransom notes.
     - **Billing Spikes**: Excessive read/write operations (e.g., large data transfers).
4. Check billing for abuse (gray-box):
   - AWS Cost Explorer:  
     `aws ce get-cost-and-usage --time-period Start=2025-05-01,End=2025-05-27 --granularity DAILY --metrics "UnblendedCost"`
     Look for spikes in S3 `DataTransfer-Out-Bytes` or `Requests-Tier1`.
   - GCP Billing:  
     `gcloud billing accounts describe [ACCOUNT_ID] --format="value(usage)"`
     Check for unexpected storage costs.
5. Use gsutil (gray-box):
   - Run:  
     `gsutil ls gs://example-bucket`
6. Use az (gray-box):
   - Run:  
     `az storage blob list --container-name example-container`
7. Use OWASP ZAP:
   - Spider bucket URLs to identify accessible objects.

**Remediation**:
- **AWS S3**: Set object-level permissions:  
  `aws s3api put-object-acl --bucket example-bucket --key test.txt --acl private`
  Remove malicious files:  
  `aws s3 rm s3://example-bucket/miner.bin`  
  `aws s3 rm s3://example-bucket/backup.zip`  
  `aws s3 rm s3://example-bucket/warez.exe`
- **Google Cloud Storage**: Restrict object access:  
  `gsutil acl ch -u allUsers:-r gs://example-bucket/test.txt`
- **Azure Blob Storage**: Restrict blob access:  
  `az storage blob set-tier --container-name example-container --name test.txt --access-tier Archive`
- **Billing Spikes**: Set budget alerts:  
  AWS: `aws budgets create-budget --account-id [ACCOUNT_ID] --budget file://budget.json`  
  GCP: `gcloud billing budgets create --billing-account=[ACCOUNT_ID] --budget-amount=1000`
- Investigate abuse: Check CloudTrail/Audit Logs for unauthorized access.
- Verify:  
  `curl https://example-bucket.s3.amazonaws.com/test.txt`

**Tip**: Save accessible object URLs and abuse evidence.

### 4. Credential Exposure Checks

**Objective**: Identify exposed cloud credentials in public buckets or source code.

**Steps**:
1. Use curl (black-box):
   - Run:  
     `curl -A "Mozilla/5.0 (Compatible; SecurityScan)" https://example-bucket.s3.amazonaws.com/config.json`
   - **Vulnerable Example**:  
     ```json
     {"aws_access_key_id": "AKIA...", "aws_secret_access_key": "..."}
     ```
   - **Secure Example**:  
     ```xml
     <Error><Code>AccessDenied</Code></Error>
     ```
2. Use TruffleHog (black-box/gray-box):
   - Run:  
     `trufflehog filesystem /path/to/repo --only-verified > $LOG_DIR/trufflehog_results.txt`
   - Look for verified credentials (e.g., AWS keys, GCP service accounts).
3. Use GitLeaks (gray-box):
   - Run:  
     `gitleaks detect -s /path/to/repo --report-path $LOG_DIR/gitleaks_results.json`
   - Look for secrets in Git history.
4. Use grep (gray-box, if source code access):
   - Run:  
     `grep -r "aws_access_key_id\|client_secret\|sas_token" /path/to/repo`
5. Use OWASP ZAP:
   - Run Passive Scan to detect credentials in responses.

**Remediation**:
- **AWS S3**: Rotate exposed credentials:  
  `aws iam update-access-key --access-key-id AKIA... --status Inactive`
- **Google Cloud Storage**: Revoke service accounts:  
  `gcloud iam service-accounts keys delete`
- **Azure Blob Storage**: Regenerate SAS tokens:  
  `az storage account generate-sas --account-name example-account`
- Secure source code: Use secret management (e.g., AWS Secrets Manager, HashiCorp Vault).
- Verify:  
  `grep -r "aws_access_key_id" /path/to/repo`

**Tip**: Document exposed credential findings.

### 5. Automated Cloud Storage Scanning

**Objective**: Use automated tools to scan for cloud storage vulnerabilities.

**Steps**:
1. Save the following script as `cloud_storage_test.sh`:
   ```bash
   #!/bin/bash

   # Usage: ./cloud_storage_test.sh example.com

   TARGET_DOMAIN=$1
   LOG_DIR="logs/$(date +%F)"
   mkdir -p "$LOG_DIR"

   if [[ -z "$TARGET_DOMAIN" ]]; then
     echo "Usage: $0 <target_domain>"
     exit 1
   fi

   # Check for required tools
   command -v curl >/dev/null 2>&1 || { echo >&2 "curl not found"; exit 1; }
   command -v cloudbrute >/dev/null 2>&1 || { echo >&2 "cloudbrute not found"; exit 1; }
   command -v s3scanner >/dev/null 2>&1 || { echo >&2 "s3scanner not found"; exit 1; }
   command -v aws >/dev/null 2>&1 || { echo >&2 "awscli not found"; exit 1; }
   command -v scout >/dev/null 2>&1 || { echo >&2 "scoutsuite not found"; exit 1; }
   command -v prowler >/dev/null 2>&1 || { echo >&2 "prowler not found"; exit 1; }

   echo "[*] Starting cloud storage testing on $TARGET_DOMAIN at $(date)" > "$LOG_DIR/scan_timing.log"
   echo "[*] Starting cloud storage testing on $TARGET_DOMAIN"

   ### 1. Enumerate buckets with CloudBrute
   echo "[*] Enumerating buckets with CloudBrute..."
   cloudbrute -d "$TARGET_DOMAIN" -o "$LOG_DIR/cloudbrute.txt"

   ### 2. Scan buckets with S3Scanner
   echo "[*] Scanning buckets with S3Scanner..."
   for bucket in {"$TARGET_DOMAIN","public-$TARGET_DOMAIN","test-$TARGET_DOMAIN"}; do
     s3scanner scan --bucket "$bucket" --out-file "$LOG_DIR/s3scanner.txt"
   done

   ### 3. Check public access with curl
   echo "[*] Checking public bucket URLs..."
   for bucket in {"$TARGET_DOMAIN","public-$TARGET_DOMAIN","test-$TARGET_DOMAIN"}; do
     curl -s -I -A "Mozilla/5.0 (Compatible; SecurityScan)" \
       "https://$bucket.s3.amazonaws.com" >> "$LOG_DIR/s3_buckets.txt"
     curl -s -I -A "Mozilla/5.0 (Compatible; SecurityScan)" \
       "https://$bucket.storage.googleapis.com" >> "$LOG_DIR/gcs_buckets.txt"
     curl -s -I -A "Mozilla/5.0 (Compatible; SecurityScan)" \
       "https://$bucket.blob.core.windows.net" >> "$LOG_DIR/azure_buckets.txt"
   done

   ### 4. Check for resource abuse (AWS S3)
   echo "[*] Checking for resource abuse..."
   if command -v aws >/dev/null 2>&1; then
     for bucket in $(grep -o 's3://[^ ]*' "$LOG_DIR/s3scanner.txt"); do
       aws s3 ls "$bucket" --recursive | grep -E '\.bin|\.js|\.zip|\.exe' >> "$LOG_DIR/abuse_files.txt"
     done
   fi

   ### 5. Check billing for abuse (AWS)
   echo "[*] Checking AWS Cost Explorer for billing spikes..."
   aws ce get-cost-and-usage --time-period Start=2025-05-01,End=2025-05-27 --granularity DAILY \
     --metrics "UnblendedCost" > "$LOG_DIR/billing_spikes.txt"

   ### 6. Run ScoutSuite for cloud posture
   echo "[*] Running ScoutSuite scan..."
   scout aws --report-dir "$LOG_DIR/scoutsuite_report" --no-browser

   ### 7. Run Prowler for AWS security
   echo "[*] Running Prowler scan..."
   prowler aws --output-directory "$LOG_DIR/prowler_report"

   echo "[*] Scan completed at $(date)" >> "$LOG_DIR/scan_timing.log"

   ### Summary output
   echo "-------------------------------------------"
   echo "Scan completed. Results saved to $LOG_DIR"
   echo "- CloudBrute results: $LOG_DIR/cloudbrute.txt"
   echo "- S3Scanner results: $LOG_DIR/s3scanner.txt"
   echo "- S3 bucket logs: $LOG_DIR/s3_buckets.txt"
   echo "- GCS bucket logs: $LOG_DIR/gcs_buckets.txt"
   echo "- Azure bucket logs: $LOG_DIR/azure_buckets.txt"
   echo "- Resource abuse: $LOG_DIR/abuse_files.txt"
   echo "- Billing spikes: $LOG_DIR/billing_spikes.txt"
   echo "- ScoutSuite report: $LOG_DIR/scoutsuite_report"
   echo "- Prowler report: $LOG_DIR/prowler_report"
   echo "- Scan timing: $LOG_DIR/scan_timing.log"
   echo "-------------------------------------------"
   ```
2. Set executable permissions:  
   `chmod +x cloud_storage_test.sh`
3. Run the script:
   - Example:  
     `./cloud_storage_test.sh example.com`
   - **Vulnerable Example**:  
     - `s3_buckets.txt`:  
       ```plaintext
       HTTP/1.1 200 OK
       Server: AmazonS3
       ```
     - `abuse_files.txt`:  
       ```text
       2025-05-01 10:00:00 123456789 miner.bin
       ```
     - `billing_spikes.txt`:  
       ```json
       {"ResultsByTime":[{"TimePeriod":{"Start":"2025-05-05"},"Total":{"UnblendedCost":"1000.00"}}]}
       ```
   - **Secure Example**:  
     ```plaintext
     [Empty file]
     ```
4. Use OWASP ZAP:
   - Run:  
     `zap-cli quick-scan https://example-bucket.s3.amazonaws.com`

**How the Script Works**:
- **Inputs**: Takes a target domain for black-box testing.
- **Checks**:
  - Enumerates buckets with `cloudbrute` and `s3scanner`.
  - Tests common bucket names (e.g., `public-$TARGET_DOMAIN`).
  - Checks public access with `curl` using a user-agent.
  - Scans for resource abuse (e.g., `.bin`, `.js`, `.zip`, `.exe` files).
  - Checks AWS Cost Explorer for billing spikes.
  - Runs `scoutsuite` and `prowler` for cloud posture assessment.
- **Outputs**: Saves results in `logs/YYYY-MM-DD`, including bucket logs, abuse reports, billing data, and posture reports.
- **Requirements**:
  - `curl`, `cloudbrute`, `s3scanner`, `awscli`, `scoutsuite`, `prowler` installed.
  - AWS credentials with `AmazonS3ReadOnlyAccess` and `ce:GetCostAndUsage` for billing checks.
  - Run as a user with network access.

**Remediation**:
- **AWS S3**: Secure public buckets:  
  ```bash
  aws s3api put-public-access-block --bucket example-bucket --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  ```
  Remove malicious files:  
  `aws s3 rm s3://example-bucket/miner.bin`
- **Google Cloud Storage**: Restrict access:  
  `gsutil iam ch -d allUsers gs://example-bucket`
- **Azure Blob Storage**: Disable public access:  
  `az storage account update --name example-account --default-action Deny`
- **Billing Spikes**: Set budget alerts:  
  ```bash
  aws budgets create-budget --account-id [ACCOUNT_ID] --budget file://budget.json
  ```
- Verify:  
  `curl -I https://example-bucket.s3.amazonaws.com`
- Update bucket policy (AWS S3 example):  
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::example-bucket/*",
        "Condition": {
          "Bool": {"aws:SecureTransport": "false"}
        }
      }
    ]
  }
  ```

**Tip**: Save script output and logs in a report.

### 6. Continuous Monitoring

**Objective**:  
Implement continuous monitoring to detect and prevent cloud storage vulnerabilities and abuse.

**Steps**:
1. **AWS Config**:
   - Enable Config:  
     ```bash
     aws configservice start-configuration-recorder --configuration-recorder-name default
     ```
   - Set up rules:  
     ```bash
     aws configservice put-config-rule --config-rule file://s3-public-rule.json
     ```
     Example `s3-public-rule.json`:  
     ```json
     {
       "ConfigRuleName": "s3-bucket-public-read-prohibited",
       "Source": {
         "Owner": "AWS",
         "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
       }
     }
     ```
2. **AWS CloudTrail**:
   - Enable CloudTrail:  
     ```bash
     aws cloudtrail create-trail --name trail-name --s3-bucket-name trail-bucket
     ```
   - Configure SNS alerts:  
     ```bash
     aws sns subscribe --topic-arn arn:aws:sns:region:account-id:topic-name --protocol email --notification-endpoint alert@example.com
     ```
3. **Google Cloud Audit Logs**:
   - Enable Audit Logs:  
     ```bash
     gcloud logging sinks create audit-sink pubsub.googleapis.com/projects/[PROJECT_ID]/topics/[TOPIC_ID] --log-filter='resource.type="gcs_bucket"'
     ```
   - Configure notifications:  
     ```bash
     gcloud pubsub subscriptions create audit-sub --topic audit-topic
     ```
4. **Azure Monitor**:
   - Set up alerts:  
     ```bash
     az monitor activity-log alert create --name alert-name --scope /subscriptions/[SUBSCRIPTION_ID]/ --condition 'category=Administrative and operation=Microsoft.Storage/storageAccounts/write'
     ```
   - Enable diagnostics:  
     ```bash
      az monitor diagnostic-settings create --resource /subscriptions/[SUBSCRIPTION_ID]/resourceGroups/[RG]/providers/Microsoft.Storage/storageAccounts/[ACCOUNT] --name diag --logs '[{"category":"StorageRead","enabled":true}]'
     ```
5. Schedule periodic scans:
   - Run:  
     ```bash
     crontab -e
     ```
     Add: `0 2 * * * /path/to/cloud_storage_test.sh example.com`
6. Check IAM permissions (gray-box):
   - Run:  
     ```bash
     aws iam list-users
     ```
   - Verify:  
     ```bash
     ps aux | egrep '(apache|nginx)'
     ```

**Remediation**:
- Deploy monitoring: Use AWS Config/CloudTrail, Google Cloud Audit Logs, or Azure Monitor.
- Verify:  
  ```bash
  aws configservice describe-configuration-recorders
  gcloud logging sinks list
  az monitor activity-log alert list
  ```

**Tip**: Document monitoring setup in a log file.

## References

- [OWASP Cloud Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Cloud_Storage_Testing/): OWASP’s guidance on cloud storage testing.
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html): Best practices for securing S3 buckets.
- [Google Cloud Storage Security](https://cloud.google.com/storage/docs/access-control): Securing GCP buckets.
- [Azure Blob Storage Security](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations): Security recommendations for Azure storage.
- [S3Scanner Documentation](https://github.com/sa7mon/S3Scanner): AWS S3 bucket scanning tool.
- [ScoutSuite Documentation](https://github.com/nccgroup/ScoutSuite): Multi-cloud security auditing.
- [Prowler Documentation](https://github.com/prowler-cloud/prowler): AWS security assessments.
- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog): Credential leak detection.
- [GitLeaks Documentation](https://github.com/gitleaks/gitleaks): Secret detection in Git repositories.