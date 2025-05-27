# Testing for Weak Security Question/Answer

## Overview

Testing for Weak Security Question/Answer (WSTG-AUTH-08) involves verifying that security questions and answers used for account recovery or authentication are robust, not easily guessable, and securely implemented to prevent unauthorized access. According to OWASP, weak security questions (e.g., "What is your favorite color?") or answers based on publicly available information can be exploited through social engineering or brute-force attacks. This test focuses on evaluating question strength, answer validation, client-side exposure, brute-force protection, and support for custom questions to ensure secure recovery mechanisms.

**Impact**: Weak security question/answer implementations can lead to:
- Unauthorized account recovery via guessed or brute-forced answers.
- Exposure of accounts through social engineering using public data.
- Compromise of user accounts due to insecure answer storage or validation.
- Non-compliance with security standards (e.g., NIST 800-63B, GDPR).

This guide provides a practical, hands-on methodology for testing security question/answer vulnerabilities, adhering to OWASP’s WSTG-AUTH-08, with detailed tool setups, specific commands integrated into test steps, remediation strategies, and ethical considerations for professional penetration testing. 

**Ethical Note**: Obtain explicit permission for testing, as submitting multiple recovery requests or inspecting client-side code may trigger security alerts or violate terms of service.

## Testing Tools

The following tools are recommended for testing weak security question/answer vulnerabilities, with setup and configuration instructions:

- **Browser Developer Tools**: Inspects security question options and client-side code.
  - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
  - No setup required.

- **cURL**: Sends requests to test answer validation and brute-force protection.
  - Install on Linux:
    ```bash
    sudo apt install curl
    ```
  - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).

- **Burp Suite Community Edition**: Intercepts and analyzes responses for answer exposure.
  - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
  - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
  - Enable “Intercept” in Proxy tab.

## Testing Methodology

This methodology follows OWASP’s black-box approach for WSTG-AUTH-08, focusing on testing security question strength, answer validation, client-side exposure, brute-force protection, and custom question support.

### 1. Test Security Question Strength with Browser Developer Tools

**Objective**: Ensure security questions are robust and not easily guessable.

**Steps**:
1. Access the account setup or recovery page (e.g., `https://example.com/security-questions`) and open Browser Developer Tools.
2. Inspect the security question dropdown or input field:
   ```
   Elements tab -> Inspect <select> for security questions -> List question options
   ```
3. Check for a custom question option or evaluate predefined questions for predictability:
   ```
   Elements tab -> Check for <input> with name="custom_question" or analyze question strength
   ```
4. Analyze findings; expected secure response includes custom question support or strong predefined questions.

**Example Secure Response**:
```
<input type="text" name="custom_question" placeholder="Enter your own question">
<select name="question_id">
    <option value="1">What is the name of your first pet?</option>
</select>
```

**Example Vulnerable Response**:
```
<select name="question_id">
    <option value="1">What is your favorite color?</option>
    <option value="2">What is your birth year?</option>
</select>
[No custom question option]
```

**Remediation**:
- Support custom security questions (Python/Flask):
  ```python
  @app.post('/setup-security')
  def setup_security():
      custom_question = request.form.get('custom_question')
      if custom_question:
          # Store custom question securely
          return jsonify({'status': 'success'})
      return jsonify({'error': 'Custom question required'}), 400
  ```

**Tip**: Save screenshots of Browser Developer Tools Elements tab showing question options. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., weak questions).

### 2. Test Answer Validation and Rate Limiting with cURL

**Objective**: Verify that security answers are validated server-side and protected by rate limiting.

**Steps**:
1. Identify the recovery endpoint (e.g., `POST /recovery`) using Burp Suite.
2. Submit a recovery request with a common or incorrect answer:
   ```bash
   curl -i -X POST -d "question_id=1&answer=blue" https://example.com/recovery
   ```
3. Test another common answer (e.g., "red"):
   ```bash
   curl -i -X POST -d "question_id=1&answer=red" https://example.com/recovery
   ```
4. Analyze responses; expected secure response rejects incorrect answers and enforces rate limiting.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Incorrect answer"}
[After multiple attempts]
HTTP/1.1 429 Too Many Requests
{"error": "Too many attempts, please try again later"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Incorrect answer"}
[No rate limiting after multiple attempts]
```

**Remediation**:
- Implement rate limiting and validation (Node.js):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/recovery', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5 // 5 attempts
  }));
  app.post('/recovery', (req, res) => {
      const { answer } = req.body;
      if (!validateAnswer(answer)) {
          return res.status(400).json({ error: 'Incorrect answer' });
      }
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., HTTP responses).

### 3. Test Answer Exposure in Client-Side Code with Burp Suite

**Objective**: Ensure security answers are not exposed in client-side code or responses.

**Steps**:
1. Configure Burp Suite by setting up the browser proxy (127.0.0.1:8080) and adding `example.com` to the target scope.
2. Submit a recovery request and inspect the response for answer exposure:
   ```
   HTTP History -> Select POST /recovery -> Check Response for answer data
   ```
3. Inspect client-side code for embedded answers:
   ```
   HTTP History -> Select GET /recovery -> Check HTML/JavaScript for answer exposure
   ```
4. Analyze findings; expected secure response contains no answer data in responses or code.

**Example Secure Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Incorrect answer"}
[No answer data in HTML/JavaScript]
```

**Example Vulnerable Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Answer does not match: petname"}
<script>var answer = "petname";</script>
```

**Remediation**:
- Prevent answer exposure (Python/Flask):
  ```python
  @app.post('/recovery')
  def recovery():
      answer = request.form['answer']
      if not validate_answer(answer):
          return jsonify({'error': 'Incorrect answer'}), 400
      return jsonify({'status': 'success'})
  ```

**Tip**: Save Burp Suite HTTP History responses as screenshots. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., exposed answers).

### 4. Test Brute-Force Protection for Security Answers with cURL

**Objective**: Ensure the application prevents brute-forcing of security answers.

**Steps**:
1. Identify the recovery endpoint (e.g., `POST /recovery`) using Burp Suite.
2. Submit multiple incorrect answers in rapid succession:
   ```bash
   curl -i -X POST -d "question_id=1&answer=wrong1" https://example.com/recovery
   ```
3. Repeat with another incorrect answer:
   ```bash
   curl -i -X POST -d "question_id=1&answer=wrong2" https://example.com/recovery
   ```
4. Analyze responses; expected secure response includes rate limiting, lockout, or CAPTCHA.

**Example Secure Response**:
```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
{"error": "Too many attempts, please try again later"}
```

**Example Vulnerable Response**:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json
{"error": "Incorrect answer"}
[No rate limiting or lockout]
```

**Remediation**:
- Enforce brute-force protection (Node.js):
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/recovery', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5 // 5 attempts
  }));
  app.post('/recovery', (req, res) => {
      res.json({ status: 'success' });
  });
  ```

**Tip**: Save cURL commands and responses to a file (e.g., `curl -i ... > output.txt`). Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., lack of rate limiting).

### 5. Test Custom Security Question Support with Browser Developer Tools

**Objective**: Ensure the application supports custom security questions or provides strong predefined options.

**Steps**:
1. Access the account setup or recovery page (e.g., `https://example.com/security-questions`) and open Browser Developer Tools.
2. Check for a custom question input field:
   ```
   Elements tab -> Inspect for <input name="custom_question"> -> Verify presence
   ```
3. Evaluate predefined questions for strength if no custom option exists:
   ```
   Elements tab -> Inspect <select> for security questions -> List question options
   ```
4. Analyze findings; expected secure response includes custom question support or strong questions.

**Example Secure Response**:
```
<input type="text" name="custom_question" placeholder="Enter your own question">
```

**Example Vulnerable Response**:
```
<select name="question_id">
    <option value="1">What is your favorite color?</option>
    <option value="2">What is your birth year?</option>
</select>
[No custom question option]
```

**Remediation**:
- Allow custom questions (Python/Flask):
  ```python
  @app.post('/setup-security')
  def setup_security():
      custom_question = request.form.get('custom_question')
      if custom_question:
          # Store custom question securely
          return jsonify({'status': 'success'})
      return jsonify({'error': 'Custom question required'}), 400
  ```

**Tip**: Save screenshots of Browser Developer Tools Elements tab showing question inputs. Organize findings in a report with timestamps, test descriptions, and evidence of vulnerabilities (e.g., weak questions).
