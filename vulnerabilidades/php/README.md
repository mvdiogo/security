# Vulnerable PHP App with Exploits

This repository contains a deliberately vulnerable PHP application demonstrating real-world vulnerabilities (based on fictional CVEs for educational purposes). It includes a bash script to test and exploit each vulnerability using `curl`.

**Purpose:** Educational only. Use in isolated test environments. Do not deploy in production or use against unauthorized systems.

## Files Created

1. **vulnerable_app.php**  
   A PHP application with 7 implemented vulnerabilities:  
   - CVE-2025-6491 - SOAP XML Namespace Overflow  
   - CVE-2025-1861 - HTTP Redirect URL Truncation  
   - CVE-2025-1736 - HTTP Header Injection  
   - CVE-2025-1220 - Null Byte in Hostname  
   - CVE-2022-31631 - PDO SQLite Quote Overflow  
   - CVE-2025-1734 - Invalid HTTP Headers  
   - CVE-2025-1217 - Folded HTTP Headers  

2. **exploit_tests.sh**  
   A bash script with `curl` tests to exploit each vulnerability.

## How to Use

1. Save the files: `vulnerable_app.php` and `exploit_tests.sh`.

2. Start the PHP server:  
   ```
   php -S localhost:8000 vulnerable_app.php
   ```

3. In another terminal, run the tests:  
   ```
   chmod +x exploit_tests.sh
   ./exploit_tests.sh
   ```

## What Each Test Does

- **CVE-2025-6491:** Sends XML with a giant namespace prefix (10KB) to cause a crash.  
- **CVE-2025-1861:** Sends a URL of 2000+ bytes that gets truncated to 1024 bytes.  
- **CVE-2025-1736:** Injects malicious headers via CRLF characters (`\r\n`).  
- **CVE-2025-1220:** Uses a null byte (`\x00`) to bypass hostname validation.  
- **CVE-2022-31631:** Sends a 1MB string to cause overflow in `PDO::quote()`.  
- **CVE-2025-1734:** Sends a header without a colon that is accepted as valid.  
- **CVE-2025-1217:** Sends a "folded" header that is parsed incorrectly.

## What Each Test Returns

- HTTP Status  
- Vulnerability Detection  
- Exact Failure Location (code line)  
- Root Cause of the Issue  
- Security Impact  

## IMPORTANT

This code is **FOR EDUCATIONAL PURPOSES ONLY**. Use exclusively in isolated test environments. Never use in production or against systems without explicit authorization!
