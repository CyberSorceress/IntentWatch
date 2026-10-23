# INTENTWATCH SECURITY AUDIT REPORT
## Android Deep-Link Hijacking & Intent Redirection Assessment

**Document ID:** `IW-AUDIT-2026-001`  
**Assessment Date:** 2026-10-23  
**Classification:** Confidential — Security Assessment  
**Academic Course:** Android Application Development (24CYS404)  
**Faculty Advisor:** Dr. S. Udhayakumar, Associate Professor, Cyber Security  
**Lead Auditor:** IntentWatch Automated Security Engine (`com.intentwatch.security`)  

---

## 1. Executive Summary

During the security evaluation of mobile application deep-linking architecture, IntentWatch performed a dual-mode assessment comprising:
1. **Static Manifest & Binary AXML Analysis** of package intent filters, exported component boundaries, and URI handler registrations.
2. **Dynamic Heuristic Conflict Analysis & Controlled Fuzzing** across custom URI schemes, HTTP/HTTPS web links, and internal intent redirection pipelines.

The audit identified **5 major security vulnerabilities**, ranging from **Medium (CVSS 5.3)** to **Critical (CVSS 9.1)**. Most critically, an unreserved custom URI scheme (`intentwatch-test://`) was found to be co-registered across multiple independent package namespaces (`com.intentwatch.security` and `com.vulnerable.bank`), creating a high-probability **Deep-Link Hijacking Vector**. Under standard device conditions, an attacker application installed on the target device can intercept authorization tokens, payment intents, or sensitive user actions.

### Overall Risk Posture

| Risk Score | Risk Tier | Discovered Vulnerabilities | Handlers Inspected |
| :---: | :---: | :---: | :---: |
| **88 / 100** | **CRITICAL** | 5 (2 Critical, 2 High, 1 Medium) | 12 Deep-Link Endpoints |

---

## 2. Assessment Scope & Target Inventory

The assessment encompassed both local device runtime inspection and offline APK manifest decoding:

| Target Package | Application Name | Version | Exported Activities | Monitored Schemes |
| :--- | :--- | :---: | :---: | :--- |
| `com.intentwatch.security` | IntentWatch Analyzer | 1.0.0 | 5 | `intentwatch-test`, `intentwatch-insecure`, `https` |
| `com.vulnerable.bank` | Vulnerable Bank Demo | 1.0.0 | 4 | `intentwatch-test`, `bankpay`, `myapp`, `debug`, `https` |

---

## 3. Discovered Vulnerability Taxonomy

```
+-----------------------------------------------------------------------------------+
| ID: IW-VULN-001                                                Severity: CRITICAL |
| Title: Unreserved Custom URI Scheme Hijacking & Ambiguous Intent Resolution       |
| CVSS v3.1: 9.1 (CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)                    |
| CWE: CWE-940 (Improper Verification of Source of Communication Direction)         |
+-----------------------------------------------------------------------------------+
```

### Description
Both `com.intentwatch.security` and `com.vulnerable.bank` declare identical intent filters for the custom URI scheme `intentwatch-test://vulnerable` within their `AndroidManifest.xml` files. Because Android custom URI schemes do not possess a central ownership verification authority (unlike RFC domain-verified App Links), the Android OS cannot establish a definitive handler.

### Impact
When a user or external web browser clicks `intentwatch-test://vulnerable?auth_token=SECRET`, Android triggers the System Intent Chooser dialog. If the user selects the rogue application, or if the rogue application matches default selection criteria, all sensitive parameters are leaked directly into the untrusted application's memory space.

### Evidence
- Handler 1: `com.intentwatch.security.testtarget.VulnerableDeepLinkActivity`
- Handler 2: `com.intentwatch.security.testtarget.CompetingTargetActivity`
- Handler 3: `com.vulnerable.bank.VulnerableDeepLinkActivity`
- Intent Filter Definition:
  ```xml
  <intent-filter>
      <action android:name="android.intent.action.VIEW" />
      <category android:name="android.intent.category.DEFAULT" />
      <category android:name="android.intent.category.BROWSABLE" />
      <data android:scheme="intentwatch-test" android:host="vulnerable" />
  </intent-filter>
  ```

---

```
+-----------------------------------------------------------------------------------+
| ID: IW-VULN-002                                                    Severity: HIGH |
| Title: Insecure Intent Redirection (Arbitrary Open Redirection)                   |
| CVSS v3.1: 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)                    |
| CWE: CWE-601 (URL Redirection to Untrusted Site - 'Open Redirect')                |
+-----------------------------------------------------------------------------------+
```

### Description
`VulnerableDeepLinkActivity` receives a `redirect_url` query parameter via `getIntent().getData().getQueryParameter("redirect_url")` and dispatches it directly into an unvalidated `Intent.ACTION_VIEW` or WebView launch without verifying the destination host against an allowed whitelist.

### Impact
An external attacker can construct a malicious link `intentwatch-test://vulnerable?redirect_url=https://phishing-site.example.com` that uses the trusted application as an open trampoline, misleading users into phishing domains or exfiltrating tokens via HTTP Referer headers.

### Evidence
- Test Execution Log:
  ```
  Payload: intentwatch-test://vulnerable?redirect_url=https://attacker-controlled.site&action=redirect
  Result: UNVALIDATED_REDIRECT_DETECTED
  Observation: Target activity initiated external intent forwarding without domain validation.
  ```

---

```
+-----------------------------------------------------------------------------------+
| ID: IW-VULN-003                                                    Severity: HIGH |
| Title: Broken Android App Links (Missing autoVerify & Digital Asset Links)        |
| CVSS v3.1: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)                    |
| CWE: CWE-300 (Channel Accessible by Non-Endpoint)                                |
+-----------------------------------------------------------------------------------+
```

### Description
The target application registers an HTTP/HTTPS handler for `https://bank.example.com` but omits the mandatory `android:autoVerify="true"` attribute in the `<intent-filter>` declaration, and no valid `/.well-known/assetlinks.json` endpoint exists to cryptographically anchor the domain to the app's signing certificate.

### Impact
Any third-party app installed on the device can register the exact same `https://bank.example.com` domain. Clicking bank links on the device will present an App Chooser rather than opening the authentic app directly, creating severe user-confusion and credential interception vectors.

---

```
+-----------------------------------------------------------------------------------+
| ID: IW-VULN-004                                                    Severity: HIGH |
| Title: Unprotected Exported Diagnostic & Debug Components                        |
| CVSS v3.1: 7.8 (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)                    |
| CWE: CWE-215 (Insertion of Sensitive Information into Debug Code)                |
+-----------------------------------------------------------------------------------+
```

### Description
The secondary package `com.vulnerable.bank` declares `android:exported="true"` on internal administrative activities listening on `debug://execute` and `myapp://debug` without enforcing signature-level permissions (`android:protectionLevel="signature"`).

### Impact
Any unprivileged application on the same Android device can issue background commands to invoke internal debugging routines, extract diagnostic dumps, or toggle developer features.

---

```
+-----------------------------------------------------------------------------------+
| ID: IW-VULN-005                                                  Severity: MEDIUM |
| Title: Plaintext Credential & Token Exposure in Deep-Link Query Strings          |
| CVSS v3.1: 5.5 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)                    |
| CWE: CWE-598 (Information Exposure Through Query Strings in GET Request)         |
+-----------------------------------------------------------------------------------+
```

### Description
The application architecture relies on passing authentication tokens (`auth_token`) directly as plain URI query string parameters in custom deep links.

### Impact
Android logs all launched intents and their complete URIs to the system `logcat` buffer (`ActivityManager: START u0 {act=android.intent.action.VIEW dat=intentwatch-test://...}`). Any application on the device with `READ_LOGS` (on rooted devices or older APIs) or forensic USB adb sessions can extract valid authentication tokens from the log history.

---

## 4. Test Lab Dynamic Fuzzing & Evidence Matrix

During the assessment, 10 structured fuzzer payloads were executed against the targets:

| # | Test Scenario | Payload Input | Target Handler | Result | Severity |
| :-: | :--- | :--- | :--- | :-: | :-: |
| 01 | **Valid Baseline** | `intentwatch-test://vulnerable?action=view` | `VulnerableDeepLinkActivity` | SUCCESS | INFO |
| 02 | **Missing Parameters** | `intentwatch-test://vulnerable` | Multiple (Collision) | **CHOOSER DIALOG** | **CRITICAL** |
| 03 | **Empty Parameters** | `intentwatch-test://vulnerable?redirect_url=&action=` | `VulnerableDeepLinkActivity` | NULL_FALLBACK | LOW |
| 04 | **Malformed Syntax** | `intentwatch-test://[invalid-host]:99999/test` | Intent Resolver | REJECTED_BY_OS | INFO |
| 05 | **Double Encoded Traversal** | `intentwatch-test://vulnerable?path=%252e%252e%252f` | `VulnerableDeepLinkActivity` | RAW_PASSTHROUGH | MEDIUM |
| 06 | **Dangerous Scheme** | `javascript:alert(1);//vulnerable` | Safe Test Harness | **BLOCKED_BY_GUARD** | LOW |
| 07 | **Open Redirection** | `intentwatch-test://vulnerable?redirect_url=https://attacker-site` | `VulnerableDeepLinkActivity` | **UNVALIDATED_REDIRECT** | **HIGH** |
| 08 | **Host Ambiguity** | `intentwatch-test://admin/dashboard` | `VulnerableDeepLinkActivity` | UNMATCHED_HOST | INFO |
| 09 | **Parameter Tampering** | `intentwatch-test://vulnerable?is_admin=true&role=superuser` | `VulnerableDeepLinkActivity` | ACCEPTED_PARAMS | HIGH |
| 10 | **Hardened Whitelist** | `intentwatch-test://secure?redirect_url=https://evil.com` | `SecureDeepLinkActivity` | **SECURITY_EXCEPTION** | **PASS** |

---

## 5. Strategic Remediation Roadmap & Hardening Guide

```
+-----------------------------------------------------------------------------------+
| Remediation Phase 1: Migrate from Custom Schemes to Verified Android App Links    |
+-----------------------------------------------------------------------------------+
```

Replace proprietary custom schemes (`bankpay://`, `intentwatch-test://`) with standard HTTPS Android App Links using cryptographic domain ownership:

```xml
<!-- HARDENED MANIFEST DECLARATION -->
<activity
    android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:scheme="https"
            android:host="intentwatch.security"
            android:pathPrefix="/auth" />
    </intent-filter>
</activity>
```

Host the Digital Asset Links statement at `https://intentwatch.security/.well-known/assetlinks.json`:
```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.intentwatch.security",
    "sha256_cert_fingerprints": [
      "28:B6:3E:47:04:E2:4C:59:71:3B:19:62:3C:D0:6B:3E:0F:15:..."
    ]
  }
}]
```

```
+-----------------------------------------------------------------------------------+
| Remediation Phase 2: Implement Strict Destination Whitelisting for Redirections  |
+-----------------------------------------------------------------------------------+
```

In all activities handling intent redirections, validate both the scheme and host against an immutable whitelist:

```java
public class SecureDeepLinkHandler {
    private static final Set<String> ALLOWED_HOSTS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("intentwatch.security", "auth.intentwatch.security"))
    );

    public static boolean isSafeDestination(Uri destinationUri) {
        if (destinationUri == null) return false;
        String scheme = destinationUri.getScheme();
        String host = destinationUri.getHost();
        
        // Strict HTTPS and Host validation
        return "https".equalsIgnoreCase(scheme) && 
               host != null && 
               ALLOWED_HOSTS.contains(host.toLowerCase(Locale.ROOT));
    }
}
```

```
+-----------------------------------------------------------------------------------+
| Remediation Phase 3: Short-Lived Ephemeral Authorization Exchange Codes           |
+-----------------------------------------------------------------------------------+
```

Never pass long-lived JWTs or API keys directly inside URI query strings. Use short-lived, single-use authorization codes with PKCE (RFC 7636).

---

## 6. Audit Conclusion & Sign-Off

The findings documented herein indicate that reliance on unreserved custom URI schemes without strict sanitization exposes mobile applications to intent hijacking and unvalidated redirection. Implementing Android App Links with cryptographic domain verification and rigorous URI sanitization remediates all identified high-severity vectors.

**Report Generated By:** `PdfReportGenerator` & `JsonReportGenerator`  
**IntentWatch Analyzer Engine:** Build v1.0.0 (API 26–34)  
**Academic Endorsement:** Dr. S. Udhayakumar, Associate Professor, Cyber Security
