package com.intentwatch.security.testing;

import android.net.Uri;

import com.intentwatch.security.models.TestCase;

import java.util.ArrayList;
import java.util.List;

/**
 * Implements Deep-Link Fuzzer & Mutation Generator.
 * Generates security-focused test cases across 10 critical vulnerability vectors.
 */
public class DeepLinkFuzzer {

    public static List<TestCase> generateFuzzTestCases(String baselineUri) {
        List<TestCase> cases = new ArrayList<>();
        if (baselineUri == null || baselineUri.trim().isEmpty()) {
            baselineUri = "intentwatch-test://vulnerable?redirect_url=https://example.com/callback&action=view&id=101";
        }

        String scheme = "intentwatch-test";
        String host = "vulnerable";
        String path = "";

        int schemeIdx = baselineUri.indexOf("://");
        if (schemeIdx != -1) {
            scheme = baselineUri.substring(0, schemeIdx);
            String rest = baselineUri.substring(schemeIdx + 3);
            int slashIdx = rest.indexOf("/");
            int queryIdx = rest.indexOf("?");
            if (slashIdx != -1 && (queryIdx == -1 || slashIdx < queryIdx)) {
                host = rest.substring(0, slashIdx);
                if (queryIdx != -1) {
                    path = rest.substring(slashIdx, queryIdx);
                } else {
                    path = rest.substring(slashIdx);
                }
            } else if (queryIdx != -1) {
                host = rest.substring(0, queryIdx);
            } else {
                host = rest;
            }
        }

        // 1. Valid Baseline
        cases.add(new TestCase(
                "TC-01-BASELINE",
                "Valid Baseline URI",
                "Baseline Validation",
                "Normal expected deep-link structure for functional verification.",
                baselineUri,
                "BASELINE"
        ));

        // 2. Missing Parameters
        String missingParamUri = scheme + "://" + host + path;
        cases.add(new TestCase(
                "TC-02-NO-PARAMS",
                "Missing Parameters Mutation",
                "Input Validation",
                "Strips all query parameters to test for NullPointerExceptions or improper default fallbacks.",
                missingParamUri,
                "MISSING_PARAMS"
        ));

        // 3. Empty Parameter Values
        String emptyParamsUri = scheme + "://" + host + path + "?redirect_url=&action=&id=";
        cases.add(new TestCase(
                "TC-03-EMPTY-VALUES",
                "Empty Parameter Values",
                "Input Validation",
                "Supplies empty strings for critical parameters to detect missing length or null checks.",
                emptyParamsUri,
                "EMPTY_VALUES"
        ));

        // 4. Malformed URI Syntax
        String malformedUri = scheme + "://" + host + ":99999999/path?key=[invalid{bracket]";
        cases.add(new TestCase(
                "TC-04-MALFORMED-SYNTAX",
                "Malformed URI Structure",
                "Syntax Robustness",
                "Supplies illegal port numbers and unescaped brackets to test URI parser resilience.",
                malformedUri,
                "MALFORMED_SYNTAX"
        ));

        // 5. Encoded and Double-Encoded Traversal
        String doubleEncodedUri = scheme + "://" + host + path + "?redirect_url=%252e%252e%252f%252e%252e%252fetc%252fshadow&file=..%2f..%2fprivate.xml";
        cases.add(new TestCase(
                "TC-05-DOUBLE-ENCODED",
                "Double-Encoded Path Traversal",
                "Path Traversal",
                "Injects double URL-encoded directory traversal sequences (%252e%252e%252f) to bypass single-decode filters.",
                doubleEncodedUri,
                "DOUBLE_ENCODING"
        ));

        // 6. Unexpected Schemes (javascript, file, content)
        String unexpectedSchemeUri = "javascript:alert(document.cookie);//" + host + path;
        cases.add(new TestCase(
                "TC-06-UNEXPECTED-SCHEME",
                "Dangerous Scheme Injection (javascript:)",
                "Scheme Injection",
                "Supplies javascript: pseudo-protocol to verify whether internal WebViews execute arbitrary script.",
                unexpectedSchemeUri,
                "UNEXPECTED_SCHEME"
        ));

        // 7. Untrusted Redirect Destination
        String untrustedRedirectUri = scheme + "://" + host + path + "?redirect_url=https://attacker-controlled.site/phishing/login&callback=evil.com";
        cases.add(new TestCase(
                "TC-07-OPEN-REDIRECT",
                "Untrusted Redirection Destination",
                "Open Redirection",
                "Supplies external attacker domain in redirect_url to verify whether intent forwarder validates domains.",
                untrustedRedirectUri,
                "OPEN_REDIRECT"
        ));

        // 8. Invalid Host & Path Collision
        String hostCollisionUri = scheme + "://rogue-host.internal/restricted/admin";
        cases.add(new TestCase(
                "TC-08-HOST-COLLISION",
                "Rogue Host & Restricted Path Collision",
                "Access Control",
                "Targets unverified host with administrative path to probe wildcard path matching weaknesses.",
                hostCollisionUri,
                "HOST_COLLISION"
        ));

        // 9. HTTP Parameter Pollution & Injection
        String paramPollutionUri = scheme + "://" + host + path + "?action=user&action=admin&is_admin=true&auth=1";
        cases.add(new TestCase(
                "TC-09-PARAM-POLLUTION",
                "Parameter Pollution & Flag Injection",
                "Parameter Tampering",
                "Repeats query keys and injects administrative privilege flags to assess parameter precedence.",
                paramPollutionUri,
                "PARAM_POLLUTION"
        ));

        // 10. Malformed Intent Extras Injection
        TestCase tc10 = new TestCase(
                "TC-10-INTENT-EXTRAS",
                "Sensitive Intent Extras Simulation",
                "Intent Injection",
                "Tests whether the receiving activity handles untrusted extras or sensitive flags from deep-links.",
                scheme + "://" + host + path + "?action=verify_session",
                "EXTRAS_INJECTION"
        );
        tc10.setExtrasJson("{\"internal_token\":\"sec_test_admin_key_99\",\"debug_mode\":true}");
        cases.add(tc10);

        return cases;
    }
}
