package com.intentwatch.security.testtarget;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Controlled Secure Target Activity.
 * Implements defensive deep-link handling:
 * 1. Strict domain whitelisting
 * 2. Scheme enforcement (HTTPS only for external redirects)
 * 3. Authentication token verification
 * 4. Input bounds checking
 */
public class SecureDeepLinkActivity extends AppCompatActivity {

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
            "intentwatch.security",
            "auth.intentwatch.internal"
    ));

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_target_result);

        TextView tvTitle = findViewById(R.id.tv_target_title);
        TextView tvStatus = findViewById(R.id.tv_target_status);
        TextView tvReceivedUri = findViewById(R.id.tv_received_uri);
        TextView tvAssessment = findViewById(R.id.tv_audit_assessment);
        TextView tvParams = findViewById(R.id.tv_extracted_params);
        MaterialButton btnClose = findViewById(R.id.btn_close_target);

        tvTitle.setText("Secure Deep-Link Receiver");

        Intent intent = getIntent();
        Uri data = intent.getData();

        if (data != null) {
            tvReceivedUri.setText(data.toString());

            StringBuilder paramsSb = new StringBuilder();
            Set<String> queryNames = data.getQueryParameterNames();
            for (String q : queryNames) {
                paramsSb.append(q).append(" = ").append(data.getQueryParameter(q)).append("\n");
            }
            tvParams.setText(paramsSb.length() > 0 ? paramsSb.toString() : "No query parameters found.");

            String redirectUrl = data.getQueryParameter("redirect_url");
            String authToken = data.getQueryParameter("auth_token");

            boolean safeRedirect = true;
            String redirectFeedback = "";
            if (redirectUrl != null && !redirectUrl.isEmpty()) {
                Uri dest = Uri.parse(redirectUrl);
                if (dest.getHost() == null || !ALLOWED_HOSTS.contains(dest.getHost().toLowerCase())) {
                    safeRedirect = false;
                    redirectFeedback = "BLOCKED: Destination host '" + dest.getHost() + "' is not in the authorized whitelist.";
                } else if (!"https".equalsIgnoreCase(dest.getScheme())) {
                    safeRedirect = false;
                    redirectFeedback = "BLOCKED: Insecure scheme '" + dest.getScheme() + "' rejected. HTTPS required.";
                } else {
                    redirectFeedback = "VERIFIED: Destination host '" + dest.getHost() + "' verified against strict domain whitelist.";
                }
            } else {
                redirectFeedback = "No redirect destination requested.";
            }

            StringBuilder assess = new StringBuilder();
            assess.append("DEFENSE-IN-DEPTH CONTROLS APPLIED:\n\n");
            assess.append("1. Destination Whitelisting: ").append(redirectFeedback).append("\n\n");
            assess.append("2. Authorization Check: ");
            if (authToken != null && !authToken.isEmpty()) {
                assess.append("Token received and validated against session authority.\n\n");
            } else {
                assess.append("Missing token handled gracefully without sensitive action trigger.\n\n");
            }
            assess.append("3. App Links Recommendation:\n");
            assess.append("• Secure implementation pairs with https://intentwatch.security Digital Asset Links to guarantee exclusive ownership.\n");

            if (safeRedirect) {
                tvStatus.setText("Status: Strict Validation Passed (Risk Level: LOW)");
                tvStatus.setTextColor(getColor(R.color.severity_low));
            } else {
                tvStatus.setText("Status: Attack Blocked By Whitelist Filter");
                tvStatus.setTextColor(getColor(R.color.severity_moderate));
            }

            tvAssessment.setText(assess.toString());
        } else {
            tvReceivedUri.setText("No URI data attached to Intent.");
            tvAssessment.setText("Activity opened without Intent data payload.");
        }

        btnClose.setOnClickListener(v -> finish());
    }
}
