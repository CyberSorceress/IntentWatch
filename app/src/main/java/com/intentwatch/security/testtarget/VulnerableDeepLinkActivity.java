package com.intentwatch.security.testtarget;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;

import java.util.Set;

/**
 * Controlled Vulnerable Target Activity.
 * Demonstrates unsafe deep-link parameter parsing and unvalidated intent redirection.
 * Specifically registered to demonstrate custom scheme hijacking risks.
 */
public class VulnerableDeepLinkActivity extends AppCompatActivity {

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

        tvTitle.setText("Vulnerable Deep-Link Receiver");
        tvStatus.setText("Status: Insecure Handler Executed (Risk Level: CRITICAL)");
        tvStatus.setTextColor(getColor(R.color.severity_critical));

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
            StringBuilder assess = new StringBuilder();
            assess.append("CRITICAL VULNERABILITIES DETECTED:\n\n");
            assess.append("1. Missing Whitelist Validation:\n");
            if (redirectUrl != null && !redirectUrl.isEmpty()) {
                assess.append("• Received redirect_url='").append(redirectUrl).append("'.\n");
                assess.append("• The application blindly accepted this destination without checking host or scheme authorization.\n");
            } else {
                assess.append("• Target accepts unvalidated redirection parameters.\n");
            }
            assess.append("\n2. Custom Scheme Hijackable:\n");
            assess.append("• Registers 'intentwatch-test://vulnerable' without Android App Links cryptographic verification.\n");
            assess.append("• A malicious app can register this exact scheme and intercept sensitive user transactions.\n");

            tvAssessment.setText(assess.toString());
        } else {
            tvReceivedUri.setText("No URI data attached to Intent.");
            tvAssessment.setText("Activity opened without Intent data payload.");
        }

        btnClose.setOnClickListener(v -> finish());
    }
}
