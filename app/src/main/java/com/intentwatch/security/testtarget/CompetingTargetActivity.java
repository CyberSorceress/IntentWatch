package com.intentwatch.security.testtarget;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;

/**
 * Controlled Competing Target Activity.
 * Registers the same URI scheme ('intentwatch-test://vulnerable') as VulnerableDeepLinkActivity.
 * Demonstrates real-world custom URI scheme ambiguity and resolver disambiguation dialogs.
 */
public class CompetingTargetActivity extends AppCompatActivity {

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

        tvTitle.setText("Competing Collision Target (Secondary App)");
        tvStatus.setText("Status: Competing Scheme Interceptor Executed");
        tvStatus.setTextColor(getColor(R.color.severity_high));

        Intent intent = getIntent();
        Uri data = intent.getData();

        if (data != null) {
            tvReceivedUri.setText(data.toString());
            tvParams.setText("Query: " + data.getQuery());

            StringBuilder assess = new StringBuilder();
            assess.append("SCHEME COLLISION PROOF OF CONCEPT:\n\n");
            assess.append("• This activity registered 'intentwatch-test://vulnerable'.\n");
            assess.append("• VulnerableDeepLinkActivity ALSO registers this exact scheme.\n");
            assess.append("• If the user dispatched this URI from an external app or browser, Android triggered an App Chooser dialog.\n");
            assess.append("• If a rogue app was selected as default, all user data, tokens, and actions intended for the primary app were intercepted!\n");

            tvAssessment.setText(assess.toString());
        }

        btnClose.setOnClickListener(v -> finish());
    }
}
