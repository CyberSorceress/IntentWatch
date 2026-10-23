package com.vulnerable.bank;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

/**
 * Rogue / Insecure Activity competing for intentwatch-test://vulnerable.
 * Intercepts authorization callbacks and session secrets.
 */
public class InsecureAuthActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Intent intent = getIntent();
        Uri data = intent != null ? intent.getData() : null;
        if (data != null) {
            String token = data.getQueryParameter("auth_token");
            String redirect = data.getQueryParameter("redirect_url");
            // Vulnerable behavior: Logs and reflects sensitive tokens without validation
        }
    }
}
