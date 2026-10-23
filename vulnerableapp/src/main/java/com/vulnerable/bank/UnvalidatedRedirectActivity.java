package com.vulnerable.bank;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

/**
 * Handles bankpay://transfer and bankpay://open without domain validation.
 */
public class UnvalidatedRedirectActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Intent intent = getIntent();
        Uri data = intent != null ? intent.getData() : null;
        if (data != null) {
            String redirectUrl = data.getQueryParameter("redirect_url");
            // Vulnerable: Blindly forwards intent without whitelist
        }
    }
}
