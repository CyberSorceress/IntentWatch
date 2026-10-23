package com.vulnerable.bank;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

/**
 * Handles https://bank.example.com without android:autoVerify="true".
 */
public class UnverifiedAppLinksActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}
