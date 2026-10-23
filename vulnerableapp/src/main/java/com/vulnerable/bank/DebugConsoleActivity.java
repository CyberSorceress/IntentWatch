package com.vulnerable.bank;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

/**
 * Handles myapp://debug and debug://execute. Exported without permission check.
 */
public class DebugConsoleActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}
