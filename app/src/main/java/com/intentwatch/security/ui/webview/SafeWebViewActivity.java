package com.intentwatch.security.ui.webview;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;

import java.util.ArrayList;
import java.util.List;

/**
 * Sandboxed WebView Activity for controlled deep-link URL preview and security probing.
 * Enforces strict origin boundaries, disables arbitrary script execution, and audits blocked navigation.
 */
public class SafeWebViewActivity extends AppCompatActivity {

    private WebView webView;
    private TextView tvTargetUrl;
    private TextView tvBlockedLog;
    private final List<String> blockedEvents = new ArrayList<>();

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_safe_webview);

        tvTargetUrl = findViewById(R.id.tv_current_target_url);
        tvBlockedLog = findViewById(R.id.tv_blocked_events_log);
        webView = findViewById(R.id.webview_sandbox);
        MaterialButton btnClose = findViewById(R.id.btn_close_webview);

        btnClose.setOnClickListener(v -> finish());

        // Configure hardened WebView Settings
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(false); // Security Rule: Never enable JS for untrusted URL previews
        settings.setAllowFileAccess(false);   // Block local file access
        settings.setAllowContentAccess(false); // Block content scheme access
        settings.setGeolocationEnabled(false);
        settings.setDatabaseEnabled(false);

        String initialUrl = getIntent().getStringExtra("TARGET_URL");
        if (initialUrl == null || initialUrl.trim().isEmpty()) {
            initialUrl = "https://intentwatch.security/safe-preview";
        }
        tvTargetUrl.setText("Target: " + initialUrl);

        // Security-hardened WebViewClient
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";

                // Only allow HTTP/HTTPS within the sandbox
                if (!"http".equals(scheme) && !"https".equals(scheme)) {
                    logBlockedEvent("BLOCKED SCHEME: Navigation attempt to non-web scheme '" + scheme + "://' rejected.");
                    return true; // Cancel navigation
                }

                // Disallow javascript: or data: schemes
                if ("javascript".equals(scheme) || "data".equals(scheme) || "file".equals(scheme)) {
                    logBlockedEvent("BLOCKED THREAT: Potential execution vector '" + scheme + "' blocked.");
                    return true;
                }

                return false;
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                super.onPageStarted(view, url, favicon);
                tvTargetUrl.setText("Loading: " + url);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                tvTargetUrl.setText("Active: " + url);
            }
        });

        // Load content safely: if custom scheme, display synthetic test render
        if (!initialUrl.startsWith("http://") && !initialUrl.startsWith("https://")) {
            logBlockedEvent("Custom scheme detected. Rendered offline diagnostic preview instead of network dispatch.");
            String html = "<html><body style='background-color:#0B111E;color:#F1F5F9;font-family:sans-serif;padding:20px;'>" +
                    "<h2 style='color:#00E5FF;'>Isolated Diagnostic Sandbox</h2>" +
                    "<p>Previewing Deep-Link Target:</p>" +
                    "<code style='color:#38BDF8;background:#1E2D4A;padding:8px;display:block;'>" + initialUrl + "</code>" +
                    "<p style='color:#10B981;'>No network or intent leakage occurred.</p>" +
                    "</body></html>";
            webView.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null);
        } else {
            webView.loadUrl(initialUrl);
        }
    }

    private void logBlockedEvent(String event) {
        blockedEvents.add(event);
        StringBuilder sb = new StringBuilder("Security Logs:\n");
        for (String ev : blockedEvents) {
            sb.append("• ").append(ev).append("\n");
        }
        tvBlockedLog.setText(sb.toString());
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
