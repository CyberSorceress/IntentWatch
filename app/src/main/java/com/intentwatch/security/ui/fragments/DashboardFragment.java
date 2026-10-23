package com.intentwatch.security.ui.fragments;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;
import com.intentwatch.security.analysis.ConflictAnalyzer;
import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.models.DiscoveredDeepLink;
import com.intentwatch.security.models.ScanSession;
import com.intentwatch.security.scanner.ApkManifestParser;
import com.intentwatch.security.scanner.InstalledAppScanner;
import com.intentwatch.security.ui.MainActivity;
import com.intentwatch.security.ui.adapters.RecentScanAdapter;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DashboardFragment extends Fragment {

    private TextView tvKpiHandlers, tvKpiSchemes, tvKpiConflicts, tvKpiExported;
    private TextView tvScanStatusDesc, tvEmptyScans;
    private ProgressBar progressScan;
    private MaterialButton btnScan, btnImportApk;
    private RecyclerView recyclerRecentScans;
    private RecentScanAdapter scanAdapter;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private ActivityResultLauncher<String> apkPickerLauncher;

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        apkPickerLauncher = registerForActivityResult(
                new ActivityResultContracts.GetContent(),
                this::handleApkSelected
        );
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_dashboard, container, false);

        tvKpiHandlers = view.findViewById(R.id.tv_kpi_handlers);
        tvKpiSchemes = view.findViewById(R.id.tv_kpi_schemes);
        tvKpiConflicts = view.findViewById(R.id.tv_kpi_conflicts);
        tvKpiExported = view.findViewById(R.id.tv_kpi_exported);
        tvScanStatusDesc = view.findViewById(R.id.tv_scan_status_desc);
        tvEmptyScans = view.findViewById(R.id.tv_empty_scans);
        progressScan = view.findViewById(R.id.progress_scan);
        btnScan = view.findViewById(R.id.btn_dashboard_scan);
        btnImportApk = view.findViewById(R.id.btn_dashboard_import_apk);
        recyclerRecentScans = view.findViewById(R.id.recycler_recent_scans);

        recyclerRecentScans.setLayoutManager(new LinearLayoutManager(getContext()));
        scanAdapter = new RecentScanAdapter();
        recyclerRecentScans.setAdapter(scanAdapter);

        btnScan.setOnClickListener(v -> performInstalledScan());
        btnImportApk.setOnClickListener(v -> apkPickerLauncher.launch("*/*"));

        loadDashboardData();
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        loadDashboardData();
    }

    private void loadDashboardData() {
        if (getContext() == null) return;
        DatabaseHelper db = DatabaseHelper.getInstance(getContext());
        Map<String, Integer> stats = db.getStatistics();

        tvKpiHandlers.setText(String.valueOf(stats.getOrDefault("total_handlers", 0)));
        tvKpiSchemes.setText(String.valueOf(stats.getOrDefault("distinct_schemes", 0)));
        tvKpiConflicts.setText(String.valueOf(stats.getOrDefault("conflicts_count", 0)));
        tvKpiExported.setText(String.valueOf(stats.getOrDefault("exported_count", 0)));

        List<ScanSession> sessions = db.getRecentScanSessions(5);
        if (sessions.isEmpty()) {
            tvEmptyScans.setVisibility(View.VISIBLE);
            recyclerRecentScans.setVisibility(View.GONE);
        } else {
            tvEmptyScans.setVisibility(View.GONE);
            recyclerRecentScans.setVisibility(View.VISIBLE);
            scanAdapter.setItems(sessions);
        }
    }

    private void performInstalledScan() {
        if (getContext() == null) return;
        Context appContext = getContext().getApplicationContext();

        btnScan.setEnabled(false);
        btnImportApk.setEnabled(false);
        progressScan.setVisibility(View.VISIBLE);
        tvScanStatusDesc.setText("Resolving installed package intent filters...");

        executor.execute(() -> {
            InstalledAppScanner.ScanResult scanResult = InstalledAppScanner.scanInstalledApplications(appContext);
            ConflictAnalyzer.AnalysisResult analysis = ConflictAnalyzer.analyzeHandlers(scanResult.discoveredLinks);

            DatabaseHelper db = DatabaseHelper.getInstance(appContext);
            db.insertDiscoveredDeepLinks(scanResult.discoveredLinks);
            db.replaceSchemeConflicts(analysis.conflicts);
            db.upsertSecurityFindings(analysis.findings);

            ScanSession session = new ScanSession();
            session.setScanType("INSTALLED_PACKAGES");
            session.setTargetName("Installed Apps Audit");
            session.setTotalHandlers(scanResult.discoveredLinks.size());
            session.setCollisionCount(analysis.conflicts.size());
            session.setExportedActivitiesCount(analysis.exportedUnprotectedCount);
            session.setCriticalFindingsCount((int) analysis.findings.stream().filter(f -> "CRITICAL".equals(f.getSeverity())).count());
            session.setHighFindingsCount((int) analysis.findings.stream().filter(f -> "HIGH".equals(f.getSeverity())).count());
            db.insertScanSession(session);

            mainHandler.post(() -> {
                btnScan.setEnabled(true);
                btnImportApk.setEnabled(true);
                progressScan.setVisibility(View.GONE);
                tvScanStatusDesc.setText(scanResult.statusMessage);
                loadDashboardData();
                Toast.makeText(appContext, "Scan completed: " + scanResult.discoveredLinks.size() + " handlers cataloged.", Toast.LENGTH_SHORT).show();
            });
        });
    }

    private void handleApkSelected(Uri uri) {
        if (uri == null || getContext() == null) return;
        Context appContext = getContext().getApplicationContext();

        btnScan.setEnabled(false);
        btnImportApk.setEnabled(false);
        progressScan.setVisibility(View.VISIBLE);
        tvScanStatusDesc.setText("Parsing APK AndroidManifest.xml (AXML)...");

        executor.execute(() -> {
            ApkManifestParser.ParseResult parse = ApkManifestParser.parseApkFromUri(appContext, uri);
            if (parse.success) {
                ConflictAnalyzer.AnalysisResult analysis = ConflictAnalyzer.analyzeHandlers(parse.deepLinks);
                DatabaseHelper db = DatabaseHelper.getInstance(appContext);
                db.insertDiscoveredDeepLinks(parse.deepLinks);
                db.replaceSchemeConflicts(analysis.conflicts);
                db.upsertSecurityFindings(analysis.findings);

                ScanSession session = new ScanSession();
                session.setScanType("APK_FILE");
                session.setTargetName(parse.appName.isEmpty() ? parse.packageName : parse.appName);
                session.setTotalHandlers(parse.deepLinks.size());
                session.setCollisionCount(analysis.conflicts.size());
                session.setExportedActivitiesCount(analysis.exportedUnprotectedCount);
                session.setCriticalFindingsCount((int) analysis.findings.stream().filter(f -> "CRITICAL".equals(f.getSeverity())).count());
                session.setHighFindingsCount((int) analysis.findings.stream().filter(f -> "HIGH".equals(f.getSeverity())).count());
                db.insertScanSession(session);

                mainHandler.post(() -> {
                    btnScan.setEnabled(true);
                    btnImportApk.setEnabled(true);
                    progressScan.setVisibility(View.GONE);
                    tvScanStatusDesc.setText("Parsed APK: " + parse.appName + " (" + parse.deepLinks.size() + " handlers)");
                    loadDashboardData();
                    Toast.makeText(appContext, "Successfully imported APK manifest: " + parse.deepLinks.size() + " handlers discovered.", Toast.LENGTH_SHORT).show();
                });
            } else {
                mainHandler.post(() -> {
                    btnScan.setEnabled(true);
                    btnImportApk.setEnabled(true);
                    progressScan.setVisibility(View.GONE);
                    tvScanStatusDesc.setText("Failed: " + parse.errorMessage);
                    Toast.makeText(appContext, "Failed to inspect APK: " + parse.errorMessage, Toast.LENGTH_LONG).show();
                });
            }
        });
    }
}
