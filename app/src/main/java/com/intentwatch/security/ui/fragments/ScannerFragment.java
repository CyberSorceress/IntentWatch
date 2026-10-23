package com.intentwatch.security.ui.fragments;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
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
import com.intentwatch.security.ui.adapters.DeepLinkAdapter;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ScannerFragment extends Fragment {

    private EditText etSearch;
    private TextView tvScannerCount, tvScannerEmpty;
    private ProgressBar progressScanner;
    private ImageButton btnRefresh, btnImportApk;
    private MaterialButton btnFilterAll, btnFilterCustom, btnFilterHttp, btnFilterExported;
    private RecyclerView recyclerDeeplinks;
    private DeepLinkAdapter adapter;

    private String currentSchemeFilter = "ALL";
    private Boolean currentExportedOnly = false;
    private String currentQuery = "";

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
        View view = inflater.inflate(R.layout.fragment_scanner, container, false);

        etSearch = view.findViewById(R.id.et_search_deeplinks);
        tvScannerCount = view.findViewById(R.id.tv_scanner_count);
        tvScannerEmpty = view.findViewById(R.id.tv_scanner_empty);
        progressScanner = view.findViewById(R.id.progress_scanner);
        btnRefresh = view.findViewById(R.id.btn_refresh_scan);
        btnImportApk = view.findViewById(R.id.btn_scanner_import_apk);
        btnFilterAll = view.findViewById(R.id.btn_filter_all);
        btnFilterCustom = view.findViewById(R.id.btn_filter_custom);
        btnFilterHttp = view.findViewById(R.id.btn_filter_http);
        btnFilterExported = view.findViewById(R.id.btn_filter_exported);
        recyclerDeeplinks = view.findViewById(R.id.recycler_deeplinks);

        recyclerDeeplinks.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new DeepLinkAdapter();
        recyclerDeeplinks.setAdapter(adapter);

        adapter.setOnItemClickListener(this::showItemDetailsDialog);

        btnRefresh.setOnClickListener(v -> performScan());
        btnImportApk.setOnClickListener(v -> apkPickerLauncher.launch("*/*"));

        btnFilterAll.setOnClickListener(v -> {
            currentSchemeFilter = "ALL";
            currentExportedOnly = false;
            applyFilter();
        });

        btnFilterCustom.setOnClickListener(v -> {
            currentSchemeFilter = "CUSTOM";
            currentExportedOnly = false;
            applyFilter();
        });

        btnFilterHttp.setOnClickListener(v -> {
            currentSchemeFilter = "HTTP";
            currentExportedOnly = false;
            applyFilter();
        });

        btnFilterExported.setOnClickListener(v -> {
            currentExportedOnly = !currentExportedOnly;
            applyFilter();
        });

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                currentQuery = s.toString();
                applyFilter();
            }
            @Override public void afterTextChanged(Editable s) {}
        });

        loadFromDatabase();
        return view;
    }

    private void applyFilter() {
        if (getContext() == null) return;
        DatabaseHelper db = DatabaseHelper.getInstance(getContext());
        List<DiscoveredDeepLink> filtered = db.filterDiscoveredDeepLinks(currentQuery, currentSchemeFilter, currentExportedOnly);
        adapter.setItems(filtered);

        tvScannerCount.setText(filtered.size() + " handlers matching filter");
        if (filtered.isEmpty()) {
            tvScannerEmpty.setVisibility(View.VISIBLE);
            recyclerDeeplinks.setVisibility(View.GONE);
        } else {
            tvScannerEmpty.setVisibility(View.GONE);
            recyclerDeeplinks.setVisibility(View.VISIBLE);
        }
    }

    private void loadFromDatabase() {
        applyFilter();
    }

    private void performScan() {
        if (getContext() == null) return;
        Context appContext = getContext().getApplicationContext();

        progressScanner.setVisibility(View.VISIBLE);
        btnRefresh.setEnabled(false);

        executor.execute(() -> {
            InstalledAppScanner.ScanResult res = InstalledAppScanner.scanInstalledApplications(appContext);
            ConflictAnalyzer.AnalysisResult analysis = ConflictAnalyzer.analyzeHandlers(res.discoveredLinks);

            DatabaseHelper db = DatabaseHelper.getInstance(appContext);
            db.insertDiscoveredDeepLinks(res.discoveredLinks);
            db.replaceSchemeConflicts(analysis.conflicts);
            db.upsertSecurityFindings(analysis.findings);

            ScanSession session = new ScanSession();
            session.setScanType("INSTALLED_PACKAGES");
            session.setTargetName("Installed Apps Audit");
            session.setTotalHandlers(res.discoveredLinks.size());
            session.setCollisionCount(analysis.conflicts.size());
            session.setExportedActivitiesCount(analysis.exportedUnprotectedCount);
            db.insertScanSession(session);

            mainHandler.post(() -> {
                progressScanner.setVisibility(View.GONE);
                btnRefresh.setEnabled(true);
                applyFilter();
                Toast.makeText(appContext, "Cataloged " + res.discoveredLinks.size() + " deep-link handlers.", Toast.LENGTH_SHORT).show();
            });
        });
    }

    private void handleApkSelected(Uri uri) {
        if (uri == null || getContext() == null) return;
        Context appContext = getContext().getApplicationContext();

        progressScanner.setVisibility(View.VISIBLE);
        executor.execute(() -> {
            ApkManifestParser.ParseResult parse = ApkManifestParser.parseApkFromUri(appContext, uri);
            if (parse.success) {
                ConflictAnalyzer.AnalysisResult analysis = ConflictAnalyzer.analyzeHandlers(parse.deepLinks);
                DatabaseHelper db = DatabaseHelper.getInstance(appContext);
                db.insertDiscoveredDeepLinks(parse.deepLinks);
                db.replaceSchemeConflicts(analysis.conflicts);
                db.upsertSecurityFindings(analysis.findings);

                mainHandler.post(() -> {
                    progressScanner.setVisibility(View.GONE);
                    applyFilter();
                    Toast.makeText(appContext, "Imported " + parse.deepLinks.size() + " handlers from APK.", Toast.LENGTH_SHORT).show();
                });
            } else {
                mainHandler.post(() -> {
                    progressScanner.setVisibility(View.GONE);
                    Toast.makeText(appContext, "Error importing APK: " + parse.errorMessage, Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void showItemDetailsDialog(DiscoveredDeepLink item) {
        if (getContext() == null) return;
        new AlertDialog.Builder(getContext())
                .setTitle("Deep-Link Inspector")
                .setMessage("Application: " + item.getAppName() + "\n" +
                        "Package: " + item.getPackageName() + "\n" +
                        "Activity: " + item.getActivityName() + "\n\n" +
                        "URI Pattern: " + item.getDisplayUriPattern() + "\n" +
                        "Scheme: " + item.getScheme() + "\n" +
                        "Host: " + (item.getHost().isEmpty() ? "*(Wildcard)" : item.getHost()) + "\n" +
                        "Path Constraint: " + (item.getPath().isEmpty() ? "Unrestricted" : item.getPath()) + "\n\n" +
                        "Exported: " + item.isExported() + "\n" +
                        "AutoVerify: " + item.isAutoVerify() + "\n" +
                        "LaunchMode: " + item.getLaunchMode() + "\n" +
                        "Calculated Risk: " + item.getRiskScore() + "/100")
                .setPositiveButton("Close", null)
                .show();
    }
}
