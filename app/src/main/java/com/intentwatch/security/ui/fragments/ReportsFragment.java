package com.intentwatch.security.ui.fragments;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;
import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.reports.PdfReportGenerator;
import com.intentwatch.security.reports.ReportExporter;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ReportsFragment extends Fragment {

    private TextView tvTimestamp, tvHandlers, tvSchemes, tvConflicts, tvCritical, tvTests;
    private MaterialButton btnExportPdf, btnExportJson, btnPreviewPdf, btnShareReport;

    private File lastGeneratedPdfFile = null;
    private File lastGeneratedJsonFile = null;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_reports, container, false);

        tvTimestamp = view.findViewById(R.id.tv_report_timestamp);
        tvHandlers = view.findViewById(R.id.tv_report_stat_handlers);
        tvSchemes = view.findViewById(R.id.tv_report_stat_schemes);
        tvConflicts = view.findViewById(R.id.tv_report_stat_conflicts);
        tvCritical = view.findViewById(R.id.tv_report_stat_critical);
        tvTests = view.findViewById(R.id.tv_report_stat_tests);

        btnExportPdf = view.findViewById(R.id.btn_export_pdf);
        btnExportJson = view.findViewById(R.id.btn_export_json);
        btnPreviewPdf = view.findViewById(R.id.btn_preview_pdf);
        btnShareReport = view.findViewById(R.id.btn_share_report);

        btnExportPdf.setOnClickListener(v -> generatePdfReport(false));
        btnExportJson.setOnClickListener(v -> generateJsonReport());
        btnPreviewPdf.setOnClickListener(v -> previewPdf());
        btnShareReport.setOnClickListener(v -> shareReport());

        loadReportStats();
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        loadReportStats();
    }

    private void loadReportStats() {
        if (getContext() == null) return;
        DatabaseHelper db = DatabaseHelper.getInstance(getContext());
        Map<String, Integer> stats = db.getStatistics();

        String dateStr = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
        tvTimestamp.setText("Audit Engine Synchronized: " + dateStr);

        tvHandlers.setText("• Discovered Handlers: " + stats.getOrDefault("total_handlers", 0));
        tvSchemes.setText("• Distinct URI Schemes: " + stats.getOrDefault("distinct_schemes", 0));
        tvConflicts.setText("• Scheme Collisions Identified: " + stats.getOrDefault("conflicts_count", 0));
        tvCritical.setText("• Critical Risk Findings: " + stats.getOrDefault("critical_findings", 0));
        tvTests.setText("• Fuzzing Tests Executed: " + stats.getOrDefault("tests_run", 0));
    }

    private void generatePdfReport(boolean autoPreview) {
        if (getContext() == null) return;
        Toast.makeText(getContext(), "Compiling multi-page PDF audit report...", Toast.LENGTH_SHORT).show();

        executor.execute(() -> {
            try {
                File pdf = PdfReportGenerator.generatePdfReport(getContext());
                lastGeneratedPdfFile = pdf;
                mainHandler.post(() -> {
                    Toast.makeText(getContext(), "PDF Exported: " + pdf.getName(), Toast.LENGTH_LONG).show();
                    if (autoPreview) {
                        ReportExporter.previewPdfFile(getContext(), pdf);
                    }
                });
            } catch (Exception e) {
                mainHandler.post(() -> {
                    Toast.makeText(getContext(), "Failed to export PDF: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void generateJsonReport() {
        if (getContext() == null) return;
        executor.execute(() -> {
            try {
                File json = ReportExporter.exportJsonFile(getContext());
                lastGeneratedJsonFile = json;
                mainHandler.post(() -> {
                    Toast.makeText(getContext(), "JSON Report Exported: " + json.getName(), Toast.LENGTH_LONG).show();
                });
            } catch (Exception e) {
                mainHandler.post(() -> {
                    Toast.makeText(getContext(), "Failed to export JSON: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void previewPdf() {
        if (lastGeneratedPdfFile != null && lastGeneratedPdfFile.exists()) {
            ReportExporter.previewPdfFile(getContext(), lastGeneratedPdfFile);
        } else {
            generatePdfReport(true);
        }
    }

    private void shareReport() {
        if (lastGeneratedPdfFile != null && lastGeneratedPdfFile.exists()) {
            ReportExporter.shareReportFile(getContext(), lastGeneratedPdfFile, "application/pdf");
        } else if (lastGeneratedJsonFile != null && lastGeneratedJsonFile.exists()) {
            ReportExporter.shareReportFile(getContext(), lastGeneratedJsonFile, "application/json");
        } else {
            // Generate PDF and share
            executor.execute(() -> {
                try {
                    File pdf = PdfReportGenerator.generatePdfReport(getContext());
                    lastGeneratedPdfFile = pdf;
                    mainHandler.post(() -> ReportExporter.shareReportFile(getContext(), pdf, "application/pdf"));
                } catch (Exception e) {
                    mainHandler.post(() -> Toast.makeText(getContext(), "Error generating report to share: " + e.getMessage(), Toast.LENGTH_SHORT).show());
                }
            });
        }
    }
}
