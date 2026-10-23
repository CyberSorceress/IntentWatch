package com.intentwatch.security.reports;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.widget.Toast;

import androidx.core.content.FileProvider;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;

/**
 * Handles saving, sharing, and previewing exported JSON and PDF security audit reports.
 */
public class ReportExporter {

    public static File exportJsonFile(Context context) throws Exception {
        JSONObject reportJson = JsonReportGenerator.generateJsonReport(context);
        File reportsDir = new File(context.getExternalFilesDir(null), "reports");
        if (!reportsDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            reportsDir.mkdirs();
        }

        File jsonFile = new File(reportsDir, "IntentWatch_Audit_Report_" + System.currentTimeMillis() + ".json");
        FileOutputStream fos = new FileOutputStream(jsonFile);
        fos.write(reportJson.toString(2).getBytes());
        fos.flush();
        fos.close();

        return jsonFile;
    }

    public static void shareReportFile(Context context, File file, String mimeType) {
        try {
            Uri contentUri = FileProvider.getUriForFile(
                    context,
                    context.getPackageName() + ".fileprovider",
                    file
            );

            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType(mimeType);
            shareIntent.putExtra(Intent.EXTRA_STREAM, contentUri);
            shareIntent.putExtra(Intent.EXTRA_SUBJECT, "IntentWatch Security Audit Report");
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

            context.startActivity(Intent.createChooser(shareIntent, "Share Security Audit Report"));
        } catch (Exception e) {
            Toast.makeText(context, "Error sharing report: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public static void previewPdfFile(Context context, File pdfFile) {
        try {
            Uri contentUri = FileProvider.getUriForFile(
                    context,
                    context.getPackageName() + ".fileprovider",
                    pdfFile
            );

            Intent viewIntent = new Intent(Intent.ACTION_VIEW);
            viewIntent.setDataAndType(contentUri, "application/pdf");
            viewIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            context.startActivity(Intent.createChooser(viewIntent, "Open PDF Audit Report"));
        } catch (Exception e) {
            Toast.makeText(context, "No PDF viewer app found or error opening file: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
}
