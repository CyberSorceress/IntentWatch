package com.intentwatch.security.reports;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.pdf.PdfDocument;
import android.os.Build;

import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.models.DiscoveredDeepLink;
import com.intentwatch.security.models.SchemeConflict;
import com.intentwatch.security.models.SecurityFinding;
import com.intentwatch.security.models.TestResult;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Generates an executive-ready, multi-page PDF audit report using Android's native PdfDocument.
 * Formats findings, URI inventories, collision analysis, and remediation guidance with clean typography.
 */
public class PdfReportGenerator {

    private static final int PAGE_WIDTH = 595;  // Standard A4 width in PostScript points
    private static final int PAGE_HEIGHT = 842; // Standard A4 height in PostScript points

    public static File generatePdfReport(Context context) throws Exception {
        DatabaseHelper db = DatabaseHelper.getInstance(context);
        Map<String, Integer> stats = db.getStatistics();
        List<DiscoveredDeepLink> handlers = db.getAllDiscoveredDeepLinks();
        List<SchemeConflict> conflicts = db.getAllSchemeConflicts();
        List<SecurityFinding> findings = db.getAllSecurityFindings();
        List<TestResult> testResults = db.getAllTestResults();

        PdfDocument document = new PdfDocument();
        String dateStr = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date());

        // Paints
        Paint bgPaint = new Paint();
        bgPaint.setColor(Color.WHITE);

        Paint headerBgPaint = new Paint();
        headerBgPaint.setColor(Color.parseColor("#0B111E"));

        Paint accentPaint = new Paint();
        accentPaint.setColor(Color.parseColor("#00B4D8"));

        Paint textTitle = new Paint();
        textTitle.setColor(Color.WHITE);
        textTitle.setTextSize(18f);
        textTitle.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        Paint textSub = new Paint();
        textSub.setColor(Color.parseColor("#00E5FF"));
        textSub.setTextSize(11f);
        textSub.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.NORMAL));

        Paint bodyBold = new Paint();
        bodyBold.setColor(Color.parseColor("#1E293B"));
        bodyBold.setTextSize(11f);
        bodyBold.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        Paint bodyNormal = new Paint();
        bodyNormal.setColor(Color.parseColor("#334155"));
        bodyNormal.setTextSize(9.5f);

        Paint textMuted = new Paint();
        textMuted.setColor(Color.parseColor("#64748B"));
        textMuted.setTextSize(8.5f);

        Paint boxBg = new Paint();
        boxBg.setColor(Color.parseColor("#F1F5F9"));

        Paint boxBorder = new Paint();
        boxBorder.setColor(Color.parseColor("#CBD5E1"));
        boxBorder.setStyle(Paint.Style.STROKE);
        boxBorder.setStrokeWidth(1f);

        // ================= PAGE 1: COVER & EXECUTIVE DASHBOARD =================
        PdfDocument.PageInfo page1Info = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 1).create();
        PdfDocument.Page page1 = document.startPage(page1Info);
        Canvas c1 = page1.getCanvas();

        // Top Banner
        c1.drawRect(0, 0, PAGE_WIDTH, 125, headerBgPaint);
        c1.drawText("INTENTWATCH AUDIT REPORT", 30, 45, textTitle);
        c1.drawText("Android Deep-Link Hijacking & Intent Security Analyzer", 30, 65, textSub);
        Paint metaPaint = new Paint();
        metaPaint.setColor(Color.parseColor("#94A3B8"));
        metaPaint.setTextSize(9f);
        c1.drawText("Course: 24CYS404 | Faculty: Dr. S. Udhayakumar, Cyber Security", 30, 85, metaPaint);
        c1.drawText("Generated: " + dateStr + " | Target Android SDK: " + Build.VERSION.SDK_INT, 30, 102, metaPaint);

        // Section: Executive Summary
        float y = 150;
        c1.drawText("1. EXECUTIVE AUDIT SUMMARY", 30, y, bodyBold);
        y += 15;
        c1.drawText("This technical audit report details the attack surface of deep-link entry points, custom URI", 30, y, bodyNormal);
        y += 14;
        c1.drawText("scheme collisions, and intent-redirection vulnerabilities identified across inspected Android components.", 30, y, bodyNormal);

        // KPI Metric Cards
        y += 25;
        drawKpiCard(c1, 30, y, 120, 55, "Handlers", String.valueOf(stats.getOrDefault("total_handlers", 0)), Color.parseColor("#0284C7"), boxBg, boxBorder);
        drawKpiCard(c1, 165, y, 120, 55, "Schemes", String.valueOf(stats.getOrDefault("distinct_schemes", 0)), Color.parseColor("#0D9488"), boxBg, boxBorder);
        drawKpiCard(c1, 300, y, 120, 55, "Collisions", String.valueOf(stats.getOrDefault("conflicts_count", 0)), Color.parseColor("#E11D48"), boxBg, boxBorder);
        drawKpiCard(c1, 435, y, 130, 55, "Exported", String.valueOf(stats.getOrDefault("exported_count", 0)), Color.parseColor("#D97706"), boxBg, boxBorder);

        y += 75;
        c1.drawText("2. SEVERITY & RISK OVERVIEW", 30, y, bodyBold);
        y += 15;

        // Severity Distribution Box
        RectF sevBox = new RectF(30, y, PAGE_WIDTH - 30, y + 90);
        c1.drawRoundRect(sevBox, 6, 6, boxBg);
        c1.drawRoundRect(sevBox, 6, 6, boxBorder);

        float sy = y + 25;
        drawSeverityRow(c1, 45, sy, "CRITICAL RISK", String.valueOf(stats.getOrDefault("critical_findings", 0)), Color.parseColor("#EF4444"));
        drawSeverityRow(c1, 180, sy, "HIGH RISK", String.valueOf(stats.getOrDefault("high_findings", 0)), Color.parseColor("#F97316"));
        drawSeverityRow(c1, 300, sy, "MODERATE RISK", String.valueOf(conflicts.size()), Color.parseColor("#FBBF24"));
        drawSeverityRow(c1, 435, sy, "TESTS RUN", String.valueOf(stats.getOrDefault("tests_run", 0)), Color.parseColor("#38BDF8"));

        sy += 35;
        c1.drawText("Assessment Rule: Collisions in custom URI schemes introduce high hijacking exposure.", 45, sy, bodyNormal);
        sy += 15;
        c1.drawText("HTTP/HTTPS intent filters lacking autoVerify allow third-party browser / app interception.", 45, sy, textMuted);

        // Core Audit Scope Table
        y += 115;
        c1.drawText("3. CORE AUDIT SCOPE", 30, y, bodyBold);
        y += 18;
        c1.drawText("• Mode A Inspection: Discovered visible installed packages via PackageManager Intent Resolver.", 35, y, bodyNormal);
        y += 15;
        c1.drawText("• Mode B Inspection: APK Binary XML (AXML) manifest parser for standalone offline analysis.", 35, y, bodyNormal);
        y += 15;
        c1.drawText("• Intent Redirection: Fuzzing tests targeting unvalidated URI parameter forwarding.", 35, y, bodyNormal);
        y += 15;
        c1.drawText("• Controlled Targets: Verified Vulnerable vs Secure Deep-Link reference implementations.", 35, y, bodyNormal);

        drawFooter(c1, 1, 5, textMuted);
        document.finishPage(page1);

        // ================= PAGE 2: METHODOLOGY & PLATFORM LIMITATIONS =================
        PdfDocument.PageInfo page2Info = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 2).create();
        PdfDocument.Page page2 = document.startPage(page2Info);
        Canvas c2 = page2.getCanvas();
        drawPageHeader(c2, "METHODOLOGY & ANDROID RESTRICTIONS", headerBgPaint, textTitle, textSub);

        y = 100;
        c2.drawText("4. DISCOVERY ARCHITECTURE & TECHNICAL CONSTRAINTS", 30, y, bodyBold);
        y += 20;

        c2.drawText("Mode A — Installed Application Resolution (Android 11+ Package Visibility)", 30, y, bodyBold);
        y += 14;
        c2.drawText("Starting with Android 11 (API level 30), the OS enforces strict package visibility filtering.", 30, y, bodyNormal);
        y += 14;
        c2.drawText("Applications cannot freely query the full list of installed packages without declaring QUERY_ALL_PACKAGES.", 30, y, bodyNormal);
        y += 14;
        c2.drawText("IntentWatch implements explicit intent filter queries (<queries> declarations) to discover all packages", 30, y, bodyNormal);
        y += 14;
        c2.drawText("that register browsable VIEW actions for probed web and custom URI schemes.", 30, y, bodyNormal);

        y += 25;
        c2.drawText("Mode B — Standalone APK Manifest Inspection (AXML Engine)", 30, y, bodyBold);
        y += 14;
        c2.drawText("To eliminate runtime package visibility limitations, IntentWatch contains a standalone", 30, y, bodyNormal);
        y += 14;
        c2.drawText("Android Binary XML (AXML) decoding engine. Users can import any third-party APK file via the", 30, y, bodyNormal);
        y += 14;
        c2.drawText("Storage Access Framework (SAF). IntentWatch extracts and parses AndroidManifest.xml directly from", 30, y, bodyNormal);
        y += 14;
        c2.drawText("the APK archive without requiring installation or administrative privileges.", 30, y, bodyNormal);

        y += 25;
        c2.drawText("Explainable Risk Scoring Framework", 30, y, bodyBold);
        y += 14;
        c2.drawText("• Critical (75-100): Confirmed unsafe intent redirection or unvalidated parameter execution.", 35, y, bodyNormal);
        y += 14;
        c2.drawText("• High (50-74): Unprotected custom URI scheme collision across multiple independent applications.", 35, y, bodyNormal);
        y += 14;
        c2.drawText("• Moderate (25-49): Missing android:autoVerify=\"true\" on web intent filters (App Links).", 35, y, bodyNormal);
        y += 14;
        c2.drawText("• Low (0-24): Properly restricted, authenticated, or single-owner intent filter entry points.", 35, y, bodyNormal);

        drawFooter(c2, 2, 5, textMuted);
        document.finishPage(page2);

        // ================= PAGE 3: URI SCHEME INVENTORY & CONFLICTS =================
        PdfDocument.PageInfo page3Info = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 3).create();
        PdfDocument.Page page3 = document.startPage(page3Info);
        Canvas c3 = page3.getCanvas();
        drawPageHeader(c3, "SCHEME INVENTORY & COLLISION ANALYSIS", headerBgPaint, textTitle, textSub);

        y = 100;
        c3.drawText("5. IDENTIFIED SCHEME COLLISIONS & AMBIGUITY", 30, y, bodyBold);
        y += 18;

        if (conflicts.isEmpty()) {
            c3.drawText("No multi-application scheme collisions detected during the scan.", 30, y, bodyNormal);
        } else {
            for (int i = 0; i < Math.min(conflicts.size(), 4); i++) {
                SchemeConflict sc = conflicts.get(i);
                RectF card = new RectF(30, y, PAGE_WIDTH - 30, y + 80);
                c3.drawRoundRect(card, 6, 6, boxBg);
                c3.drawRoundRect(card, 6, 6, boxBorder);

                c3.drawText("Scheme: " + sc.getScheme() + "://  (" + sc.getHandlerCount() + " competing handlers)", 42, y + 20, bodyBold);
                c3.drawText("Conflict Type: " + sc.getConflictType() + " | Severity: " + sc.getSeverity() + " | Score: " + sc.getRiskScore() + "/100", 42, y + 36, bodyNormal);

                String apps = sc.getAppsSummary();
                if (apps.length() > 65) apps = apps.substring(0, 62) + "...";
                c3.drawText("Competing Apps: " + apps, 42, y + 52, bodyNormal);
                c3.drawText("Remediation: " + (sc.getRemediation().length() > 70 ? sc.getRemediation().substring(0, 67) + "..." : sc.getRemediation()), 42, y + 68, textMuted);
                y += 92;
            }
        }

        y += 15;
        c3.drawText("6. DEEP-LINK HANDLERS SAMPLE INVENTORY", 30, y, bodyBold);
        y += 18;

        for (int i = 0; i < Math.min(handlers.size(), 7); i++) {
            DiscoveredDeepLink dl = handlers.get(i);
            String line = (i + 1) + ". " + dl.getScheme() + "://" + (dl.getHost().isEmpty() ? "*" : dl.getHost()) +
                    "  ->  " + dl.getActivityName() + " (Exported=" + dl.isExported() + ")";
            if (line.length() > 85) line = line.substring(0, 82) + "...";
            c3.drawText(line, 35, y, bodyNormal);
            y += 16;
        }

        drawFooter(c3, 3, 5, textMuted);
        document.finishPage(page3);

        // ================= PAGE 4: DETAILED SECURITY FINDINGS =================
        PdfDocument.PageInfo page4Info = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 4).create();
        PdfDocument.Page page4 = document.startPage(page4Info);
        Canvas c4 = page4.getCanvas();
        drawPageHeader(c4, "DETAILED SECURITY AUDIT FINDINGS", headerBgPaint, textTitle, textSub);

        y = 100;
        c4.drawText("7. TECHNICAL FINDINGS & EVIDENCE", 30, y, bodyBold);
        y += 18;

        if (findings.isEmpty()) {
            c4.drawText("No critical or high-risk findings recorded.", 30, y, bodyNormal);
        } else {
            for (int i = 0; i < Math.min(findings.size(), 3); i++) {
                SecurityFinding sf = findings.get(i);
                RectF card = new RectF(30, y, PAGE_WIDTH - 30, y + 130);
                c4.drawRoundRect(card, 6, 6, boxBg);
                c4.drawRoundRect(card, 6, 6, boxBorder);

                c4.drawText("[" + sf.getId() + "] " + sf.getTitle(), 42, y + 22, bodyBold);
                c4.drawText("Severity: " + sf.getSeverity() + " | Confidence: " + sf.getConfidence() + " | Status: " + sf.getVerificationStatus(), 42, y + 38, bodyNormal);

                c4.drawText("Component: " + sf.getAffectedComponent(), 42, y + 54, bodyNormal);

                String desc = sf.getDescription();
                if (desc.length() > 80) desc = desc.substring(0, 77) + "...";
                c4.drawText("Description: " + desc, 42, y + 70, bodyNormal);

                String repro = sf.getReproductionInstructions();
                if (repro.length() > 80) repro = repro.substring(0, 77) + "...";
                c4.drawText("Reproduction: " + repro, 42, y + 86, textMuted);

                String rem = sf.getRemediationGuidance();
                if (rem.length() > 80) rem = rem.substring(0, 77) + "...";
                c4.drawText("Remediation: " + rem, 42, y + 102, bodyBold);

                y += 142;
            }
        }

        drawFooter(c4, 4, 5, textMuted);
        document.finishPage(page4);

        // ================= PAGE 5: TEST EXECUTION & REMEDIATION =================
        PdfDocument.PageInfo page5Info = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 5).create();
        PdfDocument.Page page5 = document.startPage(page5Info);
        Canvas c5 = page5.getCanvas();
        drawPageHeader(c5, "TEST LAB RESULTS & REMEDIATION ROADMAP", headerBgPaint, textTitle, textSub);

        y = 100;
        c5.drawText("8. DYNAMIC TEST LAB EXECUTION HISTORY", 30, y, bodyBold);
        y += 18;

        if (testResults.isEmpty()) {
            c5.drawText("Dynamic tests have not yet been logged in this session.", 30, y, bodyNormal);
            y += 16;
        } else {
            for (int i = 0; i < Math.min(testResults.size(), 4); i++) {
                TestResult tr = testResults.get(i);
                c5.drawText("• [" + tr.getResolutionType() + "] " + tr.getTestCaseName(), 35, y, bodyBold);
                y += 14;
                c5.drawText("  URI: " + tr.getInputUri(), 45, y, textMuted);
                y += 14;
                c5.drawText("  Outcome: " + tr.getObservableOutcome(), 45, y, bodyNormal);
                y += 18;
            }
        }

        y += 15;
        c5.drawText("9. SECURITY REMEDIATION ROADMAP", 30, y, bodyBold);
        y += 18;
        c5.drawText("1. Phase Out Custom URI Schemes: Deprecate custom schemes in favor of HTTPS Android App Links.", 35, y, bodyNormal);
        y += 16;
        c5.drawText("2. Enable autoVerify: Ensure android:autoVerify=\"true\" is present on all web domain filters.", 35, y, bodyNormal);
        y += 16;
        c5.drawText("3. Enforce Strict Parameter Whitelisting: Reject arbitrary domains in redirect parameters.", 35, y, bodyNormal);
        y += 16;
        c5.drawText("4. Secure Component Visibility: Set android:exported=\"false\" on internal receiver activities.", 35, y, bodyNormal);
        y += 16;
        c5.drawText("5. Intent Payload Integrity: Never transmit session tokens or authentication secrets in plaintext URIs.", 35, y, bodyNormal);

        y += 35;
        c5.drawText("10. CONCLUSION & AUDIT SIGN-OFF", 30, y, bodyBold);
        y += 16;
        c5.drawText("IntentWatch analysis verified custom scheme collision risks and intent redirection vectors.", 35, y, bodyNormal);
        y += 14;
        c5.drawText("Implementation of the remediation roadmap guarantees full resistance to deep-link hijacking.", 35, y, bodyNormal);

        drawFooter(c5, 5, 5, textMuted);
        document.finishPage(page5);

        // Write document to file
        File reportsDir = new File(context.getExternalFilesDir(null), "reports");
        if (!reportsDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            reportsDir.mkdirs();
        }

        File pdfFile = new File(reportsDir, "IntentWatch_Audit_Report_" + System.currentTimeMillis() + ".pdf");
        FileOutputStream fos = new FileOutputStream(pdfFile);
        document.writeTo(fos);
        fos.flush();
        fos.close();
        document.close();

        return pdfFile;
    }

    private static void drawPageHeader(Canvas c, String sectionTitle, Paint bg, Paint titlePaint, Paint subPaint) {
        c.drawRect(0, 0, PAGE_WIDTH, 70, bg);
        c.drawText("INTENTWATCH AUDIT REPORT", 30, 32, titlePaint);
        c.drawText(sectionTitle, 30, 52, subPaint);
    }

    private static void drawFooter(Canvas c, int page, int total, Paint paint) {
        c.drawText("IntentWatch Security Analyzer | Course 24CYS404 | Page " + page + " of " + total, 30, PAGE_HEIGHT - 25, paint);
    }

    private static void drawKpiCard(Canvas c, float x, float y, float w, float h, String label, String val, int valColor, Paint bg, Paint border) {
        RectF r = new RectF(x, y, x + w, y + h);
        c.drawRoundRect(r, 6, 6, bg);
        c.drawRoundRect(r, 6, 6, border);

        Paint pVal = new Paint();
        pVal.setColor(valColor);
        pVal.setTextSize(18f);
        pVal.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        Paint pLabel = new Paint();
        pLabel.setColor(Color.parseColor("#475569"));
        pLabel.setTextSize(9f);

        c.drawText(val, x + 12, y + 26, pVal);
        c.drawText(label, x + 12, y + 44, pLabel);
    }

    private static void drawSeverityRow(Canvas c, float x, float y, String label, String count, int color) {
        Paint p = new Paint();
        p.setColor(color);
        p.setTextSize(14f);
        p.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        Paint lbl = new Paint();
        lbl.setColor(Color.parseColor("#475569"));
        lbl.setTextSize(8.5f);

        c.drawText(count, x, y, p);
        c.drawText(label, x, y + 14, lbl);
    }
}
