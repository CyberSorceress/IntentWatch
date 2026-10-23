package com.intentwatch.security.reports;

import android.content.Context;
import android.os.Build;

import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.models.DiscoveredDeepLink;
import com.intentwatch.security.models.SchemeConflict;
import com.intentwatch.security.models.SecurityFinding;
import com.intentwatch.security.models.TestResult;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Serializes complete IntentWatch security audit results into structured JSON.
 */
public class JsonReportGenerator {

    public static JSONObject generateJsonReport(Context context) {
        JSONObject root = new JSONObject();
        try {
            DatabaseHelper db = DatabaseHelper.getInstance(context);
            Map<String, Integer> stats = db.getStatistics();
            List<DiscoveredDeepLink> handlers = db.getAllDiscoveredDeepLinks();
            List<SchemeConflict> conflicts = db.getAllSchemeConflicts();
            List<SecurityFinding> findings = db.getAllSecurityFindings();
            List<TestResult> testResults = db.getAllTestResults();

            // 1. Report Metadata
            JSONObject meta = new JSONObject();
            meta.put("application", "IntentWatch");
            meta.put("subtitle", "Android Deep-Link Hijacking & Intent Security Analyzer");
            meta.put("course", "Android Application Development (24CYS404)");
            meta.put("faculty", "Dr. S. Udhayakumar, Associate Professor, Cyber Security");
            meta.put("generated_timestamp", System.currentTimeMillis());
            meta.put("generated_date", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()));
            meta.put("platform_android_sdk", Build.VERSION.SDK_INT);
            meta.put("device_model", Build.MANUFACTURER + " " + Build.MODEL);
            meta.put("report_version", "1.0");
            root.put("audit_metadata", meta);

            // 2. Executive Summary KPIs
            JSONObject kpis = new JSONObject();
            kpis.put("total_discovered_handlers", stats.getOrDefault("total_handlers", 0));
            kpis.put("distinct_uri_schemes", stats.getOrDefault("distinct_schemes", 0));
            kpis.put("scheme_collisions_detected", stats.getOrDefault("conflicts_count", 0));
            kpis.put("exported_target_activities", stats.getOrDefault("exported_count", 0));
            kpis.put("critical_severity_findings", stats.getOrDefault("critical_findings", 0));
            kpis.put("high_severity_findings", stats.getOrDefault("high_findings", 0));
            kpis.put("dynamic_tests_executed", stats.getOrDefault("tests_run", 0));
            root.put("executive_kpis", kpis);

            // 3. Discovered Handlers Inventory
            JSONArray handlersArray = new JSONArray();
            for (DiscoveredDeepLink h : handlers) {
                JSONObject obj = new JSONObject();
                obj.put("app_name", h.getAppName());
                obj.put("package_name", h.getPackageName());
                obj.put("activity_name", h.getActivityName());
                obj.put("scheme", h.getScheme());
                obj.put("host", h.getHost());
                obj.put("path", h.getPath());
                obj.put("path_prefix", h.getPathPrefix());
                obj.put("is_exported", h.isExported());
                obj.put("is_browsable", h.isBrowsable());
                obj.put("auto_verify", h.isAutoVerify());
                obj.put("launch_mode", h.getLaunchMode());
                obj.put("discovery_source", h.getDiscoverySource());
                obj.put("risk_score", h.getRiskScore());
                handlersArray.put(obj);
            }
            root.put("discovered_handlers", handlersArray);

            // 4. Scheme Conflicts
            JSONArray conflictsArray = new JSONArray();
            for (SchemeConflict c : conflicts) {
                JSONObject obj = new JSONObject();
                obj.put("scheme", c.getScheme());
                obj.put("handler_count", c.getHandlerCount());
                obj.put("conflict_type", c.getConflictType());
                obj.put("severity", c.getSeverity());
                obj.put("confidence", c.getConfidence());
                obj.put("risk_score", c.getRiskScore());
                obj.put("description", c.getDescription());
                obj.put("remediation", c.getRemediation());
                obj.put("competing_packages", new JSONArray(c.getPackageNames()));
                obj.put("competing_activities", new JSONArray(c.getActivities()));
                conflictsArray.put(obj);
            }
            root.put("scheme_conflicts", conflictsArray);

            // 5. Security Findings
            JSONArray findingsArray = new JSONArray();
            for (SecurityFinding f : findings) {
                JSONObject obj = new JSONObject();
                obj.put("id", f.getId());
                obj.put("title", f.getTitle());
                obj.put("description", f.getDescription());
                obj.put("affected_component", f.getAffectedComponent());
                obj.put("package_name", f.getPackageName());
                obj.put("scheme", f.getScheme());
                obj.put("severity", f.getSeverity());
                obj.put("confidence", f.getConfidence());
                obj.put("verification_status", f.getVerificationStatus());
                obj.put("evidence_source", f.getEvidenceSource());
                obj.put("reproduction_instructions", f.getReproductionInstructions());
                obj.put("remediation_guidance", f.getRemediationGuidance());
                obj.put("risk_score", f.getRiskScore());
                findingsArray.put(obj);
            }
            root.put("security_findings", findingsArray);

            // 6. Test Execution Results
            JSONArray testsArray = new JSONArray();
            for (TestResult tr : testResults) {
                JSONObject obj = new JSONObject();
                obj.put("test_case_id", tr.getTestCaseId());
                obj.put("test_case_name", tr.getTestCaseName());
                obj.put("input_uri", tr.getInputUri());
                obj.put("timestamp", tr.getExecutionTimestamp());
                obj.put("resolution_type", tr.getResolutionType());
                obj.put("target_count", tr.getTargetCount());
                obj.put("observable_outcome", tr.getObservableOutcome());
                obj.put("exception_details", tr.getExceptionDetails());
                obj.put("confidence", tr.getConfidence());
                obj.put("verification_status", tr.getVerificationStatus());
                obj.put("is_safe", tr.isSafe());
                obj.put("resolved_targets", new JSONArray(tr.getResolvedTargets()));
                testsArray.put(obj);
            }
            root.put("test_execution_history", testsArray);

            // 7. Remediation Guide & Best Practices
            JSONArray recommendations = new JSONArray();
            recommendations.put("Migrate legacy custom URI schemes (myscheme://) to cryptographically verified Android App Links (https://example.com) with Digital Asset Links.");
            recommendations.put("Enforce android:autoVerify=\"true\" on all HTTP/HTTPS intent-filters to ensure exclusive automatic link domain verification.");
            recommendations.put("Perform strict origin and URL domain whitelist validation before opening or redirecting to URLs supplied in deep-link parameters.");
            recommendations.put("Set android:exported=\"false\" on internal activities, or require custom signature-level permissions for sensitive endpoints.");
            recommendations.put("Avoid passing sensitive session tokens, authorization codes, or user credentials via unencrypted URI query parameters.");
            root.put("remediation_recommendations", recommendations);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return root;
    }
}
