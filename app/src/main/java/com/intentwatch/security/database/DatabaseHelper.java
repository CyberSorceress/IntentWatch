package com.intentwatch.security.database;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import com.intentwatch.security.models.DiscoveredDeepLink;
import com.intentwatch.security.models.ScanSession;
import com.intentwatch.security.models.SchemeConflict;
import com.intentwatch.security.models.SecurityFinding;
import com.intentwatch.security.models.TestResult;

import org.json.JSONArray;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Local SQLite persistence layer for IntentWatch.
 * Handles storage of discovered intent filters, scheme collisions, findings, and test outcomes.
 */
public class DatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "intentwatch_audit.db";
    private static final int DATABASE_VERSION = 1;

    private static DatabaseHelper instance;

    public static synchronized DatabaseHelper getInstance(Context context) {
        if (instance == null) {
            instance = new DatabaseHelper(context.getApplicationContext());
        }
        return instance;
    }

    public DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        // 1. Scan Sessions Table
        db.execSQL("CREATE TABLE scan_sessions (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "timestamp INTEGER, " +
                "scan_type TEXT, " +
                "target_name TEXT, " +
                "total_handlers INTEGER, " +
                "distinct_schemes INTEGER, " +
                "collision_count INTEGER, " +
                "exported_count INTEGER, " +
                "critical_count INTEGER, " +
                "high_count INTEGER)");

        // 2. Discovered Deep Links Table
        db.execSQL("CREATE TABLE discovered_deeplinks (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "app_name TEXT, " +
                "package_name TEXT, " +
                "activity_name TEXT, " +
                "scheme TEXT, " +
                "host TEXT, " +
                "port TEXT, " +
                "path TEXT, " +
                "path_prefix TEXT, " +
                "path_pattern TEXT, " +
                "is_exported INTEGER, " +
                "has_action_view INTEGER, " +
                "is_browsable INTEGER, " +
                "is_default_category INTEGER, " +
                "auto_verify INTEGER, " +
                "launch_mode TEXT, " +
                "discovery_source TEXT, " +
                "analysis_status TEXT, " +
                "risk_score INTEGER, " +
                "timestamp INTEGER)");

        // 3. Scheme Conflicts Table
        db.execSQL("CREATE TABLE scheme_conflicts (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "scheme TEXT, " +
                "handler_count INTEGER, " +
                "app_names_json TEXT, " +
                "package_names_json TEXT, " +
                "activities_json TEXT, " +
                "conflict_type TEXT, " +
                "severity TEXT, " +
                "confidence TEXT, " +
                "risk_score INTEGER, " +
                "evidence_source TEXT, " +
                "description TEXT, " +
                "remediation TEXT, " +
                "timestamp INTEGER)");

        // 4. Security Findings Table
        db.execSQL("CREATE TABLE security_findings (" +
                "id TEXT PRIMARY KEY, " +
                "title TEXT, " +
                "description TEXT, " +
                "affected_component TEXT, " +
                "package_name TEXT, " +
                "scheme TEXT, " +
                "severity TEXT, " +
                "confidence TEXT, " +
                "verification_status TEXT, " +
                "evidence_source TEXT, " +
                "reproduction_instructions TEXT, " +
                "remediation_guidance TEXT, " +
                "risk_score INTEGER, " +
                "first_seen INTEGER, " +
                "last_seen INTEGER)");

        // 5. Test Results Table
        db.execSQL("CREATE TABLE test_results (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "test_case_id TEXT, " +
                "test_case_name TEXT, " +
                "input_uri TEXT, " +
                "execution_timestamp INTEGER, " +
                "resolution_type TEXT, " +
                "target_count INTEGER, " +
                "resolved_targets_json TEXT, " +
                "selected_target TEXT, " +
                "exception_details TEXT, " +
                "observable_outcome TEXT, " +
                "confidence TEXT, " +
                "verification_status TEXT, " +
                "is_safe INTEGER)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS scan_sessions");
        db.execSQL("DROP TABLE IF EXISTS discovered_deeplinks");
        db.execSQL("DROP TABLE IF EXISTS scheme_conflicts");
        db.execSQL("DROP TABLE IF EXISTS security_findings");
        db.execSQL("DROP TABLE IF EXISTS test_results");
        onCreate(db);
    }

    // --- Scan Sessions ---

    public synchronized long insertScanSession(ScanSession session) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("timestamp", session.getTimestamp());
        cv.put("scan_type", session.getScanType());
        cv.put("target_name", session.getTargetName());
        cv.put("total_handlers", session.getTotalHandlers());
        cv.put("distinct_schemes", session.getDistinctSchemes());
        cv.put("collision_count", session.getCollisionCount());
        cv.put("exported_count", session.getExportedActivitiesCount());
        cv.put("critical_count", session.getCriticalFindingsCount());
        cv.put("high_count", session.getHighFindingsCount());
        return db.insert("scan_sessions", null, cv);
    }

    public synchronized List<ScanSession> getRecentScanSessions(int limit) {
        List<ScanSession> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT * FROM scan_sessions ORDER BY timestamp DESC LIMIT ?",
                new String[]{String.valueOf(limit)});
        if (c.moveToFirst()) {
            do {
                ScanSession s = new ScanSession();
                s.setId(c.getLong(c.getColumnIndexOrThrow("id")));
                s.setTimestamp(c.getLong(c.getColumnIndexOrThrow("timestamp")));
                s.setScanType(c.getString(c.getColumnIndexOrThrow("scan_type")));
                s.setTargetName(c.getString(c.getColumnIndexOrThrow("target_name")));
                s.setTotalHandlers(c.getInt(c.getColumnIndexOrThrow("total_handlers")));
                s.setDistinctSchemes(c.getInt(c.getColumnIndexOrThrow("distinct_schemes")));
                s.setCollisionCount(c.getInt(c.getColumnIndexOrThrow("collision_count")));
                s.setExportedActivitiesCount(c.getInt(c.getColumnIndexOrThrow("exported_count")));
                s.setCriticalFindingsCount(c.getInt(c.getColumnIndexOrThrow("critical_count")));
                s.setHighFindingsCount(c.getInt(c.getColumnIndexOrThrow("high_count")));
                list.add(s);
            } while (c.moveToNext());
        }
        c.close();
        return list;
    }

    // --- Discovered Deep Links ---

    public synchronized void insertDiscoveredDeepLinks(List<DiscoveredDeepLink> links) {
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            for (DiscoveredDeepLink item : links) {
                ContentValues cv = new ContentValues();
                cv.put("app_name", item.getAppName());
                cv.put("package_name", item.getPackageName());
                cv.put("activity_name", item.getActivityName());
                cv.put("scheme", item.getScheme());
                cv.put("host", item.getHost());
                cv.put("port", item.getPort());
                cv.put("path", item.getPath());
                cv.put("path_prefix", item.getPathPrefix());
                cv.put("path_pattern", item.getPathPattern());
                cv.put("is_exported", item.isExported() ? 1 : 0);
                cv.put("has_action_view", item.hasActionView() ? 1 : 0);
                cv.put("is_browsable", item.isBrowsable() ? 1 : 0);
                cv.put("is_default_category", item.isDefaultCategory() ? 1 : 0);
                cv.put("auto_verify", item.isAutoVerify() ? 1 : 0);
                cv.put("launch_mode", item.getLaunchMode());
                cv.put("discovery_source", item.getDiscoverySource());
                cv.put("analysis_status", item.getAnalysisStatus());
                cv.put("risk_score", item.getRiskScore());
                cv.put("timestamp", item.getTimestamp());
                db.insert("discovered_deeplinks", null, cv);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized List<DiscoveredDeepLink> getAllDiscoveredDeepLinks() {
        return filterDiscoveredDeepLinks(null, null, null);
    }

    public synchronized List<DiscoveredDeepLink> filterDiscoveredDeepLinks(String query, String schemeType, Boolean exportedOnly) {
        List<DiscoveredDeepLink> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();

        StringBuilder sql = new StringBuilder("SELECT * FROM discovered_deeplinks WHERE 1=1 ");
        List<String> args = new ArrayList<>();

        if (query != null && !query.trim().isEmpty()) {
            sql.append("AND (app_name LIKE ? OR package_name LIKE ? OR scheme LIKE ? OR host LIKE ? OR activity_name LIKE ?) ");
            String q = "%" + query.trim() + "%";
            args.add(q);
            args.add(q);
            args.add(q);
            args.add(q);
            args.add(q);
        }

        if (schemeType != null && !schemeType.equals("ALL")) {
            if (schemeType.equals("CUSTOM")) {
                sql.append("AND (LOWER(scheme) NOT IN ('http', 'https', 'file', 'content') AND scheme != '') ");
            } else if (schemeType.equals("HTTP")) {
                sql.append("AND (LOWER(scheme) IN ('http', 'https')) ");
            }
        }

        if (exportedOnly != null && exportedOnly) {
            sql.append("AND is_exported = 1 ");
        }

        sql.append("ORDER BY id DESC");

        Cursor c = db.rawQuery(sql.toString(), args.toArray(new String[0]));
        if (c.moveToFirst()) {
            do {
                DiscoveredDeepLink item = new DiscoveredDeepLink();
                item.setId(c.getLong(c.getColumnIndexOrThrow("id")));
                item.setAppName(c.getString(c.getColumnIndexOrThrow("app_name")));
                item.setPackageName(c.getString(c.getColumnIndexOrThrow("package_name")));
                item.setActivityName(c.getString(c.getColumnIndexOrThrow("activity_name")));
                item.setScheme(c.getString(c.getColumnIndexOrThrow("scheme")));
                item.setHost(c.getString(c.getColumnIndexOrThrow("host")));
                item.setPort(c.getString(c.getColumnIndexOrThrow("port")));
                item.setPath(c.getString(c.getColumnIndexOrThrow("path")));
                item.setPathPrefix(c.getString(c.getColumnIndexOrThrow("path_prefix")));
                item.setPathPattern(c.getString(c.getColumnIndexOrThrow("path_pattern")));
                item.setExported(c.getInt(c.getColumnIndexOrThrow("is_exported")) == 1);
                item.setHasActionView(c.getInt(c.getColumnIndexOrThrow("has_action_view")) == 1);
                item.setBrowsable(c.getInt(c.getColumnIndexOrThrow("is_browsable")) == 1);
                item.setDefaultCategory(c.getInt(c.getColumnIndexOrThrow("is_default_category")) == 1);
                item.setAutoVerify(c.getInt(c.getColumnIndexOrThrow("auto_verify")) == 1);
                item.setLaunchMode(c.getString(c.getColumnIndexOrThrow("launch_mode")));
                item.setDiscoverySource(c.getString(c.getColumnIndexOrThrow("discovery_source")));
                item.setAnalysisStatus(c.getString(c.getColumnIndexOrThrow("analysis_status")));
                item.setRiskScore(c.getInt(c.getColumnIndexOrThrow("risk_score")));
                item.setTimestamp(c.getLong(c.getColumnIndexOrThrow("timestamp")));
                list.add(item);
            } while (c.moveToNext());
        }
        c.close();
        return list;
    }

    // --- Scheme Conflicts ---

    public synchronized void replaceSchemeConflicts(List<SchemeConflict> conflicts) {
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            db.delete("scheme_conflicts", null, null);
            for (SchemeConflict c : conflicts) {
                ContentValues cv = new ContentValues();
                cv.put("scheme", c.getScheme());
                cv.put("handler_count", c.getHandlerCount());
                cv.put("app_names_json", new JSONArray(c.getAppNames()).toString());
                cv.put("package_names_json", new JSONArray(c.getPackageNames()).toString());
                cv.put("activities_json", new JSONArray(c.getActivities()).toString());
                cv.put("conflict_type", c.getConflictType());
                cv.put("severity", c.getSeverity());
                cv.put("confidence", c.getConfidence());
                cv.put("risk_score", c.getRiskScore());
                cv.put("evidence_source", c.getEvidenceSource());
                cv.put("description", c.getDescription());
                cv.put("remediation", c.getRemediation());
                cv.put("timestamp", c.getTimestamp());
                db.insert("scheme_conflicts", null, cv);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized List<SchemeConflict> getAllSchemeConflicts() {
        List<SchemeConflict> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT * FROM scheme_conflicts ORDER BY risk_score DESC", null);
        if (c.moveToFirst()) {
            do {
                SchemeConflict sc = new SchemeConflict();
                sc.setId(c.getLong(c.getColumnIndexOrThrow("id")));
                sc.setScheme(c.getString(c.getColumnIndexOrThrow("scheme")));
                sc.setHandlerCount(c.getInt(c.getColumnIndexOrThrow("handler_count")));
                sc.setConflictType(c.getString(c.getColumnIndexOrThrow("conflict_type")));
                sc.setSeverity(c.getString(c.getColumnIndexOrThrow("severity")));
                sc.setConfidence(c.getString(c.getColumnIndexOrThrow("confidence")));
                sc.setRiskScore(c.getInt(c.getColumnIndexOrThrow("risk_score")));
                sc.setEvidenceSource(c.getString(c.getColumnIndexOrThrow("evidence_source")));
                sc.setDescription(c.getString(c.getColumnIndexOrThrow("description")));
                sc.setRemediation(c.getString(c.getColumnIndexOrThrow("remediation")));
                sc.setTimestamp(c.getLong(c.getColumnIndexOrThrow("timestamp")));

                try {
                    JSONArray arrApps = new JSONArray(c.getString(c.getColumnIndexOrThrow("app_names_json")));
                    List<String> apps = new ArrayList<>();
                    for (int i = 0; i < arrApps.length(); i++) apps.add(arrApps.getString(i));
                    sc.setAppNames(apps);

                    JSONArray arrPkgs = new JSONArray(c.getString(c.getColumnIndexOrThrow("package_names_json")));
                    List<String> pkgs = new ArrayList<>();
                    for (int i = 0; i < arrPkgs.length(); i++) pkgs.add(arrPkgs.getString(i));
                    sc.setPackageNames(pkgs);

                    JSONArray arrActs = new JSONArray(c.getString(c.getColumnIndexOrThrow("activities_json")));
                    List<String> acts = new ArrayList<>();
                    for (int i = 0; i < arrActs.length(); i++) acts.add(arrActs.getString(i));
                    sc.setActivities(acts);
                } catch (Exception ignored) {}

                list.add(sc);
            } while (c.moveToNext());
        }
        c.close();
        return list;
    }

    // --- Security Findings ---

    public synchronized void upsertSecurityFindings(List<SecurityFinding> findings) {
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            for (SecurityFinding f : findings) {
                ContentValues cv = new ContentValues();
                cv.put("id", f.getId());
                cv.put("title", f.getTitle());
                cv.put("description", f.getDescription());
                cv.put("affected_component", f.getAffectedComponent());
                cv.put("package_name", f.getPackageName());
                cv.put("scheme", f.getScheme());
                cv.put("severity", f.getSeverity());
                cv.put("confidence", f.getConfidence());
                cv.put("verification_status", f.getVerificationStatus());
                cv.put("evidence_source", f.getEvidenceSource());
                cv.put("reproduction_instructions", f.getReproductionInstructions());
                cv.put("remediation_guidance", f.getRemediationGuidance());
                cv.put("risk_score", f.getRiskScore());
                cv.put("first_seen", f.getFirstSeenTimestamp());
                cv.put("last_seen", f.getLastSeenTimestamp());
                db.insertWithOnConflict("security_findings", null, cv, SQLiteDatabase.CONFLICT_REPLACE);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized List<SecurityFinding> getAllSecurityFindings() {
        List<SecurityFinding> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT * FROM security_findings ORDER BY risk_score DESC", null);
        if (c.moveToFirst()) {
            do {
                SecurityFinding f = new SecurityFinding();
                f.setId(c.getString(c.getColumnIndexOrThrow("id")));
                f.setTitle(c.getString(c.getColumnIndexOrThrow("title")));
                f.setDescription(c.getString(c.getColumnIndexOrThrow("description")));
                f.setAffectedComponent(c.getString(c.getColumnIndexOrThrow("affected_component")));
                f.setPackageName(c.getString(c.getColumnIndexOrThrow("package_name")));
                f.setScheme(c.getString(c.getColumnIndexOrThrow("scheme")));
                f.setSeverity(c.getString(c.getColumnIndexOrThrow("severity")));
                f.setConfidence(c.getString(c.getColumnIndexOrThrow("confidence")));
                f.setVerificationStatus(c.getString(c.getColumnIndexOrThrow("verification_status")));
                f.setEvidenceSource(c.getString(c.getColumnIndexOrThrow("evidence_source")));
                f.setReproductionInstructions(c.getString(c.getColumnIndexOrThrow("reproduction_instructions")));
                f.setRemediationGuidance(c.getString(c.getColumnIndexOrThrow("remediation_guidance")));
                f.setRiskScore(c.getInt(c.getColumnIndexOrThrow("risk_score")));
                f.setFirstSeenTimestamp(c.getLong(c.getColumnIndexOrThrow("first_seen")));
                f.setLastSeenTimestamp(c.getLong(c.getColumnIndexOrThrow("last_seen")));
                list.add(f);
            } while (c.moveToNext());
        }
        c.close();
        return list;
    }

    public synchronized void updateFindingStatus(String findingId, String status) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("verification_status", status);
        cv.put("last_seen", System.currentTimeMillis());
        db.update("security_findings", cv, "id = ?", new String[]{findingId});
    }

    // --- Test Results ---

    public synchronized long insertTestResult(TestResult r) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("test_case_id", r.getTestCaseId());
        cv.put("test_case_name", r.getTestCaseName());
        cv.put("input_uri", r.getInputUri());
        cv.put("execution_timestamp", r.getExecutionTimestamp());
        cv.put("resolution_type", r.getResolutionType());
        cv.put("target_count", r.getTargetCount());
        cv.put("resolved_targets_json", new JSONArray(r.getResolvedTargets()).toString());
        cv.put("selected_target", r.getSelectedTarget());
        cv.put("exception_details", r.getExceptionDetails());
        cv.put("observable_outcome", r.getObservableOutcome());
        cv.put("confidence", r.getConfidence());
        cv.put("verification_status", r.getVerificationStatus());
        cv.put("is_safe", r.isSafe() ? 1 : 0);
        return db.insert("test_results", null, cv);
    }

    public synchronized List<TestResult> getAllTestResults() {
        List<TestResult> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor c = db.rawQuery("SELECT * FROM test_results ORDER BY execution_timestamp DESC", null);
        if (c.moveToFirst()) {
            do {
                TestResult r = new TestResult();
                r.setId(c.getLong(c.getColumnIndexOrThrow("id")));
                r.setTestCaseId(c.getString(c.getColumnIndexOrThrow("test_case_id")));
                r.setTestCaseName(c.getString(c.getColumnIndexOrThrow("test_case_name")));
                r.setInputUri(c.getString(c.getColumnIndexOrThrow("input_uri")));
                r.setExecutionTimestamp(c.getLong(c.getColumnIndexOrThrow("execution_timestamp")));
                r.setResolutionType(c.getString(c.getColumnIndexOrThrow("resolution_type")));
                r.setTargetCount(c.getInt(c.getColumnIndexOrThrow("target_count")));
                r.setSelectedTarget(c.getString(c.getColumnIndexOrThrow("selected_target")));
                r.setExceptionDetails(c.getString(c.getColumnIndexOrThrow("exception_details")));
                r.setObservableOutcome(c.getString(c.getColumnIndexOrThrow("observable_outcome")));
                r.setConfidence(c.getString(c.getColumnIndexOrThrow("confidence")));
                r.setVerificationStatus(c.getString(c.getColumnIndexOrThrow("verification_status")));
                r.setSafe(c.getInt(c.getColumnIndexOrThrow("is_safe")) == 1);

                try {
                    JSONArray arr = new JSONArray(c.getString(c.getColumnIndexOrThrow("resolved_targets_json")));
                    List<String> tgts = new ArrayList<>();
                    for (int i = 0; i < arr.length(); i++) tgts.add(arr.getString(i));
                    r.setResolvedTargets(tgts);
                } catch (Exception ignored) {}

                list.add(r);
            } while (c.moveToNext());
        }
        c.close();
        return list;
    }

    // --- Statistics ---

    public synchronized Map<String, Integer> getStatistics() {
        Map<String, Integer> stats = new HashMap<>();
        SQLiteDatabase db = getReadableDatabase();

        // Total handlers
        Cursor c1 = db.rawQuery("SELECT COUNT(*) FROM discovered_deeplinks", null);
        stats.put("total_handlers", c1.moveToFirst() ? c1.getInt(0) : 0);
        c1.close();

        // Distinct schemes
        Cursor c2 = db.rawQuery("SELECT COUNT(DISTINCT scheme) FROM discovered_deeplinks WHERE scheme != ''", null);
        stats.put("distinct_schemes", c2.moveToFirst() ? c2.getInt(0) : 0);
        c2.close();

        // Scheme conflicts
        Cursor c3 = db.rawQuery("SELECT COUNT(*) FROM scheme_conflicts", null);
        stats.put("conflicts_count", c3.moveToFirst() ? c3.getInt(0) : 0);
        c3.close();

        // Exported activities
        Cursor c4 = db.rawQuery("SELECT COUNT(*) FROM discovered_deeplinks WHERE is_exported = 1", null);
        stats.put("exported_count", c4.moveToFirst() ? c4.getInt(0) : 0);
        c4.close();

        // Critical findings
        Cursor c5 = db.rawQuery("SELECT COUNT(*) FROM security_findings WHERE severity = 'CRITICAL'", null);
        stats.put("critical_findings", c5.moveToFirst() ? c5.getInt(0) : 0);
        c5.close();

        // High findings
        Cursor c6 = db.rawQuery("SELECT COUNT(*) FROM security_findings WHERE severity = 'HIGH'", null);
        stats.put("high_findings", c6.moveToFirst() ? c6.getInt(0) : 0);
        c6.close();

        // Total tests run
        Cursor c7 = db.rawQuery("SELECT COUNT(*) FROM test_results", null);
        stats.put("tests_run", c7.moveToFirst() ? c7.getInt(0) : 0);
        c7.close();

        return stats;
    }

    public synchronized void clearAllData() {
        SQLiteDatabase db = getWritableDatabase();
        db.delete("scan_sessions", null, null);
        db.delete("discovered_deeplinks", null, null);
        db.delete("scheme_conflicts", null, null);
        db.delete("security_findings", null, null);
        db.delete("test_results", null, null);
    }
}
