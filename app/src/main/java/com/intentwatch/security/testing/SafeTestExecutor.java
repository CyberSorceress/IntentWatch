package com.intentwatch.security.testing;

import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.models.TestCase;
import com.intentwatch.security.models.TestResult;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Executes deep-link test scenarios safely.
 * Implements non-intrusive resolver query simulation and explicit confirmation launching.
 */
public class SafeTestExecutor {
    private static final String TAG = "SafeTestExecutor";

    /**
     * Safe Query Simulation: Discovers resolving targets without launching any activity.
     */
    public static TestResult queryResolutionSimulated(Context context, TestCase testCase) {
        TestResult result = new TestResult();
        result.setTestCaseId(testCase.getId());
        result.setTestCaseName(testCase.getName());
        result.setInputUri(testCase.getModifiedUri());

        try {
            Uri uri = Uri.parse(testCase.getModifiedUri());
            Intent intent = new Intent(Intent.ACTION_VIEW, uri);
            intent.addCategory(Intent.CATEGORY_BROWSABLE);

            PackageManager pm = context.getPackageManager();
            List<ResolveInfo> matches;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                matches = pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_ALL));
            } else {
                matches = pm.queryIntentActivities(intent, PackageManager.MATCH_ALL);
            }

            List<String> targetNames = new ArrayList<>();
            if (matches != null && !matches.isEmpty()) {
                for (ResolveInfo ri : matches) {
                    if (ri.activityInfo != null) {
                        targetNames.add(ri.activityInfo.packageName + "/" + ri.activityInfo.name);
                    }
                }
                result.setResolvedTargets(targetNames);

                if (targetNames.size() > 1) {
                    result.setResolutionType("RESOLVER_CHOOSER_DIALOG");
                    result.setObservableOutcome("Multiple handlers match URI. System would display App Chooser disambiguation dialog.");
                    result.setVerificationStatus("CONFIRMED");
                    result.setSafe(false); // Ambiguity detected
                } else {
                    result.setResolutionType("SINGLE_MATCH");
                    result.setSelectedTarget(targetNames.get(0));
                    result.setObservableOutcome("Single handler resolved directly: " + targetNames.get(0));
                    result.setVerificationStatus("CONFIRMED");
                    result.setSafe(true);
                }
            } else {
                result.setResolutionType("UNRESOLVED");
                result.setObservableOutcome("No registered activity matched this URI pattern on the current system.");
                result.setVerificationStatus("NOT_TESTED");
                result.setSafe(true);
            }

        } catch (Exception e) {
            Log.e(TAG, "Error querying resolution: " + e.getMessage(), e);
            result.setResolutionType("EXCEPTION");
            result.setExceptionDetails(e.getClass().getSimpleName() + ": " + e.getMessage());
            result.setObservableOutcome("URI parsing or resolver query raised an exception.");
            result.setVerificationStatus("INCONCLUSIVE");
            result.setSafe(false);
        }

        // Persist to database
        DatabaseHelper.getInstance(context).insertTestResult(result);
        return result;
    }

    /**
     * Controlled Launch Execution: Dispatches Intent to Android OS after explicit confirmation.
     */
    public static TestResult executeLiveLaunch(Context context, TestCase testCase, boolean forceTarget) {
        TestResult result = new TestResult();
        result.setTestCaseId(testCase.getId());
        result.setTestCaseName(testCase.getName());
        result.setInputUri(testCase.getModifiedUri());

        try {
            Uri uri = Uri.parse(testCase.getModifiedUri());

            // Scheme safety check
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
            if ("javascript".equals(scheme)) {
                result.setResolutionType("BLOCKED_SANDBOX");
                result.setObservableOutcome("Blocked dangerous javascript: pseudo-protocol from external dispatch.");
                result.setExceptionDetails("Safety Sandbox Rule: Direct dispatch of javascript: URI prevented.");
                result.setVerificationStatus("CONFIRMED");
                result.setSafe(true);
                DatabaseHelper.getInstance(context).insertTestResult(result);
                return result;
            }

            Intent intent = new Intent(Intent.ACTION_VIEW, uri);
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            // Add simulated extras if present
            if (testCase.getExtrasJson() != null && !testCase.getExtrasJson().trim().isEmpty()) {
                try {
                    JSONObject obj = new JSONObject(testCase.getExtrasJson());
                    Iterator<String> keys = obj.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        Object val = obj.get(key);
                        if (val instanceof Boolean) intent.putExtra(key, (Boolean) val);
                        else if (val instanceof Integer) intent.putExtra(key, (Integer) val);
                        else intent.putExtra(key, String.valueOf(val));
                    }
                } catch (Exception ignored) {}
            }

            if (forceTarget && testCase.getTargetPackage() != null && !testCase.getTargetPackage().isEmpty()) {
                if (testCase.getTargetActivity() != null && !testCase.getTargetActivity().isEmpty()) {
                    intent.setComponent(new ComponentName(testCase.getTargetPackage(), testCase.getTargetActivity()));
                } else {
                    intent.setPackage(testCase.getTargetPackage());
                }
            }

            context.startActivity(intent);

            result.setResolutionType("EXPLICIT_LAUNCH_SUCCESS");
            result.setObservableOutcome("Intent successfully dispatched to Android framework.");
            result.setVerificationStatus("CONFIRMED");
            result.setSafe(true);

        } catch (ActivityNotFoundException e) {
            result.setResolutionType("ACTIVITY_NOT_FOUND");
            result.setExceptionDetails("ActivityNotFoundException: No target activity could handle the URI.");
            result.setObservableOutcome("No installed application accepted the Intent.");
            result.setVerificationStatus("CONFIRMED");
            result.setSafe(true);
        } catch (SecurityException e) {
            result.setResolutionType("SECURITY_EXCEPTION");
            result.setExceptionDetails("SecurityException: " + e.getMessage());
            result.setObservableOutcome("Android OS rejected Intent dispatch due to permission or component export protection.");
            result.setVerificationStatus("CONFIRMED");
            result.setSafe(true);
        } catch (Exception e) {
            result.setResolutionType("UNEXPECTED_EXCEPTION");
            result.setExceptionDetails(e.getClass().getSimpleName() + ": " + e.getMessage());
            result.setObservableOutcome("Encountered unexpected runtime error during launch.");
            result.setVerificationStatus("INCONCLUSIVE");
            result.setSafe(false);
        }

        // Persist to database
        DatabaseHelper.getInstance(context).insertTestResult(result);
        return result;
    }
}
