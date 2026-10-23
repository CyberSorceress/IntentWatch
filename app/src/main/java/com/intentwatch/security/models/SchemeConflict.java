package com.intentwatch.security.models;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an identified scheme collision or routing ambiguity between one or more
 * intent filters across installed applications or APKs.
 */
public class SchemeConflict implements Serializable {
    private long id;
    private String scheme;
    private int handlerCount;
    private List<String> appNames;
    private List<String> packageNames;
    private List<String> activities;
    private String conflictType;
    private String severity; // "CRITICAL", "HIGH", "MODERATE", "LOW"
    private String confidence; // "CONFIRMED", "HIGH", "MEDIUM", "LOW"
    private int riskScore; // 0 - 100
    private String evidenceSource;
    private String description;
    private String remediation;
    private long timestamp;

    public SchemeConflict() {
        this.appNames = new ArrayList<>();
        this.packageNames = new ArrayList<>();
        this.activities = new ArrayList<>();
        this.severity = "MODERATE";
        this.confidence = "HIGH";
        this.timestamp = System.currentTimeMillis();
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public String getScheme() { return scheme != null ? scheme : ""; }
    public void setScheme(String scheme) { this.scheme = scheme; }

    public int getHandlerCount() { return handlerCount; }
    public void setHandlerCount(int handlerCount) { this.handlerCount = handlerCount; }

    public List<String> getAppNames() { return appNames; }
    public void setAppNames(List<String> appNames) { this.appNames = appNames != null ? appNames : new ArrayList<>(); }

    public List<String> getPackageNames() { return packageNames; }
    public void setPackageNames(List<String> packageNames) { this.packageNames = packageNames != null ? packageNames : new ArrayList<>(); }

    public List<String> getActivities() { return activities; }
    public void setActivities(List<String> activities) { this.activities = activities != null ? activities : new ArrayList<>(); }

    public String getConflictType() { return conflictType != null ? conflictType : "CUSTOM_SCHEME_COLLISION"; }
    public void setConflictType(String conflictType) { this.conflictType = conflictType; }

    public String getSeverity() { return severity != null ? severity : "MODERATE"; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getConfidence() { return confidence != null ? confidence : "HIGH"; }
    public void setConfidence(String confidence) { this.confidence = confidence; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getEvidenceSource() { return evidenceSource != null ? evidenceSource : ""; }
    public void setEvidenceSource(String evidenceSource) { this.evidenceSource = evidenceSource; }

    public String getDescription() { return description != null ? description : ""; }
    public void setDescription(String description) { this.description = description; }

    public String getRemediation() { return remediation != null ? remediation : ""; }
    public void setRemediation(String remediation) { this.remediation = remediation; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getAppsSummary() {
        if (appNames == null || appNames.isEmpty()) {
            return "No applications listed";
        }
        return String.join(", ", appNames);
    }
}
