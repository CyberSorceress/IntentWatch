package com.intentwatch.security.models;

import java.io.Serializable;

/**
 * Represents a persistent security finding discovered through static manifest analysis,
 * conflict correlation, or dynamic test execution.
 */
public class SecurityFinding implements Serializable {
    private String id;
    private String title;
    private String description;
    private String affectedComponent;
    private String packageName;
    private String scheme;
    private String severity; // "CRITICAL", "HIGH", "MODERATE", "LOW", "INFO"
    private String confidence; // "CONFIRMED", "HIGH", "MEDIUM", "LOW"
    private String verificationStatus; // "CONFIRMED", "POTENTIAL", "INCONCLUSIVE", "NOT_TESTED", "RESOLVED"
    private String evidenceSource;
    private String reproductionInstructions;
    private String remediationGuidance;
    private int riskScore; // 0 - 100
    private long firstSeenTimestamp;
    private long lastSeenTimestamp;

    public SecurityFinding() {
        this.severity = "MODERATE";
        this.confidence = "HIGH";
        this.verificationStatus = "POTENTIAL";
        long now = System.currentTimeMillis();
        this.firstSeenTimestamp = now;
        this.lastSeenTimestamp = now;
    }

    public String getId() { return id != null ? id : ""; }
    public void setId(String id) { this.id = id; }

    public String getTitle() { return title != null ? title : ""; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description != null ? description : ""; }
    public void setDescription(String description) { this.description = description; }

    public String getAffectedComponent() { return affectedComponent != null ? affectedComponent : ""; }
    public void setAffectedComponent(String affectedComponent) { this.affectedComponent = affectedComponent; }

    public String getPackageName() { return packageName != null ? packageName : ""; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getScheme() { return scheme != null ? scheme : ""; }
    public void setScheme(String scheme) { this.scheme = scheme; }

    public String getSeverity() { return severity != null ? severity : "MODERATE"; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getConfidence() { return confidence != null ? confidence : "HIGH"; }
    public void setConfidence(String confidence) { this.confidence = confidence; }

    public String getVerificationStatus() { return verificationStatus != null ? verificationStatus : "POTENTIAL"; }
    public void setVerificationStatus(String verificationStatus) { this.verificationStatus = verificationStatus; }

    public String getEvidenceSource() { return evidenceSource != null ? evidenceSource : ""; }
    public void setEvidenceSource(String evidenceSource) { this.evidenceSource = evidenceSource; }

    public String getReproductionInstructions() { return reproductionInstructions != null ? reproductionInstructions : ""; }
    public void setReproductionInstructions(String reproductionInstructions) { this.reproductionInstructions = reproductionInstructions; }

    public String getRemediationGuidance() { return remediationGuidance != null ? remediationGuidance : ""; }
    public void setRemediationGuidance(String remediationGuidance) { this.remediationGuidance = remediationGuidance; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public long getFirstSeenTimestamp() { return firstSeenTimestamp; }
    public void setFirstSeenTimestamp(long firstSeenTimestamp) { this.firstSeenTimestamp = firstSeenTimestamp; }

    public long getLastSeenTimestamp() { return lastSeenTimestamp; }
    public void setLastSeenTimestamp(long lastSeenTimestamp) { this.lastSeenTimestamp = lastSeenTimestamp; }
}
