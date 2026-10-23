package com.intentwatch.security.models;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Records dynamic intent resolution, fuzzer mutation execution, or redirection verification.
 */
public class TestResult implements Serializable {
    private long id;
    private String testCaseId;
    private String testCaseName;
    private String inputUri;
    private long executionTimestamp;
    private String resolutionType; // "RESOLVER_CHOOSER", "EXPLICIT_TARGET", "UNRESOLVED", "EXCEPTION", "BLOCKED_SANDBOX"
    private int targetCount;
    private List<String> resolvedTargets;
    private String selectedTarget;
    private String exceptionDetails;
    private String observableOutcome;
    private String confidence;
    private String verificationStatus;
    private boolean isSafe;

    public TestResult() {
        this.resolvedTargets = new ArrayList<>();
        this.executionTimestamp = System.currentTimeMillis();
        this.resolutionType = "UNRESOLVED";
        this.confidence = "HIGH";
        this.verificationStatus = "CONFIRMED";
        this.isSafe = true;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public String getTestCaseId() { return testCaseId != null ? testCaseId : ""; }
    public void setTestCaseId(String testCaseId) { this.testCaseId = testCaseId; }

    public String getTestCaseName() { return testCaseName != null ? testCaseName : ""; }
    public void setTestCaseName(String testCaseName) { this.testCaseName = testCaseName; }

    public String getInputUri() { return inputUri != null ? inputUri : ""; }
    public void setInputUri(String inputUri) { this.inputUri = inputUri; }

    public long getExecutionTimestamp() { return executionTimestamp; }
    public void setExecutionTimestamp(long executionTimestamp) { this.executionTimestamp = executionTimestamp; }

    public String getResolutionType() { return resolutionType != null ? resolutionType : "UNRESOLVED"; }
    public void setResolutionType(String resolutionType) { this.resolutionType = resolutionType; }

    public int getTargetCount() { return targetCount; }
    public void setTargetCount(int targetCount) { this.targetCount = targetCount; }

    public List<String> getResolvedTargets() { return resolvedTargets; }
    public void setResolvedTargets(List<String> resolvedTargets) {
        this.resolvedTargets = resolvedTargets != null ? resolvedTargets : new ArrayList<>();
        this.targetCount = this.resolvedTargets.size();
    }

    public String getSelectedTarget() { return selectedTarget != null ? selectedTarget : ""; }
    public void setSelectedTarget(String selectedTarget) { this.selectedTarget = selectedTarget; }

    public String getExceptionDetails() { return exceptionDetails != null ? exceptionDetails : ""; }
    public void setExceptionDetails(String exceptionDetails) { this.exceptionDetails = exceptionDetails; }

    public String getObservableOutcome() { return observableOutcome != null ? observableOutcome : ""; }
    public void setObservableOutcome(String observableOutcome) { this.observableOutcome = observableOutcome; }

    public String getConfidence() { return confidence != null ? confidence : "HIGH"; }
    public void setConfidence(String confidence) { this.confidence = confidence; }

    public String getVerificationStatus() { return verificationStatus != null ? verificationStatus : "CONFIRMED"; }
    public void setVerificationStatus(String verificationStatus) { this.verificationStatus = verificationStatus; }

    public boolean isSafe() { return isSafe; }
    public void setSafe(boolean safe) { isSafe = safe; }
}
