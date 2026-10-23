package com.intentwatch.security.models;

import java.io.Serializable;

/**
 * Tracks a distinct scan session metadata, summary KPIs, and timestamp.
 */
public class ScanSession implements Serializable {
    private long id;
    private long timestamp;
    private String scanType; // "INSTALLED_PACKAGES", "APK_FILE", "COMBINED"
    private String targetName; // e.g. "Full Device Scan" or APK filename
    private int totalHandlers;
    private int distinctSchemes;
    private int collisionCount;
    private int exportedActivitiesCount;
    private int criticalFindingsCount;
    private int highFindingsCount;

    public ScanSession() {
        this.timestamp = System.currentTimeMillis();
        this.scanType = "INSTALLED_PACKAGES";
        this.targetName = "Full Device Audit";
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getScanType() { return scanType != null ? scanType : "INSTALLED_PACKAGES"; }
    public void setScanType(String scanType) { this.scanType = scanType; }

    public String getTargetName() { return targetName != null ? targetName : "Device Audit"; }
    public void setTargetName(String targetName) { this.targetName = targetName; }

    public int getTotalHandlers() { return totalHandlers; }
    public void setTotalHandlers(int totalHandlers) { this.totalHandlers = totalHandlers; }

    public int getDistinctSchemes() { return distinctSchemes; }
    public void setDistinctSchemes(int distinctSchemes) { this.distinctSchemes = distinctSchemes; }

    public int getCollisionCount() { return collisionCount; }
    public void setCollisionCount(int collisionCount) { this.collisionCount = collisionCount; }

    public int getExportedActivitiesCount() { return exportedActivitiesCount; }
    public void setExportedActivitiesCount(int exportedActivitiesCount) { this.exportedActivitiesCount = exportedActivitiesCount; }

    public int getCriticalFindingsCount() { return criticalFindingsCount; }
    public void setCriticalFindingsCount(int criticalFindingsCount) { this.criticalFindingsCount = criticalFindingsCount; }

    public int getHighFindingsCount() { return highFindingsCount; }
    public void setHighFindingsCount(int highFindingsCount) { this.highFindingsCount = highFindingsCount; }
}
