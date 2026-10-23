package com.intentwatch.security.models;

import java.io.Serializable;

/**
 * Represents a discovered deep-link handler extracted from an installed application
 * or an unpacked APK manifest file.
 */
public class DiscoveredDeepLink implements Serializable {
    private long id;
    private String appName;
    private String packageName;
    private String activityName;
    private String scheme;
    private String host;
    private String port;
    private String path;
    private String pathPrefix;
    private String pathPattern;
    private boolean isExported;
    private boolean hasActionView;
    private boolean isBrowsable;
    private boolean isDefaultCategory;
    private boolean autoVerify;
    private String launchMode;
    private String discoverySource; // "INSTALLED_APP" or "APK_FILE"
    private String analysisStatus;
    private int riskScore; // 0 - 100
    private long timestamp;

    public DiscoveredDeepLink() {
        this.discoverySource = "INSTALLED_APP";
        this.analysisStatus = "DISCOVERED";
        this.launchMode = "standard";
        this.timestamp = System.currentTimeMillis();
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public String getAppName() { return appName != null ? appName : ""; }
    public void setAppName(String appName) { this.appName = appName; }

    public String getPackageName() { return packageName != null ? packageName : ""; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getActivityName() { return activityName != null ? activityName : ""; }
    public void setActivityName(String activityName) { this.activityName = activityName; }

    public String getScheme() { return scheme != null ? scheme : ""; }
    public void setScheme(String scheme) { this.scheme = scheme; }

    public String getHost() { return host != null ? host : ""; }
    public void setHost(String host) { this.host = host; }

    public String getPort() { return port != null ? port : ""; }
    public void setPort(String port) { this.port = port; }

    public String getPath() { return path != null ? path : ""; }
    public void setPath(String path) { this.path = path; }

    public String getPathPrefix() { return pathPrefix != null ? pathPrefix : ""; }
    public void setPathPrefix(String pathPrefix) { this.pathPrefix = pathPrefix; }

    public String getPathPattern() { return pathPattern != null ? pathPattern : ""; }
    public void setPathPattern(String pathPattern) { this.pathPattern = pathPattern; }

    public boolean isExported() { return isExported; }
    public void setExported(boolean exported) { isExported = exported; }

    public boolean hasActionView() { return hasActionView; }
    public void setHasActionView(boolean hasActionView) { this.hasActionView = hasActionView; }

    public boolean isBrowsable() { return isBrowsable; }
    public void setBrowsable(boolean browsable) { isBrowsable = browsable; }

    public boolean isDefaultCategory() { return isDefaultCategory; }
    public void setDefaultCategory(boolean defaultCategory) { isDefaultCategory = defaultCategory; }

    public boolean isAutoVerify() { return autoVerify; }
    public void setAutoVerify(boolean autoVerify) { this.autoVerify = autoVerify; }

    public String getLaunchMode() { return launchMode != null ? launchMode : "standard"; }
    public void setLaunchMode(String launchMode) { this.launchMode = launchMode; }

    public String getDiscoverySource() { return discoverySource != null ? discoverySource : "INSTALLED_APP"; }
    public void setDiscoverySource(String discoverySource) { this.discoverySource = discoverySource; }

    public String getAnalysisStatus() { return analysisStatus != null ? analysisStatus : "DISCOVERED"; }
    public void setAnalysisStatus(String analysisStatus) { this.analysisStatus = analysisStatus; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    /**
     * Reconstructs human-readable URI pattern representation.
     */
    public String getDisplayUriPattern() {
        StringBuilder sb = new StringBuilder();
        if (scheme != null && !scheme.isEmpty()) {
            sb.append(scheme).append("://");
        } else {
            sb.append("*://");
        }
        if (host != null && !host.isEmpty()) {
            sb.append(host);
        } else {
            sb.append("*");
        }
        if (port != null && !port.isEmpty()) {
            sb.append(":").append(port);
        }
        if (path != null && !path.isEmpty()) {
            sb.append(path);
        } else if (pathPrefix != null && !pathPrefix.isEmpty()) {
            sb.append(pathPrefix).append("*");
        } else if (pathPattern != null && !pathPattern.isEmpty()) {
            sb.append(pathPattern);
        }
        return sb.toString();
    }

    public boolean isCustomScheme() {
        if (scheme == null) return false;
        String s = scheme.toLowerCase().trim();
        return !s.equals("http") && !s.equals("https") && !s.equals("file") && !s.equals("content");
    }
}
