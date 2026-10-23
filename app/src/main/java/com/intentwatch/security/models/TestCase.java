package com.intentwatch.security.models;

import java.io.Serializable;

/**
 * Represents a test scenario payload generated in the Deep-Link Fuzzing & Redirection Lab.
 */
public class TestCase implements Serializable {
    private String id;
    private String name;
    private String category;
    private String description;
    private String baselineUri;
    private String modifiedUri;
    private String payloadType;
    private String targetPackage;
    private String targetActivity;
    private String intentAction;
    private String intentCategory;
    private String extrasJson;

    public TestCase() {
        this.intentAction = "android.intent.action.VIEW";
        this.intentCategory = "android.intent.category.BROWSABLE";
    }

    public TestCase(String id, String name, String category, String description, String modifiedUri, String payloadType) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.description = description;
        this.modifiedUri = modifiedUri;
        this.payloadType = payloadType;
        this.intentAction = "android.intent.action.VIEW";
        this.intentCategory = "android.intent.category.BROWSABLE";
    }

    public String getId() { return id != null ? id : ""; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name != null ? name : ""; }
    public void setName(String name) { this.name = name; }

    public String getCategory() { return category != null ? category : ""; }
    public void setCategory(String category) { this.category = category; }

    public String getDescription() { return description != null ? description : ""; }
    public void setDescription(String description) { this.description = description; }

    public String getBaselineUri() { return baselineUri != null ? baselineUri : ""; }
    public void setBaselineUri(String baselineUri) { this.baselineUri = baselineUri; }

    public String getModifiedUri() { return modifiedUri != null ? modifiedUri : ""; }
    public void setModifiedUri(String modifiedUri) { this.modifiedUri = modifiedUri; }

    public String getPayloadType() { return payloadType != null ? payloadType : ""; }
    public void setPayloadType(String payloadType) { this.payloadType = payloadType; }

    public String getTargetPackage() { return targetPackage != null ? targetPackage : ""; }
    public void setTargetPackage(String targetPackage) { this.targetPackage = targetPackage; }

    public String getTargetActivity() { return targetActivity != null ? targetActivity : ""; }
    public void setTargetActivity(String targetActivity) { this.targetActivity = targetActivity; }

    public String getIntentAction() { return intentAction != null ? intentAction : "android.intent.action.VIEW"; }
    public void setIntentAction(String intentAction) { this.intentAction = intentAction; }

    public String getIntentCategory() { return intentCategory != null ? intentCategory : "android.intent.category.BROWSABLE"; }
    public void setIntentCategory(String intentCategory) { this.intentCategory = intentCategory; }

    public String getExtrasJson() { return extrasJson != null ? extrasJson : ""; }
    public void setExtrasJson(String extrasJson) { this.extrasJson = extrasJson; }
}
