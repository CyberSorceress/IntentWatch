package com.intentwatch.security;

import com.intentwatch.security.analysis.ConflictAnalyzer;
import com.intentwatch.security.models.DiscoveredDeepLink;
import com.intentwatch.security.models.SchemeConflict;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class ConflictAnalyzerTest {

    @Test
    public void testDetectsCustomSchemeCollisionBetweenCompetingApps() {
        List<DiscoveredDeepLink> handlers = new ArrayList<>();

        // App 1 registers custom scheme
        DiscoveredDeepLink app1 = new DiscoveredDeepLink();
        app1.setAppName("App One");
        app1.setPackageName("com.example.appone");
        app1.setActivityName(".PrimaryActivity");
        app1.setScheme("mycustomscheme");
        app1.setHost("payment");
        app1.setExported(true);
        app1.setBrowsable(true);
        handlers.add(app1);

        // App 2 registers same custom scheme (Malicious or competing)
        DiscoveredDeepLink app2 = new DiscoveredDeepLink();
        app2.setAppName("App Two");
        app2.setPackageName("com.example.apptwo");
        app2.setActivityName(".CompetingActivity");
        app2.setScheme("mycustomscheme");
        app2.setHost("payment");
        app2.setExported(true);
        app2.setBrowsable(true);
        handlers.add(app2);

        ConflictAnalyzer.AnalysisResult result = ConflictAnalyzer.analyzeHandlers(handlers);

        Assert.assertEquals(1, result.totalCollisions);
        Assert.assertFalse(result.conflicts.isEmpty());

        SchemeConflict conflict = result.conflicts.get(0);
        Assert.assertEquals("mycustomscheme", conflict.getScheme());
        Assert.assertEquals(2, conflict.getHandlerCount());
        Assert.assertTrue("HIGH".equals(conflict.getSeverity()) || "CRITICAL".equals(conflict.getSeverity()));
        Assert.assertTrue(conflict.getRiskScore() >= 75);
    }

    @Test
    public void testDetectsUnverifiedAppLinksWithoutAutoVerify() {
        List<DiscoveredDeepLink> handlers = new ArrayList<>();

        DiscoveredDeepLink webLink = new DiscoveredDeepLink();
        webLink.setAppName("Bank Web App");
        webLink.setPackageName("com.bank.portal");
        webLink.setActivityName(".WebLinkActivity");
        webLink.setScheme("https");
        webLink.setHost("bank.example.com");
        webLink.setExported(true);
        webLink.setAutoVerify(false); // Missing autoVerify
        handlers.add(webLink);

        ConflictAnalyzer.AnalysisResult result = ConflictAnalyzer.analyzeHandlers(handlers);

        Assert.assertFalse(result.findings.isEmpty());
        Assert.assertTrue(result.findings.stream()
                .anyMatch(f -> f.getTitle().contains("Unverified App Link") || f.getTitle().contains("autoVerify")));
    }
}
