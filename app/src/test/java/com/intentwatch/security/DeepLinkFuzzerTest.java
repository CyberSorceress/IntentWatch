package com.intentwatch.security;

import com.intentwatch.security.models.TestCase;
import com.intentwatch.security.testing.DeepLinkFuzzer;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class DeepLinkFuzzerTest {

    @Test
    public void testGenerateFuzzTestCasesGenerates10Vectors() {
        String baseline = "intentwatch-test://vulnerable?redirect_url=https://target.com&action=open";
        List<TestCase> cases = DeepLinkFuzzer.generateFuzzTestCases(baseline);

        Assert.assertNotNull(cases);
        Assert.assertEquals(10, cases.size());

        // Check Baseline
        Assert.assertEquals("TC-01-BASELINE", cases.get(0).getId());
        Assert.assertEquals("BASELINE", cases.get(0).getPayloadType());

        // Check Unexpected Scheme
        TestCase tc6 = cases.get(5);
        Assert.assertTrue(tc6.getModifiedUri().startsWith("javascript:"));

        // Check Open Redirect
        TestCase tc7 = cases.get(6);
        Assert.assertTrue(tc7.getModifiedUri().contains("attacker-controlled.site"));

        // Check Intent Extras
        TestCase tc10 = cases.get(9);
        Assert.assertNotNull(tc10.getExtrasJson());
        Assert.assertTrue(tc10.getExtrasJson().contains("internal_token"));
    }
}
