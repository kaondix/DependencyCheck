package org.owasp.dependencycheck.analyzer;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * createTime: 2023/10/30 17:40 <br>
 *
 * @author regedit0726
 */
public class MavenSourceAnalyzerTest extends BaseTest {

    @Test
    public void testAnalyze() throws Exception {

        //File file = BaseTest.getResourceAsFile(this, "core/pom.xml");
        File file = new File("pom.xml");
        Dependency result = new Dependency(file);
        MavenSourceAnalyzer instance = new MavenSourceAnalyzer();
        instance.initialize(getSettings());
        instance.prepareFileTypeAnalyzer(null);
        Engine engine = new Engine(getSettings());
        instance.analyze(result, engine);
        assert engine.getDependencies().length > 0;
    }

    /**
     * Test of getSupportedExtensions method, of class PomAnalyzer.
     */
    @Test
    public void testAcceptSupportedExtensions() throws Exception {
        MavenSourceAnalyzer instance = new MavenSourceAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        instance.setEnabled(true);
        String[] files4True = {"pom.xml"};
        for (String name : files4True) {
            assertTrue(name, instance.accept(new File(name)));
        }

        String[] files4False = {"test.jar", "test.war"};
        for (String name : files4False) {
            assertFalse(name, instance.accept(new File(name)));
        }
    }

    /**
     * Test of getName method, of class PomAnalyzer.
     */
    @Test
    public void testGetName() {
        MavenSourceAnalyzer instance = new MavenSourceAnalyzer();
        String expResult = "Maven source Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class PomAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        MavenSourceAnalyzer instance = new MavenSourceAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class PomAnalyzer.
     */
    @Test
    public void testGetAnalyzerEnabledSettingKey() {
        MavenSourceAnalyzer instance = new MavenSourceAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_MAVENSOURCE_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }


    @Test
    public void testClassInformation() {
        JarAnalyzer.ClassNameInformation instance = new JarAnalyzer.ClassNameInformation("org/owasp/dependencycheck/analyzer/MavenSourceAnalyzer");
        assertEquals("org/owasp/dependencycheck/analyzer/MavenSourceAnalyzer", instance.getName());
        List<String> expected = Arrays.asList("owasp", "dependencycheck", "analyzer", "mavensourceanalyzer");
        List<String> results = instance.getPackageStructure();
        assertEquals(expected, results);
    }
}
