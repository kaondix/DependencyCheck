/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2017 IBM Corporation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Integration tests for testing certain analyzers working together.
 * 
 * @author Bianca Jiang (@biancajiang)
 */
public class AnalyzersIntegrationTest extends BaseTest {

	private Engine engine;

    /**
     * Setup the engine initially for testing. 
     * Start with analyzers disabled except the common ones required by other analyzers.
     * Individual test cases should enable the analyzers to test the integrations for.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        
        //common analyzers required by other analyzers.
        Settings.setBoolean(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, true);
        Settings.setBoolean(Settings.KEYS.ANALYZER_FILE_NAME_ENABLED, true);
        Settings.setBoolean(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, true);
        
        //Individual test cases to enable these if needed. Default disabled for better performance.
        Settings.setBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.UPDATE_VERSION_CHECK_ENABLED, false);
    	
        //initial start with no specific analyzers.  Individual test cases should enable the ones to test integration for.
        Settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_AUTOCONF_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_CMAKE_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_COCOAPODS_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_CPE_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_CPE_SUPPRESSION_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_BUNDLING_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_MERGING_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_FALSE_POSITIVE_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_HINT_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NVD_CVE_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_OPENSSL_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_VERSION_FILTER_ENABLED, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_VULNERABILITY_SUPPRESSION_ENABLED, false);
			
    	engine = new Engine();
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    public void tearDown() throws Exception {
    	engine.cleanup();
    	engine = null;
    }

    /**
     * Test Node.js package.json and bower.json analyzer with bundling and merging analyzers.
     */
    @Test
    public void testNodeDependencyBundling() throws Exception {
    	String testCase = "target/test-classes/nodejs/node_modules/pump";
        Settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, true);
        Settings.setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_BUNDLING_ENABLED, true);
        Settings.setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_MERGING_ENABLED, true);
        
        try {
            engine.scan(testCase);
            int n = engine.getDependencies().size();
            assertTrue(String.format("Scan of Node \"pump\" found %d dependencies.", n), n == 5);
            engine.analyzeDependencies();
            Iterator<Dependency> dependencies = engine.getDependencies().iterator();
            validateDependencies(dependencies);
        } catch (Exception ex) {
        	throw ex;
        }
    }
    
    /**
     * Test Swift.package and .podspec analyzers with bundling and merging analyzers.
     */
    @Test
    public void testSwiftDependencyBundling() throws Exception {
    	String testCase = "target/test-classes/swift/Gloss";
        Settings.setBoolean(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, true);
        Settings.setBoolean(Settings.KEYS.ANALYZER_COCOAPODS_ENABLED, true);
        Settings.setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_BUNDLING_ENABLED, true);
        Settings.setBoolean(Settings.KEYS.ANALYZER_DEPENDENCY_MERGING_ENABLED, true);
        
        try {
            engine.scan(testCase);
            int n = engine.getDependencies().size();
            assertTrue(String.format("Scan of SWIFT \"Gloss\" found %d dependencies.", n), n == 2);
            engine.analyzeDependencies();

            List<Dependency> dependencies = engine.getDependencies();
            assertTrue(String.format("Analyze of SWIFT \"Gloss\" found %d dependencies.", dependencies.size()), dependencies.size() == 1);
            
            validateDependencies(dependencies.iterator());
            validateDependencyEvidence(dependencies.get(0), SwiftPackageManagerAnalyzer.SPM_FILE_NAME);
        } catch (Exception ex) {
        	throw ex;
        }
    }
    
    private void validateDependencies(Iterator<Dependency> dependencies) {
    	while(dependencies.hasNext()) {
        	Dependency depd = dependencies.next();
        	validateDependencyEvidence(depd, null);

        	Set<Dependency> relatedSet = depd.getRelatedDependencies();
        	if(!relatedSet.isEmpty()) {
        		validateDependencies(relatedSet.iterator());
        	}
    	}
    }
    
    private void validateDependencyEvidence(Dependency depd, String sourceNotExpected) {
    	int totalEvidences = depd.getProductEvidence().size() + depd.getVendorEvidence().size() + depd.getVersionEvidence().size();
    	assertTrue(depd.getFilePath() + " does not have any evidence." , totalEvidences > 0);
    	
    	if(sourceNotExpected != null) {
    		validateEvidenceSource(depd, depd.getProductEvidence(), sourceNotExpected);
    		validateEvidenceSource(depd, depd.getVersionEvidence(), sourceNotExpected);
    		validateEvidenceSource(depd, depd.getVendorEvidence(), sourceNotExpected);
    	}
    }
    
    private void validateEvidenceSource(Dependency depd, EvidenceCollection evidenceColl, String sourceNotExpected) {
    	Iterator<Evidence> evidences = evidenceColl.iterator();
    	while(evidences.hasNext()) {
    		Evidence evd = evidences.next();
        	assertTrue(evd.toString() + " is from unexpected source " + sourceNotExpected, !evd.getSource().equals(sourceNotExpected));
        }
    }

}
