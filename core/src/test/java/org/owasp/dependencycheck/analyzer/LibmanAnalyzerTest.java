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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.owasp.dependencycheck.analyzer.LibmanAnalyzer.DEPENDENCY_ECOSYSTEM;

public class LibmanAnalyzerTest extends BaseTest {

    private Engine engine;
    private LibmanAnalyzer analyzer;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        engine = new Engine(this.getSettings());

        analyzer = new LibmanAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.prepare(engine);
        analyzer.setEnabled(true);
        analyzer.setFilesMatched(true);
    }

    @Test
    public void testGetAnalyzerName() {
        assertEquals("Libman Analyzer", analyzer.getName());
    }

    @Test
    public void testSupportedFileNames() {
        assertTrue(analyzer.accept(new File("libman.json")));
    }

    @Test
    public void testLibmanAnalysis() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            File file = BaseTest.getResourceAsFile(this, "libman/libman.json");
            Dependency toScan = new Dependency(file);

            analyzer.analyze(toScan, engine);

            int foundCount = 0;

            for (Dependency result : engine.getDependencies()) {
                assertEquals(DEPENDENCY_ECOSYSTEM, result.getEcosystem());

                switch (result.getName()) {
                    case "bootstrap":
                        foundCount++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("bootstrap"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("4.6.0"));
                        break;

                    case "jquery":
                        foundCount++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("jquery"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("3.6.3"));
                        break;

                    case "font-awesome":
                        foundCount++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("font-awesome"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("6.2.1"));
                        break;

                    default:
                        break;
                }
            }

            assertEquals("3 dependencies should be found", 3, foundCount);
        }
    }
}
