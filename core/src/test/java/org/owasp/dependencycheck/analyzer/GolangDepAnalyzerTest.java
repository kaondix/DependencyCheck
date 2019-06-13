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
 * Copyright (c) 2019 Nima Yahyazadeh. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.io.File;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

public class GolangDepAnalyzerTest extends BaseTest {

    private GolangDepAnalyzer analyzer;
    private Engine engine;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new GolangDepAnalyzer();
        engine = new Engine(this.getSettings());
    }

    @Test
    public void testName() {
        assertEquals("Analyzer name wrong.", "Golang Dep Analyzer",
                analyzer.getName());
    }

    @Test
    public void testSupportsFiles() {
        assertThat(analyzer.accept(new File("Gopkg.lock")), is(true));
    }

    @Test
    public void testGopkgLock() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "golang/Gopkg.lock"));
        analyzer.analyze(result, engine);
        assertEquals(12, engine.getDependencies().length);
        for (Dependency d : engine.getDependencies()) {
            System.out.println(d.getSoftwareIdentifiers().toArray()[0]);
        }
    }
}
