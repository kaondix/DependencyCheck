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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

/**
 * Unit tests for {@link EmbeddedIDAnalyzer}.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class EmbeddedIDAnalyzerTest extends BaseTest {

    /**
     * Reference to test file.
     */
    File validIDobject;

    /**
     * The analyzer to test.
     */
    EmbeddedIDAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        validIDobject = getResourceAsFile(this, "binutils/hello_id.o");
        analyzer = new EmbeddedIDAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
    }

    /**
     * Test of getName method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testGetName() {
        assertThat(analyzer.getName(), is(equalTo("Object File Embedded ID Analyzer")));
    }


    @Test
    public void testFileFilter(){
        assertThat(analyzer.getFileFilter().accept(validIDobject), is(true));
    }

    @Test
    public void testDetectProductIDinBinary() throws AnalysisException {
        final Dependency result = new Dependency(validIDobject);
        analyzer.analyze(result, null);
        assertEvidenceFound(result);
    }

    @Test
    public void testDetectProductIDinSource() throws AnalysisException {
        final Dependency result = new Dependency(getResourceAsFile(this, "binutils/hello_id.c"));
        analyzer.analyze(result, null);
        assertEvidenceFound(result);
    }


    private void assertEvidenceFound(Dependency result) {
        assertThat(result.getVendorEvidence().toString(), containsString("Institute for Defense Analyses"));
        assertThat(result.getProductEvidence().toString(), containsString("ID Embedding Tests"));
        assertThat(result.getVersionEvidence().toString(), containsString("0.2"));
    }

    @Test
    public void testDetectCPEProductIDinBinary() throws AnalysisException {
        final Dependency result = new Dependency(getResourceAsFile(this, "binutils/hello_cpe.o"));
        analyzer.analyze(result, null);
        assertEvidenceFound(result);
    }

    @Test
    public void testDetectCPEProductIDinSource() throws AnalysisException {
        final Dependency result = new Dependency(getResourceAsFile(this, "binutils/hello_cpe.c"));
        analyzer.analyze(result, null);
        assertEvidenceFound(result);
    }


    @Test
    public void testNoDetectCPEwithoutHeader() throws AnalysisException {
        final Dependency result = new Dependency(getResourceAsFile(this, "binutils/hello_cpe_noheader.o"));
        analyzer.analyze(result, null);
        assertEvidenceNotFound(result);
    }

    @Test
    public void testNoDetectCPEwithoutHeaderInSource() throws AnalysisException {
        final Dependency result = new Dependency(getResourceAsFile(this, "binutils/hello_cpe_noheader.c"));
        analyzer.analyze(result, null);
        assertEvidenceNotFound(result);
    }

    private void assertEvidenceNotFound(Dependency result) {
        assertThat(result.getVendorEvidence().toString(), not(containsString("Institute_for_Defense_Analyses")));
        assertThat(result.getProductEvidence().toString(), not(containsString("ID_Embedding_Tests")));
        assertThat(result.getVersionEvidence().toString(), not(containsString("0.2")));
    }

    @Test
    public void testNoDetectIDWithWrongHeader() throws AnalysisException {
        final Dependency result = new Dependency(getResourceAsFile(this, "binutils/hello_id_wrongheader.o"));
        analyzer.analyze(result, null);
        assertEvidenceNotFound(result);
    }

    @Test
    public void testNoDetectIDWithWrongHeaderInSource() throws AnalysisException {
        final Dependency result = new Dependency(getResourceAsFile(this, "binutils/hello_id_wrongheader.c"));
        analyzer.analyze(result, null);
        assertEvidenceNotFound(result);
    }
}
