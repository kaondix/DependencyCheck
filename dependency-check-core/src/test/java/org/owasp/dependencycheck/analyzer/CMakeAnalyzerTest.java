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

import org.apache.commons.lang.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.util.Arrays;
import java.util.HashSet;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

/**
 * Unit tests for CmakeAnalyzer.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class CMakeAnalyzerTest extends BaseTest {

    /**
     * The package analyzer to test.
     */
    CMakeAnalyzer analyzer;

    /**
     * Setup the CmakeAnalyzer.
     *
     * @throws Exception if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new CMakeAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    /**
     * Cleanup any resources used.
     *
     * @throws Exception if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
    }

    /**
     * Test of getName method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Analyzer name wrong.", "CMake Analyzer",
                analyzer.getName());
    }

    /**
     * Test of getSupportedExtensions method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        final String[] expected = {"txt", "cmake"};
        assertEquals("Supported extensions should just have the following: "
                        + StringUtils.join(expected, ", "),
                new HashSet<String>(Arrays.asList(expected)),
                analyzer.getSupportedExtensions());
    }

    /**
     * Test of supportsExtension method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        assertTrue("Should support \"txt\" extension.",
                analyzer.supportsExtension("txt"));
        assertTrue("Should support \"cmake\" extension.",
                analyzer.supportsExtension("txt"));
    }

    /**
     * Test whether expected evidence is gathered from OpenCV's CMakeLists.txt.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsOpenCV() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "cmake/opencv/CMakeLists.txt"));
        analyzer.analyze(result, null);
        final String product = "OpenCV";
        assertTrue("Expected product evidence to contain \"" + product + "\".",
                result.getProductEvidence().toString().contains(product));
    }

    /**
     * Test whether expected evidence is gathered from OpenCV's CMakeLists.txt.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsZlib() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "cmake/zlib/CMakeLists.txt"));
        analyzer.analyze(result, null);
        final String product = "zlib";
        assertTrue("Expected product evidence to contain \"" + product + "\".",
                result.getProductEvidence().toString().contains(product));
    }

    // libavutil_VERSION 52.38.100

    /**
     * Test whether expected version evidence is gathered from OpenCV's third
     * party cmake files.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsOpenCV3rdParty() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "cmake/opencv/3rdparty/ffmpeg/ffmpeg_version.cmake"));
        analyzer.analyze(result, null);
        final String product = "libavutil";
        final String productString = result.getProductEvidence().toString();
        assertTrue("Expected product evidence to contain \"" + product + "\".",
                productString.contains(product));
        final String version = "52.38.100";
        assertTrue("Expected version evidence to contain \"" + version + "\".",
                result.getVersionEvidence().toString().contains(version));
        assertFalse("ALIASOF_ prefix shouldn't be present.",
                Pattern.compile("\\bALIASOF_\\w+").matcher(productString).find());
    }

}
