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

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Used to analyze a Python package, and collect information that can be used to
 * determine the associated CPE.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class CMakeAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(CMakeAnalyzer.class
            .getName());

    /**
     * Used when compiling file scanning regex patterns.
     */
    private static final int REGEX_OPTIONS = Pattern.DOTALL
            | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;

    private static final Pattern PROJECT = Pattern.compile(
            "^ *project *\\([ \\n]*(\\w+)[ \\n]*.*?\\)", REGEX_OPTIONS);

    // Group 1: Product
    // Group 2: Version
    private static final Pattern SET_VERSION = Pattern
            .compile(
                    "^ *set\\s*\\(\\s*(\\w+)_version\\s+\"?(\\d+(?:\\.\\d+)+)[\\s\"]?\\)",
                    REGEX_OPTIONS);

    /**
     * Filename extensions for files to be analyzed.
     */
    private static final Set<String> EXTENSIONS = Collections
            .unmodifiableSet(newHashSet("txt", "cmake"));

    /**
     * Returns the name of the Python Package Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "CMake Analyzer";
    }

    /**
     * Tell that we are used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the set of supported file extensions.
     *
     * @return the set of supported file extensions
     */
    @Override
    protected Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * No-op initializer implementation.
     *
     * @throws Exception never thrown
     */
    @Override
    protected void initializeFileTypeAnalyzer() throws Exception {
        // Nothing to do here.
    }

    /**
     * Analyzes python packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine     the engine being used to perform the scan
     * @throws AnalysisException thrown if there is an unrecoverable error analyzing the
     *                           dependency
     */
    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File file = dependency.getActualFile();
        final String parentName = file.getParentFile().getName();
        final String name = file.getName();
        dependency.setDisplayFileName(String.format("%s%c%s", parentName, File.separatorChar, name));
        String contents;
        try {
            contents = FileUtils.readFileToString(file).trim();
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }

        if (StringUtils.isNotBlank(contents)) {
            LOGGER.fine(PROJECT.pattern());
            Matcher m = PROJECT.matcher(contents);
            int count = 0;
            while (m.find()) {
                count++;
                LOGGER.fine(String.format(
                        "Found project command match with %d groups: %s",
                        m.groupCount(), m.group(0)));
                final String group = m.group(1);
                LOGGER.fine("Group 1: " + group);
                dependency.getProductEvidence().addEvidence(name, "Project",
                        group, Confidence.HIGH);
            }
            LOGGER.fine(String.format("Found %d matches.", count));
            analyzeSetVersionCommand(dependency, engine, name, contents);
        }
    }

    private void analyzeSetVersionCommand(Dependency dependency, Engine engine, String name, String contents) {
        final Dependency orig = dependency;
        Matcher m = SET_VERSION.matcher(contents);
        int count = 0;
        LOGGER.fine(SET_VERSION.pattern());
        while (m.find()) {
            count++;
            LOGGER.fine(String.format(
                    "Found project command match with %d groups: %s",
                    m.groupCount(), m.group(0)));
            String product = m.group(1);
            final String version = m.group(2);
            LOGGER.fine("Group 1: " + product);
            LOGGER.fine("Group 2: " + version);
            final String alias_prefix = "ALIASOF_";
            if (product.startsWith(alias_prefix)) {
                product = product.replaceFirst(alias_prefix, "");
            }
            if (count > 1) {
                dependency = new Dependency(orig.getActualFile());
                dependency.setDisplayFileName(String.format("%s:%s", orig.getDisplayFileName(), product));
                engine.getDependencies().add(dependency);
            }
            dependency.getProductEvidence().addEvidence(name, "Product",
                    product, Confidence.MEDIUM);
            dependency.getVersionEvidence().addEvidence(name, "Version",
                    version, Confidence.MEDIUM);
        }
        LOGGER.fine(String.format("Found %d matches.", count));
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CMAKE_ENABLED;
    }
}
