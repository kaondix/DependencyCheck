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

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.AsciiFileScanner;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Used to analyze object code files with embedded IDs in the file system.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class EmbeddedIDAnalyzer extends AbstractFileTypeAnalyzer {

    public static final Logger LOGGER = LoggerFactory.getLogger(EmbeddedIDAnalyzer.class);
    public static final String EMBEDDED_CPE = "Embedded CPE";
    public static final String VENDOR = "vendor";
    public static final String PRODUCT = "product";

    private static final String ID_FIELD = "(?:(vendor|product|version)=(.*?);)";
    private static final String MAGIC_NUMBER = "50CA347E-88EF4066";
    private static final String MAGIC_HEADER = String.format("EID:%s:", MAGIC_NUMBER);

    /**
     * n = 1..3
     * Group 2n-1: "vendor", "product" or "version"
     * Group 2n: corresponding value
     */
    private static final Pattern PATTERN = Pattern.compile(
            String.format("%1$s%2$s%2$s?%2$s?", MAGIC_HEADER, ID_FIELD),
            Pattern.CASE_INSENSITIVE);

    private static final String AVSTRING = "[^:]+?";
    /**
     * Group 1: Vendor
     * Group 2: Product
     * Group 3: Version
     */
    private static final Pattern CPE_PATTERN = Pattern.compile(
            String.format("%2$scpe:2.3:a:(%1$s):(%1$s):(%1$s):%1$s:%1$s:%1$s:%1$s:%1$s:%1$s", AVSTRING, MAGIC_HEADER),
            Pattern.CASE_INSENSITIVE);

    private HashSet<FileTypeAnalyzer> otherFileTypeAnalyzers = new HashSet<FileTypeAnalyzer>();

    /**
     * Returns the name of the Object File Embedded ID Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "Object File Embedded ID Analyzer";
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

    private static final AsciiFileScanner SCANNER = new AsciiFileScanner(MAGIC_HEADER);

    private static final FileFilter MAGIC_FILTER = new FileFilter() {
        public boolean accept(File file) {
            boolean accept = false;
            if (file.exists()) {
                accept = SCANNER.search(file) >= 0;
                try {
                    SCANNER.reset();
                } catch (IOException e) {
                    LOGGER.warn("Problem while resetting file scanner.");
                }
            }
            return accept;
        }
    };

    /**
     * Returns a filter which accepts any readable file.
     *
     * @return the set of supported file extensions
     */
    @Override
    protected FileFilter getFileFilter() {
        return MAGIC_FILTER;
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
     * Searches binary files for embedded ASCII strings and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine     the engine being used to perform the scan
     * @throws AnalysisException thrown if there is an unrecoverable error analyzing the dependency
     */
    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        boolean found = false;
        final File file = dependency.getActualFile();
        final String parentName = file.getParentFile().getName();
        final boolean coveredByOther = isCoveredByOther(engine, file);
        if (!coveredByOther) {
            try {
                final long position = SCANNER.search(file);
                if (0L <= position) {
                    // The spec states at most one valid embedded identifier in the file. Regardless, we will gather
                    // every identifier that can be found in the file.
                    for (String string : SCANNER.getStrings(position)) {
                        found |= findEmbeddedID(dependency, string) || findEmbeddedCPE(dependency, string);
                    }
                }
            } catch (IOException ioe) {
                LOGGER.error("Problem analyzing strings in binary file.", ioe);
            } finally {
                try {
                    SCANNER.reset();
                } catch (IOException e) {
                    LOGGER.warn("Exception while trying to reset file scanner.", e);
                }
            }
        }
        if (found) {
            dependency.setDisplayFileName(parentName + File.separatorChar + file.getName());
        } else if (!coveredByOther && null != engine) {
            engine.getDependencies().remove(dependency);
        }
    }

    private boolean findEmbeddedID(Dependency dependency, String string) {
        final Matcher matcher = PATTERN.matcher(string);
        final boolean found = matcher.find();
        if (found) {
            final int numValues = matcher.groupCount() / 2;
            for (int i = 1; i <= numValues; i++) {
                String name = matcher.group(2 * i - 1);
                String value = matcher.group(2 * i);
                EvidenceCollection evidence;
                if (VENDOR.equalsIgnoreCase(name)) {
                    evidence = dependency.getVendorEvidence();
                } else if (PRODUCT.equalsIgnoreCase(name)) {
                    evidence = dependency.getProductEvidence();
                } else {
                    evidence = dependency.getVersionEvidence();
                }
                evidence.addEvidence("Embedded ID", name, value, Confidence.HIGHEST);
            }
        }
        return found;
    }

    private String getGroup(Matcher matcher, int group) {
        return matcher.group(group).replaceAll("_", " ");
    }

    private boolean findEmbeddedCPE(Dependency dependency, String string) {
        final Matcher matcher = CPE_PATTERN.matcher(string);
        final boolean found = matcher.find();
        if (found) {
            dependency.getVendorEvidence().addEvidence(EMBEDDED_CPE, VENDOR, getGroup(matcher, 1), Confidence.HIGHEST);
            dependency.getProductEvidence().addEvidence(EMBEDDED_CPE, PRODUCT, getGroup(matcher, 2), Confidence.HIGHEST);
            dependency.getVersionEvidence().addEvidence(EMBEDDED_CPE, "version", getGroup(matcher, 3), Confidence.HIGHEST);
        }
        return found;
    }

    private boolean isCoveredByOther(Engine engine, File file) {
        if (null != engine && otherFileTypeAnalyzers.isEmpty()) {
            otherFileTypeAnalyzers.addAll(engine.getFileTypeAnalyzers());
            otherFileTypeAnalyzers.remove(this);
        }
        boolean coveredByOther = false;
        for (FileTypeAnalyzer a : otherFileTypeAnalyzers) {
            coveredByOther = a.accept(file);
            if (coveredByOther) {
                break;
            }
        }
        return coveredByOther;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_EMBEDDED_ID_ENABLED;
    }
}