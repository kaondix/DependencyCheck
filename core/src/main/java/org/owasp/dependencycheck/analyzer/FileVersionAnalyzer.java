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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.IOError;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;
import org.boris.pecoff4j.PE;
import org.boris.pecoff4j.ResourceDirectory;
import org.boris.pecoff4j.ResourceEntry;
import org.boris.pecoff4j.constant.ResourceType;
import org.boris.pecoff4j.io.PEParser;
import org.boris.pecoff4j.io.ResourceParser;
import org.boris.pecoff4j.resources.StringFileInfo;
import org.boris.pecoff4j.resources.StringTable;
import org.boris.pecoff4j.resources.VersionInfo;
import org.boris.pecoff4j.util.ResourceHelper;

import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Takes a dependency and analyze the version from the windows file version metadata, only for .exe and .dll
 * 
 * @author Amodio Pesce
 */
@ThreadSafe
public class FileVersionAnalyzer extends AbstractAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "File Version Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_FILE_VERSION_ENABLED;
    }

    /**
     * Collects information about the file name.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     */
    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) {
        // strip any path information that may get added by ArchiveAnalyzer, etc.
        try {
            final File fileToCheck = dependency.getActualFile();
            final String ext = FilenameUtils.getExtension(fileToCheck.getName());
            if (ext.equals("dll") || ext.equals(".exe")) {
                final PE pe = PEParser.parse(fileToCheck.getPath());
                final ResourceDirectory rd = pe.getImageData().getResourceTable();
                final ResourceEntry[] entries = ResourceHelper.findResources(rd, ResourceType.VERSION_INFO);
                for (int i = 0; i < entries.length; i++) {
                    final byte[] data = entries[i].getData();
                    final VersionInfo version = ResourceParser.readVersionInfo(data);
                    final StringFileInfo strings = version.getStringFileInfo();
                    final StringTable table = strings.getTable(0);
                    for (int j = 0; j < table.getCount(); j++) {
                        final String key = table.getString(j).getKey();
                        final String value = table.getString(j).getValue();
                        if (key.equals("ProductVersion")) {
                            dependency.addEvidence(EvidenceType.VERSION, "winmetadata", "version", value,
                                    Confidence.HIGHEST);
                        }
                    }
                }
            }
        } catch (final IOException e) 
        {

        }
    }
}