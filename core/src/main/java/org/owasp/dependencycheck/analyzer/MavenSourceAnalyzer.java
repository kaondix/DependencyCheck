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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.processing.MvnListProcessor;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.processing.ProcessReader;
import org.owasp.dependencycheck.utils.processing.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.FileFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <p>
 * An analyzer that By finding the pom.xml file in the Maven source code directory and executing
 * the 'mvn dependency:list' command to obtain the dependency information by parsing the result.
 * Maven should be installed, and it is recommended to execute the Maven build command in the Maven
 * source code directory before scanning and analyzing.
 * This helps reduce network access requests during scanning and makes the scanning time shorter.
 * </p>
 * createTime: 2023/10/29 15:01 <br>
 *
 * @author regedit0726
 */
@ThreadSafe
public class MavenSourceAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.JAVA;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(MavenSourceAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Maven source Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INITIAL;

    /**
     * The config filen ame for maven source;
     */
    private static final String POM_XML = "pom.xml";

    /**
     * Match any files that named pom.xml.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames(POM_XML).build();

    private String[] array;

    private static final String MVN_VERSION = "mvn -version";

    private static final String MVN_SETTINGS = "mvn help:effective-settings";

    private static final String MVN_LIST = "mvn dependency:list -f %s";

    /**
     * set to save the analyzed module name
     */
    private Set<String> analyzedModule = new HashSet<>();

    /**
     * The capture group #1 is the verion of maven. e.g.:"Apache Maven 3.6.3"
     */
    private static final Pattern MAVEN_VERSION = Pattern.compile("Apache Maven ((\\d+\\.?)+)");

    /**
     * The capture group #2 is the local repository of maven. e.g.:"<localRepository>/repository</localRepository>"
     */
    private static final Pattern LOCAL_REPO = Pattern.compile(".*(<localRepository>(.*)</localRepository>).*");

    /**
     * the directory path of maven local repository, if maven not installed ,then null
     */
    private String mavenLocalRepository;

    /**
     *  parse result from 'mvn dependency:list -f pomPath' to get dependencies
     * @param dependency the dependency to analyze
     * @param engine     the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error analyzing dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try(MvnListProcessor processor = new MvnListProcessor(engine, this)) {
            runProcessor(launchMvnList(dependency), "dependency:list", processor, null);
        } catch (Exception e) {
            throw new AnalysisException("error occurs when analyzer maven source", e);
        }

    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_MAVENSOURCE_ENABLED;
    }

    /**
     * Returns the FileFilter.
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Initializes the JarAnalyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException is thrown if there is an exception
     * check the maven version installed and get maven local repository path.
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        LOGGER.debug("Initializing Maven source analyzer");
        LOGGER.debug("Maven source analyzer enabled: {}", isEnabled());
        if (isEnabled()) {
            try {
                String os = System.getenv("os");
                this.array = (os != null && os.toLowerCase(Locale.ROOT).startsWith("windows"))
                        ? new String[]{"cmd", "/c"}
                        : new String[]{"/bin/sh", "-c"};
                checkMavenVersion();
                initMavenLocalRepositoryPath();
            } catch (Exception ex) {
                setEnabled(false);
                throw new InitializationException("pom analyzer can not work : " + ex.getMessage(), ex);
            }
        }
    }

    /**
     * parse result from "mvn help:effective-settings" to get the maven local repository
     * @throws AnalysisException
     */
    private void initMavenLocalRepositoryPath() throws AnalysisException {
        runProcessor(launchMvnSettings(), "mvn-setttings", null, output -> {
            Matcher matcher = LOCAL_REPO.matcher(output);
            if(matcher.find()) {
                mavenLocalRepository = matcher.group(2);
            }
        });
    }

    /**
     * parse result from "mvn -version" to get the maven local repository
     * @throws AnalysisException
     */
    private void checkMavenVersion() throws AnalysisException {
        runProcessor(launchMvnVersion(), "mvn-version", null, output -> {
            Matcher matcher = MAVEN_VERSION.matcher(output);
            if(matcher.find()) {
                String version = matcher.group(1);
                // fixme version3 is supported, version2 unknown, version4 not supported
                if(version.charAt(0) != '3') {
                    throw new RuntimeException("unsupported version of maven(version 3 supported):" + version);
                }
            }
        });
    }

    private void runProcessor(Process process, String name, Processor processor, Consumer<String> consumer) throws AnalysisException {
        try(ProcessReader processReader = new ProcessReader(process, processor)) {
            processReader.readAll();
            final int exitValue = process.exitValue();
            if (exitValue < 0 || exitValue > 1) {
                final String error = processReader.getError();
                if (StringUtils.isNoneBlank(error)) {
                    LOGGER.warn("Warnings from {} {}", name, error);
                }
                final String msg = String.format("Unexpected exit code from {} "
                        + "process; exit code: %s", name, exitValue);
                throw new AnalysisException(msg);
            }
            final String output = processReader.getOutput();
            if (StringUtils.isNoneBlank(output)) {
                LOGGER.debug("Warnings from {} {}", name, output);
                if(consumer != null) {
                    // parse output
                    consumer.accept(output);
                }
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AnalysisException(name + " process interrupted", ie);
        } catch (IOException ioe) {
            LOGGER.warn("mvn-setttings failure", ioe);
            throw new AnalysisException(name + " error: " + ioe.getMessage(), ioe);
        }
    }

    /**
     * launch "mavn -version"
     */
    private Process launchMvnVersion() throws AnalysisException {
        return startProcess(MVN_VERSION);
    }

    /**
     * launch "mavn help:effective-settings"
     */
    private Process launchMvnSettings() throws AnalysisException {
        return startProcess(MVN_SETTINGS);
    }

    /**
     * launch "mavn dependency:list"
     */
    private Process launchMvnList(Dependency dependency) throws AnalysisException {
        return startProcess(String.format(MVN_LIST, dependency.getActualFilePath()));
    }

    /**
     * start a Proccess
     * @param command
     * @return Proccess
     * @throws AnalysisException
     */
    private Process startProcess(String command) throws AnalysisException {
        try {
            final List<String> args = new ArrayList<>();
            args.addAll(Arrays.asList(array));
            args.add(command);
            final ProcessBuilder builder = new ProcessBuilder(args);
            return builder.start();
        } catch (IOException e) {
            throw new AnalysisException(command + " error occurs", e);
        }
    }

    /**
     * Whether the analyzer is configured to support parallel processing.
     *
     * @return true if configured to support parallel processing; otherwise
     * false
     */
    @Override
    public boolean supportsParallelProcessing() {
        return true;
    }

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
     * Add module to analyzedModule set if the analyzedModule set doesn't contain the module.
     *
     * @return true if module is added to the analyzedModule set.
     */
    public boolean addAnalyzedModule(String module) {
        if(!analyzedModule.contains(module)) {
            synchronized (analyzedModule) {
                if(!analyzedModule.contains(module)) {
                    analyzedModule.add(module);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Return mavenLocalRepositoryPath.
     *
     * @return mavenLocalRepositoryPath.
     */
    public String getMavenLocalRepository() {
        return mavenLocalRepository;
    }
}
