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
package org.owasp.dependencycheck.processing;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.MavenSourceAnalyzer;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.processing.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * description： <br>
 * createTime: 2023/11/9 16:11 <br>
 *
 * @author regedit0726
 */
public class MvnListProcessor extends Processor<InputStream> {
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(MvnListProcessor.class);
    /**
     * Reference to the dependency-check engine.
     */
    private final Engine engine;

    private final MavenSourceAnalyzer mavenSourceAnalyzer;

    /**
     * the directory path of maven local repository
     */
    private String mavenLocalRepositoryPath;

    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private IOException ioException;

    /**
     * a parsing state to search for moduleName(groupId, artifactId and version)
     * searching for info e.g.:
     * [INFO] -------------------< org.owasp:dependency-check-ant >-------------------
     * [INFO] Building Dependency-Check Ant Task 8.4.3-SNAPSHOT                  [5/7]
     * [INFO] --------------------------------[ jar ]---------------------------------
     */
    State parseModuleName = new State() {
        /**
         * The capture group #2 is the groupId in a pom. The capture group #3 is the artifactId in a pom.
         * e.g.:"[INFO] ------------------< org.owasp:dependency-check-core >-------------------"
         */
        Pattern pattern = Pattern.compile("<\\s*(([^\\s>]+?):([^\\s>]+?))\\s*>");

        /**
         * a flag, true when parsing for groupId and artifactId. false when parsing for version
         */
        boolean findModuleName = true;

        /**
         * groupId in pom
         */
        String groupId;

        /**
         * artfactId in pom
         */
        String artfactId;

        /**
         * version in pom
         */
        String version;
        @Override
        public void parse(String line) {
            if(findModuleName) {
                Matcher matcher = pattern.matcher(line);
                if(matcher.find()) {
                    LOGGER.debug("find module:{}", line);
                    groupId = matcher.group(2);
                    artfactId = matcher.group(3);
                    findModuleName = false;
                } else {
                    LOGGER.debug("not match:{}", line);
                }
            } else {
                String[] arr = line.split("\\s+");
                if(arr.length > 3) {
                    version = arr[3];
                    String module = String.format("%s:%s:%s", groupId, artfactId, version);
                    if(mavenSourceAnalyzer.addAnalyzedModule(module)) {
                        LOGGER.debug("switch to findDependency state");
                        currentState = findDependency;
                    } else {
                        LOGGER.debug("module:{} is analyzed", module);
                    }
                }else {
                    LOGGER.warn("____________________________Version not match: {}", line);
                }
                reset();
            }
        }

        /**
         * reset parseModuleName state
         */
        private void reset() {
            findModuleName = true;
            groupId = null;
            artfactId = null;
            version = null;
        }
    };

    /**
     * a state to search for start of the dependency list
     * e.g.:
     * [INFO] The following files have been resolved:
     */
    State findDependency = new State() {
        @Override
        public void parse(String line) {
            if(line.endsWith("resolved:")) {
                LOGGER.debug("switch to parseDependency state");
                currentState = parseDependency;
            }
        }
    };

    /**
     * a state to get out the dependency from list
     * e.g.:
     * [INFO]    org.anarres.jdiagnostics:jdiagnostics:jar:1.0.7:compile
     */
    State parseDependency = new State() {
        @Override
        public void parse(String line) {
            if(!line.contains(":")) {
                LOGGER.debug("switch to parseModuleName state");
                currentState = parseModuleName;
            } else {
                String[] array = line.split("\\s+");
                String[] split = array[1].split(":");
                if(split.length < 4) {
                    return;
                }
                String groupId = split[0];
                String artifactId = split[1];
                String type = split[2];
                String version = split[3];
                String scope = split[4];
                LOGGER.debug("groupId:{}, \tartifactId:{}, \ttype:{}\tversion:{}, \tscope:{}", groupId, artifactId, type, version, scope);
                if("test".equals(scope) || "provided".equals(scope)) {
                    return;
                }

                // add dependency
                String jarFilePath = getFilePath(groupId, artifactId, version, ".jar");
                File jarFile = new File(jarFilePath);
                if(jarFile.exists()) {
                    engine.addDependency(new Dependency(jarFile));
                }
            }
        }

        private String getFilePath(String groupId, String artifactId, String version, String fileSuffix) {
            return String.format("%s%s%s%s", mavenLocalRepositoryPath,
                    getPath(groupId, artifactId, version, File.separator),
                    getFileName(artifactId, version, "-"), fileSuffix);
        }

        private String getPath(String groupId, String artifactId, String version, String separator) {
            String replaceMent = "\\".equals(separator) ? "\\\\" : separator;
            return getPath(separator, "", groupId.replaceAll("\\.", replaceMent), artifactId, version, "");
        }

        private String getPath(String separator, String... args) {
            return String.join(separator, args);
        }

        private String getFileName(String artifactId, String version, String separator) {
            return String.join(separator, artifactId, version);
        }
    };

    State currentState = parseModuleName;

    /**
     * Constructs a new processor to consume the output of `bundler-audit`.
     *
     * @param mavenSourceAnalyzer instance of MavenSourceAnalyzer
     * @param engine a reference to the dependency-check engine
     */
    public MvnListProcessor(Engine engine, MavenSourceAnalyzer mavenSourceAnalyzer) {
        this.engine = engine;
        this.mavenSourceAnalyzer = mavenSourceAnalyzer;
        this.mavenLocalRepositoryPath = mavenSourceAnalyzer.getMavenLocalRepository();
    }

    /**
     * Throws any exceptions that occurred during processing.
     *
     * @throws IOException thrown if an IO Exception occurred
     * @throws Exception thrown if a CPE validation exception
     * occurred
     */
    @Override
    public void close() throws Exception {
        if (ioException != null) {
            addSuppressedExceptions(ioException);
            throw ioException;
        }
    }

    @Override
    public void run() {
        LOGGER.debug("MvnListProcessor run");
        try (InputStreamReader ir = new InputStreamReader(getInput(), StandardCharsets.UTF_8);
             BufferedReader br = new BufferedReader(ir)) {
            String nextLine;
            while ((nextLine = br.readLine()) != null) {
                currentState.parse(nextLine);
            }
        } catch (IOException ex) {
            this.ioException = ex;
        }
    }

    public interface State {
        void parse(String line);
    }
}
