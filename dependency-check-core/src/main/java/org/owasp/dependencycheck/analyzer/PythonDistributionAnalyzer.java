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
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.ExtractionException;
import org.owasp.dependencycheck.utils.ExtractionUtil;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Used to load a Wheel distriution file and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class PythonDistributionAnalyzer extends AbstractFileTypeAnalyzer {

	private static final String MANIFEST = "MANIFEST";

	// <editor-fold defaultstate="collapsed"
	// desc="Constants and Member Variables">
	/**
	 * The logger.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(PythonDistributionAnalyzer.class.getName());

	/**
	 * The count of directories created during analysis. This is used for
	 * creating temporary directories.
	 */
	private static int dirCount = 0;

	/**
	 * Constructs a new JarAnalyzer.
	 */
	public PythonDistributionAnalyzer() {
		super();
	}

	// <editor-fold defaultstate="collapsed"
	// desc="All standard implmentation details of Analyzer">
	/**
	 * The name of the analyzer.
	 */
	private static final String ANALYZER_NAME = "Python Distribution Analyzer";
	/**
	 * The phase that this analyzer is intended to run in.
	 */
	private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

	/**
	 * The set of file extensions supported by this analyzer.
	 */
	private static final Set<String> EXTENSIONS = newHashSet("whl");

	/**
	 * Returns a list of file EXTENSIONS supported by this analyzer.
	 *
	 * @return a list of file EXTENSIONS supported by this analyzer.
	 */
	@Override
	public Set<String> getSupportedExtensions() {
		return EXTENSIONS;
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
	public AnalysisPhase getAnalysisPhase() {
		return ANALYSIS_PHASE;
	}

	// </editor-fold>

	/**
	 * Returns the key used in the properties file to reference the analyzer's
	 * enabled property.
	 *
	 * @return the analyzer's enabled property setting key
	 */
	@Override
	protected String getAnalyzerEnabledSettingKey() {
		return Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED;
	}

	/**
	 * Loads a specified JAR file and collects information from the manifest and
	 * checksums to identify the correct CPE information.
	 *
	 * @param dependency
	 *            the dependency to analyze.
	 * @param engine
	 *            the engine that is scanning the dependencies
	 * @throws AnalysisException
	 *             is thrown if there is an error reading the JAR file.
	 */
	@Override
	public void analyzeFileType(Dependency dependency, Engine engine)
			throws AnalysisException {
		try {
			final File f = new File(dependency.getActualFilePath());
			final File tmpWheelFolder = getNextTempDirectory();
			ExtractionUtil.extractFiles(f, tmpWheelFolder, engine);
			collectWheelMetadata(dependency, tmpWheelFolder);
		} catch (ExtractionException ex) {
			throw new AnalysisException(
					"Exception occurred reading the wheel file.", ex);
		}
	}

	/**
	 * The parent directory for the individual directories per archive.
	 */
	private File tempFileLocation = null;

	/**
	 * Initializes the JarAnalyzer.
	 *
	 * @throws Exception
	 *             is thrown if there is an exception creating a temporary
	 *             directory
	 */
	@Override
	public void initializeFileTypeAnalyzer() throws Exception {
		final File baseDir = Settings.getTempDirectory();
		tempFileLocation = File.createTempFile("check", "tmp", baseDir);
		if (!tempFileLocation.delete()) {
			final String msg = String.format(
					"Unable to delete temporary file '%s'.",
					tempFileLocation.getAbsolutePath());
			throw new AnalysisException(msg);
		}
		if (!tempFileLocation.mkdirs()) {
			final String msg = String.format(
					"Unable to create directory '%s'.",
					tempFileLocation.getAbsolutePath());
			throw new AnalysisException(msg);
		}
	}

	/**
	 * Deletes any files extracted from the Wheel during analysis.
	 */
	@Override
	public void close() {
		if (tempFileLocation != null && tempFileLocation.exists()) {
			LOGGER.log(Level.FINE, "Attempting to delete temporary files");
			final boolean success = FileUtils.delete(tempFileLocation);
			if (!success) {
				LOGGER.log(Level.WARNING,
						"Failed to delete some temporary files, see the log for more details");
			}
		}
	}

	private static final Pattern vendorCapture = Pattern
			.compile("^[a-zA-Z]+*://.*\\.(.+)\\.[a-zA-Z]+/?.*$");

	/**
	 * Gathers evidence from the METADATA file.
	 *
	 * @param dependency
	 *            the dependency being analyzed
	 */
	private void collectWheelMetadata(Dependency dependency, File wheelFolder) {
		Properties p = getManifestProperties(wheelFolder);
		this.addPropertyToEvidence(p, dependency.getVersionEvidence(),
				"Version", Confidence.HIGHEST);
		this.addPropertyToEvidence(p, dependency.getProductEvidence(), "Name",
				Confidence.HIGHEST);
		String url = p.getProperty("Home-page");
		EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
		if (StringUtils.isNotBlank(url)) {
			Matcher m = vendorCapture.matcher(url);
			if (m.matches()) {
				vendorEvidence.addEvidence(MANIFEST, "vendor", m.group(1),
						Confidence.MEDIUM);
			}
		}
		this.addPropertyToEvidence(p, vendorEvidence, "Author", Confidence.LOW);
		String summary = p.getProperty("Summary");
		if (StringUtils.isNotBlank(summary)) {
			JarAnalyzer
					.addDescription(dependency, summary, MANIFEST, "summary");
		}
	}

	private void addPropertyToEvidence(Properties properties,
			EvidenceCollection evidence, String property, Confidence confidence) {
		String value = properties.getProperty(property);
		if (StringUtils.isNotBlank(value)) {
			evidence.addEvidence(MANIFEST, property.toLowerCase(), value,
					confidence);
		}
	}

	private Properties getManifestProperties(File wheelFolder) {
		Properties p = new Properties();
		File[] dist_info = wheelFolder.listFiles(new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.endsWith(".dist-info");
			}
		});
		if (null != dist_info && 1 == dist_info.length) {
			File dist_info_file = dist_info[0];
			if (dist_info_file.isDirectory()) {
				File[] manifest = dist_info_file
						.listFiles(new FilenameFilter() {
							public boolean accept(File dir, String name) {
								return name.equals(MANIFEST);
							}
						});
				if (null != manifest && 1 == manifest.length) {
					File manifest_file = manifest[0];
					try {
						p.load(new FileReader(manifest_file));
					} catch (IOException e) {
						LOGGER.log(Level.WARNING, e.getMessage(), e);
					}
				}
			}
		}
		return p;
	}

	/**
	 * Retrieves the next temporary destingation directory for extracting an
	 * archive.
	 *
	 * @return a directory
	 * @throws AnalysisException
	 *             thrown if unable to create temporary directory
	 */
	private File getNextTempDirectory() throws AnalysisException {
		File directory;

		// getting an exception for some directories not being able to be
		// created; might be because the directory already exists?
		do {
			dirCount += 1;
			directory = new File(tempFileLocation, String.valueOf(dirCount));
		} while (directory.exists());
		if (!directory.mkdirs()) {
			throw new AnalysisException(String.format(
					"Unable to create temp directory '%s'.",
					directory.getAbsolutePath()));
		}
		return directory;
	}
}
