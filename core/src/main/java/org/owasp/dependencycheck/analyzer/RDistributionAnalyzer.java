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

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2Utils;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipUtils;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.ArchiveExtractionException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Used to analyze a tgz distribution files, or their contents in
 * unzipped form, and collect information that can be used to determine the
 * associated CPE.
 *
 * @author Cameron Townshend - Sonatype
 */
@Experimental
@ThreadSafe
public class RDistributionAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "R.Dist";

    /**
     * Name of tgz metadata files to analyze.
     */
    private static final String METADATA = "DESCRIPTION";
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RDistributionAnalyzer.class);
    /**
     * The count of directories created during analysis. This is used for
     * creating temporary directories.
     */
    private static final AtomicInteger DIR_COUNT = new AtomicInteger(0);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "R Distribution Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String EXTENSION = "tgz";
    //private static final String[] EXTENSIONS = {EXTENSION};

//    private Set<String> getSupportedExtensions() {
//        Set<String> h = newHashSet(EXTENSION);
//        return h;
//    }

    private static final Set<String>  KNOWN_ZIP_EXT = newHashSet("zip", "ear", "war", "jar", "sar", "apk", "nupkg");
    /**
     * The set of file extensions supported by this analyzer. Note for
     * developers, any additions to this list will need to be explicitly handled
     * in {@link #extractFiles(File, File, Engine)}.
     */
    private static final Set<String> EXTENSIONS = newHashSet("tar", "tgz");



    private static final NameFileFilter METADATA_FILTER = new NameFileFilter(METADATA);

    /**
     * Used to match on tgz archive candidate extensions.
     */
    //private static final FileFilter TGZ = FileFilterBuilder.newInstance().addExtensions(EXTENSION).build();
    /**
     * Used to detect files with a .tgz extension.
     */
    private static final FileFilter TGZ_FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSION).build();
    /**
     * The parent directory for the individual directories per archive.
     */
    private File tempFileLocation;
    /**
     * Filter that detects *.dist-info files (but doesn't verify they are
     * directories.
     */
//    private static final NameFileFilter DIST_INFO_FILTER = new NameFileFilter("DESCRIPTION");

    private static List<File> results = new ArrayList<File>();
    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFileFilters(
            METADATA_FILTER).addExtensions(EXTENSIONS).build();

//    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();

//    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFileFilters(
//            METADATA_FILTER).build();


    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
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
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_R_DISTRIBUTION_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {

        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        final File actualFile = dependency.getActualFile();
        if (TGZ_FILTER.accept(actualFile)) {
            collectMetadataFromArchiveFormat(dependency,
                    METADATA_FILTER, engine);
        }
    }

    /**
     * Collects the meta data from an archive.
     *
     * @param dependency the archive being scanned
     * @param folderFilter the filter to apply to the folder
     * @param metadataFilter the filter to apply to the meta data
     * @throws AnalysisException thrown when there is a problem analyzing the
     * dependency
     */
    private void collectMetadataFromArchiveFormat(Dependency dependency,
            FilenameFilter metadataFilter, Engine engine)
            throws AnalysisException {
        try {
            final File temp = getNextTempDirectory();
            LOGGER.debug("{} exists? {}", temp, temp.exists());
            File archive = new File(dependency.getActualFilePath());

            //final File destination = getNextTempDirectory();

            extractFiles(archive, temp, engine);

            File matchingFile = getMatchingFile(temp, metadataFilter);
            if (matchingFile != null) {
                collectRMetadata(dependency, matchingFile);
            }


        }
        catch (AnalysisException ex){
            throw ex;
        }

    }

    /**
     * Makes sure a usable temporary directory is available.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException an AnalyzeException is thrown when the
     * temp directory cannot be created
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        try {
            final File baseDir = getSettings().getTempDirectory();
            tempFileLocation = File.createTempFile("check", "tmp", baseDir);
            if (!tempFileLocation.delete()) {
                setEnabled(false);
                final String msg = String.format(
                        "Unable to delete temporary file '%s'.",
                        tempFileLocation.getAbsolutePath());
                throw new InitializationException(msg);
            }
            if (!tempFileLocation.mkdirs()) {
                setEnabled(false);
                final String msg = String.format(
                        "Unable to create directory '%s'.",
                        tempFileLocation.getAbsolutePath());
                throw new InitializationException(msg);
            }
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create a temporary file", ex);
        }
    }

    /**
     * Deletes any files extracted from the Wheel during analysis.
     */
    @Override
    public void closeAnalyzer() {
        if (tempFileLocation != null && tempFileLocation.exists()) {
            LOGGER.debug("Attempting to delete temporary files");
            final boolean success = FileUtils.delete(tempFileLocation);
            if (!success && tempFileLocation.exists()) {
                final String[] l = tempFileLocation.list();
                if (l != null && l.length > 0) {
                    LOGGER.warn("Failed to delete some temporary files, see the log for more details");
                }
            }
        }
    }

    /**
     * Gathers evidence from the METADATA file.
     *
     * @param dependency the dependency being analyzed
     * @param file a reference to the manifest/properties file
     */
    private static void collectRMetadata(Dependency dependency, File file) {
        final InternetHeaders headers = getManifestProperties(file);
        addPropertyToEvidence(dependency, EvidenceType.VERSION, Confidence.HIGHEST, headers, "Version");
        addPropertyToEvidence(dependency, EvidenceType.PRODUCT, Confidence.HIGHEST, headers, "Package");
        addPropertyToEvidence(dependency, EvidenceType.PRODUCT, Confidence.MEDIUM, headers, "Package");
        dependency.setName(headers.getHeader("Package", null));
        dependency.setVersion(headers.getHeader("Version", null));
        final String url = headers.getHeader("URL", null);
        if (StringUtils.isNotBlank(url)) {
            if (UrlStringUtils.isUrl(url)) {
                dependency.addEvidence(EvidenceType.VENDOR, METADATA, "vendor", url, Confidence.MEDIUM);
            }
        }
        addPropertyToEvidence(dependency, EvidenceType.VENDOR, Confidence.LOW, headers, "Author");
        addPropertyToEvidence(dependency, EvidenceType.PRODUCT, Confidence.LOW, headers, "Description");
        addPropertyToEvidence(dependency, EvidenceType.PRODUCT, Confidence.LOW, headers, "Title");
    }

    /**
     * Adds a value to the evidence collection.
     *
     * @param dependency the dependency being analyzed
     * @param type the type of evidence to add
     * @param confidence the confidence in the evidence being added
     * @param headers the properties collection
     * @param property the property name
     */
    private static void addPropertyToEvidence(Dependency dependency, EvidenceType type, Confidence confidence,
            InternetHeaders headers, String property) {
        final String value = headers.getHeader(property, null);
        LOGGER.debug("Property: {}, Value: {}", property, value);
        if (StringUtils.isNotBlank(value)) {
            dependency.addEvidence(type, METADATA, property, value, confidence);
        }
    }

    /**
     * Returns a list of files that match the given filter, this
     * recursively scan the directory.
     *
     * @param folder the folder to filter
     * @param filter the filter to apply to the files in the directory
     * @return the list of Files in the directory that match the provided filter
     */
    private static File getMatchingFile(File folder, FilenameFilter filter) {
        File result = null;
        //final File[] matches = folder.listFiles(filter, dirFilter);
        final File[] matches = listFilesAsArray(folder, filter, true);
        if (null != matches && 1 == matches.length) {
            result = matches[0];
        }
        return result;
    }
    public static File[] listFilesAsArray(
            File directory,
            FilenameFilter filter,
            boolean recurse)
    {
        Collection<File> files = listFiles(directory, filter, recurse);
        File[] arr = new File[files.size()];
        return files.toArray(arr);

    }
    public static Collection<File> listFiles(
            File directory,
            FilenameFilter filter,
            boolean recurse)
    {
        // List of files / directories
        Vector files = new Vector();
        // Get files / directories in the directory
        File[] entries = directory.listFiles();

        // Go over entries
        for (File entry : entries)
        {
            // If there is no filter or the filter accepts the
            // file / directory, add it to the list
            if (filter == null || filter.accept(directory, entry.getName()))
            {
                files.add(entry);
            }

            // If the file is a directory and the recurse flag
            // is set, recurse into the directory
            if (recurse && entry.isDirectory())
            {
                files.addAll(listFiles(entry, filter, recurse));
            }
        }
        // Return collection of files
        return files;
    }

    /**
     * Reads the manifest entries from the provided file.
     *
     * @param manifest the manifest
     * @return the manifest entries
     */
    private static InternetHeaders getManifestProperties(File manifest) {
        final InternetHeaders result = new InternetHeaders();
        if (null == manifest) {
            LOGGER.debug("Manifest file not found.");
        } else {
            try (InputStream in = new BufferedInputStream(new FileInputStream(manifest))) {
                result.load(in);
            } catch (MessagingException | FileNotFoundException e) {
                LOGGER.warn(e.getMessage(), e);
            } catch (IOException ex) {
                LOGGER.warn(ex.getMessage(), ex);
            }
        }
        return result;
    }

    /**
     * Retrieves the next temporary destination directory for extracting an
     * archive.
     *
     * @return a directory
     * @throws AnalysisException thrown if unable to create temporary directory
     */
    private File getNextTempDirectory() throws AnalysisException {
        File directory;

        // getting an exception for some directories not being able to be
        // created; might be because the directory already exists?
        do {
            final int dirCount = DIR_COUNT.incrementAndGet();
            directory = new File(tempFileLocation, String.valueOf(dirCount));
        } while (directory.exists());
        if (!directory.mkdirs()) {
            throw new AnalysisException(String.format(
                    "Unable to create temp directory '%s'.",
                    directory.getAbsolutePath()));
        }
        return directory;
    }

    /**
     * <p>
     * Utility method to help in the creation of the extensions set. This
     * constructs a new Set that can be used in a final static declaration.</p>
     * <p>
     * This implementation was copied from
     * http://stackoverflow.com/questions/2041778/prepare-java-hashset-values-by-construction</p>
     *
     * @param strings a list of strings to add to the set.
     * @return a Set of strings.
     */
    protected static Set<String> newHashSet(String... strings) {
        final Set<String> set = new HashSet<>(strings.length);
        Collections.addAll(set, strings);
        return set;
    }


    /**
     * Extracts the contents of an archive into the specified directory.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param destination a directory to extract the contents to
     * @param engine the scanning engine
     * @throws AnalysisException thrown if the archive is not found
     */
    private void extractFiles(File archive, File destination, Engine engine) throws AnalysisException {
        if (archive != null && destination != null) {
            String archiveExt = FileUtils.getFileExtension(archive.getName());
            if (archiveExt == null) {
                return;
            }
            archiveExt = archiveExt.toLowerCase();

            final FileInputStream fis;
            try {
                fis = new FileInputStream(archive);
            } catch (FileNotFoundException ex) {
                final String msg = String.format("Error extracting file `%s`: %s", archive.getAbsolutePath(), ex.getMessage());
                LOGGER.debug(msg, ex);
                throw new AnalysisException(msg);
            }
            BufferedInputStream in = null;

            TarArchiveInputStream tin = null;
            GzipCompressorInputStream gin = null;

            try {
                if ("gz".equals(archiveExt) || "tgz".equals(archiveExt)) {
                    final String uncompressedName = GzipUtils.getUncompressedFilename(archive.getName());
                    final File uncompressedFile = new File(destination, uncompressedName);
                    if (engine.accept(uncompressedFile)) {
                        final String destPath = destination.getCanonicalPath();
                        if (!uncompressedFile.getCanonicalPath().startsWith(destPath)) {
                            final String msg = String.format(
                                    "Archive (%s) contains a file that would be written outside of the destination directory",
                                    archive.getPath());
                            throw new AnalysisException(msg);
                        }
                        in = new BufferedInputStream(fis);
                        gin = new GzipCompressorInputStream(in);
                        decompressFile(gin, uncompressedFile);
                        final FileInputStream uncompressedfis = new FileInputStream(uncompressedFile);
                        String uncarchiveExt = FileUtils.getFileExtension(uncompressedFile.getName());
                        if (uncarchiveExt == null) {
                            return;
                        }
                        uncarchiveExt = uncarchiveExt.toLowerCase();
                        if ("tar".equals(uncarchiveExt)) {
                            BufferedInputStream uncin = null;
                            uncin = new BufferedInputStream(uncompressedfis);
                            tin = new TarArchiveInputStream(uncin);
                            extractArchive(tin, destination, engine);
                        }
                    }
                }
            } catch (ArchiveExtractionException ex) {
                LOGGER.warn("Exception extracting archive '{}'.", archive.getName());
                LOGGER.debug("", ex);
            } catch (IOException ex) {
                LOGGER.warn("Exception reading archive '{}'.", archive.getName());
                LOGGER.debug("", ex);
            } finally {
                //overly verbose and not needed... but keeping it anyway due to
                //having issue with file handles being left open
                FileUtils.close(fis);
                FileUtils.close(in);
                FileUtils.close(tin);
                FileUtils.close(gin);
            }
        }
    }
    /**
     * Decompresses a file.
     *
     * @param inputStream the compressed file
     * @param outputFile the location to write the decompressed file
     * @throws ArchiveExtractionException thrown if there is an exception
     * decompressing the file
     */
    private void decompressFile(CompressorInputStream inputStream, File outputFile) throws ArchiveExtractionException {
        LOGGER.debug("Decompressing '{}'", outputFile.getPath());
        try (FileOutputStream out = new FileOutputStream(outputFile)) {
            IOUtils.copy(inputStream, out);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new ArchiveExtractionException(ex);
        }
    }


    /**
     * Extracts files from an archive.
     *
     * @param input the archive to extract files from
     * @param destination the location to write the files too
     * @param engine the dependency-check engine
     * @throws ArchiveExtractionException thrown if there is an exception
     * extracting files from the archive
     */
    private void extractArchive(ArchiveInputStream input, File destination, Engine engine) throws ArchiveExtractionException {
        ArchiveEntry entry;
        try {
            final String destPath = destination.getCanonicalPath();
            while ((entry = input.getNextEntry()) != null) {
                final File file = new File(destination, entry.getName());
                if (!file.getCanonicalPath().startsWith(destPath)) {
                    final String msg = String.format(
                            "Archive contains a file (%s) that would be extracted outside of the target directory.",
                            file.getName());
                    throw new ArchiveExtractionException(msg);
                }
                if (entry.isDirectory()) {
                    if (!file.exists() && !file.mkdirs()) {
                        final String msg = String.format("Unable to create directory '%s'.", file.getAbsolutePath());
                        throw new AnalysisException(msg);
                    }
                } else if (engine.accept(file)) {
                    extractAcceptedFile(input, file);
                }
            }
        } catch (IOException | AnalysisException ex) {
            throw new ArchiveExtractionException(ex);
        } finally {
            org.owasp.dependencycheck.utils.FileUtils.close(input);
        }
    }

    /**
     * Extracts a file from an archive.
     *
     * @param input the archives input stream
     * @param file the file to extract
     * @throws AnalysisException thrown if there is an error
     */
    private static void extractAcceptedFile(ArchiveInputStream input, File file) throws AnalysisException {
        LOGGER.debug("Extracting '{}'", file.getPath());
        final File parent = file.getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs()) {
            final String msg = String.format("Unable to build directory '%s'.", parent.getAbsolutePath());
            throw new AnalysisException(msg);
        }
        try (FileOutputStream fos = new FileOutputStream(file)) {
            IOUtils.copy(input, fos);
        } catch (FileNotFoundException ex) {
            LOGGER.debug("", ex);
            final String msg = String.format("Unable to find file '%s'.", file.getName());
            throw new AnalysisException(msg, ex);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            final String msg = String.format("IO Exception while parsing file '%s'.", file.getName());
            throw new AnalysisException(msg, ex);
        }
    }


}
