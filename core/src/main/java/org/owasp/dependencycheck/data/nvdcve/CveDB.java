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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;
//CSOFF: AvoidStarImport

import org.apache.commons.collections.map.ReferenceMap;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.JDBCType;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.stream.Collectors;

import static org.apache.commons.collections.map.AbstractReferenceMap.HARD;
import static org.apache.commons.collections.map.AbstractReferenceMap.SOFT;
import org.owasp.dependencycheck.analyzer.exception.LambdaExceptionWrapper;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.data.nvd.json.BaseMetricV2;
import org.owasp.dependencycheck.data.nvd.json.BaseMetricV3;
import org.owasp.dependencycheck.data.nvd.json.CpeMatchStreamCollector;
import org.owasp.dependencycheck.data.nvd.json.DefCpeMatch;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.LangString;
import org.owasp.dependencycheck.data.nvd.json.NodeFlatteningCollector;
import org.owasp.dependencycheck.data.nvd.json.ProblemtypeDatum;
import org.owasp.dependencycheck.data.nvd.json.Reference;
import static org.owasp.dependencycheck.data.nvdcve.CveDB.PreparedStatementCveDb.*;
import org.owasp.dependencycheck.data.update.cpe.CpeEcosystemCache;
import org.owasp.dependencycheck.data.update.cpe.CpePlus;
import org.owasp.dependencycheck.dependency.CvssV2;
import org.owasp.dependencycheck.dependency.CvssV3;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

/**
 * The database holding information about the NVD CVE data. This class is safe
 * to be accessed from multiple threads in parallel, however internally only one
 * connection will be used.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class CveDB implements AutoCloseable {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CveDB.class);

    /**
     * The database connection factory.
     */
    private final ConnectionFactory connectionFactory;
    /**
     * Database connection
     */
    private Connection connection;
    /**
     * The bundle of statements used when accessing the database.
     */
    private ResourceBundle statementBundle;
    /**
     * Database properties object containing the 'properties' from the database
     * table.
     */
    private DatabaseProperties databaseProperties;
    /**
     * The prepared statements.
     */
    private final EnumMap<PreparedStatementCveDb, PreparedStatement> preparedStatements = new EnumMap<>(PreparedStatementCveDb.class);

    /**
     * A reference to the vulnerable software builder.
     */
    private final VulnerableSoftwareBuilder vulnerableSoftwareBuilder = new VulnerableSoftwareBuilder();
    /**
     * The filter for 2.3 CPEs in the CVEs - we don't import unless we get a
     * match.
     */
    private final String cpeStartsWithFilter;
    /**
     * Cache for CVE lookup; used to speed up the vulnerability search process.
     */
    @SuppressWarnings("unchecked")
    private final Map<String, List<Vulnerability>> vulnerabilitiesForCpeCache = Collections.synchronizedMap(new ReferenceMap(HARD, SOFT));
    /**
     * The configured settings
     */
    private final Settings settings;

    /**
     * Utility to extract information from
     * {@linkplain org.owasp.dependencycheck.data.nvd.json.DefCveItem}.
     */
    private final CveItemOperator cveItemConverter = new CveItemOperator();
    private boolean isOracle=false;

    /**
     * The enumeration value names must match the keys of the statements in the
     * statement bundles "dbStatements*.properties".
     */
    enum PreparedStatementCveDb {
        /**
         * Key for SQL Statement.
         */
        CLEANUP_ORPHANS,
        /**
         * Key for update ecosystem.
         */
        UPDATE_ECOSYSTEM,
        /**
         * Key for update ecosystem.
         */
        UPDATE_ECOSYSTEM2,
        /**
         * Key for SQL Statement.
         */
        COUNT_CPE,
        /**
         * Key for SQL Statement.
         */
        DELETE_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        INSERT_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        INSERT_CWE,
        /**
         * Key for SQL Statement.
         */
        INSERT_REFERENCE,
        /**
         * Key for SQL Statement.
         */
        INSERT_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        MERGE_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        SELECT_CPE_ENTRIES,
        /**
         * Key for SQL Statement.
         */
        SELECT_CVE_FROM_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        SELECT_PROPERTIES,
        /**
         * Key for SQL Statement.
         */
        SELECT_VULNERABILITY_CWE,
        /**
         * Key for SQL Statement.
         */
        SELECT_REFERENCES,
        /**
         * Key for SQL Statement.
         */
        SELECT_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        SELECT_VENDOR_PRODUCT_LIST,
        /**
         * Key for SQL Statement.
         */
        SELECT_VENDOR_PRODUCT_LIST_FOR_NODE,
        /**
         * Key for SQL Statement.
         */
        SELECT_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        UPDATE_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        UPDATE_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        SELECT_CPE_ECOSYSTEM,
        /**
         * Key for SQL Statement.
         */
        MERGE_CPE_ECOSYSTEM
    }

    /**
     * Creates a new CveDB object and opens the database connection. Note, the
     * connection must be closed by the caller by calling the close method.
     *
     * @param settings the configured settings
     * @throws DatabaseException thrown if there is an exception opening the
     * database.
     */
    public CveDB(Settings settings) throws DatabaseException {
        this.settings = settings;
        this.cpeStartsWithFilter = this.settings.getString(Settings.KEYS.CVE_CPE_STARTS_WITH_FILTER, "cpe:2.3:a:");
        connectionFactory = new ConnectionFactory(settings);
        open();
    }

    /**
     * Tries to determine the product name of the database.
     *
     * @param conn the database connection
     * @return the product name of the database if successful, {@code null} else
     */
    private String determineDatabaseProductName(Connection conn) {
        try {
            final String databaseProductName = conn.getMetaData().getDatabaseProductName().toLowerCase();
            LOGGER.debug("Database product: {}", databaseProductName);
            return databaseProductName;
        } catch (SQLException se) {
            LOGGER.warn("Problem determining database product!", se);
            return null;
        }
    }

    /**
     * Opens the database connection. If the database does not exist, it will
     * create a new one.
     *
     * @throws DatabaseException thrown if there is an error opening the
     * database connection
     */
    private synchronized void open() throws DatabaseException {
        try {
            if (!isOpen()) {
                connection = connectionFactory.getConnection();
                final String databaseProductName = determineDatabaseProductName(this.connection);
                isOracle = "oracle".equals(databaseProductName);
                statementBundle = databaseProductName != null
                        ? ResourceBundle.getBundle("data/dbStatements", new Locale(databaseProductName))
                        : ResourceBundle.getBundle("data/dbStatements");
                prepareStatements();
                databaseProperties = new DatabaseProperties(this);
            }
        } catch (DatabaseException e) {
            releaseResources();
            throw e;
        }
    }

    /**
     * Closes the database connection. Close should be called on this object
     * when it is done being used.
     */
    @Override
    public synchronized void close() {
        if (isOpen()) {
            LOGGER.debug("Closing database");
            clearCache();
            LOGGER.debug("Cache cleared");
            closeStatements();
            LOGGER.debug("Statments closed");
            try {
                connection.close();
                LOGGER.debug("Connection closed");
            } catch (SQLException ex) {
                LOGGER.error("There was an error attempting to close the CveDB, see the log for more details.");
                LOGGER.debug("", ex);
            } catch (Throwable ex) {
                LOGGER.error("There was an exception attempting to close the CveDB, see the log for more details.");
                LOGGER.debug("", ex);
            }
            releaseResources();
            LOGGER.debug("Resources released");
            connectionFactory.cleanup();
        }
    }

    /**
     * Releases the resources used by CveDB.
     */
    private synchronized void releaseResources() {
        statementBundle = null;
        preparedStatements.clear();
        databaseProperties = null;
        connection = null;
    }

    /**
     * Returns whether the database connection is open or closed.
     *
     * @return whether the database connection is open or closed
     */
    protected synchronized boolean isOpen() {
        return connection != null;
    }

    /**
     * Prepares all statements to be used.
     *
     * @throws DatabaseException thrown if there is an error preparing the
     * statements
     */
    private void prepareStatements() throws DatabaseException {
        for (PreparedStatementCveDb key : values()) {
            final PreparedStatement preparedStatement = prepareStatement(key);
            if (preparedStatement != null) {
                preparedStatements.put(key, preparedStatement);
            }
        }
    }

    /**
     * Creates a prepared statement from the given key. The SQL is stored in a
     * properties file and the key is used to lookup the specific query.
     *
     * @param key the key to select the prepared statement from the properties
     * file
     * @return the prepared statement
     * @throws DatabaseException throw if there is an error generating the
     * prepared statement
     */
    private PreparedStatement prepareStatement(PreparedStatementCveDb key) throws DatabaseException {
        PreparedStatement preparedStatement = null;
        try {
            final String statementString = statementBundle.getString(key.name());
//            if (key == INSERT_CPE) {
//                final String[] returnedColumns = {"id"};
//                preparedStatement = connection.prepareStatement(statementString, returnedColumns);
//            } else {
            if (isOracle && key == UPDATE_VULNERABILITY) {
                preparedStatement = connection.prepareCall(statementString);
            } else {
                preparedStatement = connection.prepareStatement(statementString);
            }
//            }
        } catch (SQLException ex) {
            throw new DatabaseException(ex);
        } catch (MissingResourceException ex) {
            if (!ex.getMessage().contains("key MERGE_PROPERTY")) {
                throw new DatabaseException(ex);
            }
        }
        return preparedStatement;
    }

    /**
     * Closes all prepared statements.
     */
    private synchronized void closeStatements() {
        preparedStatements.values().forEach((preparedStatement) -> DBUtils.closeStatement(preparedStatement));
    }

    /**
     * Returns the specified prepared statement.
     *
     * @param key the prepared statement from {@link PreparedStatementCveDb} to
     * return
     * @return the prepared statement
     * @throws SQLException thrown if a SQL Exception occurs
     */
    private synchronized PreparedStatement getPreparedStatement(PreparedStatementCveDb key) throws SQLException {
        if (!preparedStatements.containsKey(key)) {
            return null;
        }
        final PreparedStatement preparedStatement = preparedStatements.get(key);
        preparedStatement.clearParameters();
        return preparedStatement;
    }

    /**
     * Commits all completed transactions.
     *
     * @throws SQLException thrown if a SQL Exception occurs
     */
    @SuppressWarnings("EmptyMethod")
    public synchronized void commit() throws SQLException {
        //temporarily remove this as autocommit is on.
        //if (isOpen()) {
        //    connection.commit();
        //}
    }

    /**
     * Cleans up the object and ensures that "close" has been called.
     *
     * @throws Throwable thrown if there is a problem
     */
    @Override
    @SuppressWarnings("FinalizeDeclaration")
    protected void finalize() throws Throwable {
        LOGGER.debug("Entering finalize");
        close();
        super.finalize();
    }

    /**
     * Get the value of databaseProperties.
     *
     * @return the value of databaseProperties
     */
    public synchronized DatabaseProperties getDatabaseProperties() {
        return databaseProperties;
    }

    /**
     * Used within the unit tests to reload the database properties.
     *
     * @return the database properties
     */
    protected synchronized DatabaseProperties reloadProperties() {
        databaseProperties = new DatabaseProperties(this);
        return databaseProperties;
    }

    /**
     * Searches the CPE entries in the database and retrieves all entries for a
     * given vendor and product combination. The returned list will include all
     * versions of the product that are registered in the NVD CVE data.
     *
     * @param vendor the identified vendor name of the dependency being analyzed
     * @param product the identified name of the product of the dependency being
     * analyzed
     * @return a set of vulnerable software
     */
    public synchronized Set<CpePlus> getCPEs(String vendor, String product) {
        final Set<CpePlus> cpe = new HashSet<>();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_CPE_ENTRIES);
            if (ps == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_CPE_ENTRIES);
            }
            //part, vendor, product, version, update_version, edition,
            //lang, sw_edition, target_sw, target_hw, other, ecosystem
            ps.setString(1, vendor);
            ps.setString(2, product);
            rs = ps.executeQuery();
            final CpeBuilder builder = new CpeBuilder();
            while (rs.next()) {
                final Cpe entry = builder
                        .part(rs.getString(1))
                        .vendor(rs.getString(2))
                        .product(rs.getString(3))
                        .version(rs.getString(4))
                        .update(rs.getString(5))
                        .edition(rs.getString(6))
                        .language(rs.getString(7))
                        .swEdition(rs.getString(8))
                        .targetSw(rs.getString(9))
                        .targetHw(rs.getString(10))
                        .other(rs.getString(11)).build();
                final CpePlus plus = new CpePlus(entry, rs.getString(12));
                cpe.add(plus);
            }
        } catch (SQLException | CpeParsingException | CpeValidationException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return cpe;
    }

    /**
     * Returns the entire list of vendor/product combinations.
     *
     * @return the entire list of vendor/product combinations
     * @throws DatabaseException thrown when there is an error retrieving the
     * data from the DB
     */
    public synchronized Set<Pair<String, String>> getVendorProductList() throws DatabaseException {
        final Set<Pair<String, String>> data = new HashSet<>();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_VENDOR_PRODUCT_LIST);
            if (ps == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_VENDOR_PRODUCT_LIST);
            }
            rs = ps.executeQuery();
            while (rs.next()) {
                data.add(new Pair<>(rs.getString(1), rs.getString(2)));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            throw new DatabaseException(msg, ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return data;
    }

    /**
     * Returns the entire list of vendor/product combinations filtered for just
     * Node JS related products.
     *
     * @return the list of vendor/product combinations that are known to be
     * related to Node JS
     * @throws DatabaseException thrown when there is an error retrieving the
     * data from the DB
     */
    public synchronized Set<Pair<String, String>> getVendorProductListForNode() throws DatabaseException {
        final Set<Pair<String, String>> data = new HashSet<>();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_VENDOR_PRODUCT_LIST_FOR_NODE);
            if (ps == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_VENDOR_PRODUCT_LIST_FOR_NODE);
            }
            rs = ps.executeQuery();
            while (rs.next()) {
                data.add(new Pair<>(rs.getString(1), rs.getString(2)));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            throw new DatabaseException(msg, ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return data;
    }

    /**
     * Returns a set of properties.
     *
     * @return the properties from the database
     */
    public synchronized Properties getProperties() {
        final Properties prop = new Properties();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_PROPERTIES);
            if (ps == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_PROPERTIES);
            }
            rs = ps.executeQuery();
            while (rs.next()) {
                prop.setProperty(rs.getString(1), rs.getString(2));
            }
        } catch (SQLException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return prop;
    }

    /**
     * Saves a property to the database.
     *
     * @param key the property key
     * @param value the property value
     */
    public synchronized void saveProperty(String key, String value) {
        clearCache();
        try {
            final PreparedStatement mergeProperty = getPreparedStatement(MERGE_PROPERTY);
            if (mergeProperty != null) {
                mergeProperty.setString(1, key);
                mergeProperty.setString(2, value);
                mergeProperty.execute();
            } else {
                // No Merge statement, so doing an Update/Insert...
                final PreparedStatement updateProperty = getPreparedStatement(UPDATE_PROPERTY);
                if (updateProperty == null) {
                    throw new SQLException("Database query does not exist in the resource bundle: " + UPDATE_PROPERTY);
                }
                updateProperty.setString(1, value);
                updateProperty.setString(2, key);
                if (updateProperty.executeUpdate() == 0) {
                    final PreparedStatement insertProperty = getPreparedStatement(INSERT_PROPERTY);
                    if (insertProperty == null) {
                        throw new SQLException("Database query does not exist in the resource bundle: " + INSERT_PROPERTY);
                    }
                    insertProperty.setString(1, key);
                    insertProperty.setString(2, value);
                    insertProperty.executeUpdate();
                }
            }
        } catch (SQLException ex) {
            LOGGER.warn("Unable to save property '{}' with a value of '{}' to the database", key, value);
            LOGGER.debug("", ex);
        }
    }

    /**
     * Clears cache. Should be called whenever something is modified. While this
     * is not the optimal cache eviction strategy, this is good enough for
     * typical usage (update DB and then only read) and it is easier to maintain
     * the code.
     * <p>
     * It should be also called when DB is closed.
     * </p>
     */
    private synchronized void clearCache() {
        vulnerabilitiesForCpeCache.clear();
    }

    /**
     * Retrieves the vulnerabilities associated with the specified CPE.
     *
     * @param cpe the CPE to retrieve vulnerabilities for
     * @return a list of Vulnerabilities
     * @throws DatabaseException thrown if there is an exception retrieving data
     */
    public synchronized List<Vulnerability> getVulnerabilities(Cpe cpe) throws DatabaseException {
        final List<Vulnerability> cachedVulnerabilities = vulnerabilitiesForCpeCache.get(cpe.toCpe23FS());
        if (cachedVulnerabilities != null) {
            LOGGER.debug("Cache hit for {}", cpe.toCpe23FS());
            return cachedVulnerabilities;
        } else {
            LOGGER.debug("Cache miss for {}", cpe.toCpe23FS());
        }

        final List<Vulnerability> vulnerabilities = new ArrayList<>();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_CVE_FROM_SOFTWARE);
            ps.setString(1, cpe.getVendor());
            ps.setString(2, cpe.getProduct());
            rs = ps.executeQuery();
            String currentCVE = "";

            final Set<VulnerableSoftware> vulnSoftware = new HashSet<>();
            while (rs.next()) {
                final String cveId = rs.getString(1);
                if (currentCVE.isEmpty()) {
                    //first loop we don't have the cveId
                    currentCVE = cveId;
                }
                if (!vulnSoftware.isEmpty() && !currentCVE.equals(cveId)) { //check for match and add
                    final VulnerableSoftware matchedCPE = getMatchingSoftware(cpe, vulnSoftware);
                    if (matchedCPE != null) {
                        final Vulnerability v = getVulnerability(currentCVE);
                        if (v != null) {
                            v.setMatchedVulnerableSoftware(matchedCPE);
                            v.setSource(Vulnerability.Source.NVD);
                            vulnerabilities.add(v);
                        }
                    }
                    vulnSoftware.clear();
                    currentCVE = cveId;
                }
                // 1 cve, 2 part, 3 vendor, 4 product, 5 version, 6 update_version, 7 edition,
                // 8 lang, 9 sw_edition, 10 target_sw, 11 target_hw, 12 other, 13 versionEndExcluding,
                //14 versionEndIncluding, 15 versionStartExcluding, 16 versionStartIncluding, 17 vulnerable
                final VulnerableSoftware vs;
                try {
                    vs = vulnerableSoftwareBuilder.part(rs.getString(2)).vendor(rs.getString(3))
                            .product(rs.getString(4)).version(rs.getString(5)).update(rs.getString(6))
                            .edition(rs.getString(7)).language(rs.getString(8)).swEdition(rs.getString(9))
                            .targetSw(rs.getString(10)).targetHw(rs.getString(11)).other(rs.getString(12))
                            .versionEndExcluding(rs.getString(13)).versionEndIncluding(rs.getString(14))
                            .versionStartExcluding(rs.getString(15)).versionStartIncluding(rs.getString(16))
                            .vulnerable(rs.getBoolean(17)).build();
                } catch (CpeParsingException | CpeValidationException ex) {
                    throw new DatabaseException("Database contains an invalid Vulnerable Software Entry", ex);
                }
                vulnSoftware.add(vs);
            }
            //remember to process the last set of CVE/CPE entries
            final VulnerableSoftware matchedCPE = getMatchingSoftware(cpe, vulnSoftware);
            if (matchedCPE != null) {
                final Vulnerability v = getVulnerability(currentCVE);
                if (v != null) {
                    v.setMatchedVulnerableSoftware(matchedCPE);
                    v.setSource(Vulnerability.Source.NVD);
                    vulnerabilities.add(v);
                }
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Exception retrieving vulnerability for " + cpe.toCpe23FS(), ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        vulnerabilitiesForCpeCache.put(cpe.toCpe23FS(), vulnerabilities);
        return vulnerabilities;
    }

    /**
     * Gets a vulnerability for the provided CVE.
     *
     * @param cve the CVE to lookup
     * @return a vulnerability object
     * @throws DatabaseException if an exception occurs
     */
    public synchronized Vulnerability getVulnerability(String cve) throws DatabaseException {
        ResultSet rsV = null;
        ResultSet rsC = null;
        ResultSet rsR = null;
        ResultSet rsS = null;
        Vulnerability vuln = null;

        try {
            final PreparedStatement psV = getPreparedStatement(SELECT_VULNERABILITY);
            if (psV == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_VULNERABILITY);
            }
            psV.setString(1, cve);
            rsV = psV.executeQuery();
            if (rsV.next()) {
                //1.id, 2.description,
                final int cveId = rsV.getInt(1);
                vuln = new Vulnerability();
                vuln.setSource(Vulnerability.Source.NVD);
                vuln.setName(cve);
                vuln.setDescription(rsV.getString(2));

                //3.v2Severity, 4.v2ExploitabilityScore, 5.v2ImpactScore, 6.v2AcInsufInfo, 7.v2ObtainAllPrivilege,
                //8.v2ObtainUserPrivilege, 9.v2ObtainOtherPrivilege, 10.v2UserInteractionRequired, 11.v2Score,
                //12.v2AccessVector, 13.v2AccessComplexity, 14.v2Authentication, 15.v2ConfidentialityImpact,
                //16.v2IntegrityImpact, 17.v2AvailabilityImpact, 18.v2Version,
                if (rsV.getObject(11) != null) {
                    final CvssV2 cvss = new CvssV2(rsV.getFloat(11), rsV.getString(12),
                            rsV.getString(13), rsV.getString(14), rsV.getString(15),
                            rsV.getString(16), rsV.getString(17), rsV.getString(3),
                            getFloatValue(rsV, 4), getFloatValue(rsV, 5),
                            getBooleanValue(rsV, 6), getBooleanValue(rsV, 7), getBooleanValue(rsV, 8),
                            getBooleanValue(rsV, 9), getBooleanValue(rsV, 10), rsV.getString(18));
                    vuln.setCvssV2(cvss);
                }
                //19.v3ExploitabilityScore, 20.v3ImpactScore, 21.v3AttackVector, 22.v3AttackComplexity, 23.v3PrivilegesRequired,
                //24.v3UserInteraction, 25.v3Scope, 26.v3ConfidentialityImpact, 27.v3IntegrityImpact, 28.v3AvailabilityImpact,
                //29.v3BaseScore, 30.v3BaseSeverity, 21.v3Version
                if (rsV.getObject(21) != null) {
                    final CvssV3 cvss = new CvssV3(rsV.getString(21), rsV.getString(22),
                            rsV.getString(23), rsV.getString(24), rsV.getString(25),
                            rsV.getString(26), rsV.getString(27), rsV.getString(28),
                            rsV.getFloat(29), rsV.getString(30), getFloatValue(rsV, 19),
                            getFloatValue(rsV, 20), rsV.getString(31));
                    vuln.setCvssV3(cvss);
                }
                final PreparedStatement psCWE = getPreparedStatement(SELECT_VULNERABILITY_CWE);
                if (psCWE == null) {
                    throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_VULNERABILITY_CWE);
                }
                psCWE.setInt(1, cveId);
                rsC = psCWE.executeQuery();
                while (rsC.next()) {
                    vuln.addCwe(rsC.getString(1));
                }

                final PreparedStatement psR = getPreparedStatement(SELECT_REFERENCES);
                if (psR == null) {
                    throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_REFERENCES);
                }
                psR.setInt(1, cveId);
                rsR = psR.executeQuery();
                while (rsR.next()) {
                    vuln.addReference(rsR.getString(1), rsR.getString(2), rsR.getString(3));
                }

                final PreparedStatement psS = getPreparedStatement(SELECT_SOFTWARE);
                if (psS == null) {
                    throw new SQLException("Database query does not exist in the resource bundle: " + SELECT_SOFTWARE);
                }
                //1 part, 2 vendor, 3 product, 4 version, 5 update_version, 6 edition, 7 lang,
                //8 sw_edition, 9 target_sw, 10 target_hw, 11 other, 12 versionEndExcluding,
                //13 versionEndIncluding, 14 versionStartExcluding, 15 versionStartIncluding, 16 vulnerable
                psS.setInt(1, cveId);
                rsS = psS.executeQuery();
                while (rsS.next()) {
                    vulnerableSoftwareBuilder.part(rsS.getString(1))
                            .vendor(rsS.getString(2))
                            .product(rsS.getString(3))
                            .version(rsS.getString(4))
                            .update(rsS.getString(5))
                            .edition(rsS.getString(6))
                            .language(rsS.getString(7))
                            .swEdition(rsS.getString(8))
                            .targetSw(rsS.getString(9))
                            .targetHw(rsS.getString(10))
                            .other(rsS.getString(11))
                            .versionEndExcluding(rsS.getString(12))
                            .versionEndIncluding(rsS.getString(13))
                            .versionStartExcluding(rsS.getString(14))
                            .versionStartIncluding(rsS.getString(15))
                            .vulnerable(rsS.getBoolean(16));
                    vuln.addVulnerableSoftware(vulnerableSoftwareBuilder.build());
                }
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Error retrieving " + cve, ex);
        } catch (CpeParsingException | CpeValidationException ex) {
            throw new DatabaseException("The database contains an invalid Vulnerable Software Entry", ex);
        } finally {
            DBUtils.closeResultSet(rsV);
            DBUtils.closeResultSet(rsC);
            DBUtils.closeResultSet(rsR);
            DBUtils.closeResultSet(rsS);
        }
        return vuln;
    }

    /**
     * Updates the vulnerability within the database. If the vulnerability does
     * not exist it will be added.
     *
     * @param cve the vulnerability from the NVD CVE Data Feed to add to the
     * database
     * @param baseEcosystem the ecosystem the CVE belongs to; this is based off
     * of things like the CVE description
     * @throws DatabaseException is thrown if the database
     */
    public void updateVulnerability(DefCveItem cve, String baseEcosystem) {
        clearCache();
        final String cveId = cve.getCve().getCVEDataMeta().getId();
        try {
            final String description = cveItemConverter.extractDescription(cve);
            if (cveItemConverter.isRejected(description)) {
                deleteVulnerability(cveId);
            } else {
                final int vulnerabilityId = updateOrInsertVulnerability(cve, description);
                updateVulnerabilityInsertCwe(vulnerabilityId, cve);
                updateVulnerabilityInsertReferences(vulnerabilityId, cve);

                //parse the CPEs outside of a synchronized method
                final List<VulnerableSoftware> software = parseCpes(cve);
                updateVulnerabilityInsertSoftware(vulnerabilityId, cveId, software, baseEcosystem);
            }

        } catch (SQLException ex) {
            final String msg = String.format("Error updating '%s'", cveId);
            LOGGER.debug(msg, ex);
            throw new DatabaseException(msg, ex);
        } catch (CpeValidationException ex) {
            final String msg = String.format("Error parsing CPE entry from '%s'", cveId);
            LOGGER.debug(msg, ex);
            throw new DatabaseException(msg, ex);
        }
    }

    private void loadCpeEcosystemCache() {
        final Map<Pair<String, String>, String> map = new HashMap<>();
        final ResultSet rs;
        try (PreparedStatement ps = prepareStatement(SELECT_CPE_ECOSYSTEM)) {
            rs = ps.executeQuery();
            while (rs.next()) {
                final Pair<String, String> key = new Pair<>(rs.getString(1), rs.getString(2));
                final String value = rs.getString(3);
                map.put(key, value);
            }
        } catch (SQLException ex) {
            final String msg = String.format("Error loading the Cpe Ecosystem Cache: %s", ex.getMessage());
            LOGGER.debug(msg, ex);
            throw new DatabaseException(msg, ex);
        }

        CpeEcosystemCache.setCache(map);
    }

    private void saveCpeEcosystemCache() {
        final Map<Pair<String, String>, String> map = CpeEcosystemCache.getChanged();
        if (map != null && !map.isEmpty()) {
            try (PreparedStatement ps = prepareStatement(MERGE_CPE_ECOSYSTEM)) {
                for (Map.Entry<Pair<String, String>, String> entry : map.entrySet()) {
                    ps.setString(1, entry.getKey().getLeft());
                    ps.setString(2, entry.getKey().getRight());
                    ps.setString(3, entry.getValue());
                    if (isBatchInsertEnabled()) {
                        ps.addBatch();
                    } else {
                        ps.execute();
                    }
                }
                if (isBatchInsertEnabled()) {
                    ps.executeBatch();
                }
            } catch (SQLException ex) {
                final String msg = String.format("Error saving the Cpe Ecosystem Cache: %s", ex.getMessage());
                LOGGER.debug(msg, ex);
                throw new DatabaseException(msg, ex);
            }
        }
    }

    /**
     * Used when updating a vulnerability - this method inserts the
     * vulnerability entry itself.
     *
     * @param cve the CVE data
     * @param description the description of the CVE entry
     * @return the vulnerability ID
     */
    private synchronized int updateOrInsertVulnerability(DefCveItem cve, String description) {
        if (CpeEcosystemCache.isEmpty()) {
            loadCpeEcosystemCache();
        }
        final int vulnerabilityId;
        try (PreparedStatement callUpdate = prepareStatement(UPDATE_VULNERABILITY)) {
            if (callUpdate == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + UPDATE_VULNERABILITY);
            }
            int parmOffset = 0;
            if (isOracle) {
                parmOffset = 1; // first parameter for Oracle is the return value (OUT parameter) of the stored procedure
            }
//            String 1.cve, String 2.description, String 3.v2Severity, Float 4.v2ExploitabilityScore,
//            Float 5.v2ImpactScore, Boolean 6.v2AcInsufInfo, Boolean 7.v2ObtainAllPrivilege,
//            Boolean 8.v2ObtainUserPrivilege, Boolean 9.v2ObtainOtherPrivilege, Boolean 10.v2UserInteractionRequired,
//            Float 11.v2Score, String 12.v2AccessVector, String 13.v2AccessComplexity,
//            String 14.v2Authentication, String 15.v2ConfidentialityImpact, String 16.v2IntegrityImpact,
//            String 17.v2AvailabilityImpact, String 18.v2Version, Float 19.v3ExploitabilityScore,
//            Float 20.v3ImpactScore, String 21.v3AttackVector, String 22.v3AttackComplexity,
//            String 23.v3PrivilegesRequired, String 24.v3UserInteraction, String 25.v3Scope,
//            String 26.v3ConfidentialityImpact, String 27.v3IntegrityImpact, String 28.v3AvailabilityImpact,
//            Float 29.v3BaseScore, String 30.v3BaseSeverity, String 31.v3Version
//            For Oracle due to the return-value parameter all offsets are 1 higher
            callUpdate.setString(1+parmOffset, cve.getCve().getCVEDataMeta().getId());
            callUpdate.setString(2+parmOffset, description);
            if (cve.getImpact().getBaseMetricV2() != null) {
                final BaseMetricV2 cvssv2 = cve.getImpact().getBaseMetricV2();
                Map<String, Object> props = cvssv2.getAdditionalProperties();
                callUpdate.setString(3+parmOffset, cvssv2.getSeverity());
                setFloatValue(callUpdate, 4+parmOffset, props, "exploitabilityScore");
                setFloatValue(callUpdate, 5+parmOffset, props, "impactScore");
                setBooleanValue(callUpdate, 6+parmOffset, props, "acInsufInfo");
                setBooleanValue(callUpdate, 7+parmOffset, props, "obtainAllPrivilege");
                setBooleanValue(callUpdate, 8+parmOffset, props, "obtainUserPrivilege");
                setBooleanValue(callUpdate, 9+parmOffset, props, "obtainOtherPrivilege");
                setBooleanValue(callUpdate, 10+parmOffset, props, "userInteractionRequired");
                callUpdate.setFloat(11+parmOffset, cvssv2.getCvssV2().getBaseScore().floatValue());
                callUpdate.setString(12+parmOffset, cvssv2.getCvssV2().getAccessVector().value());
                callUpdate.setString(13+parmOffset, cvssv2.getCvssV2().getAccessComplexity().value());
                callUpdate.setString(14+parmOffset, cvssv2.getCvssV2().getAuthentication().value());
                callUpdate.setString(15+parmOffset, cvssv2.getCvssV2().getConfidentialityImpact().value());
                callUpdate.setString(16+parmOffset, cvssv2.getCvssV2().getIntegrityImpact().value());
                callUpdate.setString(17+parmOffset, cvssv2.getCvssV2().getAvailabilityImpact().value());
                props = cvssv2.getCvssV2().getAdditionalProperties();
                setStringValue(callUpdate, 18+parmOffset, props, "version");
            } else {
                callUpdate.setNull(3+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(4+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(5+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(6+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(7+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(8+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(9+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(10+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(11+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(12+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(13+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(14+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(15+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(16+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(17+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(18+parmOffset, java.sql.Types.NULL);
            }
            if (cve.getImpact().getBaseMetricV3() != null) {
                final BaseMetricV3 cvssv3 = cve.getImpact().getBaseMetricV3();
                Map<String, Object> props = cvssv3.getAdditionalProperties();
                setFloatValue(callUpdate, 19+parmOffset, props, "exploitabilityScore");
                setFloatValue(callUpdate, 20+parmOffset, props, "impactScore");

                callUpdate.setString(21+parmOffset, cvssv3.getCvssV3().getAttackVector().value());
                callUpdate.setString(22+parmOffset, cvssv3.getCvssV3().getAttackComplexity().value());
                callUpdate.setString(23+parmOffset, cvssv3.getCvssV3().getPrivilegesRequired().value());
                callUpdate.setString(24+parmOffset, cvssv3.getCvssV3().getUserInteraction().value());
                callUpdate.setString(25+parmOffset, cvssv3.getCvssV3().getScope().value());
                callUpdate.setString(26+parmOffset, cvssv3.getCvssV3().getConfidentialityImpact().value());
                callUpdate.setString(27+parmOffset, cvssv3.getCvssV3().getIntegrityImpact().value());
                callUpdate.setString(28+parmOffset, cvssv3.getCvssV3().getAvailabilityImpact().value());
                callUpdate.setFloat(29+parmOffset, cvssv3.getCvssV3().getBaseScore().floatValue());
                callUpdate.setString(30+parmOffset, cvssv3.getCvssV3().getBaseSeverity().value());

                props = cvssv3.getCvssV3().getAdditionalProperties();
                setStringValue(callUpdate, 31+parmOffset, props, "version");
            } else {
                callUpdate.setNull(19+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(20+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(21+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(22+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(23+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(24+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(25+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(26+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(27+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(28+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(29+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(30+parmOffset, java.sql.Types.NULL);
                callUpdate.setNull(31+parmOffset, java.sql.Types.NULL);
            }
            if (isOracle) {
                try {
                    CallableStatement cs = (CallableStatement) callUpdate;
                    cs.registerOutParameter(1, JDBCType.INTEGER);
                    cs.executeUpdate();
                    vulnerabilityId = cs.getInt(1);
                } catch (SQLException ex) {
                    final String msg = String.format("Unable to retrieve id for new vulnerability for '%s'", cve.getCve().getCVEDataMeta().getId());
                    throw new DatabaseException(msg, ex);
                }
            } else {
                try (ResultSet rs = callUpdate.executeQuery()) {
                    rs.next();
                    vulnerabilityId = rs.getInt(1);
                } catch (SQLException ex) {
                    final String msg = String.format("Unable to retrieve id for new vulnerability for '%s'", cve.getCve().getCVEDataMeta().getId());
                    throw new DatabaseException(msg, ex);
                }
            }
        } catch (SQLException ex) {
            throw new UnexpectedAnalysisException(ex);
        }
        return vulnerabilityId;
    }

    /**
     * Used when updating a vulnerability - this method inserts the CWE entries.
     *
     * @param vulnerabilityId the vulnerability ID
     * @param cve the CVE entry that contains the CWE entries to insert
     * @throws SQLException thrown if there is an error inserting the data
     */
    private synchronized void updateVulnerabilityInsertCwe(int vulnerabilityId, DefCveItem cve) throws SQLException {
        try (PreparedStatement insertCWE = prepareStatement(INSERT_CWE)) {
            if (insertCWE == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + INSERT_CWE);
            }
            insertCWE.setInt(1, vulnerabilityId);

            for (ProblemtypeDatum datum : cve.getCve().getProblemtype().getProblemtypeData()) {
                for (LangString desc : datum.getDescription()) {
                    if ("en".equals(desc.getLang())) {
                        insertCWE.setString(2, desc.getValue());
                        if (isBatchInsertEnabled()) {
                            insertCWE.addBatch();
                        } else {
                            insertCWE.execute();
                        }
                    }
                }
            }
            if (isBatchInsertEnabled()) {
                insertCWE.executeBatch();
            }
        }
    }

    /**
     * Used when updating a vulnerability - in some cases a CVE needs to be
     * removed.
     *
     * @param cve the vulnerability CVE
     * @throws SQLException thrown if there is an error deleting the
     * vulnerability
     */
    private synchronized void deleteVulnerability(String cve) throws SQLException {
        try (PreparedStatement deleteVulnerability = prepareStatement(DELETE_VULNERABILITY)) {
            deleteVulnerability.setString(1, cve);
            deleteVulnerability.executeUpdate();
        }
    }

    /**
     * Used when updating a vulnerability - this method inserts the list of
     * vulnerable software.
     *
     * @param vulnerabilityId the vulnerability id
     * @param cveId the CVE ID - used for reporting
     * @param software the list of vulnerable software
     * @param baseEcosystem the ecosystem based off of the vulnerability
     * description
     * @throws DatabaseException thrown if there is an error inserting the data
     * @throws SQLException thrown if there is an error inserting the data
     */
    private synchronized void updateVulnerabilityInsertSoftware(int vulnerabilityId, String cveId,
            List<VulnerableSoftware> software, String baseEcosystem)
            throws DatabaseException, SQLException {
        try (PreparedStatement insertSoftware = prepareStatement(INSERT_SOFTWARE)) {
            if (insertSoftware == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + INSERT_SOFTWARE);
            }
            for (VulnerableSoftware parsedCpe : software) {
                insertSoftware.setInt(1, vulnerabilityId);
                insertSoftware.setString(2, parsedCpe.getPart().getAbbreviation());
                insertSoftware.setString(3, parsedCpe.getVendor());
                insertSoftware.setString(4, parsedCpe.getProduct());
                insertSoftware.setString(5, parsedCpe.getVersion());
                insertSoftware.setString(6, parsedCpe.getUpdate());
                insertSoftware.setString(7, parsedCpe.getEdition());
                insertSoftware.setString(8, parsedCpe.getLanguage());
                insertSoftware.setString(9, parsedCpe.getSwEdition());
                insertSoftware.setString(10, parsedCpe.getTargetSw());
                insertSoftware.setString(11, parsedCpe.getTargetHw());
                insertSoftware.setString(12, parsedCpe.getOther());
                final String ecosystem = CpeEcosystemCache.getEcosystem(parsedCpe.getVendor(), parsedCpe.getProduct(),
                        cveItemConverter.extractEcosystem(baseEcosystem, parsedCpe));

                addNullableStringParameter(insertSoftware, 13, ecosystem);
                addNullableStringParameter(insertSoftware, 14, parsedCpe.getVersionEndExcluding());
                addNullableStringParameter(insertSoftware, 15, parsedCpe.getVersionEndIncluding());
                addNullableStringParameter(insertSoftware, 16, parsedCpe.getVersionStartExcluding());
                addNullableStringParameter(insertSoftware, 17, parsedCpe.getVersionStartIncluding());
                insertSoftware.setBoolean(18, parsedCpe.isVulnerable());

                if (isBatchInsertEnabled()) {
                    insertSoftware.addBatch();
                } else {
                    try {
                        insertSoftware.execute();
                    } catch (SQLException ex) {
                        if (ex.getMessage().contains("Duplicate entry")) {
                            final String msg = String.format("Duplicate software key identified in '%s'", cveId);
                            LOGGER.info(msg, ex);
                        } else {
                            throw ex;
                        }
                    }
                }
            }
            if (isBatchInsertEnabled()) {
                executeBatch(cveId, insertSoftware);
            }
        }
    }

    /**
     * Used when updating a vulnerability - this method inserts the list of
     * references.
     *
     * @param vulnerabilityId the vulnerability id
     * @param cve the CVE entry that contains the list of references
     * @throws SQLException thrown if there is an error inserting the data
     */
    private synchronized void updateVulnerabilityInsertReferences(int vulnerabilityId, DefCveItem cve) throws SQLException {
        try (PreparedStatement insertReference = prepareStatement(INSERT_REFERENCE)) {
            if (insertReference == null) {
                throw new SQLException("Database query does not exist in the resource bundle: " + INSERT_REFERENCE);
            }
            for (Reference r : cve.getCve().getReferences().getReferenceData()) {
                insertReference.setInt(1, vulnerabilityId);
                insertReference.setString(2, r.getName());
                insertReference.setString(3, r.getUrl());
                insertReference.setString(4, r.getRefsource());
                if (isBatchInsertEnabled()) {
                    insertReference.addBatch();
                } else {
                    insertReference.execute();
                }
            }
            if (isBatchInsertEnabled()) {
                insertReference.executeBatch();
            }
        }
    }

    /**
     * Parses the configuration entries from the CVE entry into a list of
     * VulnerableSoftware objects.
     *
     * @param cve the CVE to parse the vulnerable software entries from
     * @return the list of vulnerable software
     * @throws CpeValidationException if an invalid CPE is present
     */
    private List<VulnerableSoftware> parseCpes(DefCveItem cve) throws CpeValidationException {
        final List<VulnerableSoftware> software = new ArrayList<>();
        final List<DefCpeMatch> cpeEntries = cve.getConfigurations().getNodes().stream()
                .collect(NodeFlatteningCollector.getInstance())
                .collect(CpeMatchStreamCollector.getInstance())
                .filter(predicate -> predicate.getCpe23Uri().startsWith(cpeStartsWithFilter))
                //this single CPE entry causes nearly 100% FP - so filtering it at the source.
                .filter(entry -> !("CVE-2009-0754".equals(cve.getCve().getCVEDataMeta().getId())
                && "cpe:2.3:a:apache:apache:*:*:*:*:*:*:*:*".equals(entry.getCpe23Uri())))
                .collect(Collectors.toList());
        final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();

        try {
            cpeEntries.forEach(entry -> {
                builder.cpe(parseCpe(entry, cve.getCve().getCVEDataMeta().getId()))
                        .versionEndExcluding(entry.getVersionEndExcluding())
                        .versionStartExcluding(entry.getVersionStartExcluding())
                        .versionEndIncluding(entry.getVersionEndIncluding())
                        .versionStartIncluding(entry.getVersionStartIncluding())
                        .vulnerable(entry.getVulnerable());
                try {
                    software.add(builder.build());
                } catch (CpeValidationException ex) {
                    throw new LambdaExceptionWrapper(ex);
                }
            });
        } catch (LambdaExceptionWrapper ex) {
            throw (CpeValidationException) ex.getCause();
        }
        return software;
    }

    /**
     * Helper method to convert a CpeMatch (generated code used in parsing the
     * NVD JSON) into a CPE object.
     *
     * @param cpe the CPE Match
     * @param cveId the CVE associated with the CPEMatch - used for error
     * reporting
     * @return the resulting CPE object
     * @throws DatabaseException thrown if there is an error converting the
     * CpeMatch into a CPE object
     */
    private Cpe parseCpe(DefCpeMatch cpe, String cveId) throws DatabaseException {
        Cpe parsedCpe;
        try {
            //the replace is a hack as the NVD does not properly escape backslashes in their JSON
            parsedCpe = CpeParser.parse(cpe.getCpe23Uri(), true);
        } catch (CpeParsingException ex) {
            LOGGER.debug("NVD (" + cveId + ") contain an invalid 2.3 CPE: " + cpe.getCpe23Uri());
            if (cpe.getCpe22Uri() != null && !cpe.getCpe22Uri().isEmpty()) {
                try {
                    parsedCpe = CpeParser.parse(cpe.getCpe22Uri(), true);
                } catch (CpeParsingException ex2) {
                    throw new DatabaseException("Unable to parse CPE: " + cpe.getCpe23Uri(), ex);
                }
            } else {
                throw new DatabaseException("Unable to parse CPE: " + cpe.getCpe23Uri(), ex);
            }
        }
        return parsedCpe;
    }

    /**
     * Returns the size of the batch.
     *
     * @return the size of the batch
     */
    private int getBatchSize() {
        int max;
        try {
            max = settings.getInt(Settings.KEYS.MAX_BATCH_SIZE);
        } catch (InvalidSettingException pE) {
            max = 1000;
        }
        return max;
    }

    /**
     * Determines whether or not batch insert is enabled.
     *
     * @return <code>true</code> if batch insert is enabled; otherwise
     * <code>false</code>
     */
    private boolean isBatchInsertEnabled() {
        boolean batch;
        try {
            batch = settings.getBoolean(Settings.KEYS.ENABLE_BATCH_UPDATES);
        } catch (InvalidSettingException pE) {
            //If there's no configuration, default is to not perform batch inserts
            batch = false;
        }
        return batch;
    }

    /**
     * Executes batch inserts of vulnerabilities when property
     * database.batchinsert.maxsize is reached.
     *
     * @param vulnId the vulnerability ID
     * @param statement the prepared statement to batch execute
     * @throws SQLException thrown when the batch cannot be executed
     */
    private void executeBatch(String vulnId, PreparedStatement statement)
            throws SQLException {
        try {
            statement.executeBatch();
        } catch (SQLException ex) {
            if (ex.getMessage().contains("Duplicate entry")) {
                final String msg = String.format("Duplicate software key identified in '%s'",
                        vulnId);
                LOGGER.info(msg, ex);
            } else {
                throw ex;
            }
        }
    }

    /**
     * Checks to see if data exists so that analysis can be performed.
     *
     * @return <code>true</code> if data exists; otherwise <code>false</code>
     */
    public synchronized boolean dataExists() {
        ResultSet rs = null;
        try {
            final PreparedStatement cs = getPreparedStatement(COUNT_CPE);
            if (cs == null) {
                LOGGER.error("Unable to validate if data exists in the database");
                return false;
            }
            rs = cs.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) {
                return true;
            }
        } catch (Exception ex) {
            String dd;
            try {
                dd = settings.getDataDirectory().getAbsolutePath();
            } catch (IOException ex1) {
                dd = settings.getString(Settings.KEYS.DATA_DIRECTORY);
            }
            LOGGER.error("Unable to access the local database.\n\nEnsure that '{}' is a writable directory. "
                    + "If the problem persist try deleting the files in '{}' and running {} again. If the problem continues, please "
                    + "create a log file (see documentation at http://jeremylong.github.io/DependencyCheck/) and open a ticket at "
                    + "https://github.com/jeremylong/DependencyCheck/issues and include the log file.\n\n",
                    dd, dd, settings.getString(Settings.KEYS.APPLICATION_NAME));
            LOGGER.debug("", ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return false;
    }

    /**
     * It is possible that orphaned rows may be generated during database
     * updates. This should be called after all updates have been completed to
     * ensure orphan entries are removed.
     */
    public synchronized void cleanupDatabase() {
        LOGGER.info("Begin database maintenance");
        final long start = System.currentTimeMillis();
        saveCpeEcosystemCache();
        clearCache();
        try (PreparedStatement psOrphans = getPreparedStatement(CLEANUP_ORPHANS);
                PreparedStatement psEcosystem = getPreparedStatement(UPDATE_ECOSYSTEM);
                PreparedStatement psEcosystem2 = getPreparedStatement(UPDATE_ECOSYSTEM2)) {
            if (psEcosystem != null) {
                final int count = psEcosystem.executeUpdate();
                if (count > 0) {
                    LOGGER.info("Updated the CPE ecosystem on {} NVD records", count);
                }
            }
            if (psEcosystem2 != null) {
                final int count = psEcosystem2.executeUpdate();
                if (count > 0) {
                    LOGGER.info("Removed the CPE ecosystem on {} NVD records", count);
                }
            }
            if (psOrphans != null) {
                final int count = psOrphans.executeUpdate();
                if (count > 0) {
                    LOGGER.info("Cleaned up {} orphaned NVD records", count);
                }
            }
            final long millis = System.currentTimeMillis() - start;
            //final long seconds = TimeUnit.MILLISECONDS.toSeconds(millis);
            LOGGER.info("End database maintenance ({} ms)", millis);
        } catch (SQLException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
            throw new DatabaseException("Unexpected SQL Exception", ex);
        }
    }

    /**
     * If the database is using an H2 file based database calling
     * <code>defrag()</code> will de-fragment the database.
     */
    public synchronized void defrag() {
        if (ConnectionFactory.isH2Connection(settings)) {
            final long start = System.currentTimeMillis();
            try (CallableStatement psCompaxt = connection.prepareCall("SHUTDOWN DEFRAG")) {
                if (psCompaxt != null) {
                    LOGGER.info("Begin database defrag");
                    psCompaxt.execute();
                    final long millis = System.currentTimeMillis() - start;
                    //final long seconds = TimeUnit.MILLISECONDS.toSeconds(millis);
                    LOGGER.info("End database defrag ({} ms)", millis);
                }
            } catch (SQLException ex) {
                LOGGER.error("An unexpected SQL Exception occurred compacting the database; please see the verbose log for more details.");
                LOGGER.debug("", ex);
            }
        }
    }

    /**
     * Determines if the given identifiedVersion is affected by the given cpeId
     * and previous version flag. A non-null, non-empty string passed to the
     * previous version argument indicates that all previous versions are
     * affected.
     *
     * @param cpe the CPE for the given dependency
     * @param vulnerableSoftware a set of the vulnerable software
     * @return true if the identified version is affected, otherwise false
     */
    protected VulnerableSoftware getMatchingSoftware(Cpe cpe, Set<VulnerableSoftware> vulnerableSoftware) {
        VulnerableSoftware matched = null;
        for (VulnerableSoftware vs : vulnerableSoftware) {
            if (vs.matches(cpe)) {
                if (matched == null) {
                    matched = vs;
                } else {
                    if ("*".equals(vs.getWellFormedUpdate()) && !"*".equals(matched.getWellFormedUpdate())) {
                        matched = vs;
                    }
                }
            }
        }
        return matched;
//        final boolean isVersionTwoADifferentProduct = "apache".equals(cpe.getVendor()) && "struts".equals(cpe.getProduct());
//        final Set<String> majorVersionsAffectingAllPrevious = new HashSet<>();
//        final boolean matchesAnyPrevious = identifiedVersion == null || "-".equals(identifiedVersion.toString());
//        String majorVersionMatch = null;
//        for (Entry<String, Boolean> entry : vulnerableSoftware.entrySet()) {
//            final DependencyVersion v = parseDependencyVersion(entry.getKey());
//            if (v == null || "-".equals(v.toString())) { //all versions
//                return entry;
//            }
//            if (entry.getValue()) {
//                if (matchesAnyPrevious) {
//                    return entry;
//                }
//                if (identifiedVersion != null && identifiedVersion.getVersionParts().get(0).equals(v.getVersionParts().get(0))) {
//                    majorVersionMatch = v.getVersionParts().get(0);
//                }
//                majorVersionsAffectingAllPrevious.add(v.getVersionParts().get(0));
//            }
//        }
//        if (matchesAnyPrevious) {
//            return null;
//        }
//
//        final boolean canSkipVersions = majorVersionMatch != null && majorVersionsAffectingAllPrevious.size() > 1;
//        //yes, we are iterating over this twice. The first time we are skipping versions those that affect all versions
//        //then later we process those that affect all versions. This could be done with sorting...
//        for (Entry<String, Boolean> entry : vulnerableSoftware.entrySet()) {
//            if (!entry.getValue()) {
//                final DependencyVersion v = parseDependencyVersion(entry.getKey());
//                //this can't dereference a null 'majorVersionMatch' as canSkipVersions accounts for this.
//                if (canSkipVersions && majorVersionMatch != null && !majorVersionMatch.equals(v.getVersionParts().get(0))) {
//                    continue;
//                }
//                //this can't dereference a null 'identifiedVersion' because if it was null we would have exited
//                //in the above loop or just after loop (if matchesAnyPrevious return null).
//                if (identifiedVersion != null && identifiedVersion.equals(v)) {
//                    return entry;
//                }
//            }
//        }
//        for (Entry<String, Boolean> entry : vulnerableSoftware.entrySet()) {
//            if (entry.getValue()) {
//                final DependencyVersion v = parseDependencyVersion(entry.getKey());
//                //this can't dereference a null 'majorVersionMatch' as canSkipVersions accounts for this.
//                if (canSkipVersions && majorVersionMatch != null && !majorVersionMatch.equals(v.getVersionParts().get(0))) {
//                    continue;
//                }
//                //this can't dereference a null 'identifiedVersion' because if it was null we would have exited
//                //in the above loop or just after loop (if matchesAnyPrevious return null).
//                if (entry.getValue() && identifiedVersion != null && identifiedVersion.compareTo(v) <= 0
//                        && !(isVersionTwoADifferentProduct && !identifiedVersion.getVersionParts().get(0).equals(v.getVersionParts().get(0)))) {
//                    return entry;
//                }
//            }
//        }
//        return null;
    }

    /**
     * This method is only referenced in unused code.
     * <p>
     * Deletes unused dictionary entries from the database.
     * </p>
     */
    public synchronized void deleteUnusedCpe() {
        clearCache();
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(statementBundle.getString("DELETE_UNUSED_DICT_CPE"));
            ps.executeUpdate();
        } catch (SQLException ex) {
            LOGGER.error("Unable to delete CPE dictionary entries", ex);
        } finally {
            DBUtils.closeStatement(ps);
        }
    }

    /**
     * This method is only referenced in unused code and will likely break on
     * MySQL if ever used due to the MERGE statement.
     * <p>
     * Merges CPE entries into the database.
     * </p>
     *
     * @param cpe the CPE identifier
     * @param vendor the CPE vendor
     * @param product the CPE product
     */
    public synchronized void addCpe(String cpe, String vendor, String product) {
        clearCache();
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(statementBundle.getString("ADD_DICT_CPE"));
            ps.setString(1, cpe);
            ps.setString(2, vendor);
            ps.setString(3, product);
            ps.executeUpdate();
        } catch (SQLException ex) {
            LOGGER.error("Unable to add CPE dictionary entry", ex);
        } finally {
            DBUtils.closeStatement(ps);
        }
    }

    /**
     * Helper method to add a nullable string parameter.
     *
     * @param ps the prepared statement
     * @param pos the position of the parameter
     * @param value the value of the parameter
     * @throws SQLException thrown if there is an error setting the parameter.
     */
    private void addNullableStringParameter(PreparedStatement ps, int pos, String value) throws SQLException {
        if (value == null || value.isEmpty()) {
            ps.setNull(pos, java.sql.Types.VARCHAR);
        } else {
            ps.setString(pos, value);
        }
    }

    /**
     * Sets the float parameter on a prepared statement from a properties map.
     *
     * @param ps a prepared statement
     * @param i the index of the property
     * @param props the property collection
     * @param key the property key
     * @throws SQLException thrown if there is an error adding the property
     */
    private void setFloatValue(PreparedStatement ps, int i, Map<String, Object> props, String key) throws SQLException {
        if (props != null && props.containsKey(key)) {
            try {
                ps.setFloat(i, Float.parseFloat(props.get(key).toString()));
            } catch (NumberFormatException nfe) {
                ps.setNull(i, java.sql.Types.NULL);
            }
        } else {
            ps.setNull(i, java.sql.Types.NULL);
        }
    }

    /**
     * Sets the string parameter on a prepared statement from a properties map.
     *
     * @param ps a prepared statement
     * @param i the index of the property
     * @param props the property collection
     * @param key the property key
     * @throws SQLException thrown if there is an error adding the property
     */
    private void setStringValue(PreparedStatement ps, int i, Map<String, Object> props, String key) throws SQLException {
        if (props != null && props.containsKey(key)) {
            ps.setString(i, props.get(key).toString());
        } else {
            ps.setNull(i, java.sql.Types.NULL);
        }
    }

    /**
     * Sets the boolean parameter on a prepared statement from a properties map.
     *
     * @param ps a prepared statement
     * @param i the index of the property
     * @param props the property collection
     * @param key the property key
     * @throws SQLException thrown if there is an error adding the property
     */
    private void setBooleanValue(PreparedStatement ps, int i, Map<String, Object> props, String key) throws SQLException {
        if (props != null && props.containsKey(key)) {
            ps.setBoolean(i, Boolean.valueOf(props.get(key).toString()));
        } else {
            ps.setNull(i, java.sql.Types.NULL);
        }
    }

    /**
     * Returns the Boolean value for the given index; if the value is null then
     * null is returned.
     *
     * @param rs the record set
     * @param index the parameter index
     * @return the Boolean value; or null
     * @throws SQLException thrown if there is an error obtaining the value
     */
    private Boolean getBooleanValue(ResultSet rs, int index) throws SQLException {
        if (rs.getObject(index) == null) {
            return null;
        }
        return rs.getBoolean(index);
    }

    /**
     * Returns the Float value for the given index; if the value is null then
     * null is returned.
     *
     * @param rs the record set
     * @param index the parameter index
     * @return the Float value; or null
     * @throws SQLException thrown if there is an error obtaining the value
     */
    private Float getFloatValue(ResultSet rs, int index) throws SQLException {
        if (rs.getObject(index) == null) {
            return null;
        }
        return rs.getFloat(index);
    }
}
