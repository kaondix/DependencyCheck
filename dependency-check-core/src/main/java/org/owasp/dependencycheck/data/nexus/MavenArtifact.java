package org.owasp.dependencycheck.data.nexus;

/**
 * Simple bean representing a Maven Artifact.
 *
 * @author colezlaw
 */
public class MavenArtifact {
    /**
     * The groupId
     */
    private String groupId;

    /**
     * The artifactId
     */
    private String artifactId;

    /**
     * The version
     */
    private String version;

    /**
     * The artifact url. This may change depending on which Nexus
     * server the search took place.
     */
    private String artifactUrl;


    /**
     * Creates an empty MavenArtifact.
     */
    public MavenArtifact() {
    }

    /**
     * Creates a MavenArtifact with the given attributes.
     *
     * @param groupId the groupId
     * @param artifactId the artifactId
     * @param version the version
     */
    public MavenArtifact(String groupId, String artifactId, String version) {
        setGroupId(groupId);
        setArtifactId(artifactId);
        setVersion(version);
    }

    /**
     * Creates a MavenArtifact with the given attributes.
     *
     * @param groupId the groupId
     * @param artifactId the artifactId
     * @param version the version
     */
    public MavenArtifact(String groupId, String artifactId, String version, String url) {
        setGroupId(groupId);
        setArtifactId(artifactId);
        setVersion(version);
        setArtifactUrl(url);
    }

    /**
     * Returns the Artifact coordinates as a String
     *
     * @return the String representation of the artifact coordinates
     */
    @Override
    public String toString() {
        return String.format("%s:%s:%s", groupId, artifactId, version);
    }

    /**
     * Sets the groupId
     *
     * @param groupId the groupId
     */
    public void setGroupId(String groupId) { this.groupId = groupId; }

    /**
     * Gets the groupId.
     *
     * @return the groupId
     */
    public String getGroupId() { return groupId; }

    /**
     * Sets the artifactId.
     *
     * @param artifactId the artifactId
     */
    public void setArtifactId(String artifactId) { this.artifactId = artifactId; }

    /**
     * Gets the artifactId.
     *
     * @return the artifactId
     */
    public String getArtifactId() { return artifactId; }

    /**
     * Sets the version.
     *
     * @param version the version
     */
    public void setVersion(String version) { this.version = version; }

    /**
     * Gets the version.
     *
     * @return the version
     */
    public String getVersion() { return version; }

    /**
     * Sets the artifactUrl.
     *
     * @param artifactUrl the artifactUrl
     */
    public void setArtifactUrl(String artifactUrl) {
        this.artifactUrl = artifactUrl;
    }

    /**
     * Gets the artifactUrl.
     *
     * @return the artifactUrl
     */
    public String getArtifactUrl() {
        return artifactUrl;
    }
}

// vim: cc=120:sw=4:ts=4:sts=4
