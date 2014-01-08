package org.owasp.dependencycheck.data.nexus;

import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

/**
 * Class of methods to search Nexus repositories.
 *
 * @author colezlaw
 */
public class NexusSearch {
    private final URL rootURL;

    private static final Logger LOGGER = Logger.getLogger(NexusSearch.class.getName());

    public NexusSearch(URL rootURL) {
        this.rootURL = rootURL;
    }

    public MavenArtifact searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }

        URL url = new URL(rootURL, String.format("identify/sha1/%s", sha1.toLowerCase()));

        LOGGER.fine(String.format("Searching Nexus url %s", url.toString()));

        URLConnection conn = url.openConnection();
        conn.setDoOutput(true);

        // JSON would be more elegant, but there's not currently a dependency
        // on JSON, so don't want to add one just for this
        conn.addRequestProperty("Accept", "application/xml");
        conn.connect();

        try {
            DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = builder.parse(conn.getInputStream());
            XPath xpath = XPathFactory.newInstance().newXPath();
            String groupId = xpath.evaluate("/org.sonatype.nexus.rest.model.NexusArtifact/groupId", doc);
            String artifactId = xpath.evaluate("/org.sonatype.nexus.rest.model.NexusArtifact/artifactId", doc);
            String version = xpath.evaluate("/org.sonatype.nexus.rest.model.NexusArtifact/version", doc);
            String link = xpath.evaluate("/org.sonatype.nexus.rest.model.NexusArtifact/artifactLink", doc);
            return new MavenArtifact(groupId, artifactId, version, link);
        } catch (FileNotFoundException fnfe) {
            // This is what we get when the SHA1 they sent doesn't exist in Nexus. This
            // is useful upstream for recovery, so we just re-throw it
            throw fnfe;
        } catch (Exception e) {
            // Anything else is jacked-up XML stuff that we really can't recover from well
            throw new IOException(e.getMessage(), e);
        }
    }
}

// vim: cc=120:sw=4:ts=4:sts=4
