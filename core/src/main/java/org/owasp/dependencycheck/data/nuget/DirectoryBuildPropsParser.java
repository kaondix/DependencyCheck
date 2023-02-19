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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Parses `Directory.Build.props`.
 *
 * @see <a href="https://learn.microsoft.com/en-us/visualstudio/msbuild/customize-your-build?view=vs-2019#directorybuildprops-and-directorybuildtargets">Directory.Build.props</a>
 * @author Jeremy Long
 */
public class DirectoryBuildPropsParser {

    public Map<String, String> parse(InputStream stream) {
        try {
            HashMap<String, String> props = new HashMap<>();

            final DocumentBuilder db = XmlUtils.buildSecureDocumentBuilder();
            final Document d = db.parse(stream);

            final XPath xpath = XPathFactory.newInstance().newXPath();
            final NodeList propertyGroups = (NodeList) xpath.evaluate("//PropertyGroup", d, XPathConstants.NODESET);
            if (propertyGroups != null) {
                for (int i = 0; i < propertyGroups.getLength(); i++) {
                    final Node group = propertyGroups.item(i);
                    final NodeList propertyNodes = group.getChildNodes();
                    for (int x = 0; x < propertyNodes.getLength(); x++) {
                        final Node node = propertyNodes.item(x);
                        if (node instanceof Element) {
                            Element property = (Element) node;
                            final String name = property.getNodeName();
                            final Node value = property.getChildNodes().item(0);
                            if (value != null) {
                                props.put(name, value.getNodeValue().trim());
                            }
                        }
                    }
                }
            }
            return props;
        } catch (ParserConfigurationException | SAXException | IOException | XPathExpressionException ex) {
            throw new RuntimeException(ex);
        }
    }
}
