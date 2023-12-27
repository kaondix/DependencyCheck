/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2023 Hans Aikema. All Rights Reserved.
 */

import org.w3c.dom.NodeList

import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.xpath.XPathConstants
import javax.xml.xpath.XPathFactory
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

def countMatches(String xml, String xpathQuery) {
    def xpath = XPathFactory.newInstance().newXPath()
    def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    def inputStream = new ByteArrayInputStream(xml.bytes)
    def records = builder.parse(inputStream).documentElement
    NodeList nodes = xpath.evaluate(xpathQuery, records, XPathConstants.NODESET) as NodeList
    nodes.getLength();
}

Path path = new File(basedir, "main/target/dependency-check-report.xml").toPath()
String log = new String(Files.readAllByte(path), StandardCharsets.UTF_8);
int count = countMatches(log, "/analysis/dependencies/dependency/evidenceCollected/evidence[@type='product' and ./value = 'commons-compress' and ./name = 'artifactid']");
if (count != 1) {
    System.out.println(String.format("commons-compress was identified %s times, expected 1", count));
    return false;
}
count = countMatches(log, "/analysis/dependencies/dependency/evidenceCollected/evidence[@type='product' and ./value = 'commons-pool2' and ./name = 'artifactid']");
if (count != 1) {
    System.out.println(String.format("commons-pool2  was identified %s times, expected 1", count));
    return false;
}
return true;
