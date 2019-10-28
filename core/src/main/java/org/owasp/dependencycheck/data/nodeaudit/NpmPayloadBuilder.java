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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.stream.Collectors;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Class used to create the payload to submit to the NPM Audit API service.
 *
 * @author Steve Springett
 * @author Jeremy Long
 */
@ThreadSafe
public final class NpmPayloadBuilder {

    /**
     * Private constructor for utility class.
     */
    private NpmPayloadBuilder() {
        //empty
    }

    public static JsonObject build(JsonObject lockJson, JsonObject packageJson, Map<String, String> dependencyMap) {
        final JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        addProjectInfo(packageJson, payloadBuilder);

        // NPM Audit expects 'requires' to be an object containing key/value 
        // pairs corresponding to the module name (key) and version (value).
        final JsonObjectBuilder requiresBuilder = Json.createObjectBuilder();
        packageJson.getJsonObject("dependencies").entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (oldValue, newValue) -> newValue, TreeMap::new))
                .entrySet()
                .forEach((entry) -> {
                    requiresBuilder.add(entry.getKey(), entry.getValue());
                    dependencyMap.put(entry.getKey(), entry.getValue().toString());
                });

        packageJson.getJsonObject("devDependencies").entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (oldValue, newValue) -> newValue, TreeMap::new))
                .entrySet()
                .forEach((entry) -> {
                    requiresBuilder.add(entry.getKey(), entry.getValue());
                    dependencyMap.put(entry.getKey(), entry.getValue().toString());
                });

        payloadBuilder.add("requires", requiresBuilder.build());

        final JsonObjectBuilder dependenciesBuilder = Json.createObjectBuilder();
        final JsonObject dependencies = lockJson.getJsonObject("dependencies");
        dependencies.entrySet().forEach((entry) -> {
            final JsonObject dep = ((JsonObject) entry.getValue());
            final String version = dep.getString("version");
            dependencyMap.put(entry.getKey(), version);
            dependenciesBuilder.add(entry.getKey(), buildDependencies(dep, dependencyMap));
        });
        payloadBuilder.add("dependencies", dependenciesBuilder.build());

        addConstantElements(payloadBuilder);
        return payloadBuilder.build();
    }

    /**
     * Attempts to build the request data for NPM Audit API call. This may
     * produce a payload that will fail.
     *
     * @param packageJson a raw package-lock.json file
     * @return the JSON payload for NPN Audit
     */
    public static JsonObject build(JsonObject packageJson, Map<String, String> dependencyMap) {
        final JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        addProjectInfo(packageJson, payloadBuilder);

        // NPM Audit expects 'requires' to be an object containing key/value 
        // pairs corresponding to the module name (key) and version (value).
        final JsonObjectBuilder requiresBuilder = Json.createObjectBuilder();
        final JsonObjectBuilder dependenciesBuilder = Json.createObjectBuilder();

        final JsonObject dependencies = packageJson.getJsonObject("dependencies");
        dependencies.entrySet().forEach((entry) -> {
            final String version;
            if (entry.getValue().getValueType() == JsonValue.ValueType.OBJECT) {
                final JsonObject dep = ((JsonObject) entry.getValue());
                version = dep.getString("version");
                dependencyMap.put(entry.getKey(), version);
                dependenciesBuilder.add(entry.getKey(), buildDependencies(dep, dependencyMap));
            } else {
                //TODO I think the following is dead code and no real "dependencies" 
                //     section in a lock file will look like this
                final String tmp = entry.getValue().toString();
                if (tmp.startsWith("\"")) {
                    version = tmp.substring(1, tmp.length() - 1);
                } else {
                    version = tmp;
                }
            }
            requiresBuilder.add(entry.getKey(), "^" + version);
        });
        payloadBuilder.add("requires", requiresBuilder.build());

        payloadBuilder.add("dependencies", dependenciesBuilder.build());

        addConstantElements(payloadBuilder);
        return payloadBuilder.build();
    }

    private static void addProjectInfo(JsonObject packageJson, final JsonObjectBuilder payloadBuilder) {
        final String projectName = packageJson.getString("name", "");
        final String projectVersion = packageJson.getString("version", "");
        if (!projectName.isEmpty()) {
            payloadBuilder.add("name", projectName);
        }
        if (!projectVersion.isEmpty()) {
            payloadBuilder.add("version", projectVersion);
        }
    }

    private static void addConstantElements(final JsonObjectBuilder payloadBuilder) {
        payloadBuilder.add("install", Json.createArrayBuilder().build());
        payloadBuilder.add("remove", Json.createArrayBuilder().build());
        payloadBuilder.add("metadata", Json.createObjectBuilder()
                .add("npm_version", "6.9.0")
                .add("node_version", "v10.5.0")
                .add("platform", "linux")
        );
    }

    private static JsonObject buildDependencies(JsonObject dep, Map<String, String> dependencyMap) {
        final JsonObjectBuilder depBuilder = Json.createObjectBuilder();
        depBuilder.add("version", dep.getString("version"));
        depBuilder.add("integrity", dep.getString("integrity"));
        if (dep.containsKey("requires")) {
            depBuilder.add("requires", dep.getJsonObject("requires"));
        }
        if (dep.containsKey("dependencies")) {
            final JsonObjectBuilder dependeciesBuilder = Json.createObjectBuilder();
            dep.getJsonObject("dependencies").entrySet().forEach((entry) -> {
                final String v = ((JsonObject) entry.getValue()).getString("version");
                dependencyMap.put(entry.getKey(), v);
                dependeciesBuilder.add(entry.getKey(), buildDependencies((JsonObject) entry.getValue(), dependencyMap));
            });
            depBuilder.add("dependencies", dependeciesBuilder.build());
        }
        return depBuilder.build();
    }
}
