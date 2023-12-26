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
 * Copyright (c) 2018 Nicolas Henneaux. All Rights Reserved.
 */

import org.apache.commons.lang.StringUtils

import java.nio.charset.StandardCharsets
import java.nio.file.Files

String log = new String(Files.readAllBytes(new File(basedir, "build.log").toPath()), StandardCharsets.UTF_8);
int count = StringUtils.countMatches(log, "There was an issue connecting to Artifactory . Disabling analyzer.");
if (count > 0) {
    System.out.println(String.format("There was an issue connecting to Artifactory . Disabling analyzer."));
    return false;
}
