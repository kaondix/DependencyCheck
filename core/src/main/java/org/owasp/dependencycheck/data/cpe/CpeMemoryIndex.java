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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import javax.annotation.concurrent.ThreadSafe;

/**
 * <p>
 * An in memory Lucene index that contains the vendor/product combinations from
 * the CPE (application) identifiers within the NVD CVE data.</p>
 *
 * This is the last remaining singleton in dependency-check-core; The use of
 * this singleton - while it may not technically be thread-safe (one database
 * used to build this index may not have the same entries as another) the risk
 * of this is currently believed to be small. As this memory index consumes a
 * large amount of memory we will remain using the singleton pattern for now.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class CpeMemoryIndex extends AbstractMemoryIndex {

    /**
     * Singleton instance.
     */
    private static final CpeMemoryIndex INSTANCE = new CpeMemoryIndex();

    /**
     * private constructor for singleton.
     */
    private CpeMemoryIndex() {
    }

    /**
     * Gets the singleton instance of the CpeMemoryIndex.
     *
     * @return the instance of the CpeMemoryIndex
     */
    public static CpeMemoryIndex getInstance() {
        return INSTANCE;
    }

    /**
     * Gets the singleton instance of the CpeMemoryIndex.
     *
     * @return the instance of the CpeMemoryIndex
     */
    @Override
    protected AbstractMemoryIndex instance() {
        return (AbstractMemoryIndex) INSTANCE;
    }
}
