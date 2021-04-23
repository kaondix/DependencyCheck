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
package org.owasp.dependencycheck.data.nvd.json;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;

/**
 * Test for {@linkplain CpeMatchValidityFilter}.
 * @author Stephan Fuhrmann
 */
public class CpeMatchValidityFilterTest {

    @Test
    public void testGetInstance() {
        assertNotNull(CpeMatchValidityFilter.getInstance());
    }

    @Test
    public void testApplyWithNullReference() {
        assertFalse(CpeMatchValidityFilter.getInstance().test(null));
    }

    @Test
    public void testApplyWithEmptyInstance() {
        DefCpeMatch defCpeMatch = new DefCpeMatch();
        assertFalse(CpeMatchValidityFilter.getInstance().test(defCpeMatch));
    }

    @Test
    public void testApplyWithValidInstance() {
        DefCpeMatch defCpeMatch = new DefCpeMatch();
        defCpeMatch.setCpe23Uri("cpe:2.3:a:owasp:dependency-check:5.0.0:*:*:*:*:*:*:*");
        assertFalse(CpeMatchValidityFilter.getInstance().test(defCpeMatch));
    }
}
