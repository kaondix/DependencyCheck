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
package org.owasp.dependencycheck.utils;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.*;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.*;

/**
 * Unit tests for {@link AsciiFileScanner}.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class AsciiFileScannerTest extends BaseTest {

    public static final String FIND = "EID:50CA347E-88EF4066:vendor=Institute for Defense Analyses;product=ID Embedding Tests;version=0.2;";

    @Test
    public void testDetectAndCompareString() throws IOException {
        int match_count = 0;
        final AsciiFileScanner scanner = new AsciiFileScanner(FIND);
        final File file = getResourceAsFile(this, "binutils/hello_id.o");
        final long offset = scanner.search(file);
        for (String string : scanner.getStrings(offset)) {
            if (FIND.equals(string)) {
                match_count++;
            }
        }
        assertThat(match_count, is(1));
    }

    @Test
    public void testGetPartialMatchTable() {
        int[] expected = {-1, 0, 0,0,0,0,0,0,1,2,0,0,0,0,0,0,1,2,3,0,0,0,0,0};
        String search = "participate in parachute";
        int[] searchArray = new int[search.length()];
        for (int i=0; i < search.length(); i++){
            searchArray[i] = search.charAt(i);
        }
        assertArrayEquals(expected, AsciiFileScanner.getPartialMatchTable(searchArray));
    }

    @Test
    public void testSearch() throws FileNotFoundException {
        final AsciiFileScanner scanner = new AsciiFileScanner(FIND);
        assertThat(scanner.search(getResourceAsFile(this, "binutils/hello_id.o")), greaterThan(-1L));
    }

    @Test
    public void testEasySearch() throws FileNotFoundException {
        final AsciiFileScanner scanner = new AsciiFileScanner("ABC");
        assertThat(scanner.search(getResourceAsFile(this, "binutils/search.txt")), is(2L));
    }

    @Test
    public void testSearchLongFile() throws FileNotFoundException {
        final AsciiFileScanner scanner = new AsciiFileScanner(FIND.substring(0, 21));
        assertThat(scanner.search(getResourceAsFile(this, "stagedhttp-modified.tar")), is(-1L));
    }

    @Test
    public void testDifficultSearch() throws FileNotFoundException {
        final AsciiFileScanner scanner = new AsciiFileScanner(FIND.substring(0, 21));
        assertThat(scanner.search(getResourceAsFile(this, "binutils/difficult_search.txt")), is(4080L));
    }
}
