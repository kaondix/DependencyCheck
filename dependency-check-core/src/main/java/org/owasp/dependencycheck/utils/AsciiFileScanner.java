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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A set of utility methods for efficiently extracting strings from any readable file, as well as for efficiently
 * searching for a given ASCII string.
 */
public class AsciiFileScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(AsciiFileScanner.class);
    private final int[] search, partialMatchTable;
    private ReadBufferedRandomAccessFile lastFile;

    public AsciiFileScanner(String searchString) {
        this.search = convertToIntArray(searchString);
        this.partialMatchTable = getPartialMatchTable(this.search);
    }

    public void reset() throws IOException {
        if (null != lastFile) {
            lastFile.close();
            lastFile = null;
        }
    }

    /**
     * Convert ASCII-only string to integer array for efficient computation.
     *
     * @param string ASCII-only string
     * @return array of ints corresponding to the ASCII values in the given string, which can then be used in
     * {@link #getPartialMatchTable(int[])}.
     * @throws IllegalArgumentException if the string is not at least 2 characters long, or if any of the characters
     *                                  are not 7-bit ASCII characters
     */
    public static int[] convertToIntArray(String string) {
        final int length = string.length();
        if (length <= 1) {
            throw new IllegalArgumentException(String.format("Expect non-trivial string (length > 1): \"%s\"", string));
        }
        final int[] ints = new int[length];
        for (int i = 0; i < length; i++) {
            final int character = string.charAt(i);
            if (character < 0 || character > 0x7f) {
                throw new IllegalArgumentException("Expected ASCII only. Found non-ASCII at index " + i);
            }
            ints[i] = character;
        }
        return ints;
    }

    /**
     * Computes the partial match table for the given search "string".
     *
     * @param search the search string
     * @return a partial match table which can then be used in {@link #search(File)}
     * @throws IllegalArgumentException if the search string is not at least 2 characters long
     */
    protected static int[] getPartialMatchTable(int[] search) {
        if (search.length <= 1) {
            throw new IllegalArgumentException("Expect non-trivial string length (>1), got " + search.length + ".");
        }
        int currentPosition = 2;
        int nextCandidateIndex = 0;
        int[] partialMatchTable = new int[search.length];
        partialMatchTable[0] = -1;
        partialMatchTable[1] = 0;
        while (currentPosition < search.length) {
            if (search[currentPosition - 1] == search[nextCandidateIndex]) {
                nextCandidateIndex++;
                partialMatchTable[currentPosition] = nextCandidateIndex;
                currentPosition++;
            } else if (nextCandidateIndex > 0) {
                nextCandidateIndex = partialMatchTable[nextCandidateIndex];
            } else {
                partialMatchTable[currentPosition] = 0;
                currentPosition++;
            }
        }
        return partialMatchTable;
    }

    /**
     * Get a list of printable ASCII strings from a binary file. Carriage
     * returns, linefeeds, form feeds and tabs are considered unprintable for
     * the purposes of this method. The caller is expected to close the file.
     *
     * @return a list of printable ASCII strings found in the binary file, all at least the same length as this
     * instance's search string
     * @see <a href="https://bit.ly/binary-strings-extract-java">Strings -- extract printable strings from binary file</a>
     */
    public List<String> getStrings(long offset)
            throws IOException {
        if (null == lastFile) {
            throw new IllegalStateException("Should only be called after search().");
        }
        lastFile.seek(offset);
        final ArrayList<String> result = new ArrayList<String>();
        int datum;
        final StringBuilder builder = new StringBuilder();
        while ((datum = lastFile.nextByte()) != -1) {
            final char character = (char) datum;
            if (character >= ' ' && character <= '~') {
                // printable ASCII character
                builder.append(character);
            } else {
                // if not, see if anything to output.
                if (builder.length() == 0)
                    continue;
                if (builder.length() >= search.length) {
                    result.add(builder.toString());
                }
                builder.setLength(0);
            }
        }
        return result;
    }

    /**
     * Performs a fast string search of the given file, using the Knuth-Morris-Pratt algorithm and pre-computed values
     * as generated by {@link #convertToIntArray(String)} and {@link #getPartialMatchTable(int[])}.
     *
     * @return the offset in bytes where the first instance of the string was found, or -1 if not found
     * @throws IllegalArgumentException if the string string is not at least two characters in length, or if it contains
     *                                  non-ASCII characters
     * @see <a href="http://bit.ly/KMP_algorithm">Knuth-Morris-Pratt Algorithm</a>
     */
    public long search(File file) {
        if (null != lastFile) {
            throw new IllegalStateException("Use reset() between calls to search(File).");
        }
        if (search.length <= 1) {
            throw new IllegalArgumentException("Expect non-trivial string length (>1), got " + search.length + ".");
        }
        if (search.length != partialMatchTable.length) {
            throw new IllegalArgumentException("Search string and partial match table must match in length.");
        }
        long matchOffset = 0;
        int searchStringIndex = 0;
        try {
            lastFile = new ReadBufferedRandomAccessFile(file);
            int character = lastFile.getByte(matchOffset + searchStringIndex);
            final int lastSearchStringIndex = search.length - 1;
            while (-1 != character) {
                if (search[searchStringIndex] == character) {
                    if (searchStringIndex == lastSearchStringIndex) {
                        return matchOffset;
                    }
                    searchStringIndex++;
                } else {
                    if (partialMatchTable[searchStringIndex] > -1) {
                        matchOffset = matchOffset + searchStringIndex - partialMatchTable[searchStringIndex];
                        searchStringIndex = partialMatchTable[searchStringIndex];
                    } else {
                        searchStringIndex = 0;
                        matchOffset++;
                    }
                }
                character = lastFile.getByte(matchOffset + searchStringIndex);
            }
        } catch (IOException e) {
            LOGGER.warn("Exception while searching file for ASCII string " + Arrays.toString(search), e);
        }
        return -1; // not found
    }

    /**
     * Utility wrapper around an initialized {@link RandomAccessFile} instance, that reads in entire buffers, but
     * only provides for reading forward from the initial point.
     */
    private static class ReadBufferedRandomAccessFile implements Closeable{

        /**
         * Buffer so that the only file operations internally are {@link RandomAccessFile#getFilePointer()} and
         * {@link RandomAccessFile#read(byte[])}.
         */
        private static final int BUFFER_SIZE = 4 * 0x400;
        private final RandomAccessFile file;
        private byte[] buffer = new byte[BUFFER_SIZE];
        private long bufferStart;
        private int bytesInBuffer;
        private long lastOffset;

        ReadBufferedRandomAccessFile(File file) throws IOException {
            this.file = new RandomAccessFile(file, "r");
            bufferStart = this.file.getFilePointer();
            this.lastOffset = bufferStart - 1; // so nextByte() will work properly on the first call
            bytesInBuffer = this.file.read(buffer);
        }

        @Override
        public void close() throws IOException {
            this.file.close();
        }

        void seek(long offset) throws IOException {
            if (offset >= (lastOffset + bytesInBuffer)) {
                throw new IllegalArgumentException(
                        "Attempted to set offset past file bytes already accessed: " + offset);
            } else if (offset < bufferStart) {
                file.seek(offset);
                bufferStart = offset;
                bytesInBuffer = file.read(buffer);
            }
            lastOffset = offset - 1;
        }

        int getByte(long offset) throws IOException {
            if (offset < lastOffset) {
                throw new IllegalArgumentException(
                        String.format("Offset (%d) should not be less than previous offset (%d).", offset, lastOffset));
            }
            lastOffset = offset;
            int aByte = -1;
            if (bytesInBuffer > 0 && offset < (bufferStart + bytesInBuffer)) {
                aByte = buffer[(int) (offset - bufferStart)];
            } else if (bytesInBuffer > 0) {
                bufferStart = file.getFilePointer();
                bytesInBuffer = file.read(buffer);
                if (bytesInBuffer > 0) {
                    aByte = buffer[(int) (offset - bufferStart)];
                }
            }
            return aByte;
        }

        int nextByte() throws IOException {
            return getByte(lastOffset + 1);
        }
    }
}