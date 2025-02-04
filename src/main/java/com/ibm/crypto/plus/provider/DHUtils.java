/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidParameterException;

final class DHUtils {

    final static int MIN_KEYSIZE_NONFIPS = 512;
    final static int MAX_KEYSIZE_NONFIPS = 8192;
    final static int MIN_KEYSIZE_FIPS = 2048;
    final static int MAX_KEYSIZE_FIPS = 8192;

    /**
     * Check the length of an DH key modulus/exponent to make sure it is not
     * too short or long.
     *
     * @param keySize
     *                the bit length of the modulus.
     * @param expSize
     *                the bit length of the exponent.
     * @param isFIPS
     *                whether the provider is FIPS.
     *
     * @throws InvalidParameterException
     *                             if any of the values are unacceptable.
     */
    static void checkKeySize(int keySize, int expSize, boolean isFIPS)
            throws InvalidParameterException {

        if (isFIPS) {
            checkKeySize(keySize, MIN_KEYSIZE_FIPS, MAX_KEYSIZE_FIPS, expSize);
        } else {
            checkKeySize(keySize, MIN_KEYSIZE_NONFIPS, MAX_KEYSIZE_NONFIPS, expSize);
        }
    }

    /**
     * Check the length of an DH key modulus/exponent to make sure it is not
     * too short or long. Some impls have their own min and max key sizes that
     * may or may not match with a system defined value.
     *
     * @param keySize
     *                the bit length of the modulus.
     * @param minSize
     *                the minimum length of the modulus.
     * @param maxSize
     *                the maximum length of the modulus.
     * @param expSize
     *                the bit length of the exponent.
     *
     * @throws InvalidParameterException
     *                             if any of the values are unacceptable.
     */
    static void checkKeySize(int keySize, int minSize, int maxSize, int expSize)
            throws InvalidParameterException {

        if ((keySize < minSize) || (keySize > maxSize) || ((keySize & 0x3F) != 0)) {
            throw new InvalidParameterException(
                    "DH key size must be multiple of 64, and can only range " +
                            "from " + minSize + " to " + maxSize + " (inclusive). " +
                            "The specific key size " + keySize + " is not supported");
        }

        // optional, could be 0 if not specified
        if ((expSize < 0) || (expSize > keySize)) {
            throw new InvalidParameterException("Exponent size must be positive and no larger than" +
                    " modulus size");
        }
    }
}
