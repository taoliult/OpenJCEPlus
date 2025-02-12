/*
 * Copyright IBM Corp. 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;

/**
 * This class implements a key factory for PBE (Password-Based Encryption) keys  
 * derived using PBKDF2 with HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384,  
 * or HmacSHA512 as the pseudo-random function (PRF), as defined in PKCS#5 v2.1.  
 */  
abstract class PBKDF2Core extends SecretKeyFactorySpi {

    private OpenJCEPlusProvider provider = null;
    private final String prfAlgorithm;

    PBKDF2Core(OpenJCEPlusProvider provider, String prfAlgo) {
        this.provider = provider;
        this.prfAlgorithm = prfAlgo;
    }

    /**
     * Generates PBKDF2KeyImpl object from the given key specification.
     *
     * @param keySpec the key specification containing the key material
     * @return the generated secret key
     * @throws InvalidKeySpecException if the provided key specification is
     *                                 incompatible with this key factory.
     */
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new InvalidKeySpecException("Only PBEKeySpec is allowed.");
        }
        return new PBKDF2KeyImpl(this.provider, (PBEKeySpec) keySpec, prfAlgorithm);
    }

    /**
     * Returns the key specification of the given key.
     *
     * @param key          the key to be processed
     * @param keySpecClass the desired format in which the key material should be
     *                     returned
     * @return the key specification
     * @exception InvalidKeySpecException if the requested key specification is
     *                                    incompatible with the key or cannot be
     *                                    processed
     */
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecClass)
            throws InvalidKeySpecException {
        if (key instanceof javax.crypto.interfaces.PBEKey pKey) {
            // Check if requested key spec is amongst the valid ones
            if ((keySpecClass != null) && keySpecClass.isAssignableFrom(PBEKeySpec.class)) {
                char[] passwd = pKey.getPassword();
                byte[] encoded = pKey.getEncoded();
                try {
                    return new PBEKeySpec(passwd, pKey.getSalt(), pKey.getIterationCount(),
                            encoded.length * 8);
                } finally {
                    if (passwd != null) {
                        Arrays.fill(passwd, (char) 0);
                    }
                    Arrays.fill(encoded, (byte) 0);
                }
            } else {
                throw new InvalidKeySpecException("Only PBEKeySpec is accepted");
            }
        } else {
            throw new InvalidKeySpecException("Only PBEKey is accepted");
        }
    }

    /**
     * Translates a <code>SecretKey</code> object, whose provider may be
     * unknown or potentially untrusted, into a corresponding
     * <code>SecretKey</code> object of this key factory.
     *
     * @param key the key whose provider is unknown or untrusted
     *
     * @return the translated key
     *
     * @exception InvalidKeyException if the given key cannot be processed by
     * this key factory.
     */
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if ((key != null) && (key.getAlgorithm().equalsIgnoreCase("PBKDF2With" + prfAlgorithm))
                && (key.getFormat().equalsIgnoreCase("RAW"))) {

            // Check if key originates from this factory, if true simply return it.
            if (key instanceof com.ibm.crypto.plus.provider.PBKDF2KeyImpl) {
                return key;
            }

            // Check if key implements the PBEKey
            if (key instanceof javax.crypto.interfaces.PBEKey pKey) {
                char[] password = pKey.getPassword();
                byte[] encoding = pKey.getEncoded();
                PBEKeySpec spec = new PBEKeySpec(password, pKey.getSalt(), pKey.getIterationCount(),
                        encoding.length * 8);
                try {
                    return new PBKDF2KeyImpl(this.provider, spec, prfAlgorithm);
                } catch (InvalidKeySpecException re) {
                    throw new InvalidKeyException("Invalid key component(s)", re);
                } finally {
                    if (password != null) {
                        Arrays.fill(password, (char) 0);
                        spec.clearPassword();
                    }
                    Arrays.fill(encoding, (byte) 0);
                }
            } else {
                throw new InvalidKeyException("Only PBEKey is accepted");
            }
        }
        throw new InvalidKeyException(
                "Only PBKDF2With" + prfAlgorithm + " key with RAW format is accepted");
    }

    public static final class HmacSHA1 extends PBKDF2Core {
        public HmacSHA1(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA1");
        }
    }

    public static final class HmacSHA224 extends PBKDF2Core {
        public HmacSHA224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA224");
        }
    }

    public static final class HmacSHA256 extends PBKDF2Core {
        public HmacSHA256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA256");
        }
    }

    public static final class HmacSHA384 extends PBKDF2Core {
        public HmacSHA384(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA384");
        }
    }

    public static final class HmacSHA512 extends PBKDF2Core {
        public HmacSHA512(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512");
        }
    }
}
