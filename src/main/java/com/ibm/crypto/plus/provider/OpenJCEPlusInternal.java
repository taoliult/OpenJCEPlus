/*
 * Copyright IBM Corp. 2026, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.OCKContext;
import com.ibm.crypto.plus.provider.base.OCKException;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public final class OpenJCEPlusInternal extends OpenJCEPlusProvider {

    private static final long serialVersionUID = 1L;

    private static final String info = "OpenJCEPlusInternal Provider implements the following:\n";

    private static final String PROVIDER_BASE_NAME = "OpenJCEPlusInternal";

    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile OpenJCEPlusInternal instance;

    private static boolean ockInitialized = false;
    private static OCKContext ockContext;

    @SuppressWarnings({"unchecked", "rawtypes"})
    public OpenJCEPlusInternal() {
        super(buildProviderRuntimeName(), info);

        if (debug != null) {
            debug.println("New OpenJCEPlusInternal instance");
        }

        final OpenJCEPlusProvider jce = this;

        AccessController.doPrivileged(new java.security.PrivilegedAction() {
            public Object run() {

                // Do java OCK initialization which includes loading native code
                // Don't do this in the static initializer because it might
                // be necessary for an applet running in a browser to grant
                // access rights beforehand.
                if (!ockInitialized) {
                    initializeContext();
                }

                registerAlgorithms(jce);

                return null;
            }
        });

        if (instance == null) {
            instance = this;
        }
    
        if (debug != null) {
            debug.println("OpenJCEPlusInternal Build-Level: " + getDebugDate(this.getClass().getName()));
            debug.println("OpenJCEPlusInternal library build date: " + OCKContext.getLibraryBuildDate());
            try {
                debug.println("OpenJCEPlusInternal dependent library version: " + ockContext.getOCKVersion());
                debug.println("OpenJCEPlusInternal dependent library path: " + ockContext.getOCKInstallPath());
            } catch (Throwable t) {
                t.printStackTrace(System.out);
            }
        }
    }

    private static String buildProviderRuntimeName() {
        return PROVIDER_BASE_NAME + "-" + generateRandomSuffix();
    }

    private static String generateRandomSuffix() {
        return UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 12)
                .toUpperCase();
    }

    private void registerAlgorithms(Provider jce) {

        String[] aliases = null;

        /* =======================================================================
         * Message authentication engines
         * =======================================================================
         */

        aliases = new String[] {"HMACwithMD5"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacMD5",
                "com.ibm.crypto.plus.provider.HmacCore$HmacMD5", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.7", "1.2.840.113549.2.7", "HMACwithSHA1",
                "HMACwithSHA-1", "HmacSHA-1"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA1",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA1", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.8", "1.2.840.113549.2.8", "HMACwithSHA224",
                "HMACwithSHA-224", "HmacSHA-224"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA224",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA224", aliases));

        aliases = new String[] {

                "OID.1.2.840.113549.2.9", "1.2.840.113549.2.9", "HMACwithSHA256", // Added per tag [IBM-ALIASES]/ in DesignNotes.txt
                "HMACwithSHA-256", "HmacSHA-256"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA256",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA256", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.10", "1.2.840.113549.2.10", "HMACwithSHA384", // Added per tag [IBM-ALIASES]    in DesignNotes.txt
                "HMACwithSHA-384", "HmacSHA-384"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA384",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA384", aliases));

        aliases = new String[] {"OID.1.2.840.113549.2.11", "1.2.840.113549.2.11", "HMACwithSHA512",
                "HMACwithSHA-512", "HmacSHA-512"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA512",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA512", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.13", "2.16.840.1.101.3.4.2.13",
                "HMACwithSHA3-224", "HmacSHA3-224"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-224",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_224", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.14", "2.16.840.1.101.3.4.2.14",
                "HMACwithSHA3-256", "HmacSHA3-256"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-256",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_256", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.15", "2.16.840.1.101.3.4.2.15",
                "HMACwithSHA3-384", "HmacSHA3-384"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-384",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_384", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.16", "2.16.840.1.101.3.4.2.16",
                "HMACwithSHA3-512", "HmacSHA3-512"};
        putService(new OpenJCEPlusService(jce, "MAC", "HmacSHA3-512",
                "com.ibm.crypto.plus.provider.HmacCore$HmacSHA3_512", aliases));
      
        /* =======================================================================
         * MessageDigest engines
         * =======================================================================
         */

        aliases = null;
        putService(new OpenJCEPlusService(jce, "MessageDigest", "MD5",
                "com.ibm.crypto.plus.provider.MessageDigest$MD5", aliases));

        aliases = new String[] {"SHA", "SHA1", "OID.1.3.14.3.2.26", "1.3.14.3.2.26"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-1",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA1", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.4", "SHA224"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-224",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA224", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.1", "SHA2",
                "SHA-2", "SHA256"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-256",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA256", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.2", "SHA3",
                "SHA-3", "SHA384"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-384",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA384", aliases));

        aliases = new String[] {"OID.2.16.840.1.101.3.4.2.3", "2.16.840.1.101.3.4.2.3", "SHA5",
                "SHA-5", "SHA512"};
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-512",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA512", aliases));

        // SHA512-224
        aliases = new String[] {"SHA512/224", "OID.2.16.840.1.101.3.4.2.5",
                "2.16.840.1.101.3.4.2.5", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-512/224",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA512_224", aliases));

        // SHA512-256
        aliases = new String[] {"SHA512/256", "OID.2.16.840.1.101.3.4.2.6",
                "2.16.840.1.101.3.4.2.6", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA-512/256",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA512_256", aliases));

        //SHA3 Hashes

        aliases = new String[] {"SHA3-224", "OID.2.16.840.1.101.3.4.2.7",
                "2.16.840.1.101.3.4.2.7", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-224",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_224", aliases));
        aliases = new String[] {"SHA3-256", "OID.2.16.840.1.101.3.4.2.8",
                "2.16.840.1.101.3.4.2.8", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-256",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_256", aliases));
        aliases = new String[] {"SHA3-384", "OID.2.16.840.1.101.3.4.2.9",
                "2.16.840.1.101.3.4.2.9", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-384",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_384", aliases));
        aliases = new String[] {"SHA3-512", "OID.2.16.840.1.101.3.4.2.10",
                "2.16.840.1.101.3.4.2.10", };
        putService(new OpenJCEPlusService(jce, "MessageDigest", "SHA3-512",
                "com.ibm.crypto.plus.provider.MessageDigest$SHA3_512", aliases));
        
        /* =======================================================================
         * SecureRandom
         * =======================================================================
         */
        Map<String, String> attrsSecureRandom = new HashMap<>();
        attrsSecureRandom.put("ThreadSafe", "true");
        aliases = new String[] {"HASHDRBG", "SHA2DRBG"};
        putService(new OpenJCEPlusService(jce, "SecureRandom", "SHA256DRBG",
                "com.ibm.crypto.plus.provider.HASHDRBG$SHA256DRBG", aliases, attrsSecureRandom));

        aliases = new String[] {"SHA5DRBG"};
        putService(new OpenJCEPlusService(jce, "SecureRandom", "SHA512DRBG",
                "com.ibm.crypto.plus.provider.HASHDRBG$SHA512DRBG", aliases, attrsSecureRandom));
    }

    // Return the instance of this class or create one if needed.
    //
    static OpenJCEPlusInternal getInstance() {
        if (instance == null) {
            return new OpenJCEPlusInternal();
        }
        return instance;
    }

    private static class OpenJCEPlusTransitionContext extends ProviderContext {

        private static final long serialVersionUID = 1L;

        OpenJCEPlusTransitionContext() {}

        OpenJCEPlusProvider getProvider() {
            return OpenJCEPlusInternal.getInstance();
        }
    }

    ProviderContext getProviderContext() {
        return new OpenJCEPlusTransitionContext();
    }

    // Get SecureRandom to use for crypto operations.
    //
    java.security.SecureRandom getSecureRandom(java.security.SecureRandom userSecureRandom) {
        try {
            return java.security.SecureRandom.getInstance("SHA256DRBG", this);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException("SecureRandom not available");
        }
    }

    // Initialize OCK context(s)
    //
    private synchronized void initializeContext() {
        // Leave this duplicate check in here. If two threads are both trying
        // to instantiate an OpenJCEPlus provider at the same time, we need to
        // ensure that the initialization only happens one time. We have
        // made the method synchronizaed to ensure only one thread can execute
        // the method at a time.
        //
        if (ockInitialized) {
            return;
        }

        try {
            boolean useFIPSMode = false;

            ockContext = OCKContext.createContext(useFIPSMode);
            ockInitialized = true;
        } catch (OCKException e) {
            throw providerException("Failed to initialize OpenJCEPlusInternal provider", e);
        } catch (Throwable t) {
            ProviderException exceptionToThrow = providerException(
                    "Failed to initialize OpenJCEPlusInternal provider", t);

            if (exceptionToThrow.getCause() == null) {
                // We are not including the full stack trace back to the point
                // of origin.
                // Try and obtain the message for the underlying cause of the
                // exception
                //
                // If an ExceptionInInitializerError or NoClassDefFoundError is
                // thrown, we want to get the message from the cause of that
                // exception.
                //
                if ((t instanceof java.lang.ExceptionInInitializerError)
                        || (t instanceof java.lang.NoClassDefFoundError)) {
                    Throwable cause = t.getCause();
                    if (cause != null) {
                        t = cause;
                    }
                }

                // In the case that the JNI library could not be loaded.
                //
                String message = t.getMessage();
                if ((message != null) && (message.length() > 0)) {
                    // We want to see the message for the underlying cause even
                    // if not showing the stack trace all the way back to the
                    // point of origin.
                    //
                    exceptionToThrow.initCause(new ProviderException(t.getMessage()));
                }
            }

            if (debug != null) {
                exceptionToThrow.printStackTrace(System.out);
            }

            throw exceptionToThrow;
        }
    }

    // Get OCK context for crypto operations
    //
    OCKContext getOCKContext() {
        // May need to initialize OCK here in the case that a serialized
        // OpenJCEPlus object, such as a HASHDRBG SecureRandom, is being
        // deserialized in a JVM that has not instantiated the OpenJCEPlus
        // provider yet.
        //
        if (!ockInitialized) {
            initializeContext();
        }

        return ockContext;
    }

    ProviderException providerException(String message, Throwable ockException) {
        ProviderException providerException = new ProviderException(message, ockException);
        setOCKExceptionCause(providerException, ockException);
        return providerException;
    }

    // Get the date from the ImplementationVersion in the manifest file
    private static String getDebugDate(String className) {
        String versionDate = "Unknown";
        try {
            Class<?> thisClass = Class.forName(className);
            Package thisPackage = thisClass.getPackage();
            String versionInfo = thisPackage.getImplementationVersion();
            int index = versionInfo.indexOf("_");
            versionDate = (index == -1) ? versionInfo : versionInfo.substring(index + 1);
        } catch (Exception e) {
            // IGNORE EXCEPTION
        }
        return versionDate;
    }
}
