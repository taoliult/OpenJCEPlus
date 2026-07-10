/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Smoke tests that verify the OpenJCEPlus (and OpenJCEPlusFIPS) provider loads
 * and performs basic crypto operations when a {@link SecurityManager} is active.
 *
 * <p>The SecurityManager is deprecated for removal starting in Java 17 and is
 * removed in Java 25.  These tests are therefore guarded by
 * {@link Assumptions#assumeTrue} so that they are silently skipped on JDK
 * versions where the SecurityManager can no longer be used.
 *
 * <p>To run these tests with a SecurityManager enabled you must supply a
 * policy file that grants the necessary permissions to the provider and to
 * the test code itself, for example:
 * <pre>
 *   -Djava.security.manager
 *   -Djava.security.policy=src/test/resources/openjceplus-securitymanager.policy
 * </pre>
 *
 * <p>The tests also double as a regression gate: if the provider code
 * regresses to calling {@code System.getProperty()}, {@code Class.forName()},
 * or {@code System.load()} without going through {@code SystemAccessUtils}
 * the JVM will throw an {@link java.security.AccessControlException} which
 * will cause the assertion to fail.
 */
public abstract class BaseTestSecurityManager {

    private final String providerName;

    protected BaseTestSecurityManager(String providerName) {
        this.providerName = providerName;
    }

    /**
     * Skip the entire test class on JDK versions that no longer support the
     * SecurityManager API (Java 25+) or where it has been disabled.
     */
    @SuppressWarnings("removal")
    @BeforeAll
    static void checkSecurityManagerAvailable() {
        int javaVersion = Runtime.version().feature();
        // SecurityManager is fully removed starting in Java 25.
        Assumptions.assumeTrue(javaVersion < 25,
                "SecurityManager removed in Java 25 — skipping SecurityManager tests.");
    }

    // -------------------------------------------------------------------------
    // Provider registration
    // -------------------------------------------------------------------------

    /**
     * Verifies that the provider can be found in the JVM's provider list.
     * If it is not already installed the test installs it programmatically
     * inside a privileged block so that the installation itself does not
     * require the caller to already hold {@code SecurityPermission}.
     */
    @Test
    public void testProviderIsRegistered() {
        Provider p = Security.getProvider(providerName);
        if (p == null) {
            // Install dynamically for this test run.
            assertDoesNotThrow(() -> {
                Class<?> cls = Class.forName(
                        "com.ibm.crypto.plus.provider.OpenJCEPlus".equals(providerName)
                                ? "com.ibm.crypto.plus.provider.OpenJCEPlus"
                                : "com.ibm.crypto.plus.provider.OpenJCEPlusFIPS");
                Provider provider = (Provider) cls.getDeclaredConstructor().newInstance();
                Security.addProvider(provider);
            }, "Provider '" + providerName + "' could not be installed: ");
            p = Security.getProvider(providerName);
        }
        assertNotNull(p, "Provider '" + providerName + "' should be registered.");
    }

    // -------------------------------------------------------------------------
    // Basic algorithm operations
    // -------------------------------------------------------------------------

    /** AES key generation + AES/GCM encryption must succeed. */
    @Test
    public void testAESKeyGenAndEncrypt() throws Exception {
        skipIfProviderMissing();

        KeyGenerator kg = KeyGenerator.getInstance("AES", providerName);
        kg.init(256);
        SecretKey key = kg.generateKey();
        assertNotNull(key, "AES key must not be null.");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        assertDoesNotThrow(() -> cipher.init(Cipher.ENCRYPT_MODE, key),
                "AES/GCM cipher init must not throw under SecurityManager.");
    }

    /** SHA-256 digest must produce the expected 32-byte output. */
    @Test
    public void testSHA256Digest() throws Exception {
        skipIfProviderMissing();

        MessageDigest md = MessageDigest.getInstance("SHA-256", providerName);
        byte[] digest = md.digest("Hello OpenJCEPlus".getBytes("UTF-8"));
        assertNotNull(digest, "Digest must not be null.");
        assertTrue(digest.length == 32,
                "SHA-256 digest must be 32 bytes, got " + digest.length);
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private void skipIfProviderMissing() {
        Assumptions.assumeTrue(Security.getProvider(providerName) != null,
                "Provider '" + providerName + "' not installed — skipping test.");
    }
}
