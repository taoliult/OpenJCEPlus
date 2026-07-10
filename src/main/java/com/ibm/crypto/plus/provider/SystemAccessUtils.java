/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Utility methods for accessing system-level resources (properties, classes,
 * and native libraries) needed during provider initialisation.
 *
 * <p>The SecurityManager (and with it {@link AccessController#doPrivileged})
 * was deprecated in Java 17 and <em>removed</em> in Java 25.  All methods in
 * this class therefore branch on the runtime Java version:
 * <ul>
 *   <li>Java &lt; 25 — the operation is wrapped in {@code doPrivileged} so
 *       that it succeeds even when the calling thread does not hold the
 *       required permission.
 *   <li>Java &ge; 25 — the operation is performed directly; no SecurityManager
 *       exists so no privilege escalation is needed or possible.
 * </ul>
 */
public final class SystemAccessUtils {

    /**
     * {@code true} on Java versions that still have a SecurityManager
     * (i.e. Java &lt; 25); {@code false} on Java 25 and later where the
     * SecurityManager API has been removed.
     */
    private static final boolean SECURITY_MANAGER_SUPPORTED =
            Runtime.version().feature() < 25;

    // Utility class – not instantiable.
    private SystemAccessUtils() {}

    /**
     * Read a system property, using a privileged block on Java &lt; 25.
     *
     * @param key          the name of the system property
     * @param defaultValue value to return when the property is absent
     * @return the property value, or {@code defaultValue}
     */
    public static String getProperty(String key, String defaultValue) {
        if (SECURITY_MANAGER_SUPPORTED) {
            return getPropertyWithPrivilege(key, defaultValue);
        }
        return System.getProperty(key, defaultValue);
    }

    /**
     * Read a system property, using a privileged block on Java &lt; 25.
     *
     * @param key the name of the system property
     * @return the property value, or {@code null} if absent
     */
    public static String getProperty(String key) {
        if (SECURITY_MANAGER_SUPPORTED) {
            return getPropertyWithPrivilege(key);
        }
        return System.getProperty(key);
    }

    /**
     * Load a class, using a privileged block on Java &lt; 25.
     *
     * @param className fully-qualified class name
     * @return the loaded {@link Class}
     * @throws ClassNotFoundException if the class cannot be found
     */
    public static Class<?> loadClass(String className) throws ClassNotFoundException {
        if (SECURITY_MANAGER_SUPPORTED) {
            return loadClassWithPrivilege(className);
        }
        return Class.forName(className);
    }

    /**
     * Load a native library, using a privileged block on Java &lt; 25.
     * Returns {@code false} if the file does not exist or if loading fails
     * (e.g. the library was already loaded by another ClassLoader).
     *
     * @param libraryFile the library file to load
     * @return {@code true} if the file existed and was loaded successfully,
     *         {@code false} otherwise
     */
    @SuppressWarnings("restricted")
    public static boolean loadLibrary(File libraryFile) {
        if (SECURITY_MANAGER_SUPPORTED) {
            return loadLibraryWithPrivilege(libraryFile);
        }
        if (!libraryFile.exists()) {
            return false;
        }
        try {
            System.load(libraryFile.getAbsolutePath());
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Open a file for reading, using a privileged block on Java &lt; 25.
     *
     * @param filePath absolute path to the file to open
     * @return a {@link FileReader} positioned at the start of the file
     * @throws IOException if the file cannot be opened
     */
    public static FileReader newFileReader(String filePath) throws IOException {
        if (SECURITY_MANAGER_SUPPORTED) {
            return newFileReaderWithPrivilege(filePath);
        }
        return new FileReader(filePath);
    }

    /**
     * Read a text file line-by-line and return the first line that starts with
     * the given {@code linePrefix}, with the prefix stripped and the result
     * trimmed; returns {@code null} if no such line exists or the file cannot
     * be read.  The file access is wrapped in a privileged block on Java &lt; 25.
     *
     * @param filePath   absolute path to the file
     * @param linePrefix the prefix to match at the start of a line
     * @return the content after the prefix on the first matching line, or
     *         {@code null}
     */
    public static String readVersionFromFile(String filePath, String linePrefix) {
        if (SECURITY_MANAGER_SUPPORTED) {
            return readVersionFromFileWithPrivilege(filePath, linePrefix);
        }
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(linePrefix)) {
                    return line.substring(linePrefix.length()).trim();
                }
            }
        } catch (Exception e) {
            // file unreadable — caller handles null
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Private implementation helpers — doPrivileged only called from here
    // -------------------------------------------------------------------------

    @SuppressWarnings("removal")
    private static String getPropertyWithPrivilege(String key, String defaultValue) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key, defaultValue));
    }

    @SuppressWarnings("removal")
    private static String getPropertyWithPrivilege(String key) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key));
    }

    @SuppressWarnings("removal")
    private static Class<?> loadClassWithPrivilege(String className)
            throws ClassNotFoundException {
        try {
            return AccessController.doPrivileged(
                    (java.security.PrivilegedExceptionAction<Class<?>>) () ->
                            Class.forName(className));
        } catch (java.security.PrivilegedActionException pae) {
            Throwable cause = pae.getCause();
            if (cause instanceof ClassNotFoundException cnfe) {
                throw cnfe;
            }
            throw new ClassNotFoundException(className, cause);
        }
    }

    @SuppressWarnings("removal")
    private static FileReader newFileReaderWithPrivilege(String filePath) throws IOException {
        try {
            return AccessController.doPrivileged(
                    (java.security.PrivilegedExceptionAction<FileReader>) () ->
                            new FileReader(filePath));
        } catch (java.security.PrivilegedActionException pae) {
            Throwable cause = pae.getCause();
            if (cause instanceof IOException ioe) {
                throw ioe;
            }
            throw new IOException(filePath, cause);
        }
    }

    @SuppressWarnings("removal")
    private static String readVersionFromFileWithPrivilege(String filePath, String linePrefix) {
        try {
            return AccessController.doPrivileged(
                    (java.security.PrivilegedExceptionAction<String>) () -> {
                        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
                            String line;
                            while ((line = br.readLine()) != null) {
                                if (line.startsWith(linePrefix)) {
                                    return line.substring(linePrefix.length()).trim();
                                }
                            }
                        }
                        return null;
                    });
        } catch (java.security.PrivilegedActionException pae) {
            return null;
        }
    }

    @SuppressWarnings({"removal", "restricted"})
    private static boolean loadLibraryWithPrivilege(File libraryFile) {
        if (!AccessController.doPrivileged((PrivilegedAction<Boolean>) libraryFile::exists)) {
            return false;
        }
        try {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                System.load(libraryFile.getAbsolutePath());
                return null;
            });
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
