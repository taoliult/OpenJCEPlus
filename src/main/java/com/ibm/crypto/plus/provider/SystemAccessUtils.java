/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * Utility methods for running operations needed during provider initialisation.
 *
 * <p>The SecurityManager and {@code AccessController.doPrivileged} were
 * deprecated in Java 17 and removed in Java 25.  This class targets
 * Java 25 and above where no SecurityManager exists, so all operations
 * are performed directly with no privilege wrapping.
 *
 * <p>Callers compose their own lambda, for example:
 * <pre>
 *   String home = SystemAccessUtils.doPrivileged(() -&gt; System.getProperty("java.home"));
 * </pre>
 */
public final class SystemAccessUtils {

    // Utility class – not instantiable.
    private SystemAccessUtils() {}

    /**
     * Execute the action directly.
     *
     * @param <T>    the return type
     * @param action the action to run
     * @return the value returned by {@code action}
     */
    public static <T> T doPrivileged(Supplier<T> action) {
        return action.get();
    }

    /**
     * Execute the action directly.
     *
     * @param <T>    the return type
     * @param action the action to run
     * @return the value returned by {@code action}
     * @throws Exception any checked exception thrown by {@code action}
     */
    public static <T> T doPrivilegedChecked(Callable<T> action) throws Exception {
        return action.call();
    }

    /**
     * Execute the action directly.
     *
     * @param action the action to run
     */
    public static void runPrivileged(Runnable action) {
        action.run();
    }
}
