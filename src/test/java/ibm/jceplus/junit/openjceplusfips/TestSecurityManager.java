/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplusfips;

import ibm.jceplus.junit.base.BaseTestSecurityManager;
import org.junit.jupiter.api.TestInstance;

/**
 * Exercises the OpenJCEPlusFIPS provider under a SecurityManager.
 *
 * <p>Run with:
 * <pre>
 *   mvn test -pl . -Dtest=TestSecurityManager
 *       -Djava.security.manager
 *       -Djava.security.policy=src/test/resources/openjceplus-securitymanager.policy
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestSecurityManager extends BaseTestSecurityManager {
    public TestSecurityManager() {
        super("OpenJCEPlusFIPS");
    }
}
