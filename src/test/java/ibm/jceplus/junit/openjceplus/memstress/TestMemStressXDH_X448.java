/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.memstress;

import ibm.jceplus.junit.base.memstress.BaseTestMemStressXDH;
import ibm.jceplus.junit.openjceplus.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestMemStressXDH_X448 extends BaseTestMemStressXDH {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        setAlgorithm("X448");
    }
}
