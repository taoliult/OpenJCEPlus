/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestImplementationClassesExist extends BaseTestJunit5 {

    @Test
    public void testImplementationClassesExist() throws Exception {
        Provider provider = Security.getProvider(getProviderName());
        Set<?> services = provider.getServices();
        Iterator<?> iterator = services.iterator();
        TreeSet<String> serviceClassNames = new TreeSet<String>();
        Vector<String> missingClassNames = new Vector<String>();

        // Walk through all of the provider services and generate a unique list
        // of implementation class names.
        //
        while (iterator.hasNext()) {
            Provider.Service service = (Provider.Service) iterator.next();
            serviceClassNames.add(service.getClassName());
        }

        iterator = serviceClassNames.iterator();

        while (iterator.hasNext()) {
            String className = (String) iterator.next();

            try {
                Class.forName(className);
            } catch (Exception e) {
                missingClassNames.add(className);
            }
        }

        assertTrue((missingClassNames.size() == 0), "Missing implementation classes for " + missingClassNames.toString());
    }
}
