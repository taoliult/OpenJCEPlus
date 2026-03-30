package ibm.jceplus.junit.openjceplus;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenJCEPlusTransitionAlgorithms {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
    }

    @Test
    public void testPrintOpenJCEPlusTransitionAlgorithms() {
        Provider provider = new com.ibm.crypto.plus.provider.OpenJCEPlusInternal;
        Security.addProvider(provider);

        System.out.println("Provider name: " + provider.getName());
        System.out.println("Provider info: " + provider.getInfo());
        System.out.println("===== OpenJCEPlusTransition Algorithm List =====");

        List<String> lines = new ArrayList<>();
        for (Provider.Service service : provider.getServices()) {
            lines.add(service.getType() + "." + service.getAlgorithm());
        }

        Collections.sort(lines);

        for (String line : lines) {
            System.out.println(line);
        }

        System.out.println("===== Total: " + lines.size() + " =====");
        System.out.flush();
    }
}