/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class BaseTestDHKeyFactory extends BaseTestJunit5Interop {

    @Test
    public void testDHKeyFactory() throws Exception {

        test_dh_keyFactory(getInteropProviderName(), getInteropProviderName());
        test_dh_keyFactory(getProviderName(), getProviderName());
        if (getProviderName().equals("OpenJCEPlusFIPS")
                || getInteropProviderName().equals("OpenJCEPlusFIPS")) {
            // OpenJCEPlusFIPS will not work with the static DHParams from IBMJCE. They are no longer FIPS usable.
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                test_dh_keyFactory(getProviderName(), getInteropProviderName());
            } else {
                test_dh_keyFactory(getInteropProviderName(), getProviderName());
            }
        } else {
            test_dh_keyFactory(getProviderName(), getInteropProviderName());
            test_dh_keyFactory(getInteropProviderName(), getProviderName());
        }

    }

    @Test
    public void testDHShortSecret1() throws Exception {
        test_dh_short_secret(getProviderName(), getProviderName());
        test_dh_short_secret(getInteropProviderName(), getInteropProviderName());
        test_dh_short_secret(getProviderName(), getInteropProviderName());
        test_dh_short_secret(getInteropProviderName(), getProviderName());
    }

    @Test
    public void testDHShortSecret2a() throws Exception {
        test_dh_short_secret2ndmethod(getProviderName(), getProviderName());
    }

    @Test
    public void testDHShortSecret2b() throws Exception {

        test_dh_short_secret2ndmethod(getInteropProviderName(), getInteropProviderName());


    }

    @Test
    public void testDHShortSecret2c() throws Exception {

        test_dh_short_secret2ndmethod(getProviderName(), getInteropProviderName());

    }

    @Test
    public void testDHShortSecret2d() throws Exception {

        test_dh_short_secret2ndmethod(getInteropProviderName(), getProviderName());

    }



    void test_dh_short_secret2ndmethod(String providerNameX, String providerNameY)
            throws Exception {



        byte[] aPrivKeyEnc = new BigInteger(
                "3082012102010030819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b0201020481830281806502b69705a45d97a848c97137c088a0dd7c6b4637481d6fc4cb7a70313aa1682302998c7bee0ec47408e73913656e67033385d26c54c599317071454ac96f4dcfb40ec58789353fe29e37f4b1ac567b10a037791d80b5139cab2b61746cafc0ebb7742c5fae86c1b8a3715854c2c3ce32b58ddd8cc4e387a3063382007edbb0",
                16).toByteArray();


        byte[] aPubKeyEnc = new BigInteger(
                "3082011f30819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b02010203818400028180008f223ec76dcf711abfd5693268780a920d9e2d350ba8f11acb0caaa5019cf3c8ad69343fe8f16b81874961e4b6512d3e60a78864619e99f7da3e9811661c4f25b80f8a70f9ddaa79d4bbf1ed0491df02b4f0517490a60af2b80fb5db8355dab9ef06718c89c7eda124ef61ab0dda0de682f50ff22b605cc2ba2e3f0b96803b",
                16).toByteArray();

        byte[] bPrivKeyEnc = new BigInteger(
                "3082012102010030819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b0201020481830281804cd3001b1c93f247412f5594f9d20a7125f2055981a48c5115a80414db882d41547143d487ed14eb06b44a71db6094196288872fa651c94d9aa0b0abcc5861927ecb63d747ebffd97b68bf0cb9df6e443e36f7b737154c4d2c27fda65311f1e66f88817377249ac5c19e76b0100b753e58ead682b4fd995d4b5b6609fbd370ce",
                16).toByteArray();

        byte[] bPubKeyEnc = new BigInteger(
                "3082011f30819506092a864886f70d01030130818702818100f82c32137806fe8d7d58be961f857afa35ec9434258a38e26218713b6e27db0ab435bb44575f184de8b4e0e6645999ae3a864d615de8fd759d3071d4eac75d5502d7cc13e9ca9a0ff1bdb895e557445d415182ca7561f97701718fca886bb336dedf5866cf8a2cc8ed7491f18f10e07ca7cfa4a9308a310fbb31d9d7e0eb068b020102038184000281806903be9046b2b24127614f97584ad70a6ca6c5e39b9979b7f95729c6b86803719d4677e5758add0c5c8b936446795ef3af67922323f00cc1b488cdddf28f13d75452451853cb1c84a9ae701ec2664b27d91e9b74b381e0957cb638a5c5c0acf85c297d29417f8917b2ea091da2766919dfb2e490253259d2b117e9c616d14b58",
                16).toByteArray();

        KeyFactory aKeyFac = KeyFactory.getInstance("DH", providerNameX);
        X509EncodedKeySpec x509KeySpecForB = new X509EncodedKeySpec(bPubKeyEnc);
        PublicKey bPubKey = aKeyFac.generatePublic(x509KeySpecForB);

        PrivateKey aPrivKey = aKeyFac.generatePrivate(new PKCS8EncodedKeySpec(aPrivKeyEnc));

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", providerNameX);
        aKeyAgree.init(aPrivKey);

        aKeyAgree.doPhase(bPubKey, true);

        /*
         * Let's turn over to B. B has received A's public key in encoded format. B
         * instantiates a DH public key from the encoded key material.
         */

        KeyFactory bKeyFac = KeyFactory.getInstance("DH", providerNameY);
        X509EncodedKeySpec x509KeySpecForA = new X509EncodedKeySpec(aPubKeyEnc);
        PublicKey aPubKey = bKeyFac.generatePublic(x509KeySpecForA);

        PrivateKey bPrivKey = bKeyFac.generatePrivate(new PKCS8EncodedKeySpec(bPrivKeyEnc));

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", providerNameY);
        bKeyAgree.init(bPrivKey);



        /*
         * B uses A's public key for the first (and only) phase of B's version of the DH
         * protocol.
         */

        bKeyAgree.doPhase(aPubKey, true);

        /*
         * At this stage, both A and B have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aSharedSecret = null;
        byte[] bSharedSecret = null;

        try {
            aSharedSecret = aKeyAgree.generateSecret();
            int aLen = aSharedSecret.length;
            bSharedSecret = new byte[aLen];

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } // provide output buffer of required size
        bKeyAgree.generateSecret(bSharedSecret, 0);

        if (!java.util.Arrays.equals(aSharedSecret, bSharedSecret)) {
            System.out.println("A secret: " + BaseUtils.bytesToHex(aSharedSecret));
            System.out.println("B secret: " + BaseUtils.bytesToHex(bSharedSecret));

            throw new Exception("Shared secrets differ");
        }
        System.out.println("Shared secrets are the same");

        //

    }

    void test_dh_short_secret(String providerNameX, String providerNameY) throws Exception {


        // A encodes A's public key, and sends it over to B.
        byte[] aPrivKeyEnc = new BigInteger(
                "308201a90201003082011b06092a864886f70d0103013082010c0282010100ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff0201020202040004818402818100d2564148860943c94b59dd79492429c6f4ec1297b95b1c46abef345979ecd572eb8d6ce1db671d624fb1a5d6d468007a509164b99f8355450efdd45e922fa77828f956dd1653f489593eb1dc74d842f96dc1f2c933f012425d33853f88cd221219824dfb2ed00ec2b1b2ad2fb1083dc063a48082210781b1fc59d5d658589f1d",
                16).toByteArray();
        byte[] aPubKeyEnc = new BigInteger(
                "308202283082011b06092a864886f70d0103013082010c0282010100ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff0201020202040003820105000282010064082f3573b6d07ea80cec22955a9811af4dd1fdaea4bab3938164201162a27c4599e63af2be76c06519dedbe7176834ebd6e041cb2d2103bc9b4c1786a848d7a6a974a0d268c25cca15b418cf3f36ae8e190f4f850f5e51801c0b933cc61c5d541390ae2a76837c96b6af8f7ee65addbee407b649cf4a24e164f9539ca7b4b11e2972ff76d7e20239467182e1bc94bf213bc8d849f818c41e69d9b4f0ee2325f2922f8f4699d957a1b8875dafe3417af11456ce020685a265bf07eeeb968d412a4edad6d39334ec28e8cfd26ad591ec013d0b69b934579c4c822b7c1c2eb18155db5695ceece7fb0af5f15c47c6c5d1b075a293a4586b068cf231765c231d64",
                16).toByteArray();
        byte[] bPrivKeyEnc = new BigInteger(
                "308201a90201003082011b06092a864886f70d0103013082010c0282010100ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff0201020202040004818402818100f0af507e265da94bbf90f6974c702f0d6c1e6dcd7a888df0bd87bfa464957782fe3e2c0088f55c6a139f72aec06e54349fac248a842fa22642e0fb9fd2adb02a511e0f39af092ac2df3dd28a06dc6dc6fb3b99f71f8fb8ebfb1083c2993b23bd4e655b608761c3416b0e88e969f93bbe19c47582c97f48886a23b0d1f811e8a0",
                16).toByteArray();
        byte[] bPubKeyEnc = new BigInteger(
                "308202293082011b06092a864886f70d0103013082010c0282010100ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff0201020202040003820106000282010100b8dec97101206b8c4f2b44549a9b0b48f0357dc7af3d4e26941bf57c066699c3975925299d84f6850b7c393ab8cc594d20cc3f66b722b92177627e9972d98ee11eefd4d548d0b4165643ba0906c8c0fa342a00d94b0f57add0d2ca53851717091e8544a5c477f062eba61f1bb8c4dd80de1d14bef6d8baeba50a66cce9f77b62425d39178107067b4dbbecc54d625c4856d1c1c6679c9b2242b97f00de79b96144a68edbc359b93592385705fe3fb7b20ac2e541fdaf3d426b034e67302f49fe88cd2cbcc3649a28b3e2c985917e01053ffdf7b5188cfc327f43a416cd03954a14b5c4bed669ca1f4ecc92cd0ad1915ad99834b1af40a8e9d35d9fbbd8c7343a",
                16).toByteArray();


        KeyFactory aKeyFac = KeyFactory.getInstance("DH", providerNameX);
        X509EncodedKeySpec x509KeySpecForB = new X509EncodedKeySpec(bPubKeyEnc);
        PublicKey bPubKey = aKeyFac.generatePublic(x509KeySpecForB);

        PrivateKey aPrivKey = aKeyFac.generatePrivate(new PKCS8EncodedKeySpec(aPrivKeyEnc));

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", providerNameX);
        aKeyAgree.init(aPrivKey);

        /*
         * Let's turn over to B. B has received A's public key in encoded format. B
         * instantiates a DH public key from the encoded key material.
         */

        KeyFactory bKeyFac = KeyFactory.getInstance("DH", providerNameY);
        X509EncodedKeySpec x509KeySpecForA = new X509EncodedKeySpec(aPubKeyEnc);
        PublicKey aPubKey = bKeyFac.generatePublic(x509KeySpecForA);

        PrivateKey bPrivKey = bKeyFac.generatePrivate(new PKCS8EncodedKeySpec(bPrivKeyEnc));

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", providerNameY);
        bKeyAgree.init(bPrivKey);

        aKeyAgree.doPhase(bPubKey, true);

        /*
         * B uses A's public key for the first (and only) phase of B's version of the DH
         * protocol.
         */

        bKeyAgree.doPhase(aPubKey, true);

        /*
         * At this stage, both A and B have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aSharedSecret = null;
        byte[] bSharedSecret = null;

        try {
            aSharedSecret = aKeyAgree.generateSecret();
            int aLen = aSharedSecret.length;
            bSharedSecret = new byte[aLen];

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } // provide output buffer of required size
        bKeyAgree.generateSecret(bSharedSecret, 0);

        if (!java.util.Arrays.equals(aSharedSecret, bSharedSecret)) {
            System.out.println("A secret: " + BaseUtils.bytesToHex(aSharedSecret));
            System.out.println("B secret: " + BaseUtils.bytesToHex(bSharedSecret));

            throw new Exception("Shared secrets differ");
        }
        System.out.println("Shared secrets are the same");

        //

    }

    void test_dh_keyFactory(String providerNameX, String providerNameY) throws Exception {
        /*
         * A creates own DH key pair with 2048-bit key size
         */
        //final String methodName = "test_dh_keyFactory ";

        KeyPairGenerator aKpairGen = KeyPairGenerator.getInstance("DH", providerNameX);
        aKpairGen.initialize(2048);

        KeyPair aKpair = aKpairGen.generateKeyPair();

        // A creates and initializes A DH KeyAgreement object
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", providerNameX);
        aKeyAgree.init(aKpair.getPrivate());

        // A encodes A's public key, and sends it over to B.
        byte[] aPubKeyEnc = aKpair.getPublic().getEncoded();


        /*
         * Let's turn over to B. B has received A's public key in encoded format. B
         * instantiates a DH public key from the encoded key material.
         */
        KeyFactory bKeyFac = KeyFactory.getInstance("DH", providerNameY);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(aPubKeyEnc);

        PublicKey aPubKey = bKeyFac.generatePublic(x509KeySpec);


        /*
         * B gets the DH parameters associated with A's public key.B must use the same
         * parameters when B generates B's own key pair.
         */
        DHParameterSpec dhParamFromAPubKey = ((DHPublicKey) aPubKey).getParams();

        KeyPairGenerator bKpairGen = KeyPairGenerator.getInstance("DH", providerNameY);
        bKpairGen.initialize(dhParamFromAPubKey);
        KeyPair bKpair = bKpairGen.generateKeyPair();

        // B creates and initializes DH KeyAgreement object

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", providerNameY);
        bKeyAgree.init(bKpair.getPrivate());

        // B encodes public key, and sends it over to A.
        byte[] bPubKeyEnc = bKpair.getPublic().getEncoded();


        /*
         * A uses B's public key for the first (and only) phase of A's version of the DH
         * protocol. Before A can do so, A has to instantiate a DH public key from B's
         * encoded key material.
         */
        KeyFactory aKeyFac = KeyFactory.getInstance("DH", providerNameX);
        x509KeySpec = new X509EncodedKeySpec(bPubKeyEnc);
        PublicKey bPubKey = aKeyFac.generatePublic(x509KeySpec);

        aKeyAgree.doPhase(bPubKey, true);

        /*
         * B uses A's public key for the first (and only) phase of B's version of the DH
         * protocol.
         */

        bKeyAgree.doPhase(aPubKey, true);

        /*
         * At this stage, both A and B have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aSharedSecret = null;
        byte[] bSharedSecret = null;

        try {
            aSharedSecret = aKeyAgree.generateSecret();
            int aLen = aSharedSecret.length;
            bSharedSecret = new byte[aLen];

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } // provide output buffer of required size
        bKeyAgree.generateSecret(bSharedSecret, 0);

        if (!java.util.Arrays.equals(aSharedSecret, bSharedSecret)) {
            System.out.println("A secret: " + BaseUtils.bytesToHex(aSharedSecret));
            System.out.println("B secret: " + BaseUtils.bytesToHex(bSharedSecret));

            System.out.println(
                    "KeyPairA.privKey=" + BaseUtils.bytesToHex(aKpair.getPrivate().getEncoded()));
            System.out.println(
                    "KeyPairA.publicKey=" + BaseUtils.bytesToHex(aKpair.getPublic().getEncoded()));

            System.out.println(
                    "KeyPairB.privKey=" + BaseUtils.bytesToHex(bKpair.getPrivate().getEncoded()));
            System.out.println(
                    "KeyPairB.publicKey=" + BaseUtils.bytesToHex(bKpair.getPublic().getEncoded()));

            throw new Exception("Shared secrets differ");
        }
        System.out.println("Shared secrets are the same");

        /*
         * Now let's create a SecretKey object using the shared secret and use it for
         * encryption. First, we generate SecretKeys for the "AES" algorithm (based on
         * the raw shared secret data) and Then we use AES in CBC mode, which requires
         * an initialization vector (IV) parameter. Note that you have to use the same
         * IV for encryption and decryption: If you use a different IV for decryption
         * than you used for encryption, decryption will fail.
         *
         * If you do not specify an IV when you initialize the Cipher object for
         * encryption, the underlying implementation will generate a random one, which
         * you have to retrieve using the javax.crypto.Cipher.getParameters() method,
         * which returns an instance of java.security.AlgorithmParameters. You need to
         * transfer the contents of that object (e.g., in encoded format, obtained via
         * the AlgorithmParameters.getEncoded() method) to the party who will do the
         * decryption. When initializing the Cipher for decryption, the (reinstantiated)
         * AlgorithmParameters object must be explicitly passed to the Cipher.init()
         * method.
         */

        SecretKeySpec bAesKey = new SecretKeySpec(bSharedSecret, 0, 16, "AES");
        SecretKeySpec aAesKey = new SecretKeySpec(aSharedSecret, 0, 16, "AES");

        /*
         * B encrypts, using AES in CBC mode
         */
        Cipher bCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", providerNameX);
        bCipher.init(Cipher.ENCRYPT_MODE, bAesKey);
        byte[] cleartext = "This is just an example".getBytes();
        byte[] ciphertext = bCipher.doFinal(cleartext);

        // Retrieve the parameter that was used, and transfer it to A in
        // encoded format
        byte[] encodedParams = bCipher.getParameters().getEncoded();

        /*
         * A decrypts, using AES in CBC mode
         */

        // Instantiate AlgorithmParameters object from parameter encoding
        // obtained from B
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES", providerNameX);
        aesParams.init(encodedParams);
        Cipher aCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", providerNameX);
        aCipher.init(Cipher.DECRYPT_MODE, aAesKey, aesParams);
        byte[] recovered = aCipher.doFinal(ciphertext);
        if (!java.util.Arrays.equals(cleartext, recovered))
            throw new Exception("AES in CBC mode recovered text is " + "different from cleartext");
        System.out.println("AES in CBC mode recovered text is " + "same as cleartext");
    }

}
