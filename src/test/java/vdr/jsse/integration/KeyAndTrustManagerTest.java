package vdr.jsse.integration;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static vdr.jsse.HotReloadProvider.ALGO_KEYMANAGER_X509;
import static vdr.jsse.HotReloadProvider.ALGO_KEYSTORE;
import static vdr.jsse.HotReloadProvider.ALGO_TRUSTMANAGER_X509;
import static vdr.jsse.test.TestUtils.copyFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vdr.jsse.HotReloadProvider;

class KeyAndTrustManagerTest {
    private static final Logger LOG = LoggerFactory.getLogger(KeyAndTrustManagerTest.class);
    private static final char[] PASSWORD = "confluent".toCharArray();
    private static final String CLIENT_1 = "client1";
    private static final String CLIENT_2 = "client2";
    private static final Predicate<String> MATCH_UNKNOWN_CA =
        Pattern.compile("C=GB, ST=England, L=London, .+, CN=foreignca").asPredicate();
    private static final Predicate<String> MATCH_KNOWN_CA =
        Pattern.compile("C=GB, ST=England, L=London, .+, CN=ca").asPredicate();

    @BeforeAll
    static void loadProvider() throws IOException {
        HotReloadProvider.enableLast();
    }

    @AfterAll
    static void unloadProvider() {
        HotReloadProvider.disable();
    }

    @Test
    void reloadsKeyStore() throws Exception {
        Path keyStoreFile = Files.createTempFile("keyStore", ".p12");
        copyFile("src/test/resources/client1.p12", keyStoreFile.toString());

        KeyStore keyStore = createReloadableKeystore(keyStoreFile);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(ALGO_KEYMANAGER_X509);
        kmf.init(keyStore, PASSWORD);

        X509ExtendedKeyManager keyManager = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];

        assertThat(keyManager.getPrivateKey(CLIENT_1)).isNotNull();
        assertThat(keyManager.getPrivateKey(CLIENT_2)).isNull();

        copyFile("src/test/resources/client2.p12", keyStoreFile.toString());

        await().pollInterval(1, SECONDS)
                .atMost(20, SECONDS)
                .until(() -> keyManager.getPrivateKey(CLIENT_2), Objects::nonNull);
    }

    @Test
    void reloadTrustStore() throws Exception {
        Path keyStoreFile = Files.createTempFile("trustStore", ".p12");
        copyFile("src/test/resources/foreigntruststore.p12", keyStoreFile.toString());

        KeyStore keyStore = createReloadableKeystore(keyStoreFile);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(ALGO_TRUSTMANAGER_X509);
        tmf.init(keyStore);

        X509ExtendedTrustManager trustManager = (X509ExtendedTrustManager) tmf.getTrustManagers()[0];

        assertThat(trustManager.getAcceptedIssuers()[0].getSubjectDN().getName()).matches(MATCH_UNKNOWN_CA);

        copyFile("src/test/resources/truststore.p12", keyStoreFile.toString());

        await().pollInterval(1, SECONDS)
                .atMost(20, SECONDS)
                .until(() -> trustManager.getAcceptedIssuers()[0].getSubjectDN().getName(), MATCH_KNOWN_CA);
    }

    private KeyStore createReloadableKeystore(Path path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ALGO_KEYSTORE);
        String location = "location=" + path.toAbsolutePath();
        try (InputStream stream = new ByteArrayInputStream(location.getBytes(StandardCharsets.ISO_8859_1))) {
            keyStore.load(stream, PASSWORD);
        }

        return keyStore;
    }
}
