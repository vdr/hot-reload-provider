package vdr.jsse.integration;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static vdr.jsse.HotReloadProvider.ALGO_KEYMANAGER_X509;
import static vdr.jsse.HotReloadProvider.ALGO_KEYSTORE;
import static vdr.jsse.HotReloadProvider.ALGO_TRUSTMANAGER_X509;
import static vdr.jsse.test.TestUtils.copyFile;
import static vdr.jsse.test.TestUtils.updateFile;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vdr.jsse.HotReloadProvider;
import vdr.jsse.KeystoreReloadCompleteNotifier;
import vdr.jsse.test.SimpleSSLChannel;
import vdr.jsse.test.SimpleSSLChannel.RoundTripResult;
import vdr.jsse.test.SslContextBuilder;

class SSLEngineTest {
    private static final Logger LOG = LoggerFactory.getLogger(SSLEngineTest.class);
    private SslContextBuilder clientBuilder;
    private SslContextBuilder serverBuilder;
    private Path clientKeyStoreFile;
    private Path clientPasswordFile;
    private Path clientKeypassFile;

    @BeforeAll
    static void loadProvider() throws IOException {
        HotReloadProvider.enableLast();
    }

    @AfterAll
    static void unloadProvider() {
        HotReloadProvider.disable();
    }

    private void initBuilders(String protocol) throws IOException {
        clientKeyStoreFile = Files.createTempFile("clientKeyStore", ".p12");
        clientPasswordFile = Files.createTempFile("clientPassword", ".creds");
        clientKeypassFile = Files.createTempFile("clientKeypass", ".creds");
        copyFile("src/test/resources/client1.p12", clientKeyStoreFile.toString());
        copyFile("src/test/resources/password.creds", clientPasswordFile.toString());
        copyFile("src/test/resources/keypass.creds", clientKeypassFile.toString());

        clientBuilder = new SslContextBuilder(
                protocol,
                clientKeyStoreFile.toString(), ALGO_KEYSTORE, "confluent", "confluent",
                "src/test/resources/truststore.p12", "PKCS12", "confluent",
                ALGO_KEYMANAGER_X509, ALGO_TRUSTMANAGER_X509,
                HotReloadProvider.NAME, clientPasswordFile.toString(), clientKeypassFile.toString());

        serverBuilder = new SslContextBuilder(
                protocol,
                "src/test/resources/server.p12", "PKCS12", "confluent", "confluent",
                "src/test/resources/truststore.p12", "PKCS12", "confluent",
                ALGO_KEYMANAGER_X509, ALGO_TRUSTMANAGER_X509,
                HotReloadProvider.NAME, null, null);
    }

    @Test
    void supportRegularTLSv12(TestInfo test) throws Exception {
        LOG.info(test.toString()); // As this spawn background processing tasks, this logging can help sort through the logs

        initBuilders("TLSv1.2");

        SimpleSSLChannel server = SimpleSSLChannel.server(serverBuilder.build().getSslContext());
        SimpleSSLChannel client = SimpleSSLChannel.client(clientBuilder.build().getSslContext(), server);

        String request = "Hola, Don Pepito";
        String response = "Hola, Don José";

        String responseReceived = null;
        String requestReceived = null;

        String serverPrincipal = null;
        String clientPrincipal = null;

        int i = 0;
        boolean done = false;
        while (i < 20 && !done) {
            LOG.debug("Rountrip " + (i + 1));
            RoundTripResult result = SimpleSSLChannel.roundTrip(client, request, server, response);

            done = result.isClosed();
            if (result.getClientReceived() != null) {
                responseReceived = result.getClientReceived();
                serverPrincipal = client.getPeerPrincipal();
                // We received our response, no need for the server anymore.
                client.close();
                // Let's keep looping 2 more times until the server is notified
                // and the CLOSE_NOTIFY handshake can take place.
            }
            if (result.getServerReceived() != null) {
                requestReceived = result.getServerReceived();
                clientPrincipal = server.getPeerPrincipal();
            }

            i++;
        }

        assertThat(clientPrincipal).startsWith("CN=client1");
        assertThat(serverPrincipal).startsWith("CN=server");

        assertThat(requestReceived).isEqualTo(request);
        assertThat(responseReceived).isEqualTo(response);

        assertThat(i)
                .withFailMessage("Both client and server engine should have closed nicely in less than the max iteration")
                .isLessThan(20);
    }

    @Test
    void supportReloadTLSv12(TestInfo test) throws Exception {
        LOG.info(test.toString()); // As this spawn background processing tasks, this logging can help sort through the logs

        initBuilders("TLSv1.2");

        SimpleSSLChannel server = SimpleSSLChannel.server(serverBuilder.build().getSslContext());
        SslContextBuilder.SSLContextBuilt clientContextBuilt = clientBuilder.build();
        KeyStore keyStore = clientContextBuilt.getKeyStore();
        SimpleSSLChannel client = SimpleSSLChannel.client(clientContextBuilt.getSslContext(), server);

        String request = "Ping";
        String response = "Pong";

        String serverPrincipal = null;
        String clientPrincipal = null;

        boolean reloaded = false;
        String reloadedClientPrincipal = null;

        int i = 0;
        boolean done = false;
        while (i < 20 && !done) {
            LOG.debug("Rountrip " + (i + 1));
            RoundTripResult result = SimpleSSLChannel.roundTrip(client, request, server, response);

            done = result.isClosed();
            if (client.isReady()) {
                serverPrincipal = client.getPeerPrincipal();
            }
            if (server.isReady()) {
                if (!reloaded) {
                    KeystoreReloadCompleteNotifier notifier = new KeystoreReloadCompleteNotifier(keyStore);

                    clientPrincipal = server.getPeerPrincipal();
                    copyFile("src/test/resources/client2.p12", clientKeyStoreFile.toString());
                    LOG.debug("Wait for FileChange event to be detected (wait 11sec)");
                    notifier.awaitUntilKeystoreReloaded(20, SECONDS);
                    LOG.debug("Keystore should be reloaded, resume test");

                    reloaded = true;
                } else {
                    reloadedClientPrincipal = server.getPeerPrincipal();
                    client.close();
                }
            }

            i++;
        }

        assertThat(clientPrincipal).startsWith("CN=client1");
        assertThat(reloadedClientPrincipal).startsWith("CN=client2");
        assertThat(serverPrincipal).startsWith("CN=server");

        assertThat(i)
                .withFailMessage("Both client and server engine should have closed nicely in less than the max iteration")
                .isLessThan(20);
    }

    @Test
    void supportReloadWithPasswordChangeTLSv12(TestInfo test) throws Exception {
        LOG.info(test.toString()); // As this spawn background processing tasks, this logging can help sort through the logs

        initBuilders("TLSv1.2");

        SimpleSSLChannel server = SimpleSSLChannel.server(serverBuilder.build().getSslContext());
        SslContextBuilder.SSLContextBuilt clientContextBuilt = clientBuilder.build();
        KeyStore keyStore = clientContextBuilt.getKeyStore();
        SimpleSSLChannel client = SimpleSSLChannel.client(clientContextBuilt.getSslContext(), server);

        String request = "Ping";
        String response = "Pong";

        String serverPrincipal = null;
        String clientPrincipal = null;

        boolean reloaded = false;
        String reloadedClientPrincipal = null;

        int i = 0;
        boolean done = false;
        while (i < 20 && !done) {
            LOG.debug("Rountrip " + (i + 1));
            RoundTripResult result = SimpleSSLChannel.roundTrip(client, request, server, response);

            done = result.isClosed();
            if (client.isReady()) {
                serverPrincipal = client.getPeerPrincipal();
            }
            if (server.isReady()) {
                if (!reloaded) {
                    KeystoreReloadCompleteNotifier notifier = new KeystoreReloadCompleteNotifier(keyStore);

                    clientPrincipal = server.getPeerPrincipal();
                    LOG.debug("Updating password files to match client3's password");
                    updateFile(clientPasswordFile, "notconfluent");
                    updateFile(clientKeypassFile, "notconfluent");
                    copyFile("src/test/resources/client3.p12", clientKeyStoreFile.toString());
                    LOG.debug("Wait for FileChange event to be detected (wait 11sec)");
                    notifier.awaitUntilKeystoreReloaded(20, SECONDS);
                    LOG.debug("Keystore should be reloaded, resume test");

                    reloaded = true;
                } else {
                    reloadedClientPrincipal = server.getPeerPrincipal();
                    client.close();
                }
            }

            i++;
        }

        assertThat(clientPrincipal).startsWith("CN=client1");
        assertThat(reloadedClientPrincipal).startsWith("CN=client3");
        assertThat(serverPrincipal).startsWith("CN=server");

        assertThat(i)
                .withFailMessage("Both client and server engine should have closed nicely in less than the max iteration")
                .isLessThan(20);
    }

    /** Some of our logging is intense, better check it does not break anything */
    @ParameterizedTest
    @ValueSource(strings = {"DEBUG", "TRACE"})
    void providesVerboseLoggingLevels(String targetLevel, TestInfo test) throws Exception {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        ch.qos.logback.classic.Logger logger = context.getLogger(HotReloadProvider.class.getPackage().getName());

        Level originalLevel = logger.getLevel();
        try {
            logger.setLevel(Level.toLevel(targetLevel));
            supportReloadTLSv12(test);
        } finally {
            logger.setLevel(originalLevel);
        }
    }
}
