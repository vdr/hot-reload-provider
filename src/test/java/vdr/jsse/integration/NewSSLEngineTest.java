package vdr.jsse.integration;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vdr.jsse.HotReloadProvider;
import vdr.jsse.KeystoreReloadCompleteNotifier;
import vdr.jsse.test.SslContextBuilder;
import vdr.jsse.test.TestUtils;
import vdr.jsse.test.engine.Channel;
import vdr.jsse.test.engine.NioClient;
import vdr.jsse.test.engine.NioServer;
import vdr.jsse.test.engine.SslChannel;

@Disabled // Currently, causes timeout.
class NewSSLEngineTest {
    private static final Logger LOG = LoggerFactory.getLogger(NewSSLEngineTest.class);
    private SslContextBuilder clientContextBuilder;
    private Channel.Builder clientChannelBuilder;

    private SslContextBuilder serverContextBuilder;
    private Channel.Builder serverChannelBuilder;
    private NioServer server;

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


    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop();
        }
    }

    private void init(String protocol) throws IOException {
        clientKeyStoreFile = Files.createTempFile("clientKeyStore", ".p12");
        clientPasswordFile = Files.createTempFile("clientPassword", ".creds");
        clientKeypassFile = Files.createTempFile("clientKeypass", ".creds");
        TestUtils.copyFile("src/test/resources/client1.p12", clientKeyStoreFile.toString());
        TestUtils.copyFile("src/test/resources/password.creds", clientPasswordFile.toString());
        TestUtils.copyFile("src/test/resources/keypass.creds", clientKeypassFile.toString());

        initClientBuilders(protocol);
        initServerBuilders(protocol);
    }

    private void initClientBuilders(String protocol) throws IOException {
        clientContextBuilder = new SslContextBuilder(
                protocol,
                clientKeyStoreFile.toString(), HotReloadProvider.ALGO_KEYSTORE, "confluent", "confluent",
                "src/test/resources/truststore.p12", "PKCS12", "confluent",
                HotReloadProvider.ALGO_KEYMANAGER_X509, HotReloadProvider.ALGO_TRUSTMANAGER_PKIX,
                HotReloadProvider.NAME, clientPasswordFile.toString(), clientKeypassFile.toString());
        clientChannelBuilder = channel -> SslChannel.client(channel, clientContextBuilder);
    }

    private void initServerBuilders(String protocol) throws IOException {
        serverContextBuilder = new SslContextBuilder(
                protocol,
                "src/test/resources/server.p12", "PKCS12", "confluent", "confluent",
                "src/test/resources/truststore.p12", "PKCS12", "confluent",
                HotReloadProvider.ALGO_KEYMANAGER_X509, HotReloadProvider.ALGO_TRUSTMANAGER_PKIX,
                HotReloadProvider.NAME, null, null);
        serverChannelBuilder = channel -> SslChannel.server(channel, serverContextBuilder);
    }

    @ParameterizedTest
    @CsvSource({
            "TLSv1.2, false, false,INFO",
            "TLSv1.2, true, false, INFO",
            "TLSv1.2, false, true, INFO",
            "TLSv1.3, false, false, INFO",
            "TLSv1.3, false, true, INFO",
            "TLSv1.3, true, false, INFO",
            /* Some of our logging is intense, better check it does not break anything */
            "TLSv1.2, true, false, DEBUG",
            "TLSv1.3, true, false, DEBUG",
            "TLSv1.2, true, false, TRACE",
            "TLSv1.3, true, false, TRACE",
    })
    void supportTLSCommunication(String protocol, boolean reload, boolean testPasswordChange, String logLevel, TestInfo test) throws Throwable {
        LOG.info("Running test {}", test.toString()); // As this spawn background processing tasks, this logging can help sort through the logs

        ExecutorService service = Executors.newSingleThreadExecutor();
        Future<Boolean> result = service.submit(() -> doTestSslEngine(protocol, reload, testPasswordChange, logLevel, test));

        LOG.info("Waiting for test completion: {}", test);

        try {
            result.get(30, SECONDS);
        } catch (ExecutionException e) {
            LOG.error("Test {} failed: {}", test, e.getMessage());
            throw e.getCause();
        }
    }

    boolean doTestSslEngine(String protocol, boolean reload, boolean testPasswordChange, String logLevel, TestInfo test) throws Exception {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        ch.qos.logback.classic.Logger logger = context.getLogger(HotReloadProvider.class.getPackage().getName());

        Level originalLevel = logger.getLevel();
        LOG.info(test.toString()); // As this spawn background processing tasks, this logging can help sort through the logs

        NioClient client = null;
        try {
            logger.setLevel(Level.toLevel(logLevel));
            init(protocol);

            server = new NioServer(serverChannelBuilder);
            server.startInBackground();

            client = new NioClient(clientChannelBuilder);
            client.start(server.getPort());

            String message = "Before reload";
            client.write(message);

            assertThat(client.read()).isEqualTo(message);
            assertThat(client.getChannel().getPeerPrincipal()).startsWith("CN=server");
            assertThat(server.getLastMessageSentClientPrincipal().get()).startsWith("CN=client1");

            if (reload) {
                SslChannel clientChannel = (SslChannel) client.getChannel();
                KeystoreReloadCompleteNotifier notifier = new KeystoreReloadCompleteNotifier(clientChannel.getContext().getKeyStore());
                // Trigger a reload
                TestUtils.copyFile("src/test/resources/client2.p12", clientKeyStoreFile.toString());
                notifier.awaitUntilKeystoreReloaded(20, SECONDS);
            }

            if (testPasswordChange) {
                SslChannel clientChannel = (SslChannel) client.getChannel();
                KeystoreReloadCompleteNotifier notifier = new KeystoreReloadCompleteNotifier(clientChannel.getContext().getKeyStore());
                // Trigger a reload and change password
                TestUtils.updateFile(clientPasswordFile, "notconfluent");
                TestUtils.updateFile(clientKeypassFile, "notconfluent");
                TestUtils.copyFile("src/test/resources/client3.p12", clientKeyStoreFile.toString());
                notifier.awaitUntilKeystoreReloaded(20, SECONDS);
            }

            message = "After reload";
            client.write(message);
            assertThat(client.read()).isEqualTo(message);
            assertThat(client.getChannel().getPeerPrincipal()).startsWith("CN=server");
            if(reload) {
                assertThat(server.getLastMessageSentClientPrincipal().get()).startsWith("CN=client2");
            } else if(testPasswordChange) {
                assertThat(server.getLastMessageSentClientPrincipal().get()).startsWith("CN=client3");
            } else {
                assertThat(server.getLastMessageSentClientPrincipal().get()).startsWith("CN=client1");
            }
        } finally {
            logger.setLevel(originalLevel);
            if (client != null) {
                client.close();
            }
        }

        return true;
    }
}
