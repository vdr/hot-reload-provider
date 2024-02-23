package vdr.jsse.demo;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import vdr.jsse.HotReloadProvider;
import vdr.jsse.test.TestUtils;

/**
 * An extended version of {@link SSLEngineSimpleDemo}
 * <p>
 *     Adds:
 *     <ul>
 *         <li>Multiple communication between client and server</li>
 *         <li>Trigger a reload of SSL certificates</li>
 *     </ul>
 * </p>
 * <p>
 *     Kept as close as possible to Oracle provided example.<br/>
 *     This should not be used as a basic for production code, but as an illustration of message flows.
 * </p>
 *
 * @see SSLEngineSimpleDemo
 * @see <a href='https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/samples/sslengine/SSLEngineSimpleDemo.java'>Java8 SSLEngineSimpleDemo</a>
 * @see <a href='https://www.youtube.com/watch?v=JcFjp61Vz40'>Video on TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 handshake</a>
 * @see <a href='https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384/'>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</a>
 */
public class SSLEngineSimpleDemoWithReload {
    /*
     * Enables logging of the SSLEngine operations.
     */
    private static boolean logging = true;

    /*
     * Enables the JSSE system debugging system property:
     *
     *     -Djavax.net.debug=all
     *
     * This gives a lot of low-level information about operations underway,
     * including specific handshake messages, and might be best examined
     * after gaining some familiarity with this application.
     */
    private static boolean debug = false;
    // Set to false to not reload.
    private static boolean reload = true;

    private SSLContext clientContext;
    private SSLContext serverContext;

    private KeyStore ks_client;
    private KeyStore ks_server;

    private SSLEngine clientEngine;     // client Engine
    private ByteBuffer clientOut;       // write side of clientEngine
    private ByteBuffer clientIn;        // read side of clientEngine

    private SSLEngine serverEngine;     // server Engine
    private ByteBuffer serverOut;       // write side of serverEngine
    private ByteBuffer serverIn;        // read side of serverEngine

    /*
     * For data transport, this example uses local ByteBuffers.  This
     * isn't really useful, but the purpose of this example is to show
     * SSLEngine concepts, not how to do network transport.
     */
    private ByteBuffer cTOs;            // "reliable" transport client->server
    private ByteBuffer sTOc;            // "reliable" transport server->client

    /*
     * The following is to set up the keystores.
     */
    private static final String sslProvider = HotReloadProvider.NAME;          // or SunJSSE
    private static final String keymanagerAlgo = HotReloadProvider.ALGO_KEYMANAGER_X509;       // or SunX509
    private static final String trustmanagerAlgo = HotReloadProvider.ALGO_TRUSTMANAGER_X509;   // or SunX509

    private static final String client1KeyStoreFile = "src/test/resources/client1.p12";
    private static final String client2KeyStoreFile = "src/test/resources/client2.p12";
    private static String clientKeyStoreFile;
    private static String clientPasswordFile;
    private static String clientKeypassFile;
    private static final String clientKeyStoreAlgo = HotReloadProvider.ALGO_KEYSTORE; // or PKCS12
    private static final String serverKeyStoreFile = "src/test/resources/server.p12";
    private static final String serverKeyStoreAlgo = "PKCS12";      // or PKCS12
    private static final String trustStoreFile = "src/test/resources/truststore.p12";
    private static final String trustStoreAlgo = "PKCS12";          // or PKCS12
    private static final String storepwd = "confluent";
    private static final String keypwd = "confluent";

    private static final List<String> clientMessages = new ArrayList<>(Arrays.asList(
            "> Hola, Don Pepito",
            "> ¿Pasó usted ya por casa?",
            "> ¿Vio usted a mi abuela?",
            "> Adiós, Don Pepito"));
    private static final List<String> serverMessages = new ArrayList<>(Arrays.asList(
            "< Hola, Don José",
            "< Por su casa yo pasé",
            "< A su abuela yo la vi",
            "< Adiós, Don José"));

    /*
     * Main entry point for this demo.
     */
    public static void main(String args[]) throws Exception {
        clientKeyStoreFile = Files.createTempFile("clientKeyStore", ".p12").toString();
        clientPasswordFile = Files.createTempFile("clientPassword", ".creds").toString();
        clientKeypassFile = Files.createTempFile("clientKeypass", ".creds").toString();
        TestUtils.copyFile(client1KeyStoreFile, clientKeyStoreFile);
        TestUtils.copyFile("src/test/resources/password.creds", clientPasswordFile);
        TestUtils.copyFile("src/test/resources/keypass.creds", clientKeypassFile);

        HotReloadProvider.enableLast();

        if (debug) {
            System.setProperty("javax.net.debug", "all");
        }

        SSLEngineSimpleDemoWithReload demo = new SSLEngineSimpleDemoWithReload();
        demo.runDemo();

        System.out.println("Demo Completed.");
    }

    /*
     * Create an initialized SSLContext to use for this demo.
     */
    public SSLEngineSimpleDemoWithReload() throws Exception {

        ks_client = KeyStore.getInstance(clientKeyStoreAlgo);
        ks_server = KeyStore.getInstance(serverKeyStoreAlgo);

        KeyStore ts = KeyStore.getInstance(trustStoreAlgo);

        try (InputStream cdata = loadKeyStoreData(clientKeyStoreFile, clientPasswordFile, clientKeypassFile, clientKeyStoreAlgo);
             InputStream sdata = loadKeyStoreData(serverKeyStoreFile, serverKeyStoreAlgo, "", "");
             InputStream tdata = loadKeyStoreData(trustStoreFile, trustStoreAlgo ,"", "")) {
            ks_client.load(cdata, storepwd.toCharArray());
            ks_server.load(sdata, storepwd.toCharArray());
            ts.load(tdata, storepwd.toCharArray());
        }

        log("Init Client KM");
        KeyManagerFactory kmf_client = KeyManagerFactory.getInstance(keymanagerAlgo);
        kmf_client.init(ks_client, keypwd.toCharArray());

        log("Init Server KM");
        KeyManagerFactory kmf_server = KeyManagerFactory.getInstance(keymanagerAlgo);
        kmf_server.init(ks_server, keypwd.toCharArray());

        log("Init TM");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(trustmanagerAlgo);
        tmf.init(ts);

        log("Init Client SSLContext");
        clientContext = SSLContext.getInstance("TLSv1.2", sslProvider);
        clientContext.init(kmf_client.getKeyManagers(), tmf.getTrustManagers(), null);

        log("Init Server SSLContext");
        serverContext = SSLContext.getInstance("TLSv1.2", sslProvider);
        serverContext.init(kmf_server.getKeyManagers(), tmf.getTrustManagers(), null);
    }

    private InputStream loadKeyStoreData(String keyStoreFile, String passwordFile, String keypassFile, String algo) throws Exception {
        if (algo.equals(HotReloadProvider.ALGO_KEYSTORE)) {
            String location = "location=" + new File(keyStoreFile).getAbsolutePath() + "\n" +
                    "password.location=" + new File(passwordFile).getAbsolutePath() + "\n" +
                    "keypass.location=" + new File(keypassFile).getAbsolutePath();
            return new ByteArrayInputStream(location.getBytes(StandardCharsets.ISO_8859_1));
        } else {
            return new FileInputStream(keyStoreFile);
        }
    }

    /*
     * Run the demo.
     *
     * Sit in a tight loop, both engines calling wrap/unwrap regardless
     * of whether data is available or not.  We do this until both engines
     * report back they are closed.
     *
     * The main loop handles all of the I/O phases of the SSLEngine's
     * lifetime:
     *
     *     initial handshaking
     *     application data transfer
     *     engine closing
     *
     * One could easily separate these phases into separate
     * sections of code.
     */
    private void runDemo() throws Exception {
        boolean dataDone = false;
        boolean reloaded = false;
        createSSLEngines();
        createBuffers();
        if (!createAppData()) {
            return;
        }

        SSLEngineResult clientResult;   // results from client's last operation
        SSLEngineResult serverResult;   // results from server's last operation

        /*
         * Examining the SSLEngineResults could be much more involved,
         * and may alter the overall flow of the application.
         *
         * For example, if we received a BUFFER_OVERFLOW when trying
         * to write to the output pipe, we could reallocate a larger
         * pipe, but instead we wait for the peer to drain it.
         */
        int i = 1;
        while (!isEngineClosed(clientEngine) ||
                !isEngineClosed(serverEngine)) {

            log(i + " ================");

            clientResult = clientEngine.wrap(clientOut, cTOs);
            log("client wrap: ", clientResult, clientEngine);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.wrap(serverOut, sTOc);
            log("server wrap: ", serverResult, serverEngine);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.flip();
            sTOc.flip();

            log("----");

            clientResult = clientEngine.unwrap(sTOc, clientIn);
            log("client unwrap: ", clientResult, clientEngine);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.unwrap(cTOs, serverIn);
            log("server unwrap: ", serverResult, serverEngine);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.compact();
            sTOc.compact();

            /*
             * After we've transfered all application data between the client
             * and server, we close the clientEngine's outbound stream.
             * This generates a close_notify handshake message, which the
             * server engine receives and responds by closing itself.
             *
             * In normal operation, each SSLEngine should call
             * closeOutbound().  To protect against truncation attacks,
             * SSLEngine.closeInbound() should be called whenever it has
             * determined that no more input data will ever be
             * available (say a closed input stream).
             */
            if (!dataDone && (clientOut.limit() == serverIn.position()) &&
                    (serverOut.limit() == clientIn.position())) {

                /*
                 * A sanity check to ensure we got what was sent.
                 */
                checkTransfer(clientOut, serverIn);
                checkTransfer(serverOut, clientIn);

                if (!createAppData()) {
                    log("\tClosing clientEngine's *OUTBOUND*...");
                    clientEngine.closeOutbound();
                    // serverEngine.closeOutbound();
                    dataDone = true;
                } else if (reload && !reloaded) {
                    TestUtils.copyFile(client2KeyStoreFile, clientKeyStoreFile);
                    // Wait for keystore reload.
                    // Could take a while if the JDK/OS uses PollingFileWatching that runs every 10 sec.
                    System.out.println("Wait for FileChange event to be detected (~ 10sec)");
                    await().atMost(20, SECONDS).until(() -> ks_client.containsAlias("client2"));
                    reloaded = true;
                    System.out.println("Keystore should be reloaded, resume handshaking");
                }
            }
            i++;
        }
    }

    /*
     * Using the SSLContext created during object creation,
     * create/configure the SSLEngines we'll use for this demo.
     */
    private void createSSLEngines() throws Exception {
        /*
         * Configure the serverEngine to act as a server in the SSL/TLS
         * handshake.  Also, require SSL client authentication.
         */
        log("Create Server");
        serverEngine = serverContext.createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(true);

        /*
         * Similar to above, but using client mode instead.
         */
        log("Create Client");
        clientEngine = clientContext.createSSLEngine("client", 80);
        clientEngine.setUseClientMode(true);
    }

    /*
     * Create and size the buffers appropriately.
     */
    private void createBuffers() {

        /*
         * We'll assume the buffer sizes are the same
         * between client and server.
         */
        SSLSession clientSession = clientEngine.getSession();
        SSLSession serverSession = serverEngine.getSession();

        /*
         * We'll make the input buffers a bit bigger than the max needed
         * size, so that unwrap()s following a successful data transfer
         * won't generate BUFFER_OVERFLOWS.
         *
         * We'll use a mix of direct and indirect ByteBuffers for
         * tutorial purposes only.  In reality, only use direct
         * ByteBuffers when they give a clear performance enhancement.
         */
        clientIn = ByteBuffer.allocate(clientSession.getApplicationBufferSize() + 50);
        serverIn = ByteBuffer.allocate(serverSession.getApplicationBufferSize() + 50);

        cTOs = ByteBuffer.allocateDirect(clientSession.getPacketBufferSize());
        sTOc = ByteBuffer.allocateDirect(serverSession.getPacketBufferSize());
    }

    /*
     * The data that is exchanged betweeb client and server
     */
    private boolean createAppData() {
        if (clientMessages.isEmpty() && serverMessages.isEmpty()) {
            return false;
        }

        if (!clientMessages.isEmpty()) {
            String clientMessage = clientMessages.remove(0);
            clientOut = ByteBuffer.wrap(clientMessage.getBytes());
        }

        if (!serverMessages.isEmpty()) {
            String serverMessage = serverMessages.remove(0);
            serverOut = ByteBuffer.wrap(serverMessage.getBytes());
        }

        return true;
    }

    /*
     * If the result indicates that we have outstanding tasks to do,
     * go ahead and run them in this thread.
     */
    private static void runDelegatedTasks(SSLEngineResult result,
                                          SSLEngine engine) throws Exception {

        if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                log("\trunning delegated task...");
                runnable.run();
            }
            HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == HandshakeStatus.NEED_TASK) {
                throw new Exception(
                        "handshake shouldn't need additional tasks");
            }
            log("\tnew HandshakeStatus: " + hsStatus);
        }
    }

    private static boolean isEngineClosed(SSLEngine engine) {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }

    /*
     * Simple check to make sure everything came across as expected.
     */
    private static void checkTransfer(ByteBuffer a, ByteBuffer b)
            throws Exception {
        a.flip();
        b.flip();

        if (!a.equals(b)) {
            throw new Exception("Data didn't transfer cleanly");
        } else {
            log("\t" + new String(a.array()));
        }
        a.clear();
        b.clear();
    }

    /*
     * Logging code
     */
    private static boolean resultOnce = true;

    private static void log(String str, SSLEngineResult result, SSLEngine engine) {
        if (!logging) {
            return;
        }
        if (resultOnce) {
            resultOnce = false;
            System.out.println("The format of the SSLEngineResult is: \n" +
                    "\t\"getStatus() / getHandshakeStatus()\" +\n" +
                    "\t\"bytesConsumed() / bytesProduced()\"\n");
        }
        HandshakeStatus hsStatus = result.getHandshakeStatus();
        log(str +
                result.getStatus() + "/" + hsStatus + ", " +
                result.bytesConsumed() + "/" + result.bytesProduced() +
                " bytes");
        if (hsStatus == HandshakeStatus.FINISHED) {
            log("\t...ready for application data");
            log("\t... Local: " + engine.getSession().getLocalPrincipal());
            try {
                log("\t... Peer: " + engine.getSession().getPeerPrincipal());
            } catch (SSLPeerUnverifiedException e) {
                log("\t... Peer: unverified");
            }
        }
    }

    private static void log(String str) {
        if (logging) {
            System.out.println(str);
        }
    }
}