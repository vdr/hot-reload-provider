package vdr.jsse.demo;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import vdr.jsse.HotReloadProvider;
import vdr.jsse.test.engine.TLSRecord;

/**
 * A tweaked version of Oracle provided <a href='https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/samples/sslengine/SSLEngineSimpleDemo.java'>Java8 SSLEngineSimpleDemo</a>.
 * <p>
 *     Adds multiple Keystores, and display the Principal of peers. Uses mTLS to identify Client with Server.
 *     Configure to use EssJSSE.
 * </p>
 * <p>
 *     As the original, this is simplified to an absurd point and is not a basis for production code.
 *     It is however intended to be read with Java SSL Debug logging enabled, see {@link #debug}.<br/>
 *     When running on Java8, the cypher suite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 should be selected by default,
 *     there are many resource only that describe the handshake for that specific suite.<br/>
 *     Although it uses EssJSSE, it does not affect comprehension of Java SSL Debug output and allow checking EssJSSE own
 *     logging in addition. However, it is possible to use SunJSSE as in the original file.
 * </p>
 * <p>
 *     The rest of the documentation is copied from Oracle original:
 * </p>
 * <p>
 *     The demo creates two SSLEngines, simulating a client and server.
 *     The "transport" layer consists two ByteBuffers:  think of them
 *     as directly connected pipes.
 * </p>
 * <p>
 *     Note, this is a *very* simple example: real code will be much more
 *     involved.  For example, different threading and I/O models could be
 *     used, transport mechanisms could close unexpectedly, and so on.
 * </p>
 * <p>
 *     When this application runs, notice that several messages
 *     (wrap/unwrap) pass before any application data is consumed or
 *     produced.  (For more information, please see the SSL/TLS
 *     specifications.)  There may several steps for a successful handshake,
 *     so it's typical to see the following series of operations:
 *      <pre>
 *      client          server          message
 *      ======          ======          =======
 *      wrap()          ...             ClientHello
 *      ...             unwrap()        ClientHello
 *      ...             wrap()          ServerHello/Certificate
 *      unwrap()        ...             ServerHello/Certificate
 *      wrap()          ...             ClientKeyExchange
 *      wrap()          ...             ChangeCipherSpec
 *      wrap()          ...             Finished
 *      ...             unwrap()        ClientKeyExchange
 *      ...             unwrap()        ChangeCipherSpec
 *      ...             unwrap()        Finished
 *      ...             wrap()          ChangeCipherSpec
 *      ...             wrap()          Finished
 *      unwrap()        ...             ChangeCipherSpec
 *      unwrap()        ...             Finished
 *      </pre>
 * </p>
 * @see <a href='https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/samples/sslengine/SSLEngineSimpleDemo.java'>Java8 SSLEngineSimpleDemo</a>
 * @see <a href='https://www.youtube.com/watch?v=JcFjp61Vz40'>Video on TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 handshake</a>
 * @see <a href='https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384/'>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</a>
 */
public class SSLEngineSimpleDemo {
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

    private SSLContext clientContext;
    private SSLContext serverContext;

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
    private static final String sslProvider = HotReloadProvider.NAME;                           // or SunJSSE
    private static final String keymanagerAlgo = HotReloadProvider.ALGO_KEYMANAGER_X509;       // or SunX509
    private static final String trustmanagerAlgo = HotReloadProvider.ALGO_TRUSTMANAGER_X509;   // or SunX509

    private static final String clientKeyStoreFile = "./src/test/resources/client1.p12";
    private static final String clientKeyStoreAlgo = HotReloadProvider.ALGO_KEYSTORE; // or PKCS12
    private static final String serverKeyStoreFile = "./src/test/resources/server.p12";
    private static final String serverKeyStoreAlgo = HotReloadProvider.ALGO_KEYSTORE; // or PKCS12
    private static final String trustStoreFile = "./src/test/resources/truststore.p12";
    private static final String trustStoreAlgo = HotReloadProvider.ALGO_KEYSTORE;     // or PKCS12
    private static final String storepwd = "confluent";
    private static final String keypwd = "confluent";

    /*
     * Main entry point for this demo.
     */
    public static void main(String args[]) throws Exception {
        HotReloadProvider.enableLast();

        if (debug) {
            System.setProperty("javax.net.debug", "all");
        }

        SSLEngineSimpleDemo demo = new SSLEngineSimpleDemo();
        demo.runDemo();

        System.out.println("Demo Completed.");
    }

    /*
     * Create an initialized SSLContext to use for this demo.
     */
    public SSLEngineSimpleDemo() throws Exception {

        KeyStore ks_client = KeyStore.getInstance(clientKeyStoreAlgo);
        KeyStore ks_server = KeyStore.getInstance(serverKeyStoreAlgo);
        KeyStore ts = KeyStore.getInstance(trustStoreAlgo);

        try (InputStream cdata = loadKeyStoreData(clientKeyStoreFile, clientKeyStoreAlgo);
             InputStream sdata = loadKeyStoreData(serverKeyStoreFile, serverKeyStoreAlgo);
             InputStream tdata = loadKeyStoreData(trustStoreFile, trustStoreAlgo)) {
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

    private InputStream loadKeyStoreData(String file, String algo) throws Exception {
        if (algo.equals(HotReloadProvider.ALGO_KEYSTORE)) {
            String location = "location=" + new File(file).getAbsolutePath();
            return new ByteArrayInputStream(location.getBytes(StandardCharsets.ISO_8859_1));
        } else {
            return new FileInputStream(file);
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

        createSSLEngines();
        createBuffers();

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

            log(i + "================");

            clientResult = clientEngine.wrap(clientOut, cTOs);
            log("client wrap: ", clientResult, clientEngine, sTOc, cTOs);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.wrap(serverOut, sTOc);
            log("server wrap: ", serverResult, serverEngine, cTOs, sTOc);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.flip();
            sTOc.flip();

            log("----");

            clientResult = clientEngine.unwrap(sTOc, clientIn);
            log("client unwrap: ", clientResult, clientEngine, sTOc, cTOs);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.unwrap(cTOs, serverIn);
            log("server unwrap: ", serverResult, serverEngine, cTOs, sTOc);
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
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                log("\tClosing clientEngine's *OUTBOUND*...");
                clientEngine.closeOutbound();
                // serverEngine.closeOutbound();
                dataDone = true;
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

        String clientMessage = "Hi Server, I'm client";
        clientOut = ByteBuffer.wrap(clientMessage.getBytes());

        String serverMessage = "Hello Client, I'm server";
        serverOut = ByteBuffer.wrap(serverMessage.getBytes());
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
            log("\tData transferred cleanly");
        }

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    /*
     * Logging code
     */
    private static boolean resultOnce = true;

    private static void log(String str, SSLEngineResult result, SSLEngine engine, ByteBuffer in, ByteBuffer out) {
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
                result.bytesConsumed() + TLSRecord.describe(in, result.bytesConsumed())  + "/" + result.bytesProduced() + TLSRecord.describe(out, result.bytesProduced()));
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