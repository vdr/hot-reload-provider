package vdr.jsse.test;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vdr.jsse.demo.SSLEngineSimpleDemo;

/**
 * Very simplified SSLPeer build with the whole socket and network abstracted away using buffer.
 * <p>
 *     Based on {@link SSLEngineSimpleDemo}
 * </p>
 */
@RequiredArgsConstructor
public class SimpleSSLChannel implements Closeable {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleSSLChannel.class);

    private final SSLEngine engine;
    @Getter
    private final ByteBuffer socketIn;
    @Getter
    private final ByteBuffer socketOut;

    @Getter
    private boolean ready;

    /**
     * Create a simple server using the provided context.
     * @param context the context.
     *
     * @return A simple server that has its input/output exposed as buffers.
     */
    public static SimpleSSLChannel server(SSLContext context) {
        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(false); // The engine does not really care about client/server from a network socket point of view
                                        // However, the handshaking behaviour is different between client and server:
                                        // eg: the client initiates the handshake and closes the channel (CLOSE_NOTIFY)
        engine.setNeedClientAuth(true); // mTLS, engage!

        SSLSession dummySession = context.createSSLEngine().getSession();
        ByteBuffer socketIn = ByteBuffer.allocate(dummySession.getPacketBufferSize());
        ByteBuffer socketOut = ByteBuffer.allocate(dummySession.getPacketBufferSize());
        dummySession.invalidate();

        return new SimpleSSLChannel(engine, socketIn, socketOut);
    }

    /**
     * Create a simple client using the provided context and connected to the specified server.
     * @param context the context.
     * @param server the server this client connects to.
     *
     * @return A simple client that has its input/output hardwired into the server input/output.
     */
    public static SimpleSSLChannel client(SSLContext context, SimpleSSLChannel server) {
        SSLEngine engine = context.createSSLEngine("client",  443); // Dummy values: we are not opening a socket
        engine.setUseClientMode(true);

        return new SimpleSSLChannel(engine, server.getSocketOut(), server.getSocketIn());
    }

    /**
     * Simulate a round trip communication between client and server:
     * <ol>
     *     <li>client and server sends their data</li>
     *     <li>"push" the data in the buffer that are used to simulate the network</li>
     *     <li>client and server process incoming data</li>
     * </ol>
     * @param client The client channel.
     * @param clientMessage The message the client intend to send to the server. Or null if nothing to send.
     * @param server The server channel.
     * @param serverMessage The message the server intent to send to the client. Or null if nothing to send.
     * @return The result of the operation. This does not loop through the handshake, so the
     * @throws Exception if something wrong happens.
     */
    public static RoundTripResult roundTrip(SimpleSSLChannel client, String clientMessage, SimpleSSLChannel server, String serverMessage) throws Exception {
        RoundTripResult result = new RoundTripResult();

        // The ordering of operation in here is a bit quirky.
        // The quirkiness is due to using buffer to simulate a network
        // instead of a real (socket)channel
        // and not handling operation or handshake status.

        result.clientSent = client.wrap(Objects.requireNonNull(clientMessage, ""));
        result.serverSent = server.wrap(Objects.requireNonNull(serverMessage, ""));

        client.getSocketIn().flip();
        client.getSocketOut().flip();

        result.clientReceived = client.unwrap();
        result.serverReceived = server.unwrap();

        client.getSocketIn().compact();
        client.getSocketOut().compact();

        result.closed = client.isEngineClosed() && server.isEngineClosed();

        return result;
    }

    @Data
    public static class RoundTripResult {
        private String clientReceived;
        private String serverReceived;
        private boolean clientSent;
        private boolean serverSent;
        private boolean closed;
    }

    public boolean wrap(String message) throws Exception {
        if (isEngineClosed()) {
            throw new IllegalStateException();
        }

        ByteBuffer toWrap = StandardCharsets.UTF_8.encode(message);
        SSLEngineResult result = engine.wrap(toWrap, socketOut); // In normal world, engine encrypt into a buffer
                                                                 // and the buffer is transmitted into a socket
                                                                 // Here both the client and server sees the buffer
                                                                 // "Transmitting" is just flipping and compacting the buffer at the right time.
        processResult("wrap", result);
        runDelegatedTasks();

        // If the engine decides it would rather send its own stuff rather than ours (i.e. handshaking),
        // it will simply ignore the buffer containing our stuff.
        return /* did we send our stuff ? */ toWrap.position() > 0; // otherwise, we were probably just handshaking.
    }

    public String unwrap() throws Exception {
        ByteBuffer unwrapped = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize() + 1024);
        SSLEngineResult result = engine.unwrap(socketIn, unwrapped);
        processResult("unwrap", result);
        runDelegatedTasks();

        // If the engine decides the data we received was his stuff and not ours (i.e. handshaking),
        // it will keep it for itself and not put anything unwrapped the unwrapping buffer.
        if (unwrapped.position() > 0) {
            unwrapped.flip();
            return StandardCharsets.UTF_8.decode(unwrapped).toString();
        } // else we were probably just handshaking.

        return null;
    }

    public boolean isEngineClosed() {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }

    public String getPeerPrincipal() {
        try {
            return engine.getSession().getPeerPrincipal().getName();
        } catch (SSLPeerUnverifiedException e) {
            return "ANONYMOUS";
        }
    }

    public String getPrincipal() {
        Principal principal = engine.getSession().getLocalPrincipal();
        return principal == null ? null : principal.getName();
    }

    @Override
    public void close() throws IOException {
        engine.closeOutbound();
    }

    private void runDelegatedTasks() throws Exception {
        if (engine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                debug("Running delegated task...");
                runnable.run();
            }
            HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == HandshakeStatus.NEED_TASK) {
                throw new Exception("handshake shouldn't need additional tasks");
            }
            debug("New HandshakeStatus: " + hsStatus);
            processHandshakeStatus(hsStatus);
        }
    }

    private void processResult(String stage, SSLEngineResult result) {
        debug(stage, result);
        processHandshakeStatus(result.getHandshakeStatus());
    }

    private void processHandshakeStatus(HandshakeStatus hsStatus) {
        if (hsStatus == HandshakeStatus.FINISHED) {
            ready = true;
            debug("Ready with Peer=" + getPeerPrincipal());
        } else if (hsStatus != HandshakeStatus.NOT_HANDSHAKING) {
            ready = false;
        }
    }

    private void debug(String message) {
        debug(message, null);
    }

    private void debug(String message, SSLEngineResult result) {
        String prefix = (engine.getUseClientMode() ? ">" : "<");
        String suffix = result != null ? toString(result) : "";

        LOG.debug("{} {} {}", prefix, message, suffix);
    }

    private String toString(SSLEngineResult result) {
        return String.format("%s(handshake: %s): in=%d bytes, out=%d bytes",
                result.getStatus(),
                result.getHandshakeStatus(),
                result.bytesConsumed(),
                result.bytesProduced());
    }
}
