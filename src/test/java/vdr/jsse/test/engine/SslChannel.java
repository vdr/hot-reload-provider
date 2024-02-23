package vdr.jsse.test.engine;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import lombok.Getter;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;
import vdr.jsse.test.SslContextBuilder;

/**
 * Simplified TLS wrapper around a blocking SocketChannel.
 * <p>
 *     Supports client mode, using blocking IO and transparent handshake processing.
 * </p>
 * <p>
 *     Support server mode to be used with a Channel Selector. Expect blocking channel, however no write will be done
 *     on a read call and not read will be done on a write call. The caller should refer to {@link #needsWrap()},
 *     {@link #needsUnwrap()} and {@link #isHandshaking()} to determine what IO operation the channel needs and when
 *     the channel is ready for AppData.
 * </p>
 * <p>
 *     Limitations:
 *     <ul>
 *         <li>Does not support Non-Blocking channels</li>
 *         <li>Does not support fragmented records</li>
 *         <li>Does not support sslBuffer resizing</li>
 *     </ul>
 * </p>
 */
public final class SslChannel implements Channel {
    private static final Logger LOG = LoggerFactory.getLogger(SslChannel.class);

    @Getter
    private final SslContextBuilder.SSLContextBuilt context;
    private final SocketChannel socketChannel;
    private final SSLEngine sslEngine;

    private boolean client;
    private boolean handshakingNeedsWrap;
    private boolean handshakingNeedsUnwrap;
    private String peerPrincipal = ANONYMOUS;
    private String localPrincipal = ANONYMOUS;

    private ByteBuffer sslIn;
    private ByteBuffer sslOut;

    private ByteBuffer in;
    private ByteBuffer out;

    public static SslChannel client(SocketChannel channel, SslContextBuilder contextBuilder) {
        SslContextBuilder.SSLContextBuilt built;
        try {
            built = contextBuilder.build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        SSLEngine engine = built.getSslContext().createSSLEngine();
        engine.setUseClientMode(true);

        return new SslChannel(built, channel, engine);
    }

    public static SslChannel server(SocketChannel channel, SslContextBuilder contextBuilder) {
        SslContextBuilder.SSLContextBuilt built;
        try {
            built = contextBuilder.build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        SSLEngine engine = built.getSslContext().createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);

        return new SslChannel(built, channel, engine);
    }

    private SslChannel(SslContextBuilder.SSLContextBuilt context, SocketChannel socketChannel, SSLEngine sslEngine) {
        this.context = context;
        this.socketChannel = socketChannel;
        this.sslEngine = sslEngine;
        this.client = sslEngine.getUseClientMode();

        SSLSession sslSession = sslEngine.getSession();

        // Keep Application buffer a bit bigger to avoid BUFFER_OVERFLOWS
        this.in = ByteBuffer.allocate(sslSession.getApplicationBufferSize() + 50);
        this.out = ByteBuffer.allocate(sslSession.getApplicationBufferSize() + 50);

        this.sslIn = ByteBuffer.allocate(sslSession.getPacketBufferSize());
        this.sslOut = ByteBuffer.allocate(sslSession.getPacketBufferSize());

        sslSession.invalidate();
    }

    @Override
    public boolean isHandshaking() {
        return needsWrap() || needsUnwrap();
    }

    @Override
    public boolean needsWrap() {
        return handshakingNeedsWrap;
    }

    @Override
    public boolean needsUnwrap() {
        return handshakingNeedsUnwrap;
    }

    @Override
    public String getPeerPrincipal() {
        return peerPrincipal;
    }

    @Override
    public String getLocalPrincipal() {
        return localPrincipal;
    }

    public String read() throws IOException {
        debug("Read()");
        do {
            // No complete message available, read from the channel and unwrap and try again
            doUnwrap();
        } while (socketChannel.isOpen() && client && !(in.position() > 0));

        in.flip();
        String message = StandardCharsets.UTF_8.decode(in).toString();
        in.compact();

        if (!socketChannel.isOpen()) {
            throw new ClosedChannelException();
        }

        return message;
    }

    private void doUnwrap() throws IOException {
        handshakingNeedsUnwrap = false;

        if (sslIn.position() == 0) {
            // The network input buffer is empty; read data from the channel before doing the unwrap
            readChannel();
        }
        sslIn.flip();

        SSLEngineResult result;
        try {
            result = sslEngine.unwrap(sslIn, in);
        } catch (SSLException e) {
            warn("Exception while calling SSLEngine.unwrap()", e);
            closeChannel();
            return;
        }
        trace("SSLEngine.unwrap(): {}", toString(result, false));
        sslIn.compact();

        // It is important to perform the appropriate action for the result status and the result handshake status.
        // NOTE: The handshake status FINISHED is a transient status. It is important to look at the status in the
        // result and not just call sslEngine.getStatus() because the FINISHED status will only be reported once,
        // in the result returned by wrap() or unwrap().
        switch (result.getStatus()) {
            case OK:
                checkHandshakeStatus(result.getHandshakeStatus());
                break;

            case CLOSED:
                checkHandshakeStatus(result.getHandshakeStatus());
                close();
                break;

            case BUFFER_UNDERFLOW:
                throw new IOException("BUFFER_UNDERFLOW - should not happen in this simple app");

            case BUFFER_OVERFLOW:
                throw new IOException("BUFFER_OVERFLOW - should not happen in this simple app");

            default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
        }
    }

    public void write(String message) throws IOException {
        message = message == null ? "" : message;
        debug("Write('{}')", message);
        out.put(StandardCharsets.UTF_8.encode(message));
        out.flip();
        do {
            doWrap();
        } while (socketChannel.isOpen() && client && out.hasRemaining());
        out.compact();

        if (!socketChannel.isOpen()) {
            throw new ClosedChannelException();
        }
    }

    private void doWrap() throws IOException {
        handshakingNeedsWrap = false;
        final SSLEngineResult result;

        sslOut.clear();
        try {
            result = sslEngine.wrap(out, sslOut);
        } catch (SSLException e) {
            warn("Exception while calling SSLEngine.wrap()", e);
            closeChannel();
            return;
        }
        sslOut.flip();
        trace("SSLEngine.wrap(): {}", toString(result, true));

        // It is important to perform the appropriate action for the result status and the result handshake status.
        // NOTE: The handshake status FINISHED is a transient status. It is important to look at the status in the
        // result and not just call sslEngine.getStatus() because the FINISHED status will only be reported once,
        // in the result returned by wrap() or unwrap().

        switch (result.getStatus()) {
            case OK:
                writeChannel();
                checkHandshakeStatus(result.getHandshakeStatus());
                break;

            case CLOSED:
                writeChannel();
                checkHandshakeStatus(result.getHandshakeStatus());
                close();
                break;

            case BUFFER_OVERFLOW:
                throw new IOException("BUFFER_OVERFLOW - should not happen in this simple app");

            default:
                throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
        }
    }

    private void checkHandshakeStatus() throws IOException {
        checkHandshakeStatus(sslEngine.getHandshakeStatus());
    }

    private void checkHandshakeStatus(SSLEngineResult.HandshakeStatus handshakeStatus) throws IOException {
        switch (handshakeStatus) {
            case FINISHED:
                localPrincipal = Objects.toString(sslEngine.getSession().getLocalPrincipal(), ANONYMOUS);
                try {
                    peerPrincipal = Objects.toString(sslEngine.getSession().getPeerPrincipal(), ANONYMOUS);
                } catch (SSLPeerUnverifiedException e) {
                    peerPrincipal = ANONYMOUS;
                }
                debug("SSL Handshake finished: connected to {} using protocol: {}", peerPrincipal, sslEngine.getSession().getProtocol());
            case NOT_HANDSHAKING:
                // No action necessary
                handshakingNeedsWrap = false;
                handshakingNeedsUnwrap = false;
                break;

            case NEED_WRAP:
                handshakingNeedsWrap = true;
                if (client) {
                    doWrap();
                }
                break;

            case NEED_UNWRAP:
                handshakingNeedsUnwrap = true;
                boolean hasUnreadInput = sslIn.position() > 0;
                if (client || hasUnreadInput) {
                    doUnwrap();
                }
                break;

            case NEED_TASK:
                doTask();
                break;

            default:
                throw new IllegalStateException("Invalid SSL handshake status: " + handshakeStatus);
        }
    }

    private void doTask() throws IOException {
        Runnable task;
        while ((task = sslEngine.getDelegatedTask()) != null) {
            task.run();
        }
        trace("SSLEngine.runTask(): {}", sslEngine.getHandshakeStatus());
        checkHandshakeStatus();
    }

    private void writeChannel() throws IOException {
        while (sslOut.hasRemaining()) {
            socketChannel.write(sslOut);
        }
    }

    private void readChannel() throws IOException {
        if (socketChannel.read(sslIn) == -1) {
            handleEndOfStream();
        }
    }

    private void handleEndOfStream() throws IOException {
        try {
            // This will check if the server has sent the appropriate SSL close handshake alert and throws an exception
            // if it did not. Note that some servers don't, so this should not be treated as a fatal exception.
            sslEngine.closeInbound();
            close();
        } catch (SSLException e) {
            // This exception might happen because some servers do not respond to the client's close notify alert
            // message during the SSL close handshake; they just close the connection. This is normally not a problem.
            debug("Exception while calling SSLEngine.closeInbound(): {}", e.getMessage());
            closeChannel();
        }
    }

    /**
     * Closes the connection. This will attempt to do the SSL close handshake before closing the connection.
     */
    @Override
    public void close() throws IOException {
        // This tells the SSLEngine that we are not going to pass it any more application data
        // and prepares it for the close handshake
        trace("Performing closing SSL handshake");
        sslEngine.closeOutbound();

        // Perform close handshake
        checkHandshakeStatus();

        closeChannel();
    }

    private void closeChannel() throws IOException {
        if (socketChannel.isOpen()) {
            debug("Closing socket channel");
            socketChannel.close();
        }
    }

    private String toString(SSLEngineResult result, boolean wrap) {
        int consumed = result.bytesConsumed();
        String consumedDetails = wrap ? "" : TLSRecord.describe(sslIn, consumed); // When wrapping, the bytes are consumed from "in" instead of sslIn
        int produced = result.bytesProduced();
        String producedDetails = wrap ? TLSRecord.describe(sslOut, produced) : ""; // When unwrapping, the bytes are produced to "out" instead of sslOut

        return String.format("%s/%s(in= %d%s, out=%d%s)", result.getStatus(), result.getHandshakeStatus(), consumed, consumedDetails, produced, producedDetails);
    }

    private void trace(String message, Object ...args) {
        LOG.trace(prefixMessage(message), args);
    }

    private void debug(String message, Object ...args) {
        LOG.debug(prefixMessage(message), args);
    }

    private void warn(String message, Object ...args) {
        LOG.warn(prefixMessage(message), args);
    }

    private String prefixMessage(String message) {
        String prefix = client ? "TLSClient > " : "TLSServer < ";

        return prefix + message;
    }

}
