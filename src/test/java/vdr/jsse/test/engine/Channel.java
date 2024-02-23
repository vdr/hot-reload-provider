package vdr.jsse.test.engine;

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.SocketChannel;

/**
 * SocketChannel wrapper. Can be used to transparently implement a protocol over a channel using either SSL or plain text.
 */
public interface Channel extends Closeable {
    String ANONYMOUS = "ANONYMOUS";

    void write(String message) throws IOException;
    String read() throws IOException;

    /**
     * @return true if the channel is handshaking and not ready for application data.
     */
    default boolean isHandshaking() {
        return false;
    }

    /**
     * @return true if non application data needs writing to the channel.
     */
    default boolean needsWrap() {
        return false;
    }
    /**
     * @return true if non application data needs reading from the channel.
     */
    default boolean needsUnwrap() {
        return false;
    }

    default String getPeerPrincipal() {
        return ANONYMOUS;
    }

    default String getLocalPrincipal() {
        return ANONYMOUS;
    }

    @FunctionalInterface
    interface Builder {
        Channel build(SocketChannel channel);
    }

    class EOSException extends IOException {
        public EOSException(String message) {
            super(message);
        }
    }
}
