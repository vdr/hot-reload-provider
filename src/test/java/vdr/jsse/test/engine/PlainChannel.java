package vdr.jsse.test.engine;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;

/**
 * Plaintext channel, just input/output straight to the channel.
 */
@RequiredArgsConstructor
public final class PlainChannel implements Channel {
    private final SocketChannel channel;
    private ByteBuffer buffer = ByteBuffer.allocate(1024);

    @Override
    public void write(String message) throws IOException {
        channel.write(StandardCharsets.UTF_8.encode(message));
    }

    @Override
    public String read() throws IOException {
        int readCount = channel.read(buffer);

        if (readCount == -1) {
            String message = "Connection closed by peer: " + channel.socket().getRemoteSocketAddress();

            close();

            throw new EOSException(message);
        }

        buffer.flip();
        String result = StandardCharsets.UTF_8.decode(buffer).toString();
        buffer.compact();

        return result;
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
