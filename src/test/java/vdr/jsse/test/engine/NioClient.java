package vdr.jsse.test.engine;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

@RequiredArgsConstructor
public class NioClient {
    private static final Logger LOG = LoggerFactory.getLogger(NioServer.class);
    private final Channel.Builder builder;
    @Getter
    private Channel channel;
    private int port;

    public void start(int port) throws IOException {
        this.port = port;

        InetSocketAddress hostAddress = new InetSocketAddress("localhost", port);
        SocketChannel socketChannel = SocketChannel.open(hostAddress);
        LOG.info("Client connected to Server localhost:{}", port);

        channel = builder.build(socketChannel);
    }

    public String read() throws IOException {
        try {
            return channel.read();
        } catch (ClosedChannelException e) {
            LOG.info("Client unexpectedly disconnected, try reconnecting once.");
            start(port);
            return channel.read();
        }
    }

    public void write(String message) throws IOException {
        try {
            channel.write(message);
        } catch (ClosedChannelException e) {
            LOG.info("Client unexpectedly disconnected, try reconnecting once.");
            start(port);
            channel.write(message);
        }
    }

    public void close() throws IOException {
        channel.close();
    }
}

