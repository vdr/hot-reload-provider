package vdr.jsse.test.engine;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import lombok.Getter;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

public class NioServer {
    private static final Logger LOG = LoggerFactory.getLogger(NioServer.class);
    private final Channel.Builder builder;

    private ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r);
        thread.setName("Server");
        thread.setDaemon(true); // do not prevent JVM shutdown

        return thread;
    });

    @Getter
    private volatile int port;
    private volatile boolean closed = false;
    private InetSocketAddress listenAddress;
    private Selector selector;
    @Getter
    private AtomicReference<String> lastMessageSentClientPrincipal = new AtomicReference<>(Channel.ANONYMOUS);

    public NioServer(Channel.Builder builder) {
        this(builder,"localhost", 0);
    }

    public NioServer(Channel.Builder builder, String address, int port) {
        this.builder = builder;
        this.port = port;

        listenAddress = new InetSocketAddress(address, port);
    }

    /**
     * Start the server in a background thread.
     */
    public void startInBackground() {
        closed = false;
        executor.execute(this::threadRunnable);
        await().until(() -> this.getPort() != 0);
    }

    /**
     * Stop the server.
     */
    public void stop() {
        closed = true;
        try {
            executor.awaitTermination(1, SECONDS);
        } catch (InterruptedException e) {
            LOG.error("Could not terminate server", e);
        } finally {
            executor.shutdownNow();
        }
    }

    private void threadRunnable() {
        try {
            start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public void start() throws IOException {
        this.selector = Selector.open();
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);

        // retrieve server socket and bind to port
        serverChannel.socket().bind(listenAddress);
        port = serverChannel.socket().getLocalPort();
        serverChannel.register(this.selector, SelectionKey.OP_ACCEPT);

        LOG.info("Server started on {}:{}", listenAddress.getHostName(), port);

        while (!closed) {
            // wait for events
            this.selector.select();

            //work on selected keys
            Iterator<SelectionKey> keys = this.selector.selectedKeys().iterator();
            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove();

                if (!key.isValid()) {
                    continue;
                }
                try {
                    if (key.isAcceptable()) {
                        this.accept(key);
                    } else if (key.isReadable()) {
                        this.read(key);
                    } else if (key.isWritable()) {
                        this.write(key);
                    }
                } catch (IOException e) {
                    key.cancel();
                    key.channel().close();
                }
            }
        }

        LOG.info("Server stopped on {}:{}", listenAddress.getHostName(), port);
    }

    private void accept(SelectionKey key) throws IOException {
        ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
        SocketChannel channel = serverChannel.accept();
        channel.configureBlocking(false);
        Socket socket = channel.socket();
        InetSocketAddress remoteAddr = (InetSocketAddress) socket.getRemoteSocketAddress();

        LOG.info("Accepted connection from {}:{}", remoteAddr.getHostName(), remoteAddr.getPort());

        SelectionKey clientKey = channel.register(this.selector, SelectionKey.OP_READ);

        ChannelData channelData = new ChannelData();
        channelData.channel = builder.build(channel);

        clientKey.attach(channelData);
    }

    private void read(SelectionKey key) throws IOException {
        ChannelData data = (ChannelData) key.attachment();

        try {
            String received = data.channel.read();
            data.toWrite = received;

            boolean applicationWrite = received != null && !received.isEmpty();
            if (applicationWrite) {
                LOG.debug("Received '{}'", received, received);
                key.interestOps(SelectionKey.OP_WRITE);
            }
            if (data.channel.needsWrap()) {
                LOG.debug("Received Handshaking", received, received);
                key.interestOps(SelectionKey.OP_WRITE);
            }
        } catch (Channel.EOSException e) {
            LOG.warn("Connection ended: {}", e.getMessage());
            key.cancel();
        }
    }

    private void write(SelectionKey key) throws IOException {
        ChannelData data = (ChannelData) key.attachment();
        data.channel.write(data.toWrite);
        if (data.channel.isHandshaking()) {
            LOG.debug("Write Handshaking");
        } else {
            lastMessageSentClientPrincipal.set(data.channel.getPeerPrincipal());
            LOG.debug("Write '{}'", data.toWrite);
        }
        if (data.channel.needsWrap()) {
            key.interestOps(SelectionKey.OP_WRITE);
        } else {
            key.interestOps(SelectionKey.OP_READ);
        }
    }

    private static class ChannelData {
        private Channel channel;
        private String toWrite;
    }
}