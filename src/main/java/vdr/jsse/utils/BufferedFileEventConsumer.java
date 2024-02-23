package vdr.jsse.utils;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import vdr.jsse.HotReloadProvider;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

/**
 * Buffered FileChangedEvent send to a delegate Consumer (i.e. typically {@link vdr.jsse.KeystoreWatcher})
 * <p>
 *     Because of slow file system or long update on a file, you may get multiple notifications
 *     before the file is completely processed, meaning that some reload attempts will happen before the file is ready.
 * </p>
 * <p>
 *     This BufferedConsumer will wait a configurable amount of ms before forwarding it to the downstream consumer.
 *     A list of all the {@link FileWatcher.FileChangedType} received during that buffering window will be maintained and
 *     forwarded to the delegate consumer.
 * </p>
 * @see HotReloadProvider#PROPERTY_EVENT_BUFFER_WINDOW_MS_DEFAULT
 */
@SuppressWarnings("JavadocReference")
class BufferedFileEventConsumer implements Consumer<FileWatcher.FileChangedEvent>, Closeable {
    private final Logger log = LoggerFactory.getLogger(BufferedFileEventConsumer.class);
    private final ScheduledExecutorService executorService;
    /*For testing*/ final long bufferWindowMs;
    /*For testing*/ final Consumer<FileWatcher.FileChangedEvent> delegateConsumer;
    private final Map<File, List<FileWatcher.FileChangedType>> bufferedEvents = new ConcurrentHashMap<>();

    /**
     * Create a new BufferedFileEventConsumer with the specified delegate and buffer window.
     * @param delegateConsumer the consumer to notify after buffer window.
     * @param bufferWindowMs How long do we buffer the events for.
     */
    public BufferedFileEventConsumer(Consumer<FileWatcher.FileChangedEvent> delegateConsumer, long bufferWindowMs) {
        this.delegateConsumer = delegateConsumer;
        this.bufferWindowMs = Math.max(bufferWindowMs, 0);

        DaemonThreadFactory threadFactory = new DaemonThreadFactory(BufferedFileEventConsumer.class.getSimpleName(), this::onExceptionRestart);
        executorService = Executors.newScheduledThreadPool(1, threadFactory);
    }

    @Override
    public void close() throws IOException {
        executorService.shutdownNow();
    }

    private void onExceptionRestart(Thread t, Throwable e) {
        log.warn("Restarting Notifier thread {} after unexpected exception", Thread.currentThread().getName(), e);
    }

    @Override
    public synchronized void accept(FileWatcher.FileChangedEvent event) {
        File file = event.getFile();
        bufferedEvents.computeIfAbsent(file, f -> {
            try {
                executorService.schedule(() -> notify(file), bufferWindowMs, TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException e) {
                log.error("Change in file {} will NOT be notified", file.getPath(), e);
            }
            return new ArrayList<>();
        }).addAll(event.getTypes());
    }

    private synchronized void notify(File file) {
        List<FileWatcher.FileChangedType> types = bufferedEvents.remove(file);

        log.info("Notify of changes in file {}", file.getPath());
        try {
            delegateConsumer.accept(new FileWatcher.FileChangedEvent(file, types));
        } catch (RuntimeException e) {
            log.warn("Notifier {} unexpected exception: {}", Thread.currentThread().getName(), e.toString(), e);
        }
    }
}
