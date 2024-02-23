package vdr.jsse.utils;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Consumer;
import lombok.Data;
import lombok.NonNull;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

/**
 * Utility simplifying use of {@link java.nio.file.WatchService}
 * <p>
 *     Watches file instead of directories, callback instead of pull notifications.
 * </p>
 */
public class FileWatcher implements Closeable {
    private final Logger log = LoggerFactory.getLogger(FileWatcher.class);
    private final WatchEvent.Modifier[] modifiers;
    private final ExecutorService executorService;
    private final Map<File, Path> watchedFiles = new ConcurrentHashMap<>();
    private final Map<Path, WatchKey> watchedDirectories = new ConcurrentHashMap<>();
    private final WatchService watchService;
    private final long eventsBufferWindowMs;
    /*For testing*/ Consumer<FileChangedEvent> eventConsumer;

    /**
     * Create a new FileWatcher with the specified callback.
     * @param watchService the watchservice to use. It will be closed when this watcher is closed.
     * @param eventsBufferWindowMs Per file wait period on FS event before notifying the eventConsumer.
     *                             Additional events receive in this period for that file will
     *                             be grouped in a single {@link FileChangedEvent}.
     * @param modifiers modifiers used to register Path with the Watchservice. Variable effect Depending on OS/FS/JDK
     *                  and implementation dependent. On PollingWatchService (common), a SensitivityWatchEventModifier
     *                  can be used to change the polling to 30s (LOW), 10s (MEDIUM - default), 2s (HIGH)
     */
    public FileWatcher(WatchService watchService, long eventsBufferWindowMs, WatchEvent.Modifier... modifiers) {
        this.watchService = watchService;
        this.eventsBufferWindowMs = eventsBufferWindowMs;
        this.modifiers = modifiers;

        DaemonThreadFactory threadFactory = new DaemonThreadFactory(FileWatcher.class.getSimpleName(), this::onExceptionRestart);
        executorService = Executors.newSingleThreadExecutor(threadFactory);
    }

    /**
     * Start this FileWatcher.
     * @param eventConsumer the client for notifications.
     */
    public synchronized void start(@NonNull Consumer<FileChangedEvent> eventConsumer) {
        this.eventConsumer = new BufferedFileEventConsumer(eventConsumer, eventsBufferWindowMs);
        restart();
    }

    private void restart() {
        try {
            executorService.execute(this::watchInBackground);
        } catch (RejectedExecutionException e) {
            log.error("Could not start FileWatcher thread, file will not be monitored", e);
        }
    }

    /**
     * @param file the file to watch.
     */
    public synchronized void watch(File file) throws IOException {
        Path directory = file.toPath().getParent();
        if (!watchedFiles.containsKey(file)) {
            log.info("Watching file {}", file.getPath());
            watchedFiles.put(file, directory);
            watchDirectory(directory);
        }
    }

    private void watchDirectory(Path directory) throws IOException {
        if (!watchedDirectories.containsKey(directory)) {
            log.info("Watching directory {}", directory);
            WatchEvent.Kind<?>[] events = {ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY};
            watchedDirectories.put(directory, directory.register(watchService, events, modifiers));
        }
    }

    /**
     * @param file the file to stop watching.
     */
    public synchronized void unwatch(File file) {
        log.info("Unwatching file {}", file.getPath());
        Path directory = watchedFiles.remove(file);

        if (directory != null && !watchedFiles.containsValue(directory)) {
            WatchKey watchKey = watchedDirectories.remove(directory);
            if (watchKey != null) {
                log.info("Unwatching directory {}", directory);
                watchKey.cancel();
            }
        }
    }

    @Override
    public void close() throws IOException {
        stop();
        if (eventConsumer instanceof Closeable) {
            ((Closeable) eventConsumer).close();
        }
        watchService.close();
    }

    /**
     * Stop watching the file system.
     */
    public void stop() {
        log.info("Stop watching directories");
        executorService.shutdownNow();
    }

    private synchronized void notify(WatchKey key) {
        log.debug("Filesystem change detected");
        if (watchedDirectories.containsValue(key)) {
            try {
                Path directory = (Path) key.watchable();
                log.debug("Change detected in directory {}", directory);

                for (WatchEvent<?> rawevent : key.pollEvents()) {
                    FileChangedType type;

                    WatchEvent.Kind<?> kind = rawevent.kind();
                    if (kind == ENTRY_CREATE) {
                        type = FileChangedType.CREATED;
                    } else if (kind == ENTRY_MODIFY) {
                        type = FileChangedType.MODIFIED;
                    } else if (kind == ENTRY_DELETE) {
                        type = FileChangedType.DELETED;
                    } else /* kind == OVERFLOW */ {
                        // This can always happen, nothing useful we can do.
                        continue;
                    }

                    WatchEvent<Path> event = (WatchEvent<Path>) rawevent;
                    Path filename = event.context();

                    File file = directory.resolve(filename).toFile();
                    if (watchedFiles.containsKey(file)) {
                        log.info("Change detected in file {}", file.getPath());
                        eventConsumer.accept(new FileChangedEvent(file, type));
                    } // else: File we don't care about. Ignore.
                }
            } finally {
                key.reset();
            }
        } // else: Old event queued before #unwatch was called. Ignore.
    }

    /**
     * Event indicating a file changed, grouped from one or more event
     * reported from the WatchService during the {@link #eventsBufferWindowMs}.
     * <b>Immutable</b>
     */
    @Data
    public static class FileChangedEvent {
        private final File file;
        private final List<FileChangedType> types;

        public FileChangedEvent(File file, FileChangedType type) {
            this.file = file;
            this.types = Collections.singletonList(type);
        }

        public FileChangedEvent(File file, List<FileChangedType> types) {
            this.file = file;
            this.types = Collections.unmodifiableList(new ArrayList<>(types));
        }
    }

    /**
     * Civilised enum mapping directly to
     * {@link java.nio.file.StandardWatchEventKinds#ENTRY_CREATE},
     * {@link java.nio.file.StandardWatchEventKinds#ENTRY_MODIFY},
     * {@link java.nio.file.StandardWatchEventKinds#ENTRY_DELETE}.
     */
    public enum FileChangedType {
        CREATED, DELETED, MODIFIED
    }

    private void onExceptionRestart(Thread t, Throwable e) {
        log.warn("Restarting FileWatcher thread {} after unexpected exception", Thread.currentThread().getName(), e);
        restart();
    }

    private void watchInBackground() {
        log.info("Start watching directories");
        try {
            WatchKey key;
            while ((key = watchService.take()) != null) {
                notify(key);
            }
        } catch (InterruptedException e) {
            log.warn("Background FileWatcher Thread interrupted. Shutting down.");
            Thread.currentThread().interrupt();
        }
    }
}
