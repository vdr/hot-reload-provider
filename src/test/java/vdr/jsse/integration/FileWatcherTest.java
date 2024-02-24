package vdr.jsse.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import vdr.jsse.test.TestUtils;
import vdr.jsse.utils.FileWatcher;

class FileWatcherTest {
    // We watch file at HIGH sensitivity, so the filesystem is polled every 2s.
    // Can take a bit more than 2s to run a test if unlucky, let's go with 3s.
    private static final long TEST_TIMEOUT_SEC = 3;

    // We don't expect more than 1 or 2 events, however we don't want to block on "offer", so we give the test the room.
    private final ArrayBlockingQueue<FileWatcher.FileChangedEvent> events = new ArrayBlockingQueue<>(100);
    private static Path tempdir;

    @BeforeAll
    static void setup() throws IOException {
        tempdir = Files.createTempDirectory("hotreload_watcher").toAbsolutePath();
    }

    @BeforeEach
    void clearEventQueue() {
        events.clear();
    }

    @Test
    void watchNewFiles() throws IOException, InterruptedException {
        Path file = tempdir.resolve("createdfile");

        try (FileWatcher watcher = new FileWatcher(FileSystems.getDefault().newWatchService(), 0, TestUtils.highSensitivity())) {
            watcher.start(events::offer);
            watcher.watch(file.toFile());
            Files.createFile(file);

            FileWatcher.FileChangedEvent event = poll();
            assertEvent(event, FileWatcher.FileChangedType.CREATED);
        }
    }

    @Test
    void watchUpdatedFiles() throws IOException, InterruptedException {
        Path file = tempdir.resolve("updatedfile");
        Files.createFile(file);

        try (FileWatcher watcher = new FileWatcher(FileSystems.getDefault().newWatchService(), 0, TestUtils.highSensitivity())) {
            watcher.start(events::offer);
            watcher.watch(file.toFile());
            TestUtils.updateFile(file, "some data");
            FileWatcher.FileChangedEvent event = poll();

            assertEvent(event, FileWatcher.FileChangedType.MODIFIED);
        }
    }

    @Test
    void watchDeletedFiles() throws IOException, InterruptedException {
        Path file = tempdir.resolve("deletedfile");
        Files.createFile(file);

        try (FileWatcher watcher = new FileWatcher(FileSystems.getDefault().newWatchService(), 0, TestUtils.highSensitivity())) {
            watcher.start(events::offer);
            watcher.watch(file.toFile());
            Files.delete(file);

            FileWatcher.FileChangedEvent event = poll();
            assertEvent(event, FileWatcher.FileChangedType.DELETED);
        }
    }

    @Test
    void ignoreNonWatchedFiles() throws IOException, InterruptedException {
        Path watchedFile = tempdir.resolve("watchedfile");
        Path notwatchedFile = tempdir.resolve("notwatchedfile");

        try (FileWatcher watcher = new FileWatcher(FileSystems.getDefault().newWatchService(), 0, TestUtils.highSensitivity())) {
            watcher.start(events::offer);
            watcher.watch(watchedFile.toFile());
            Files.createFile(notwatchedFile);

            FileWatcher.FileChangedEvent event = poll();
            assertThat(event).isNull();
        }
    }

    @Test
    void unwatchFilesAndDirectories() throws IOException, InterruptedException {
        Path file = tempdir.resolve("file");
        Path otherFile = tempdir.resolve("otherfile");

        try (FileWatcher watcher = new FileWatcher(FileSystems.getDefault().newWatchService(), 0, TestUtils.highSensitivity())) {
            watcher.start(events::offer);
            watcher.watch(file.toFile());
            watcher.watch(file.toFile()); // Duplicate entries for the same file should be taken into account
                                          // and not affect the rest of the test.
            watcher.watch(otherFile.toFile());

            Files.createFile(file);

            // Java only checks the filesystem every 10s, so we have to wait to be sure at what stage we are in
            FileWatcher.FileChangedEvent event = poll();
            assertEvent(event, FileWatcher.FileChangedType.CREATED);

            watcher.unwatch(file.toFile());
            Files.delete(file);
            Files.createFile(otherFile);

            // Should only watch "otherfile"
            event = poll();
            assertEvent(event, FileWatcher.FileChangedType.CREATED);

            watcher.unwatch(otherFile.toFile());

            // Should not watch anything.
            event = poll();
            assertThat(event).isNull();
        }
    }

    @Test
    void recoversForConsumerException() throws IOException {
        Path file = tempdir.resolve("recover");
        Consumer<FileWatcher.FileChangedEvent> consumer = mock(Consumer.class);
        doThrow(new RuntimeException("Expected UnitTest Error")).when(consumer).accept(any());

        try (FileWatcher watcher = new FileWatcher(FileSystems.getDefault().newWatchService(), 0, TestUtils.highSensitivity())) {
            watcher.start(consumer);
            watcher.watch(file.toFile());
            Files.createFile(file);

            verify(consumer, timeout(TEST_TIMEOUT_SEC * 60000)).accept(any());

            reset(consumer); // We want to see recovery - the best way to be sure is "do it, check, do it again".
                             // There is so much plumbing in here that a simple reset of the mock is
                             // the quick and easy way out.

            Files.delete(file);

            verify(consumer, timeout(TEST_TIMEOUT_SEC * 60000)).accept(any());
        }
    }

    private void assertEvent(FileWatcher.FileChangedEvent event, FileWatcher.FileChangedType...types) {
        assertThat(event).isNotNull();
        assertThat(event.getTypes()).containsExactly(types);
    }

    private FileWatcher.FileChangedEvent poll() throws InterruptedException {
        return events.poll(TEST_TIMEOUT_SEC, TimeUnit.SECONDS);
    }
}