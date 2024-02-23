package vdr.jsse.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.WatchService;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Bulk of the testing is done in integration this is because you can't practically
 * mock any of the WatchService functionality.<br/>
 * This unit test is only here for edge cases difficult to reproduce with an actual filesystem.
 *
 * @see vdr.integration.FileWatcherTest
 */
@SuppressWarnings("JavadocReference")
@ExtendWith(MockitoExtension.class)
class FileWatcherTest {
    private static final long DELAY = 1000;
    @Mock
    private WatchService watchService;

    @Mock
    private Consumer<FileWatcher.FileChangedEvent> consumer;

    @Test
    void shouldBufferEvents() throws IOException {
        try (FileWatcher watcher = new FileWatcher(watchService, DELAY)) {
            watcher.start(consumer);

            assertThat(watcher.eventConsumer).isInstanceOf(BufferedFileEventConsumer.class);
            BufferedFileEventConsumer bufferedConsumer = (BufferedFileEventConsumer) watcher.eventConsumer;

            assertThat(bufferedConsumer.bufferWindowMs).isEqualTo(DELAY);
            assertThat(bufferedConsumer.delegateConsumer).isEqualTo(consumer);
        }
    }
}