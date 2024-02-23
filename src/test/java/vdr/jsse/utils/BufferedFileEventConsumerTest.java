package vdr.jsse.utils;

import static org.mockito.Mockito.after;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static vdr.jsse.utils.FileWatcher.FileChangedType.CREATED;
import static vdr.jsse.utils.FileWatcher.FileChangedType.DELETED;
import static vdr.jsse.utils.FileWatcher.FileChangedType.MODIFIED;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vdr.jsse.utils.FileWatcher.FileChangedEvent;

@ExtendWith(MockitoExtension.class)
class BufferedFileEventConsumerTest {
    private static final long DELAY = 1000;
    private static final long GRACE = 100;
    private static final File FILE1 = new File("file1");
    private static final FileChangedEvent EVENT_CREATE = new FileChangedEvent(FILE1, CREATED);
    private static final FileChangedEvent EVENT_UPDATE = new FileChangedEvent(FILE1, MODIFIED);
    private static final FileChangedEvent EVENT_DELETE = new FileChangedEvent(FILE1, DELETED);
    @Mock
    private Consumer<FileChangedEvent> delegate;

    @Test
    void delaySingleEvent() throws IOException {
        try (BufferedFileEventConsumer bufferedConsumer = new BufferedFileEventConsumer(delegate, DELAY)) {
            bufferedConsumer.accept(EVENT_CREATE);
            verify(delegate, after(DELAY + GRACE).only()).accept(EVENT_CREATE);
        }
    }

    @Test
    void mergeEventsInWindow() throws IOException {
        try (BufferedFileEventConsumer bufferedConsumer = new BufferedFileEventConsumer(delegate, DELAY)) {
            bufferedConsumer.accept(EVENT_CREATE);
            bufferedConsumer.accept(EVENT_UPDATE);
            bufferedConsumer.accept(EVENT_DELETE);
            verify(delegate, after(DELAY + GRACE).only()).accept(new FileChangedEvent(FILE1, Arrays.asList(CREATED, MODIFIED, DELETED)));
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1, -1000000})
    void givenNegativeOrZeroDelay_assumesNoDelay(long delay) throws IOException {
        try (BufferedFileEventConsumer bufferedConsumer = new BufferedFileEventConsumer(delegate, delay)) {
            bufferedConsumer.accept(EVENT_CREATE);
            verify(delegate, after(GRACE).only()).accept(EVENT_CREATE);
        }
    }

    @Test
    void recoversFromDelegateError() throws IOException {
        doThrow(new RuntimeException("Expected Test Error")).when(delegate).accept(EVENT_CREATE);

        try (BufferedFileEventConsumer bufferedConsumer = new BufferedFileEventConsumer(delegate, DELAY)) {
            bufferedConsumer.accept(EVENT_CREATE);
            verify(delegate, after(DELAY + GRACE).only()).accept(EVENT_CREATE);

            reset(delegate); // We want to see recovery - the best way to be sure is "do it, check, do it again".
                             // We could use delays using awaitability library, but
                             // resetting the mock is a quick and readable alternative

            bufferedConsumer.accept(EVENT_DELETE);
            verify(delegate, after(DELAY + GRACE).only()).accept(EVENT_DELETE);
        }
    }
}