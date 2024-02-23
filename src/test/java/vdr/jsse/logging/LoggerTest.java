package vdr.jsse.logging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vdr.jsse.logging.LoggerFactory.BindingLevel;
import vdr.jsse.logging.LoggerFactory.BindingLogger;

@ExtendWith(MockitoExtension.class)
class LoggerTest {
    public static final String TESTMESSAGE = "TESTMESSAGE";
    public static final Object[] ARGS = new String[] {"a", "b", "c"};
    public static final Throwable THROWABLE = new Exception();
    public static final String TEST_LOGGER = "StandardLoggerTest";

    @Mock
    private BindingLogger delegate;

    @Test
    void delegatesName() {
        Logger logger = LoggerFactory.getLogger(TEST_LOGGER);
        assertThat(logger.getName()).isEqualTo(TEST_LOGGER);
    }

    @Test
    void delegatesLevelCheckMethod() {
        Logger logger = new Logger(delegate);

        logger.isTraceEnabled();
        verify(delegate).isTraceEnabled();

        logger.isDebugEnabled();
        verify(delegate).isDebugEnabled();

        logger.isInfoEnabled();
        verify(delegate).isInfoEnabled();

        logger.isWarnEnabled();
        verify(delegate).isWarnEnabled();

        logger.isErrorEnabled();
        verify(delegate).isErrorEnabled();
    }

    @Test
    void delegatesNonStandardisedLoggingMethod() {
        Logger logger = new Logger(delegate);

        testLogMessage(BindingLevel.TRACE, logger::trace, logger::trace);
        testLogMessage(BindingLevel.DEBUG, logger::debug, logger::debug);
        testLogMessage(BindingLevel.INFO, logger::info, logger::info);
        testLogMessage(BindingLevel.WARN, logger::warn, logger::warn);
        testLogMessage(BindingLevel.ERROR, logger::error, logger::error);
    }

    private void testLogMessage(BindingLevel expectedLevel,
                                BiConsumer<String, Object[]> logMessage,
                                BiConsumer<String, Throwable> logException) {
        logMessage.accept(TESTMESSAGE, ARGS);
        verify(delegate).log(expectedLevel, TESTMESSAGE, ARGS, null);
        reset(delegate);

        logException.accept(TESTMESSAGE, THROWABLE);
        verify(delegate).log(expectedLevel, TESTMESSAGE, null, THROWABLE);
        reset(delegate);
    }
}