package vdr.jsse.logging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.spi.LocationAwareLogger;
import vdr.jsse.logging.LoggerFactory.BindingLevel;
import vdr.jsse.logging.LoggerFactory.BindingLogger;
import vdr.jsse.logging.Slf4JBinding.Slf4jLogger;

@ExtendWith(MockitoExtension.class)
class Slf4JBindingTest {
    private static final String MESSAGE = "TESTMESSAGE";
    private static final String TEST_LOGGER = "Slf4JBindingTest";
    private static final Object[] ARGS = {1, 2, 3};
    private static final Throwable EXCEPTION = new Exception();
    private static final String APPENDER_NAME = "StandardLoggerTestAppenderName";

    private Slf4JBinding binding = new Slf4JBinding(Slf4JBindingTest.class.getClassLoader());

    @Mock
    private LocationAwareLogger delegate;

    private OutputStreamAppender<ILoggingEvent> appender;
    private ByteArrayOutputStream outputStream;
    private PatternLayoutEncoder encoder;

    @Test
    void factoryBuildsSlf4jLoggers() {
        Slf4jLogger logger = binding.getLogger("name");
        assertThat(logger.logger).isInstanceOf(LocationAwareLogger.class);
        logger = binding.getLogger(this.getClass());
        assertThat(logger.logger).isInstanceOf(LocationAwareLogger.class);
    }

    @ParameterizedTest
    @CsvSource({
            "TRACE,  0",
            "DEBUG, 10",
            "INFO,  20",
            "WARN,  30",
            "ERROR, 40"
    })
    void delegatesLogToSlf4j(BindingLevel bindingLevel, int slf4jLevel) {
        Slf4jLogger logger = binding.new Slf4jLogger(delegate);

        logger.log(bindingLevel, MESSAGE, ARGS, EXCEPTION);
        verify(delegate).log(null, BindingLogger.FQCN, slf4jLevel, MESSAGE, ARGS, EXCEPTION);
    }

    @Test
    void delegatesNameToSlf4j() {
        when(delegate.getName()).thenReturn(TEST_LOGGER);

        Slf4jLogger logger = binding.new Slf4jLogger(delegate);
        assertThat(logger.getName()).isEqualTo(TEST_LOGGER);

        verify(delegate).getName();
    }

    @Test
    void delegatesLevelCheckToSlf4j() {
        Slf4jLogger logger = binding.new Slf4jLogger(delegate);

        when(delegate.isTraceEnabled()).thenReturn(true);
        assertThat(logger.isTraceEnabled()).isTrue();
        verify(delegate).isTraceEnabled();
        reset(delegate);

        when(delegate.isDebugEnabled()).thenReturn(true);
        assertThat(logger.isDebugEnabled()).isTrue();
        verify(delegate).isDebugEnabled();
        reset(delegate);

        when(delegate.isInfoEnabled()).thenReturn(true);
        assertThat(logger.isInfoEnabled()).isTrue();
        verify(delegate).isInfoEnabled();
        reset(delegate);

        when(delegate.isWarnEnabled()).thenReturn(true);
        assertThat(logger.isWarnEnabled()).isTrue();
        verify(delegate).isWarnEnabled();
        reset(delegate);

        when(delegate.isErrorEnabled()).thenReturn(true);
        assertThat(logger.isErrorEnabled()).isTrue();
        verify(delegate).isErrorEnabled();
        reset(delegate);
    }

    @ParameterizedTest
    @CsvSource({
            // Logging should log
            "%m, " + MESSAGE,
            // Caller should be detected as this class, the actual caller, rather than the logger itself.
            "%C, vdr.jsse.logging.Slf4JBindingTest",
    })
    void testSlf4jLogging(String pattern, String expected) throws Exception {
        try (Closeable c = mockLogbackAppender(pattern)) {
            Logger logger = LoggerFactory.getLogger(TEST_LOGGER);

            logger.info(MESSAGE);

            assertThat(getLoggedMessage()).isEqualTo(expected);
        }
    }

    private Closeable mockLogbackAppender(String pattern) {
        // LoggerFactory return a singleton logger instance for each name
        // i.e. we get the same logger instance through LoggerFactory than our StandardLoggerFactory will use.
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(TEST_LOGGER);
        LoggerContext context = (LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory();

        encoder = new PatternLayoutEncoder();
        encoder.setPattern(pattern);
        encoder.setContext(context);
        encoder.start();

        outputStream = new ByteArrayOutputStream();
        appender = new OutputStreamAppender<>();

        appender.setName(APPENDER_NAME);
        appender.setImmediateFlush(true);
        appender.setEncoder(encoder);
        appender.setOutputStream(outputStream);
        appender.setContext(context);
        appender.start();

        logger.addAppender(appender);

        return this::closeMockLogbackAppender;
    }

    private String getLoggedMessage() {
        return outputStream.toString();
    }

    private void closeMockLogbackAppender() {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(TEST_LOGGER);
        appender.stop();
        encoder.stop();
        logger.detachAppender(appender);
    }
}