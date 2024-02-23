package vdr.jsse.logging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import vdr.jsse.logging.LoggerFactory.Binding;
import vdr.jsse.logging.LoggerFactory.BindingLogger;
import vdr.jsse.logging.NoopBinding.NoopLogger;

class NoopBindingTest {
    private final Binding noop = new NoopBinding();

    @Test
    void returnsSingletonLogger() {
        BindingLogger logger1 = noop.getLogger((String) null);
        BindingLogger logger2 = noop.getLogger("name");
        BindingLogger logger3 = noop.getLogger(this.getClass());

        assertThat(logger1)
                .isSameAs(logger2)
                .isSameAs(logger3);
    }

    @Test
    void loggerDoesNothing() {
        BindingLogger logger = new NoopLogger();

        logger.log(LoggerFactory.BindingLevel.ERROR, "message", new Object[] {this}, new Exception());
        assertThat(logger.getName()).isEqualTo(NoopLogger.NAME);

        assertThat(logger.isTraceEnabled()).isFalse();
        assertThat(logger.isDebugEnabled()).isFalse();
        assertThat(logger.isInfoEnabled()).isFalse();
        assertThat(logger.isWarnEnabled()).isFalse();
        assertThat(logger.isErrorEnabled()).isFalse();
    }
}