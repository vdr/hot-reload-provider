package vdr.jsse.logging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * This test should be run without slf4j on the classpath.
 * <p>
 *     Check pom.xml for surefire configuration that run this type of tests.
 * </p>
 */
@SuppressWarnings("NewClassNamingConvention") // It does not match the naming convention on purpose, see javadoc above.
class LoggerFactoryTestNoSlf4j { //NOSONAR
    @Test
    void failsToDetectSlf4j() {
        LoggerFactory.init();
        LoggerFactory.Binding actual = LoggerFactory.instance;
        assertThat(actual).isInstanceOf(NoopBinding.class);
    }
}