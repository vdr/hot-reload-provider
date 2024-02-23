package vdr.jsse.logging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class LoggerFactoryTest {
    @Test
    void detectsSlf4j() {
        LoggerFactory.Binding actual = LoggerFactory.instance;
        assertThat(actual).isInstanceOf(Slf4JBinding.class);
    }
}