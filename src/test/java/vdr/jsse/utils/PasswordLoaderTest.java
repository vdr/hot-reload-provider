package vdr.jsse.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class PasswordLoaderTest {
    private PasswordLoader passwordLoader = new PasswordLoader();

    @ParameterizedTest
    @CsvSource({
            "'',             ''",
            "' ',            ''",       // Trimmed
            "'hunter2',      'hunter2'",
            "'👍',           '👍'",
            "'hunter2\n',   'hunter2'",
            "'hunter2\n\n', 'hunter2'", // Trimmed
            "'\n1\n2\n',    '1\n2'",    // Trimmed
    })
    void shouldReturnPasswordFileContentTrimmed(String content, String expected) throws IOException {
        Path file = Files.createTempFile("password", "txt");
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));

        String actual = new String(passwordLoader.loadFromFile(file.toFile()));

        assertThat(actual).isEqualTo(expected);
    }
}