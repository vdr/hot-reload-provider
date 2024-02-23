package vdr.jsse.utils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

public class PasswordLoader {
    private final Logger log = LoggerFactory.getLogger(PasswordLoader.class);

    /**
     * Return a password stored in a file in UTF-8.
     * <b>The password is trimmed!</b>
     *
     * @param passwordFile the file containing the password. UTF-8 encoded.
     * @return the file content <b>trimmed</b>.
     * @throws IOException if the file does not exist or cannot be opened.
     */
    public char[] loadFromFile(File passwordFile) throws IOException {
        byte[] bytes = Files.readAllBytes(passwordFile.toPath());

        String password  = new String(bytes, StandardCharsets.UTF_8).trim();
        log.trace("Loaded password '{}'", password);

        return password.toCharArray();
    }
}
