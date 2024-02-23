package vdr.jsse.test;

import static org.awaitility.Awaitility.await;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.WatchEvent;
import java.nio.file.attribute.FileTime;
import java.time.Instant;

public abstract class TestUtils {
    private TestUtils() {
        // Utility class
    }

    public static void copyFile(String src, String dest) throws IOException {
        Path source = Paths.get(src);
        Path destination = Paths.get(dest);
        FileTime originalTime = Files.exists(destination) ? Files.getLastModifiedTime(destination) : null;

        Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
        updateLastModifiedTime(destination, originalTime);
    }

    public static void updateFile(Path file, String data) throws IOException {
        FileTime originalTime = Files.exists(file) ? Files.getLastModifiedTime(file) : null;
        Files.write(file, data.getBytes(StandardCharsets.UTF_8));
        updateLastModifiedTime(file, originalTime);
    }

    /**
     * Make sure that Last Modified time on a file has been updated since the original.
     * <p>
     *     Depending on the OS/JDK, Filesystem watcher may use lastModified time of the file to determine changes.<br/>
     *     Depending on OS/FS, lastModified time can have a very low resolution, like 1 sec,
     *     meaning that change occurring within 1 second may not be detected.<br/>
     *     This is a source of sporadic test failure this method prevents.
     * </p>
     *
     * @param file the file after change.
     * @param originalModifiedTime the last modified time before the change.
     */
    public static void updateLastModifiedTime(Path file, FileTime originalModifiedTime) throws IOException {
        if (originalModifiedTime != null && originalModifiedTime.equals(Files.getLastModifiedTime(file))) {
            await().until(() -> {
                Files.setLastModifiedTime(file, FileTime.from(Instant.now()));
                return !originalModifiedTime.equals(Files.getLastModifiedTime(file));
            });
        }
    }

    public static WatchEvent.Modifier highSensitivity() {
        try {
            Class cls = Class.forName("com.sun.nio.file.SensitivityWatchEventModifier");
            Object[] constants = cls.getEnumConstants();
            for (Object c : constants) {
                if (c.toString().equals("HIGH")) {
                    return WatchEvent.Modifier.class.cast(c);
                }
            }
        } catch (Exception e) {

        }

        throw new IllegalStateException("com.sun.nio.file.SensitivityWatchEventModifier.HIGH does not exist");
    }
}
