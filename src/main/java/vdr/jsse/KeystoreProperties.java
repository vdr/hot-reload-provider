package vdr.jsse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.ToString;

/**
 * Properties used by {@link DynamicFileKeystore} and {@link KeystoreWatcher} to configure
 * the keystore file location, format and watching requirements.
 *
 * <p>
 *     Properties are backed by a java Properties file that look like the following:
 *     <pre>
 *         # Path to the file
 *         #    Absolute path recommended for sanity,
 *         #    otherwise relative to the application startup folder.
 *         location=/path/to/keystore.file
 *         # The Keystore Algorithm (eg: JKS, PKCS12)
 *         #    Optional, default PKCS12
 *         keystore.algorithm=JKS
 *     </pre>
 * </p>
 */
@Getter
@Setter
@RequiredArgsConstructor
@ToString
class KeystoreProperties {
    static final String PROPERTY_LOCATION = "location";
    static final String PROPERTY_ALGORITHM = "keystore.algorithm";
    static final String PASSWORD_LOCATION = "password.location";
    static final String KEYPASS_LOCATION = "keypass.location";

    static final String DEFAULT_ALGORITHM = "PKCS12";

    private final String algorithm;
    private final File file;
    private final File passwordFile;
    private final File keypassFile;

    /**
     * Deserialize from an input stream. The Serialization format is a {@link java.util.Properties} file.<br/>
     * Note this means encoding is ISO 8859-1 and other idiosyncrasies of that legacy format.
     *
     * @param stream stream in {@link java.util.Properties} format.
     * @return the deserialized instance if valid.
     * @see java.util.Properties
     */
    static KeystoreProperties fromInputStream(InputStream stream) throws IOException {
        Properties properties = new Properties();
        properties.load(stream);

        String location = properties.getProperty(PROPERTY_LOCATION);
        String passwordLocation = properties.getProperty(PASSWORD_LOCATION);
        String keypassLocation = properties.getProperty(KEYPASS_LOCATION);
        File passwordFile = null;
        File keypassFile = null;

        if (location == null) {
            throw new IOException("Missing file location");
        }

        File file = new File(location);
        if (!file.canRead() || !file.isFile()) {
            throw new IOException("Cannot read file " + file);
        }

        if(passwordLocation != null) {
            passwordFile = new File(passwordLocation);
            if (!passwordFile.canRead() || !passwordFile.isFile()) {
                throw new IOException("Cannot read password file " + passwordFile);
            }
        }

        if(keypassLocation != null) {
            keypassFile = new File(keypassLocation);
            if (!keypassFile.canRead() || !keypassFile.isFile()) {
                throw new IOException("Cannot read keypass file " + keypassFile);
            }
        }

        String algorithm = properties.getProperty(PROPERTY_ALGORITHM, DEFAULT_ALGORITHM).trim();

        return new KeystoreProperties(algorithm, file, passwordFile, keypassFile);
    }

    /**
     * Convenience method to use a String instead of the regular InputProperties.
     *
     * @param string the string.
     * @return the deserialized instance if valid.
     */
    static KeystoreProperties fromString(String string) throws IOException {
        try (InputStream in = new ByteArrayInputStream(string.getBytes(StandardCharsets.ISO_8859_1))) {
            return fromInputStream(in);
        }
    }

    /**
     * Serialize into a stream in the {@link java.util.Properties} format.
     *
     * @param stream destination stream.
     * @throws IOException if the stream fails.
     * @see java.util.Properties
     */
    void store(OutputStream stream) throws IOException {
        Properties properties = new Properties();
        properties.setProperty(PROPERTY_ALGORITHM, algorithm);
        properties.setProperty(PROPERTY_LOCATION, file.getPath());
        if(passwordFile != null) {
            properties.setProperty(PASSWORD_LOCATION, passwordFile.getPath());
        }
        if(keypassFile != null) {
            properties.setProperty(KEYPASS_LOCATION, keypassFile.getPath());
        }

        properties.store(stream, getClass().getSimpleName() + "@" + Integer.toHexString(hashCode()));
    }
    /**
     * Convenience method that serialize {@link #store(OutputStream)} into a String.
     * @see #store(OutputStream)
     */
    @SneakyThrows(IOException.class /* Will not happen with a ByteArrayOutputStream */)
    String storeToString() {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            store(out);
            return new String(out.toByteArray(), StandardCharsets.ISO_8859_1);
        }
    }

    /**
     * Convenience method that serialize {@link #store(OutputStream)} into a ByteArrayInputStream.
     * @see #store(OutputStream)
     */
    @SneakyThrows(IOException.class /* Will not happen with a ByteArrayOutputStream */)
    ByteArrayInputStream storeToInputStream() {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            store(out);
            return new ByteArrayInputStream(out.toByteArray());
        }
    }
}
