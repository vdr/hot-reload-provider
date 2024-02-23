package vdr.jsse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class KeystorePropertiesTest {
    @Test
    void loadFromProperties() throws IOException {
        String algo = "KeystoreAlgo";
        File validFile = File.createTempFile(KeystorePropertiesTest.class.getSimpleName(), null);

        KeystoreProperties properties = buildWithProperties(algo, validFile, validFile);

        assertThat(properties.getFile()).isEqualTo(validFile);
        assertThat(properties.getAlgorithm()).isEqualTo(algo);
    }

    @Test
    void defaultsAlgo() throws IOException {
        File validFile = File.createTempFile(KeystorePropertiesTest.class.getSimpleName(), null);

        KeystoreProperties properties = buildWithProperties(null, validFile, validFile);

        assertThat(properties.getAlgorithm()).isEqualTo(KeystoreProperties.DEFAULT_ALGORITHM);
    }

    @Test
    void failsWhenInvalidFiles() {
        assertThrows(IOException.class, () -> buildWithProperties(null, null, null));
        assertThrows(IOException.class, () -> buildWithProperties(null, new File("invalid path"), new File("invalid path")));
        assertThrows(IOException.class, () -> buildWithProperties(null, new File("."),  new File(".")));
    }

    private KeystoreProperties buildWithProperties(String algo, File file, File passwordFile) throws IOException {
        StringBuilder properties = new StringBuilder();
        if (algo != null) {
            properties.append(KeystoreProperties.PROPERTY_ALGORITHM + "=").append(algo).append("\n");
        }
        if (file != null) {
            properties.append(KeystoreProperties.PROPERTY_LOCATION + "=").append(file.getPath()).append("\n");
        }
        if (passwordFile != null) {
            properties.append(KeystoreProperties.PASSWORD_LOCATION + "=").append(passwordFile.getPath()).append("\n");
        }

        return KeystoreProperties.fromString(properties.toString());
    }

    @Test
    void storeAsProperties() throws IOException {
        String algo = "KeystoreAlgo";
        String location = "filelocation";
        String passwordLocation = "passwordLocation";

        KeystoreProperties keystoreProperties = new KeystoreProperties(algo, new File(location), new File(passwordLocation), new File(passwordLocation));

        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            keystoreProperties.store(stream);

            Properties properties = new Properties();
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(stream.toByteArray())) {
                properties.load(inputStream);

                assertThat(properties)
                        .containsEntry(KeystoreProperties.PROPERTY_LOCATION, location)
                        .containsEntry(KeystoreProperties.PROPERTY_ALGORITHM, algo)
                        .containsEntry(KeystoreProperties.PASSWORD_LOCATION, passwordLocation);
            }
        }
    }

    /**
     *  The unique comment allows us to differentiate 2 different keystore instance even
     *  if they have the same properties.
     *
     *  This is useful as it allows KeystoreWatcher to indirectly distinguish 2 different
     *  instance of our KeystoreSpi from Keystore, without using reflection.
     */
    @Test
    void generateUniqueCommentInOutputStream() {
        String algo = "KeystoreAlgo";
        String location = "filelocation";
        String passwordLocation = "passwordLocation";

        KeystoreProperties ksProps1 = new KeystoreProperties(algo, new File(location), new File(passwordLocation), new File(passwordLocation));
        KeystoreProperties ksProps2 = new KeystoreProperties(algo, new File(location), new File(passwordLocation), new File(passwordLocation));

        assertThat(ksProps1.storeToString()).isNotEqualTo(ksProps2.storeToString());
    }
}