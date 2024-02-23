package vdr.jsse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DynamicFileKeystoreTest {
    private static final String ALIAS = "alias";
    private static final X509Certificate CERTIFICATE = mock(X509Certificate.class);
    private static final X509Certificate[] CHAIN = {CERTIFICATE};
    private static final PrivateKey KEY = mock(PrivateKey.class);
    private static final byte[] KEY_BYTES = "keybytes".getBytes(StandardCharsets.UTF_8);
    private static final char[] PASSWORD = "password".toCharArray();

    private KeystoreWatcher keystoreWatcher;
    private DynamicFileKeystore underTest;

    @BeforeAll
    static void loadProvider() throws IOException {
        HotReloadProvider.enableLast();
    }

    @AfterAll
    static void unloadProvider() {
        HotReloadProvider.disable();
    }

    @BeforeEach
    void init() throws Exception {
        keystoreWatcher = mock(KeystoreWatcher.class);
        HotReloadProvider.getInstance().setKeystoreWatcher(keystoreWatcher);

        String path = new File("./src/test/resources/client1.p12").getAbsolutePath();
        String properties = "location=" + path;

        underTest = new DynamicFileKeystore();
        try (InputStream ks = new ByteArrayInputStream(properties.getBytes(StandardCharsets.ISO_8859_1))) {
            underTest.engineLoad(ks, "confluent".toCharArray());
        }
    }

    @AfterEach
    void close() {
        HotReloadProvider.getInstance().setKeystoreWatcher(null);
    }

    @Test
    void registerOnLoad() throws IOException {
        verify(keystoreWatcher).register(underTest);
    }

    @Test
    void storeOwnProperties() throws Exception {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            underTest.engineStore(out, PASSWORD);

            try (InputStream in = new ByteArrayInputStream(out.toByteArray())) {
                KeystoreProperties properties = KeystoreProperties.fromInputStream(in);

                assertThat(properties.getFile()).isEqualTo(underTest.getProperties().getFile());
                assertThat(properties.getAlgorithm()).isEqualTo(underTest.getProperties().getAlgorithm());
            }
        }
    }

    @Test
    void delegateReadMethod() throws Exception {
        KeyStore keyStore = underTest.delegate.get();

        String client1 = "client1";
        String caroot = "caroot";
        char[] password = "confluent".toCharArray();

        assertThat(underTest.engineGetKey(client1, password)).isEqualTo(keyStore.getKey(client1, password));
        assertThat(underTest.engineGetCertificateChain(client1)).isEqualTo(keyStore.getCertificateChain(client1));
        assertThat(underTest.engineGetCreationDate(client1)).isEqualTo(keyStore.getCreationDate(client1));
        assertThat(Collections.list(underTest.engineAliases())).isEqualTo(Collections.list(keyStore.aliases()));
        assertThat(underTest.engineContainsAlias(client1)).isTrue();
        assertThat(underTest.engineContainsAlias(ALIAS)).isFalse();
        assertThat(underTest.engineSize()).isEqualTo(keyStore.size());
        assertThat(underTest.engineIsKeyEntry(client1)).isTrue();
        assertThat(underTest.engineIsCertificateEntry(caroot)).isTrue();
        assertThat(underTest.engineGetCertificateAlias(keyStore.getCertificate(client1))).isEqualTo(client1);
    }

    @Test
    void throwReadonlyException_onWriteMethods() {
        assertThrows(KeyStoreException.class, () -> underTest.engineSetKeyEntry(ALIAS, KEY, PASSWORD, CHAIN));
        assertThrows(KeyStoreException.class, () -> underTest.engineSetKeyEntry(ALIAS, KEY_BYTES, CHAIN));
        assertThrows(KeyStoreException.class, () -> underTest.engineSetCertificateEntry(ALIAS, CERTIFICATE));
        assertThrows(KeyStoreException.class, () -> underTest.engineDeleteEntry(ALIAS));
    }

}