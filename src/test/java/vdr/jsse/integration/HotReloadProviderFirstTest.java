package vdr.jsse.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static vdr.jsse.HotReloadProvider.ALGO_KEYMANAGER_PKIX;
import static vdr.jsse.HotReloadProvider.ALGO_KEYMANAGER_X509;
import static vdr.jsse.HotReloadProvider.ALGO_KEYSTORE;
import static vdr.jsse.HotReloadProvider.ALGO_TRUSTMANAGER_PKIX;
import static vdr.jsse.HotReloadProvider.ALGO_TRUSTMANAGER_X509;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import vdr.jsse.HotReloadProvider;

@DisplayName("Tests HotReload Provider loaded First")
class HotReloadProviderFirstTest {
    private static HotReloadProvider hotReloadProvider;

    @BeforeAll
    static void installProvider() throws IOException {
        hotReloadProvider = HotReloadProvider.enableFirst();
    }

    @AfterAll
    static void uninstallProvider() {
        HotReloadProvider.disable();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        /* Own Algo */ ALGO_KEYMANAGER_X509, ALGO_KEYMANAGER_PKIX,
        /* SunJSSE Algo */ "SunX509", "NewSunX509", "PKIX"})
    void provideKeyManagers(String algo) throws Exception {
        assertProvider(KeyManagerFactory.getInstance(algo).getProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        /* Own Algo */ ALGO_TRUSTMANAGER_X509, ALGO_TRUSTMANAGER_PKIX,
        /* SunJSSE Algo */ "SunX509", "PKIX", "SunPKIX", "X509", "X.509"})
    void provideTrustManagers(String algo) throws Exception {
        assertProvider(TrustManagerFactory.getInstance(algo).getProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1", "SSLv3", "TLSv1.1", "TLSv1.2", "TLSv1.3", "TLS", "SSL"})
    void provideSSLContext(String algo) throws Exception {
        assertProvider(SSLContext.getInstance(algo).getProvider());
    }

    @Test
    void provideDefaultSSLContext() throws Exception {
        // note: SSLContext.getDefault() caches the first SSLContext.getInstance("Default") instance
        //       Cannot be used for test or will interfere with HotReloadProviderLastTest
        assertProvider(SSLContext.getInstance("Default").getProvider());
    }

    @Test
    void provideKeystore() throws Exception {
        assertProvider(KeyStore.getInstance(ALGO_KEYSTORE).getProvider());
    }

    private static void assertProvider(Provider provider) {
        assertThat(provider).isEqualTo(hotReloadProvider);
    }
}
