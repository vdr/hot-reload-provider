package vdr.jsse.integration;

import static org.assertj.core.api.Assertions.assertThat;

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

@DisplayName("Tests HotReloadProvider loaded Last")
class HotReloadProviderLastTest {
    private static HotReloadProvider hotReloadProvider;

    @BeforeAll
    static void installProvider() throws IOException {
        hotReloadProvider = HotReloadProvider.enableLast();
    }

    @AfterAll
    static void uninstallProvider() {
        HotReloadProvider.disable();
    }

    @ParameterizedTest
    @ValueSource(strings = {/* Own Algo */ HotReloadProvider.ALGO_KEYMANAGER_X509, HotReloadProvider.ALGO_KEYMANAGER_PKIX})
    void provideKeyManagers(String algo) throws Exception {
        assertProvider(KeyManagerFactory.getInstance(algo).getProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {/* SunJSSE Algo */ "SunX509", "NewSunX509", "PKIX"})
    void doNotOverrideDefaultKeyManagers(String algo) throws Exception {
        assertNotProvider(KeyManagerFactory.getInstance(algo).getProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {/* Own Algo */ HotReloadProvider.ALGO_TRUSTMANAGER_X509, HotReloadProvider.ALGO_TRUSTMANAGER_PKIX})
    void provideTrustManagers(String algo) throws Exception {
        assertProvider(TrustManagerFactory.getInstance(algo).getProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {/* SunJSSE Algo */ "SunX509", "PKIX", "SunPKIX", "X509", "X.509"})
    void doNotOverrideDefaultTrustManagers(String algo) throws Exception {
        assertNotProvider(TrustManagerFactory.getInstance(algo).getProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1", "SSLv3", "TLSv1.1", "TLSv1.2", "TLSv1.3", "TLS", "SSL", "Default"})
    void doesNotProvideSSLContext(String algo) throws Exception {
        assertNotProvider(SSLContext.getInstance(algo).getProvider());
    }

    @Test
    void provideKeystore() throws Exception {
        assertProvider(KeyStore.getInstance(HotReloadProvider.ALGO_KEYSTORE).getProvider());
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1", "SSLv3", "TLSv1.1", "TLSv1.2", "TLSv1.3", "TLS", "SSL", "Default"})
    void whenProviderSpecified_ProvideSSLContext(String algo) throws Exception {
        assertProvider(SSLContext.getInstance(algo, hotReloadProvider).getProvider());
    }

    private static void assertProvider(Provider provider) {
        assertThat(provider).isEqualTo(hotReloadProvider);
    }

    private static void assertNotProvider(Provider provider) {
        assertThat(provider).isNotInstanceOf(HotReloadProvider.class);
    }
}
