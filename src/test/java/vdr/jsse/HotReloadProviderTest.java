package vdr.jsse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.security.Security;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HotReloadProviderTest {
    @Mock
    KeystoreWatcher keystoreWatcher;

    @Test
    void shouldEnableOnlyOnce() throws IOException {
        try {
            HotReloadProvider.enableFirst();
            assertThat(HotReloadProvider.isEnabled()).isTrue();
            assertThrows(IllegalStateException.class, HotReloadProvider::enableFirst);
        } finally {
            HotReloadProvider.disable();
            assertThat(HotReloadProvider.isEnabled()).isFalse();
        }
    }

    @Test
    void shouldDisableOnlyOnce() throws IOException {
        HotReloadProvider.enableFirst();
        assertThat(HotReloadProvider.isEnabled()).isTrue();
        HotReloadProvider.disable();
        assertThrows(IllegalStateException.class, HotReloadProvider::disable);
    }

    @Test
    void shouldSupportJava9ConfigurationEntryPoint() throws IOException {
        try {
            HotReloadProvider.enableFirst();
            HotReloadProvider provider = (HotReloadProvider) Security.getProvider(HotReloadProvider.NAME);

            assertThat(provider).isNotNull();
            assertThat(provider.configure("configuration")).isEqualTo(provider);
        } finally {
            HotReloadProvider.disable();
        }
    }

    @Test
    void offersManualReloadSwitch() throws IOException {
        try {
            HotReloadProvider.enableFirst();
            HotReloadProvider.getInstance().setKeystoreWatcher(keystoreWatcher);

            HotReloadProvider.forceReloadAllKeystores();

            verify(keystoreWatcher).reloadAll();
        } finally {
            HotReloadProvider.disable();
        }
    }
}