package vdr.jsse.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DelegatingKeyManagerTest {
    private static final String ALIAS = "alias";
    private static final String[] ALIASES = {ALIAS, "alias2"};
    public static final String KEYTYPE = "Keytype1";
    private static final String[] KEYTYPES = {KEYTYPE, "Keytype2"};
    private static final Principal[] ISSUERS = {mock(Principal.class)};
    private static final Socket SOCKET = mock(Socket.class);
    private static final SSLEngine ENGINE = mock(SSLEngine.class);
    private static final X509Certificate[] CHAIN = {mock(X509Certificate.class)};
    private static final PrivateKey KEY = mock(PrivateKey.class);

    @Mock
    private X509ExtendedKeyManager keyManager;

    @InjectMocks
    private DelegatingKeyManager underTest;

    @Test
    void delegatesListAlias() {
        when(keyManager.getClientAliases(any(), any())).thenReturn(ALIASES);
        when(keyManager.getServerAliases(any(), any())).thenReturn(ALIASES);

        assertThat(underTest.getClientAliases(KEYTYPE, ISSUERS)).isEqualTo(ALIASES);
        assertThat(underTest.getServerAliases(KEYTYPE, ISSUERS)).isEqualTo(ALIASES);

        verify(keyManager).getClientAliases(KEYTYPE, ISSUERS);
        verify(keyManager).getServerAliases(KEYTYPE, ISSUERS);
    }

    @Test
    void delegatesSocketAlias() {
        when(keyManager.chooseClientAlias(any(), any(), any())).thenReturn(ALIAS);
        when(keyManager.chooseServerAlias(any(), any(), any())).thenReturn(ALIAS);

        assertThat(underTest.chooseClientAlias(KEYTYPES, ISSUERS, SOCKET)).isEqualTo(ALIAS);
        assertThat(underTest.chooseServerAlias(KEYTYPE, ISSUERS, SOCKET)).isEqualTo(ALIAS);

        verify(keyManager).chooseClientAlias(KEYTYPES, ISSUERS, SOCKET);
        verify(keyManager).chooseServerAlias(KEYTYPE, ISSUERS, SOCKET);
    }

    @Test
    void delegatesEngineAlias() {
        when(keyManager.chooseEngineClientAlias(any(), any(), any())).thenReturn(ALIAS);
        when(keyManager.chooseEngineServerAlias(any(), any(), any())).thenReturn(ALIAS);

        assertThat(underTest.chooseEngineClientAlias(KEYTYPES, ISSUERS, ENGINE)).isEqualTo(ALIAS);
        assertThat(underTest.chooseEngineServerAlias(KEYTYPE, ISSUERS, ENGINE)).isEqualTo(ALIAS);

        verify(keyManager).chooseEngineClientAlias(KEYTYPES, ISSUERS, ENGINE);
        verify(keyManager).chooseEngineServerAlias(KEYTYPE, ISSUERS, ENGINE);
    }

    @Test
    void delegatesGetChain() {
        when(keyManager.getCertificateChain(any())).thenReturn(CHAIN);

        assertThat(underTest.getCertificateChain(ALIAS)).isEqualTo(CHAIN);

        verify(keyManager).getCertificateChain(ALIAS);
    }

    @Test
    void delegatesGetPrivateKey() {
        when(keyManager.getPrivateKey(any())).thenReturn(KEY);

        assertThat(underTest.getPrivateKey(ALIAS)).isEqualTo(KEY);

        verify(keyManager).getPrivateKey(ALIAS);
    }
}