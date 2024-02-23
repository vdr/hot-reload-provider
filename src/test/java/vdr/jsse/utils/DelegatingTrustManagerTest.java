package vdr.jsse.utils;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DelegatingTrustManagerTest {
    public static final String AUTHTYPE = "authtype";
    private static final Socket SOCKET = mock(Socket.class);
    private static final SSLEngine ENGINE = mock(SSLEngine.class);
    private static final X509Certificate[] CHAIN = {mock(X509Certificate.class)};

    @Mock
    private X509ExtendedTrustManager trustManager;

    @InjectMocks
    private DelegatingTrustManager underTest;

    @Test
    void delegateCheckClientTrusted() throws CertificateException {
        underTest.checkClientTrusted(CHAIN, AUTHTYPE);
        underTest.checkClientTrusted(CHAIN, AUTHTYPE, SOCKET);
        underTest.checkClientTrusted(CHAIN, AUTHTYPE, ENGINE);

        verify(trustManager).checkClientTrusted(CHAIN, AUTHTYPE);
        verify(trustManager).checkClientTrusted(CHAIN, AUTHTYPE, SOCKET);
        verify(trustManager).checkClientTrusted(CHAIN, AUTHTYPE, ENGINE);
    }

    @Test
    void delegateCheckClientNotTrusted() throws CertificateException {
        doThrow(new CertificateException()).when(trustManager).checkClientTrusted(CHAIN, AUTHTYPE);
        doThrow(new CertificateException()).when(trustManager).checkClientTrusted(CHAIN, AUTHTYPE, SOCKET);
        doThrow(new CertificateException()).when(trustManager).checkClientTrusted(CHAIN, AUTHTYPE, ENGINE);

        assertThrows(CertificateException.class, () -> underTest.checkClientTrusted(CHAIN, AUTHTYPE));
        assertThrows(CertificateException.class, () -> underTest.checkClientTrusted(CHAIN, AUTHTYPE, SOCKET));
        assertThrows(CertificateException.class, () -> underTest.checkClientTrusted(CHAIN, AUTHTYPE, ENGINE));

        verify(trustManager).checkClientTrusted(CHAIN, AUTHTYPE);
        verify(trustManager).checkClientTrusted(CHAIN, AUTHTYPE, SOCKET);
        verify(trustManager).checkClientTrusted(CHAIN, AUTHTYPE, ENGINE);
    }

    @Test
    void delegateCheckServerTrusted() throws CertificateException {
        underTest.checkServerTrusted(CHAIN, AUTHTYPE);
        underTest.checkServerTrusted(CHAIN, AUTHTYPE, SOCKET);
        underTest.checkServerTrusted(CHAIN, AUTHTYPE, ENGINE);

        verify(trustManager).checkServerTrusted(CHAIN, AUTHTYPE);
        verify(trustManager).checkServerTrusted(CHAIN, AUTHTYPE, SOCKET);
        verify(trustManager).checkServerTrusted(CHAIN, AUTHTYPE, ENGINE);
    }

    @Test
    void delegateCheckServerNotTrusted() throws CertificateException {
        doThrow(new CertificateException()).when(trustManager).checkServerTrusted(CHAIN, AUTHTYPE);
        doThrow(new CertificateException()).when(trustManager).checkServerTrusted(CHAIN, AUTHTYPE, SOCKET);
        doThrow(new CertificateException()).when(trustManager).checkServerTrusted(CHAIN, AUTHTYPE, ENGINE);

        assertThrows(CertificateException.class, () -> underTest.checkServerTrusted(CHAIN, AUTHTYPE));
        assertThrows(CertificateException.class, () -> underTest.checkServerTrusted(CHAIN, AUTHTYPE, SOCKET));
        assertThrows(CertificateException.class, () -> underTest.checkServerTrusted(CHAIN, AUTHTYPE, ENGINE));

        verify(trustManager).checkServerTrusted(CHAIN, AUTHTYPE);
        verify(trustManager).checkServerTrusted(CHAIN, AUTHTYPE, SOCKET);
        verify(trustManager).checkServerTrusted(CHAIN, AUTHTYPE, ENGINE);
    }
}