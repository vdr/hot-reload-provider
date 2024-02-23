package vdr.jsse.test;

import static vdr.jsse.HotReloadProvider.ALGO_KEYSTORE;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@AllArgsConstructor
public class SslContextBuilder {
    private String protocol = "TLSv1.2";
    private final String ksPath;
    private String ksType = "PKCS12";
    private final String ksPassword;
    private final String keyPassword;
    private final String tsPath;
    private String tsType = "PKCS12";
    private final String tsPassword;
    private String kmAlgo = KeyManagerFactory.getDefaultAlgorithm();
    private String tmAlgo = TrustManagerFactory.getDefaultAlgorithm();
    private String provider = "SunJSSE";
    private final String passwordPath;
    private final String keypassPath;

    public SSLContextBuilt build() throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException, NoSuchProviderException {
        KeyStore keyStore = createKeyStore(ksType, ksPath, ksPassword.toCharArray());
        KeyStore trustStore = createKeyStore(tsType, tsPath, tsPassword.toCharArray());

        KeyManager[] keyManagers = createKeyManagers(keyStore);
        TrustManager[] trustManagers = createTrustManagers(trustStore);

        SSLContext context = SSLContext.getInstance(protocol, provider);
        context.init(keyManagers, trustManagers, new SecureRandom());

        return new SSLContextBuilt(context, keyManagers, trustManagers, keyStore, trustStore);
    }

    private KeyManager[] createKeyManagers(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(kmAlgo);
        kmf.init(keyStore, keyPassword.toCharArray());

        return kmf.getKeyManagers();
    }

    private TrustManager[] createTrustManagers(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException {
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(tmAlgo);
        trustFactory.init(keyStore);

        return trustFactory.getTrustManagers();
    }

    private KeyStore createKeyStore(String type, String path, char[] password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(type);
        if (ALGO_KEYSTORE.equals(type)) {
            String location = "location=" + new File(path).getAbsolutePath() + "\n";
            if (passwordPath != null) {
                location += "password.location=" + new File(passwordPath).getAbsolutePath() + "\n";
            }
            if (keypassPath != null) {
                location += "keypass.location=" + new File(keypassPath).getAbsolutePath() + "\n";
            }

            try (InputStream stream = new ByteArrayInputStream(location.getBytes(StandardCharsets.ISO_8859_1))) {
                keyStore.load(stream, password);
            }
        } else {
            try (InputStream stream = new FileInputStream(path)) {
                keyStore.load(stream, password);
            }
        }
        return keyStore;
    }

    @Data
    public static class SSLContextBuilt {
        private final SSLContext sslContext;
        private final KeyManager[] keyManagers;
        private final TrustManager[] trustManagers;
        private final KeyStore keyStore;
        private final KeyStore trustStore;
    }
}
