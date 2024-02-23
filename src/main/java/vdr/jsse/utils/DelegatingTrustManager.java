package vdr.jsse.utils;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import lombok.SneakyThrows;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

/**
 * Boilerplate code that delegates to another keymanager instance.
 */
public class DelegatingTrustManager extends X509ExtendedTrustManager {
    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final AtomicReference<X509ExtendedTrustManager> delegate = new AtomicReference<>();

    protected DelegatingTrustManager() {}

    protected DelegatingTrustManager(X509ExtendedTrustManager delegate) {
        setDelegate(delegate);
    }

    protected X509ExtendedTrustManager setDelegate(X509ExtendedTrustManager delegate) {
        return this.delegate.getAndSet(delegate);
    }

    protected X509ExtendedTrustManager getDelegate() {
        return delegate.get();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            getDelegate().checkClientTrusted(chain, authType);
            log(true, chain, authType, null);
        } catch (RuntimeException | CertificateException e) {
            logAndRethrow(true, chain, authType, null, e);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        try {
            getDelegate().checkClientTrusted(chain, authType, socket);
            log(true, chain, authType, socket);
        } catch (RuntimeException | CertificateException e) {
            logAndRethrow(true, chain, authType, socket, e);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        try {
            getDelegate().checkClientTrusted(chain, authType, sslEngine);
            log(true, chain, authType, sslEngine);
        } catch (RuntimeException | CertificateException e) {
            logAndRethrow(true, chain, authType, sslEngine, e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            getDelegate().checkServerTrusted(chain, authType);
            log(false, chain, authType, null);
        } catch (RuntimeException | CertificateException e) {
            logAndRethrow(false, chain, authType, null, e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        try {
            getDelegate().checkServerTrusted(chain, authType, socket);
            log(false, chain, authType, socket);
        } catch (RuntimeException | CertificateException e) {
            logAndRethrow(false, chain, authType, socket, e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        log.trace("checkServerTrusted({}, {}, engine:{})", chain, authType, sslEngine);
        try {
            getDelegate().checkServerTrusted(chain, authType, sslEngine);
            log(false, chain, authType, sslEngine);
        } catch (RuntimeException | CertificateException e) {
            logAndRethrow(false, chain, authType, sslEngine, e);
        }
    }

    @SneakyThrows // Always rethrow e which is RuntimeException | CertificateException
    private void logAndRethrow(boolean client, X509Certificate[] chain, String authType, Object sslSource, Exception e) {
        log(client, chain, authType, sslSource, false, e.getMessage());
        throw e;
    }

    private void log(boolean client, X509Certificate[] chain, String authType, Object sslSource) {
        log(client, chain, authType, sslSource, true, null);
    }

    private void log(boolean client, X509Certificate[] chain, String authType, Object sslSource, boolean trusted, String reason) {
        if (log.isDebugEnabled()) {
            String method = client ? "checkClientTrusted" : "checkServerTrusted";
            String chainParam = log.isTraceEnabled() ? Arrays.toString(chain) : SslLogUtils.toShortString(chain);
            String extraParam = sslSource != null ? (", " + sslSource) : "";
            String outcome = trusted ? "=> trusted" : ("=> NOT trusted: " + reason);

            log.debug("{}({}, {}{}){}", method, chainParam, authType, extraParam, outcome);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        log.trace("getAcceptedIssuers()");
        X509Certificate[] acceptedIssuers = getDelegate().getAcceptedIssuers();
        if (log.isDebugEnabled()) {
            String issuers = log.isTraceEnabled() ? Arrays.toString(acceptedIssuers) : SslLogUtils.toShortString(acceptedIssuers);
            log.debug("getAcceptedIssuers()=> {}", issuers);
        }

        return acceptedIssuers;
    }
}