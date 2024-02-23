package vdr.jsse;

import static vdr.jsse.HotReloadProvider.SUN_JSSE;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.stream.Collectors;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;
import vdr.jsse.utils.SslLogUtils;

/**
 * SSLContext wrapper around SunJSSE implementation allowing resetting of connection (invalidation of session and renegotiation of engine)
 * when used with a {@link ReloadableKeyManager} or {@link ReloadableTrustManager} backed by a {@link DynamicFileKeystore}
 * <p>
 *     Does not support SSLSocket, however socket are not used by Kafka.
 * </p>
 * <p>
 *     Once an SSLSocket or SSLEngine is initialised and has gone through its handshake it can be used regardless
 *     of Keystore reload and certificate change. At least until the Server drops the connection. In Kafka case,
 *     Client and Server will hog an opened connection for as long as possible, which can be days after certificate change.
 *     <br/>
 *     This is not concerning, except if Certificate DN change, which means a client could run with unexpected ACL for
 *     some time. In that case, this implementation allows invalidating all the SSLSession and request a SSL renegotiation.
 *     <br/>
 *     Renegotiation is often not supported by TLS libraries, Kafka being one of them. When a new handshake request
 *     is requested the client/server closes the connection with an error and a fresh new one is recreated.
 *     In addition, it is common for server to outright forbid renegotiation (historically renegotiation had a vulnerability in TLS 1.2)
 *     <br/>
 *     In TLSv1.3, renegotiation is not longer supported. Request for renegotiation only reset the internal TLS state machine
 *     back to FINISHED but remains opened for Application Data. The state change is enough to trigger a reset in Kafka,
 *     but something more forceful is required for other libraries. This SSLContext will forcefully close the SSLEngine
 *     outbound (which should cause a TLS CLOSE_NOTIFY Alert to be sent properly to the server). A library should
 *     recover from this.
 *     <br/>
 *     In Kafka, reload of certificate can generate an error in the log, but as expected, kafka clients recovers.
 * </p>
 */
abstract class ResettableSSLContext extends SSLContextSpi implements KeystoreWatcher.KeystoreReloadListener {
    private final Logger log = LoggerFactory.getLogger(ResettableSSLContext.class);

    private final String protocol;
    private final SSLContext delegate;
    private Set<KeyStore> keystores;
    private final /*Weak*/ Set<SSLEngine> engineInstances = Collections.newSetFromMap(new WeakHashMap<>());

    ResettableSSLContext(String protocol, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.delegate = SSLContext.getInstance(protocol, provider);
        this.protocol = protocol;

        log.debug("Created {}({}, {})", this, protocol, provider);
    }

    @Override
    public Set<KeyStore> getKeystores() {
        return keystores;
    }

    @Override
    public void keystoreReloaded() {
        log.info("Resetting {}: Invalidating SSL Sessions", this);
        invalidateSessions();

        log.info("Resetting {}: Renegotiate {} SSLEngines", this, engineInstances.size());
        renegotiateSSLConnections();
    }

    private void invalidateSessions() {
        invalidateCaches(delegate.getClientSessionContext());
        invalidateCaches(delegate.getServerSessionContext());
    }

    private void invalidateCaches(SSLSessionContext sslSessionContext) {
        getSslSessions(sslSessionContext).forEach((SSLSession session) -> {
            debug("Invalidate Session {}", session);
            session.invalidate();
        });
    }

    private List<SSLSession> getSslSessions(SSLSessionContext sslSessionContext) {
        return Collections.list(sslSessionContext.getIds()).stream()
                .map(sslSessionContext::getSession)
                .filter(Objects::nonNull)
                .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
    }

    private void renegotiateSSLConnections() {
        // Trigger SSL Renegotiation which should be a full handshake as the Session are invalidated.
        // Kafka does not support renegotiation even in TLSv1.2, so this causes the following error to be logged
        //      [Producer clientId=producer-1] Got error produce response with correlation id 7 on topic-partition mach-dlq-0, retrying (2 attempts left). Error: NETWORK_EXCEPTION
        //      [Producer clientId=producer-1] Received invalid metadata error in produce request on partition mach-dlq-0 due to org.apache.kafka.common.errors.NetworkException: The server disconnected before a response was received.. Going to request metadata update now
        // Any other decent low level SSL library should handle blip on the wire, so they would recover fine.
        //
        // In Kafka case, it rebuilds its whole SSL stack, Channel and ChannelBuilder included.
        // That's what happens when it reloads certificate on server-side config change, so except for the extra error
        // in the log, it's all fine.
        engineInstances.forEach(sslEngine -> {
            try {
                if (!sslEngine.isOutboundDone()) {
                    sslEngine.getSession().invalidate();
                    if (Objects.equals("TLSv1.3", sslEngine.getSession().getProtocol())) {
                        // In TLSv1.3, renegotiation is not supported.
                        // Instead, we close the connection.
                        debug("CloseOutbound {}", sslEngine);
                        sslEngine.closeOutbound();
                    } else {
                        debug("BeginHandshake {}", sslEngine);
                        sslEngine.beginHandshake();
                    }
                } else {
                    // It's dead, Jim
                    debug("Ignoring {}", sslEngine);
                }
            } catch (SSLException e) {
                // This can happen when the connection is broken or already closed
                // eg: Peer closed its outbound and we have not handshaken it on our side
                // Do not log the stracktrace to avoid distracting noise in logs.
                log.warn("Could not BeginHandshake {}:\n{}", SslLogUtils.toString(sslEngine), SslLogUtils.getSSLExceptionMessage(e));
            }
        });
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom random) throws KeyManagementException {
        log.trace("{}$engineInit({}, {}, {})", this, km, tm, random);
        keystores = new HashSet<>();
        keystores.addAll(KeystoreWatcher.KeystoreReloadListener.getKeystores(km));
        keystores.addAll(KeystoreWatcher.KeystoreReloadListener.getKeystores(tm));

        delegate.init(km, tm, random);
        log.debug("Initialised SSLContext {}", this);
        // Register with KeystoreWatcher after delegate.init() to avoid rogue early call to #keystoreReloaded()
        // to fail. An SSLContext throws IllegalStateException on about every method before init anyway.
        HotReloadProvider.getKeystoreWatcher().listen(this);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        throw new UnsupportedOperationException("ResettableSSLContext does not support SSLSocket");
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        throw new UnsupportedOperationException("ResettableSSLContext does not support SSLSocket");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        SSLEngine engine = delegate.createSSLEngine();
        engineInstances.add(engine);

        debug(this + "$engineCreateSSLEngine()=> {}", engine);
        return engine;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        SSLEngine engine = delegate.createSSLEngine(host, port);
        engineInstances.add(engine);

        log.debug("{}$engineCreateSSLEngine({}, {})=> {}", this, host, port, engine);
        return engine;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return delegate.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return delegate.getClientSessionContext();
    }

    private void debug(String message, SSLEngine engine) {
        if (log.isDebugEnabled()) {
            log.debug(message, SslLogUtils.toString(engine));
        }
    }

    private void debug(String message, SSLSession session) {
        if (log.isDebugEnabled()) {
            log.debug(message, SslLogUtils.toString(session));
        }
    }

    @Override
    public String toString() {
        return "ResettableSSLContext_" + protocol + "@" + Integer.toHexString(hashCode()) + "[" + delegate.getClass().getSimpleName() + "@" + Integer.toHexString(delegate.hashCode()) + "]";
    }

    public static class TLS10Context extends ResettableSSLContext {
        public TLS10Context() throws NoSuchAlgorithmException, NoSuchProviderException {
            super("TLSv1", SUN_JSSE);
        }
    }

    public static class TLS11Context extends ResettableSSLContext {
        public TLS11Context() throws NoSuchAlgorithmException, NoSuchProviderException {
            super("TLSv1.1", SUN_JSSE);
        }
    }

    public static class TLS12Context extends ResettableSSLContext {
        public TLS12Context() throws NoSuchAlgorithmException, NoSuchProviderException {
            super("TLSv1.2", SUN_JSSE);
        }
    }

    public static class TLS13Context extends ResettableSSLContext {
        public TLS13Context() throws NoSuchAlgorithmException, NoSuchProviderException {
            super("TLSv1.3", SUN_JSSE);
        }
    }

    public static class TLSContext extends ResettableSSLContext {
        public TLSContext() throws NoSuchAlgorithmException, NoSuchProviderException {
            super("TLS", SUN_JSSE);
        }
    }

    public static class DefaultSSLContext extends ResettableSSLContext {
        public DefaultSSLContext() throws NoSuchAlgorithmException, NoSuchProviderException {
            super("Default", SUN_JSSE);
        }
    }
}
