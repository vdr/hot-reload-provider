package vdr.jsse.utils;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

/**
 * Boilerplate code that delegates to another keymanager instance.
 */
public class DelegatingKeyManager extends X509ExtendedKeyManager {
    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final AtomicReference<X509ExtendedKeyManager> delegate = new AtomicReference<>();

    protected DelegatingKeyManager() {}

    protected DelegatingKeyManager(X509ExtendedKeyManager delegate) {
        setDelegate(delegate);
    }

    protected X509ExtendedKeyManager setDelegate(X509ExtendedKeyManager delegate) {
        return this.delegate.getAndSet(delegate);
    }

    protected X509ExtendedKeyManager getDelegate() {
        return delegate.get();
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        log.trace("chooseEngineClientAlias({}, {}, {})", keyTypes, issuers, engine);
        String alias = getDelegate().chooseEngineClientAlias(keyTypes, issuers, engine);
        log.debug("chooseEngineClientAlias()=> {}", alias);

        return alias;
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        log.trace("chooseEngineServerAlias({}, {}, {})", keyType, issuers, engine);
        String alias = getDelegate().chooseEngineServerAlias(keyType, issuers, engine);
        log.debug("chooseEngineServerAlias()=> {}", alias);

        return alias;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        log.trace("getClientAliases({}, {})", keyType, issuers);
        String[] aliases = getDelegate().getClientAliases(keyType, issuers);
        log.debug("getClientAliases()=> {}", (Object) aliases);

        return aliases;
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        log.trace("chooseClientAlias({}, {}, {})", keyTypes, issuers, socket);
        String alias = getDelegate().chooseClientAlias(keyTypes, issuers, socket);
        log.debug("chooseClientAlias()=> {}", alias);

        return alias;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        log.trace("getServerAliases({}, {})", keyType, issuers);
        String[] aliases = getDelegate().getServerAliases(keyType, issuers);
        log.debug("getServerAliases()=> {}", (Object) aliases);

        return aliases;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        log.trace("chooseServerAlias({}, {}, {})", keyType, issuers, socket);
        String alias = getDelegate().chooseServerAlias(keyType, issuers, socket);
        log.debug("chooseServerAlias()=> {}", alias);

        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        log.trace("getCertificateChain({})", alias);
        X509Certificate[] chain = getDelegate().getCertificateChain(alias);
        if (log.isDebugEnabled()) {
            log.debug("getCertificateChain({})=> {}", alias, log.isTraceEnabled() ? chain : SslLogUtils.toShortString(chain));
        }

        return chain;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        log.trace("getPrivateKey({})", alias);
        PrivateKey key = getDelegate().getPrivateKey(alias);
        log.debug("getPrivateKey({}) => {}", alias, key == null ? "not found" : "found"); // Do not log private keys!

        return key;
    }
}
