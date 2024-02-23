package vdr.jsse;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collections;
import java.util.Set;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import vdr.jsse.utils.DelegatingTrustManager;

/**
 * Reloadable TrustManager intended to enable {@link DynamicFileKeystore} and {@link ResettableSSLContext}
 * <p>
 *     Designed to work with SunJSSE SunX509 (Simple) and PKIX when initialised using KeyStore
 *     (i.e. not ManagerFactoryParameters)
 * </p>
 * <p>
 *     Default TM PKIX (sun.security.ssl.X509TrustManagerImpl) supports updatable Keystore.
 *     It <i>could</i> potentially be used on its own with {@link DynamicFileKeystore}.
 *     However, if intending to use {@link ResettableSSLContext}, this KeyManager is still necessary
 *     to correlate SSLContext with its corresponding DynamicFileKeyStore.
 * </p>
 */
class ReloadableTrustManager extends DelegatingTrustManager implements KeystoreWatcher.KeystoreReloadListener {
    private final String algorithm;
    private final String provider;
    private final KeyStore ks;

    ReloadableTrustManager(String algorithm, String provider, KeyStore ks) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        this.algorithm = algorithm;
        this.provider = provider;
        this.ks = ks;

        try {
            reload();
            log.debug("Loaded TrustManager {}", this);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException e) {
            log.error("Could not load TrustManager {}", this);
            // Should not wrap the exception as we want to maintain the same behaviour as underlying KeyManager
            throw e;
        }

        HotReloadProvider.getKeystoreWatcher().listen(this);
    }

    private void reload() throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(algorithm, provider);
        factory.init(ks);

        // This KM is designed for SunJSSE Sun509/PKIX, their factory always return a single X509ExtendedTrustManager
        // If this isn't the case, better to fail fast, what the next line will achieve nicely.
        X509ExtendedTrustManager newDelegate = (X509ExtendedTrustManager) factory.getTrustManagers()[0];
        X509ExtendedTrustManager oldDelegate = setDelegate(newDelegate);
        log.debug("Reloaded {}: {} to {}", this, oldDelegate, newDelegate);
    }

    @Override
    public void keystoreReloaded() {
        try {
            reload();
            log.info("Reloaded TrustManager {}", this);
        } catch (Exception e) {
            log.error("Could not load TrustManager {}", this);
            throw new IllegalArgumentException("Could not reload trustmanager(" + algorithm + ", " + provider + ", " + ks + ")", e);
        }
    }

    @Override
    public Set<KeyStore> getKeystores() {
        return Collections.singleton(ks);
    }

    @Override
    public String toString() {
        X509ExtendedTrustManager currentDelegate = getDelegate();
        return "ReloadableTM@" + Integer.toHexString(hashCode()) + "[" + currentDelegate.getClass().getSimpleName() + "@" + Integer.toHexString(currentDelegate.hashCode()) + "]";
    }
}