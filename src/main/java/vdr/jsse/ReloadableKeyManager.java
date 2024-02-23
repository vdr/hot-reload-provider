package vdr.jsse;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import vdr.jsse.utils.DelegatingKeyManager;
import vdr.jsse.utils.PasswordLoader;

/**
 * Reloadable KeyManager intended to enable {@link DynamicFileKeystore} and {@link ResettableSSLContext}
 * <p>
 *     The <b>default</b> SunX509 (sun.security.ssl.SunX509KeyManagerImpl) KeyManager doesn't support updatable Keystore
 *     and cache Keystore entries.
 *     Even with {@link DynamicFileKeystore}, SunX509 needs to be replaced to use the new certificates
 *     This is the primary this class aim to solve.
 * </p>
 * <p>
 *     Designed to work with SunJSSE SunX509, but also works with NewSunX509 when initialised using KeyStore + Password
 *     (i.e. not ManagerFactoryParameters)
 * </p>
 * <p>
 *     NewSunX509 (sun.security.ssl.X509KeyManagerImpl) supports updatable Keystore. It <i>could</i> potentially be used
 *     on its own with {@link DynamicFileKeystore}. However, if intending to use {@link ResettableSSLContext}, this
 *     KeyManager is still necessary to correlate SSLContext with its corresponding DynamicFileKeyStore.
 * </p>
 */
final class ReloadableKeyManager extends DelegatingKeyManager implements KeystoreWatcher.KeystoreReloadListener {
    private final String algorithm;
    private final String provider;
    private final KeyStore ks;
    private char[] password;

    ReloadableKeyManager(String algorithm, String provider, KeyStore ks, char[] password) throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException, IOException {
        this.algorithm = algorithm;
        this.provider = provider;
        this.ks = ks;
        this.password = password;

        try {
            reload();
            log.debug("Loaded KeyManager {}", this);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | UnrecoverableKeyException | KeyStoreException | IOException e) {
            log.error("Could not load KeyManager {}", this);
            // Should not wrap the exception as we want to maintain the same behaviour as underlying KeyManager
            throw e;
        }

        retrieveKeystoreWatcher().listen(this);
    }

    private void reload() throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException, IOException {
        KeyManagerFactory factory = KeyManagerFactory.getInstance(algorithm, provider);
        String propsString = retrieveKeystoreWatcher().extractUnderlyingKeystoreProperties(ks);
        if(propsString != null) {
            KeystoreProperties properties = KeystoreProperties.fromString(propsString);
            if(properties.getKeypassFile() != null) {
                log.debug("Loaded key password from {}", properties.getKeypassFile());
                password = new PasswordLoader().loadFromFile(properties.getKeypassFile());
            }
        }
        factory.init(ks, password);

        // This KM is designed for SunJSSE Sun509/NewSun509, their factory always return a single X509ExtendedKeyManager
        // If this isn't the case, better to fail fast, what the next line will achieve nicely.
        X509ExtendedKeyManager newDelegate = (X509ExtendedKeyManager) factory.getKeyManagers()[0];
        X509ExtendedKeyManager oldDelegate = setDelegate(newDelegate);
        log.debug("Reloaded {}: {} to {}", this, oldDelegate, newDelegate);
    }

    @Override
    public Set<KeyStore> getKeystores() {
        return Collections.singleton(ks);
    }

    @Override
    public void keystoreReloaded() {
        try {
            reload();
            log.info("Reloaded KeyManager {}", this);
        } catch (Exception e) {
            log.error("Could not reload KeyManager {}", this);
            throw new IllegalArgumentException("Could not reload keymanager(" + algorithm + ", " + provider + ", " + ks + ")", e);
        }
    }

    @Override
    public String toString() {
        X509ExtendedKeyManager currentDelegate = getDelegate();

        return "ReloadableKM@" + Integer.toHexString(hashCode()) + "[" + currentDelegate.getClass().getSimpleName() + "@" + Integer.toHexString(currentDelegate.hashCode()) + "]";
    }

    private static KeystoreWatcher retrieveKeystoreWatcher() {
        return HotReloadProvider.getKeystoreWatcher();
    }
}
