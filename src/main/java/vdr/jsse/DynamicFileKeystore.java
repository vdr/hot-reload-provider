package vdr.jsse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicReference;
import lombok.SneakyThrows;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;
import vdr.jsse.utils.PasswordLoader;

/**
 * <b>ReadOnly</b> Keystore supporting dynamic reload of the Keystore from the filesystem.
 * <p>
 *      Take a properties file as input stream that points to the actual underlying keystore file and format.
 * </p>
 * <p>
 *     Reload can be triggered manually, or through file change monitor in {@link KeystoreWatcher}.
 * </p>
 * <p>
 *     Readonly means that this keystore return IllegalArgumentException when trying to add/delete/update certificate.
 *     This is done to avoid confusion between reload from file and keystore update semantic, especially if using
 *     dynamic Trust/KeyManager.<br/>
 *     example: added certificate would disappear upon reload, deleted certificate could reappear.
 * </p>
 * <p>
 *     {@link #engineStore(OutputStream, char[])} is implemented and always return the same data as the original input stream.
 * </p>
 * @see KeystoreProperties
 * @see KeystoreWatcher
 */
@SuppressWarnings("JavadocReference")
public final class DynamicFileKeystore extends KeyStoreSpi implements KeystoreWatcher.WatchableKeystore {
    private final Logger log = LoggerFactory.getLogger(DynamicFileKeystore.class);

    /* Access for testing */ final AtomicReference<KeyStore> delegate = new AtomicReference<>();
    private KeystoreProperties properties;
    private KeyStore.ProtectionParameter protectionParameter;

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        properties = KeystoreProperties.fromInputStream(stream);
        protectionParameter = new KeyStore.PasswordProtection(password);
        try {
            reload();
            log.debug("Loaded Keystore {}", this);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Could not load Keystore {}", this);
            // Should not wrap the exception as we want to maintain the same behaviour as underlying Keystore
            throw e;
        }

        if (HotReloadProvider.isEnabled()) {
            HotReloadProvider.getKeystoreWatcher().register(this);
        } // else for testing.
    }

    @Override
    public KeystoreProperties getProperties() {
        return properties;
    }

    @Override
    public void keystoreFileChanged() {
        try {
            reload();
            log.info("Reloaded Keystore {}", this);
        } catch (Exception e) {
            log.error("Could not reload Keystore {}", this);
            throw new IllegalArgumentException("Could not reload keystore: " + properties, e);
        }
    }

    private void reload() throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            if(properties.getPasswordFile() != null) {
                log.debug("(Re)Loaded keystore password from {}", properties.getPasswordFile());
                char[] password = new PasswordLoader().loadFromFile(properties.getPasswordFile());
                protectionParameter =  new KeyStore.PasswordProtection(password);
            }
            Builder builder = Builder.newInstance(properties.getAlgorithm(), null, properties.getFile(), protectionParameter);
            delegate.set(builder.getKeyStore());
        } catch (KeyStoreException e) {
            // There is a mismatch of exception thrown between the various Keystore building methods:
            //  * Keystore builder classes (Builder.newInstance)
            //  * Keystore constructor methods (Keystore.getInstance)
            //  * Keystore loading methods (Keystore.load)
            //
            // Builder uses loading under the hood, wrapping its exception in KeyStoreException
            // Try to unwrap the original exception.
            // Otherwise, use a more usual IllegalArgumentException (that the builder often also throws)
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            } else if (cause instanceof NoSuchAlgorithmException) {
                throw (NoSuchAlgorithmException) cause;
            } else if (cause instanceof CertificateException) {
                throw (CertificateException) cause;
            }
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Store <b>this</b> Keystore properties, not the delegate's.
     */
    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException {
        properties.store(stream);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return delegate.get().getKey(alias, password);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public Certificate[] engineGetCertificateChain(String alias) {
        return delegate.get().getCertificateChain(alias);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public Certificate engineGetCertificate(String alias) {
        return delegate.get().getCertificate(alias);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public Date engineGetCreationDate(String alias) {
        return delegate.get().getCreationDate(alias);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public Enumeration<String> engineAliases() {
        return delegate.get().aliases();
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public boolean engineContainsAlias(String alias) {
        return delegate.get().containsAlias(alias);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public int engineSize() {
        return delegate.get().size();
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public boolean engineIsKeyEntry(String alias) {
        return delegate.get().isKeyEntry(alias);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public boolean engineIsCertificateEntry(String alias) {
        return delegate.get().isCertificateEntry(alias);
    }

    @Override
    @SneakyThrows(KeyStoreException.class /* Bubble up KeystoreException to Keystore where it can be thrown normally */)
    public String engineGetCertificateAlias(Certificate cert) {
        return delegate.get().getCertificateAlias(cert);
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw newReadOnlyException();
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw newReadOnlyException();
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw newReadOnlyException();
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw newReadOnlyException();
    }

    private KeyStoreException newReadOnlyException() {
        return new KeyStoreException("DynamicFileKeystore does not support in memory changes");
    }

    @Override
    public String toString() {
        return "DynamicFileKeystore@" + Integer.toHexString(hashCode()) + "[" + properties + "]";
    }
}
