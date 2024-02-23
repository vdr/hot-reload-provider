package vdr.jsse;

import static vdr.jsse.HotReloadProvider.SUN_JSSE;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import lombok.SneakyThrows;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

/**
 * @see ReloadableKeyManager Factory for ReloadableKeyManager
 */
abstract class ReloadableKeyManagerFactory extends KeyManagerFactorySpi {
    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    private final String algorithm;

    private ReloadableKeyManager reloadableKeyManager;

    private ReloadableKeyManagerFactory(String algorithm) {
        this.algorithm = algorithm;
    }

    @SneakyThrows(NoSuchProviderException.class /* This cannot happen with SunJSSE */)
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        log.debug("Init KM Factory with Keystore {}", ks);
        try {
            reloadableKeyManager = new ReloadableKeyManager(algorithm, SUN_JSSE, ks, password);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not init key manager factory: ", e);
        }
    }

    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("ReloadableKeyManagerFactory does not use ManagerFactoryParameters");
    }

    protected KeyManager[] engineGetKeyManagers() {
        return new KeyManager[] {reloadableKeyManager};
    }

    public static final class SunX509 extends ReloadableKeyManagerFactory {
        public SunX509() {
            super("SunX509");
        }
    }

    public static final class NewSunX509 extends ReloadableKeyManagerFactory {
        public NewSunX509() {
            super("NewSunX509");
        }
    }
}
