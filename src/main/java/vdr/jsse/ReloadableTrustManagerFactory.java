package vdr.jsse;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

/**
 * @see ReloadableTrustManager Factory for ReloadableTrustManager
 */
abstract class ReloadableTrustManagerFactory extends TrustManagerFactorySpi {
    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    private final String algorithm;
    private ReloadableTrustManager reloadableTrustManager;

    private ReloadableTrustManagerFactory(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {
        log.debug("Init TM Factory with static Keystore {}", ks);
        try {
            reloadableTrustManager = new ReloadableTrustManager(algorithm, HotReloadProvider.SUN_JSSE, ks);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            // Keystore is commonly used in JSSE to wrap low level exception such as these.
            // see KeyStore.Builder for example
            // Note that this shouldn't happen in practice as we handpicked Algorithm and Provider
            // SunJSSE PKIX and SunX509 must be available in all java distro.
            throw new KeyStoreException(e);
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("ReloadableTrustManagerFactory does not use ManagerFactoryParameters");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[]{reloadableTrustManager};
    }

    public static final class SunX509 extends ReloadableTrustManagerFactory {
        public SunX509() {
            super("SunX509");
        }
    }

    public static final class PKIX extends ReloadableTrustManagerFactory {
        public PKIX() {
            super("PKIX");
        }
    }
}

