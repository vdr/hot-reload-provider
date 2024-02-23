package vdr.jsse;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.WatchService;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Setter;
import lombok.ToString;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;
import vdr.jsse.utils.FileWatcher;

/**
 * HotReload JSSE Provider
 * <p>
 *     Provides a FileWatching Keystore ({@value #ALGO_KEYSTORE}) and a set of
 *     TLS Context (TLS, TLSv#, Default),
 *     KeyManager ({@value #ALGO_KEYMANAGER_X509}, {@value #ALGO_KEYMANAGER_PKIX})
 *     and TrustManager ({@value #ALGO_TRUSTMANAGER_X509}, {@value ##ALGO_TRUSTMANAGER_PKIX})
 *     that will monitor keystore file to trigger reload of certificates and reset of a running SSLEngine
 * </p>
 * <p>
 *     It is recommended using this provider on its own using its specific algorithm.
 *     Alternatively if loaded as {@link #enableFirst() first JSSE provider},
 *     this will intercept default SunJSSE TLS Contexts, Keymanager and TrustManager
 * </p>
 * <p>
 *     Can be loaded dynamically using either {@link #enableFirst()} or {@link #enableLast()}, or statically in
 *     <tt>$JAVA_HOME/conf/security/java.security</tt>
 * </p>
 * @see <a href="https://github.com/cloudfoundry/java-buildpack-security-provider">Buildback JSSE</a>
 * @see <a href="https://github.com/bcgit/bc-java">BouncyCastle</a>
 * @see <a href="https://github.com/tersesystems/debugjsse">DebugJSSE</a>
 * @see sun.security.provider.Sun
 * @see sun.security.ssl.SunJSSE
 * @see apple.security.AppleProvider
 * @see <a href="https://docs.oracle.com/en/java/javase/11/security/howtoimplaprovider.html">How to Implement a Provider</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html">JSSE Documentation</a>
 */
@SuppressWarnings("JavadocReference")
@ToString
@EqualsAndHashCode(callSuper = false)
public final class HotReloadProvider extends Provider implements Closeable {
    private static final Logger LOG = LoggerFactory.getLogger(HotReloadProvider.class);

    public static final String NAME = "HotReload";
    public static final String ALGO_KEYSTORE = "DynamicKeystore";
    public static final String ALGO_KEYMANAGER_X509 = "ReloadableX509";
    public static final String ALGO_KEYMANAGER_PKIX = "ReloadablePKIX";
    public static final String ALGO_TRUSTMANAGER_X509 = "ReloadableSimple";
    public static final String ALGO_TRUSTMANAGER_PKIX = "ReloadablePKIX";

    public static final String PROPERTY_EVENT_BUFFER_WINDOW_MS = "HotReload.EventBufferWindowMs";
    public static final String PROPERTY_EVENT_BUFFER_WINDOW_MS_DEFAULT = "1000";

    public static final double VERSION = 1.0;
    public static final String INFO = "HotReload JSSE Provider (Dynamic Keystore, Reloadable KM/TM, Resettable SSLContext)";

    private static final String TYPE_KEY_MANAGER_FACTORY = "KeyManagerFactory";
    private static final String TYPE_TRUST_MANAGER_FACTORY = "TrustManagerFactory";
    private static final String TYPE_SSL_CONTEXT = "SSLContext";
    private static final String TYPE_KEYSTORE = "Keystore";

    /** Default Java JSSE implementation */
    static final String SUN_JSSE = "SunJSSE";

    private transient WatchService watchService;
    private transient FileWatcher fileWatcher;
    @Setter(AccessLevel.PACKAGE /* For testing */)
    private transient KeystoreWatcher keystoreWatcher;

    public HotReloadProvider() throws IOException {
        this(false);
    }

    HotReloadProvider(boolean dummy) throws IOException {
        super(NAME, VERSION, INFO);
        if (!dummy) {
            init();
        } else {
            // Testing only: an instance that lives outside JSSE.
            LOG.info("Loaded DUMMY Provider {} v{}: {}", NAME, VERSION, INFO);
        }
    }

    private void init() throws IOException {
        long fsEventsBufferWindowMs = Long.parseLong(System.getProperty(PROPERTY_EVENT_BUFFER_WINDOW_MS, PROPERTY_EVENT_BUFFER_WINDOW_MS_DEFAULT));
        watchService = FileSystems.getDefault().newWatchService();
        fileWatcher = new FileWatcher(watchService, fsEventsBufferWindowMs);
        keystoreWatcher = new KeystoreWatcher(fileWatcher);

        registerServices();
        LOG.info("Loaded Provider {} v{}: {}", NAME, VERSION, INFO);
        LOG.debug("HotReload Provider {} started.", this);
    }

    // Java 9+ Hook
    //@Override
    public Provider configure(String configArg) { //NOSONAR Method signature imposed by Java 9+
        // We don't have anything to configure, so just return this.
        return this;
    }

    private void registerServices() {
        // Java 17+ https://openjdk.java.net/jeps/411 AccessController.doPrivileged(...) is deprecated
        //          Vestigial pattern from bygone java 1.0 era.
        //          it shouldn't be required even in Java 8+ Apps this provider could plug into.
        doRegisterServices();
    }

    private void doRegisterServices() {
        registerService(TYPE_KEY_MANAGER_FACTORY, ALGO_KEYMANAGER_X509, ReloadableKeyManagerFactory.SunX509.class.getName(),
                Arrays.asList("SunX509"));
        registerService(TYPE_KEY_MANAGER_FACTORY, ALGO_KEYMANAGER_PKIX, ReloadableKeyManagerFactory.NewSunX509.class.getName(),
                Arrays.asList("NewSunX509", "PKIX"));
        registerService(TYPE_TRUST_MANAGER_FACTORY, ALGO_TRUSTMANAGER_X509, ReloadableTrustManagerFactory.SunX509.class.getName(),
                Arrays.asList("SunX509"));
        registerService(TYPE_TRUST_MANAGER_FACTORY, ALGO_TRUSTMANAGER_PKIX, ReloadableTrustManagerFactory.PKIX.class.getName(),
                Arrays.asList("PKIX", "SunPKIX", "X509", "X.509"));

        registerService(TYPE_KEYSTORE, ALGO_KEYSTORE, DynamicFileKeystore.class.getName());

        registerService(TYPE_SSL_CONTEXT, "TLSv1", ResettableSSLContext.TLS10Context.class.getName(),
                Arrays.asList("SSLv3"));
        registerService(TYPE_SSL_CONTEXT, "TLSv1.1", ResettableSSLContext.TLS11Context.class.getName());
        registerService(TYPE_SSL_CONTEXT, "TLSv1.2", ResettableSSLContext.TLS12Context.class.getName());
        registerService(TYPE_SSL_CONTEXT, "TLSv1.3", ResettableSSLContext.TLS13Context.class.getName());
        registerService(TYPE_SSL_CONTEXT, "TLS", ResettableSSLContext.TLSContext.class.getName(),
                Arrays.asList("SSL"));
        registerService(TYPE_SSL_CONTEXT, "Default", ResettableSSLContext.DefaultSSLContext.class.getName());
    }

    private void registerService(String type, String algo, String cn) {
        registerService(type, algo, cn, null);
    }

    private void registerService(String type, String algo, String cn, List<String> aliases) {
        putService(new Provider.Service(this, type, algo, cn, aliases, null));
    }

    @Override
    public void close() {
        safeClose(fileWatcher);
        safeClose(watchService);
    }

    private static void safeClose(Closeable closeable) {
        try {
            closeable.close();
        } catch (NullPointerException | IOException e) {
            // At least we tried.
        }
    }

    /**
     * [Recommended] Programmatically load the provider in the last position in the JSSE provider list.
     * <p>
     *     No interception of SunJSSE default implementation will happen.
     *     Use custom algorithm or specify the provider to use this provider.
     * </p>
     *
     * @return the provider instance.
     * @throws IllegalStateException if the provider is already loaded (eg: statically in security config file)
     */
    public static synchronized HotReloadProvider enableLast() throws IOException {
        return enable(false);
    }

    /**
     * [Not recommended] Programmatically load the provider in the first position in the JSSE provider list.
     * <p>
     *     This means that it will intercept SunJSSE default providers.
     * </p>
     *
     * @return the provider instance.
     * @throws IllegalStateException if the provider is already loaded (eg: statically in security config file)
     */
    public static synchronized HotReloadProvider enableFirst() throws IOException {
        return enable(true);
    }

    private static HotReloadProvider enable(boolean first) throws IOException {
        if (!isEnabled()) {
            LOG.info("Load and insert Provider {} in {} position.", NAME, first ? "first" : "last");
            HotReloadProvider provider = new HotReloadProvider();
            if (first) {
                Security.insertProviderAt(provider, 1);
            } else {
                Security.addProvider(provider);
            }

            return provider;
        } else {
            throw new IllegalStateException("Provider is already enabled, statically or dynamically");
        }
    }

    /**
     * @return true if this provider is loaded.
     */
    public static boolean isEnabled() {
        return getInstance() != null;
    }

    public static HotReloadProvider getInstance() {
        return (HotReloadProvider) Security.getProvider(NAME);
    }

    /**
     * Unload this provider.
     */
    public static void disable() {
        if (isEnabled()) {
            HotReloadProvider provider = getInstance();
            LOG.info("Unload Provider {}", NAME);
            Security.removeProvider(NAME);
            LOG.info("Shutdown FileWatcher and WatchService");
            provider.close();
        } else {
            throw new IllegalStateException("Provider is already disabled");
        }
    }

    /**
     * @return the singleton KeystoreWatcher service.
     */
    static synchronized KeystoreWatcher getKeystoreWatcher() {
        return getInstance().keystoreWatcher;
    }

    /**
     * Force the reloading of all keystores and reset ssl connections.
     */
    public static synchronized void forceReloadAllKeystores() {
        getKeystoreWatcher().reloadAll();
    }
}
