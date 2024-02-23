package vdr.jsse;

import java.security.KeyStore;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Helper class blocking until a Keystore has been reloaded and all its Listeners called.
 * <p>
 *     Technically this class registers as a listener and relies on the assumption it is the last listener.
 *     This should therefore be registered as late in the process a possible eg: right before changing a file.
 * </p>
 */
public class KeystoreReloadCompleteNotifier implements KeystoreWatcher.KeystoreReloadListener {
    private static final Logger LOG = LoggerFactory.getLogger(KeystoreReloadCompleteNotifier.class);
    private KeyStore keyStore;
    private final ArrayBlockingQueue<Boolean> events = new ArrayBlockingQueue<>(1);

    public KeystoreReloadCompleteNotifier(KeyStore keyStore) {
        this.keyStore = keyStore;

        HotReloadProvider.getKeystoreWatcher().listen(this);
    }

    @Override
    public Set<KeyStore> getKeystores() {
        return Collections.singleton(keyStore);
    }

    @Override
    public void keystoreReloaded() {
        events.offer(true);
    }

    public void awaitUntilKeystoreReloaded(long timeout, TimeUnit unit) throws InterruptedException {
        events.poll(timeout, unit);
        LOG.info("Nofify reloaded {} ", keyStore);
    }
}
