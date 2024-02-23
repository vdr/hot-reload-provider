package vdr.jsse;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import lombok.ToString;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;
import vdr.jsse.utils.FileWatcher;

/**
 * Service coordinating keystore, keystore listener and file watching.
 * <p>
 *     Trigger keystore reload on file change and propagate keystore reloaded event to listeners.
 * </p>
 */
@ToString
class KeystoreWatcher {
    private final Logger log = LoggerFactory.getLogger(KeystoreWatcher.class);
    private static final AtomicLong listenerCounter = new AtomicLong();

    private final FileWatcher fileWatcher;
    @ToString.Exclude
    private final WeakHashMap<WatchableKeystore, WeakHashMap<KeystoreReloadListener, Long>> keystores = new WeakHashMap<>();

    public KeystoreWatcher(FileWatcher fileWatcher) {
        this.fileWatcher = fileWatcher;
        fileWatcher.start(this::fileChanged);
    }

    synchronized void register(WatchableKeystore keystore) throws IOException {
        keystores.put(keystore, new WeakHashMap<>());
        fileWatcher.watch(keystore.getProperties().getFile());
        log.debug("Watching keystore {}, {} keystores watched", keystore, keystores.size());
    }

    synchronized void listen(KeystoreReloadListener listener) {
        listener.getKeystores().stream()
                .filter(ks -> ks.getProvider() instanceof HotReloadProvider)
                .map(this::extractUnderlyingKeystoreProperties)
                .filter(Objects::nonNull)
                .forEach(props -> doListenKeystore(listener, props));
    }

    private void doListenKeystore(KeystoreReloadListener listener, String expectedProperties) {
        keystores.forEach((keystore, listeners) -> {
            String currentProperties = keystore.getProperties().storeToString();
            if (Objects.equals(expectedProperties, currentProperties)) {
                listeners.put(listener, listenerCounter.getAndIncrement());
                log.debug("Adding listener {} to keystore {} reload events, {} listeners", listener, keystore, listeners.size());
            }
        });
    }

    String extractUnderlyingKeystoreProperties(KeyStore keystore) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            keystore.store(out, null);
            String properties = new String(out.toByteArray(), StandardCharsets.ISO_8859_1);
            // validate
            KeystoreProperties.fromString(properties);

            return properties;
        } catch (Exception e) {
            // KeyStoreSpi used by this KeyStore instance is not a DynamicFileKeystore.
            // Ignore.
            return null;
        }
    }

    synchronized void reloadAll() {
        log.info("Reload all keystores and notify all listeners");
        keystores.keySet().forEach(WatchableKeystore::keystoreFileChanged);
        keystores.values().stream()
                .flatMap(m -> m.entrySet().stream())
                .sorted(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .forEach(KeystoreReloadListener::keystoreReloaded);
    }

    synchronized void fileChanged(FileWatcher.FileChangedEvent event) {
        File file = event.getFile();

        List<WatchableKeystore> toReload = this.keystores.keySet().stream()
                .filter(ks -> Objects.equals(ks.getProperties().getFile(), file))
                .collect(Collectors.toList());

        log.info("Reloading {} keystores", toReload.size());
        if (toReload.isEmpty()) {
            fileWatcher.unwatch(file);
        } else {
            for (WatchableKeystore ks : toReload) {
                ks.keystoreFileChanged();
                keystores.get(ks).entrySet().stream()
                        .sorted(Map.Entry.comparingByValue())
                        .map(Map.Entry::getKey)
                        .forEach(KeystoreReloadListener::keystoreReloaded);
            }
        }
    }

    synchronized long keystoresCount() {
        return keystores.size();
    }

    synchronized long listenersCount() {
        return keystores.values().stream()
                .mapToLong(m -> m.entrySet().size())
                .sum();
    }

    /**
     * Must be implemented by Keystore SPI registering with this watcher.
     */
    interface WatchableKeystore {
        /**
         * @return the keystore properties the keystore needs watching.
         */
        KeystoreProperties getProperties();

        /**
         * The keystore underlying file listed in {@link #getProperties()} has changed.
         */
        void keystoreFileChanged();
    }

    /**
     * Listener for Keystore reload events.
     */
    interface KeystoreReloadListener {
        /**
         * @return All the Keystores this listener depends on.
         */
        Set<KeyStore> getKeystores();
        /**
         * The keystore watched by this listener has been reloaded.
         */
        void keystoreReloaded();

        /**
         * Extract the keystore from the KeystoreReloadListener in a list of objects.
         * @param o list of object, some or none implementing KeystoreReloadListener
         * @return all the keystore found on all object implementing KeystoreReloadListener.
         */
        static Set<KeyStore> getKeystores(Object[] o) {
            Set<KeyStore> keystores = new HashSet<>();
            Arrays.stream(o)
                    .filter(KeystoreWatcher.KeystoreReloadListener.class::isInstance)
                    .map(KeystoreWatcher.KeystoreReloadListener.class::cast)
                    .forEach(l -> keystores.addAll(l.getKeystores()));

            return keystores;
        }
    }
}
