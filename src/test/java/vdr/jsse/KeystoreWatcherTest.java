package vdr.jsse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static vdr.jsse.utils.FileWatcher.FileChangedType.MODIFIED;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vdr.jsse.KeystoreWatcher.KeystoreReloadListener;
import vdr.jsse.KeystoreWatcher.WatchableKeystore;
import vdr.jsse.utils.FileWatcher;
import vdr.jsse.utils.FileWatcher.FileChangedEvent;

@ExtendWith(MockitoExtension.class)
class KeystoreWatcherTest {
    private static final char[] PASSWORD = "confluent".toCharArray();
    private Path ksFile = Paths.get("src/test/resources/client1.p12").toAbsolutePath();
    private Path passFile = Paths.get("src/test/resources/password.creds").toAbsolutePath();

    private static HotReloadProvider dummyProvider;

    @Mock
    private FileWatcher fileWatcher;

    @InjectMocks
    private KeystoreWatcher keystoreWatcher;

    @BeforeAll
    static void enableProvider() throws IOException {
        dummyProvider = new HotReloadProvider(true);
        dummyProvider.setKeystoreWatcher(mock(KeystoreWatcher.class));
    }

    @Test
    void startsAndRegistersWithFileWatcher() throws IOException {
        File file1 = new File("1");
        File file2 = new File("2");

        keystoreWatcher.register(new TestWatchableKeystore(file1));
        keystoreWatcher.register(new TestWatchableKeystore(file1));
        keystoreWatcher.register(new TestWatchableKeystore(file2));

        verify(fileWatcher).start(any());
        verify(fileWatcher, times(2)).watch(file1);
        verify(fileWatcher).watch(file2);
    }

    @Test
    void triggersListenersInRegistrationOrder() throws Exception {
        TestKeyStore ks = createKeyStore();

        keystoreWatcher.register(ks.spi);

        // Just make sure our listener are not naturally ordered as they would appear in a hashset.
        // In normal code, we don't care, but in this test we want to make sure that KeyWatcher
        // is properly reordering the listeners in their registration order rather than simply in the hashmap order.
        List<KeystoreReloadListener> hashOrderedListeners = new ArrayList<>(new HashSet<>(Arrays.asList(
                mockListener(ks),
                mockListener(ks),
                mockListener(ks)
        )));
        KeystoreReloadListener listener0 = hashOrderedListeners.get(2 /* <- not 0 */);
        KeystoreReloadListener listener1 = hashOrderedListeners.get(0 /* <- not 1 */);
        KeystoreReloadListener listener2 = hashOrderedListeners.get(1 /* <- not 2 */);

        keystoreWatcher.listen(listener0);
        keystoreWatcher.listen(listener1);
        keystoreWatcher.listen(listener2);

        keystoreWatcher.fileChanged(new FileChangedEvent(ksFile.toFile(), MODIFIED));

        inOrder(listener0, listener1, listener2);

        verify(listener0).keystoreReloaded();
        verify(listener1).keystoreReloaded();
        verify(listener2).keystoreReloaded();
    }

    @Test
    void triggersAllListenersInRegistrationOrder() throws Exception {
        TestKeyStore ks1 = createKeyStore();
        TestKeyStore ks2 = createKeyStore();

        keystoreWatcher.register(ks1.spi);
        keystoreWatcher.register(ks2.spi);

        // Just make sure our listener are not naturally ordered as they would appear in a hashset.
        // In normal code, we don't care, but in this test we want to make sure that KeyWatcher
        // is properly reordering the listeners in their registration order rather than simply in the hashmap order.
        List<KeystoreReloadListener> hashOrderedListeners = new ArrayList<>(new HashSet<>(Arrays.asList(
                mockListener(ks1),
                mockListener(ks1),
                mockListener(ks2),
                mockListener(ks2)

        )));
        KeystoreReloadListener listener0 = hashOrderedListeners.get(2 /* <- not 0 */);
        KeystoreReloadListener listener1 = hashOrderedListeners.get(0 /* <- not 1 */);
        KeystoreReloadListener listener2 = hashOrderedListeners.get(3 /* <- not 2 */);
        KeystoreReloadListener listener3 = hashOrderedListeners.get(1 /* <- not 3 */);

        keystoreWatcher.listen(listener0);
        keystoreWatcher.listen(listener1);
        keystoreWatcher.listen(listener2);
        keystoreWatcher.listen(listener3);

        keystoreWatcher.reloadAll();

        inOrder(listener0, listener1, listener2, listener3);

        verify(listener0).keystoreReloaded();
        verify(listener1).keystoreReloaded();
        verify(listener2).keystoreReloaded();
        verify(listener3).keystoreReloaded();

    }

    @Test
    void doesNotAffectGarbageCollection() throws Exception {
        registerKS();

        System.gc();
        await().pollInterval(1, TimeUnit.SECONDS).until(() -> keystoreWatcher.keystoresCount() == 0);
    }

    private void registerKS() throws Exception {
        TestKeyStore ks = createKeyStore();
        keystoreWatcher.register(ks.spi);

        registerListeners(ks);

        assertThat(keystoreWatcher.keystoresCount()).isEqualTo(1);

        System.gc();
        await().pollInterval(1, TimeUnit.SECONDS).until(() -> keystoreWatcher.listenersCount() == 0);
    }

    private void registerListeners(TestKeyStore ks) {
        // Note - don't use mock like mockListener() as they are strongly referenced in Mockito.
        keystoreWatcher.listen(new TestKeystoreListener(ks));
        keystoreWatcher.listen(new TestKeystoreListener(ks));

        assertThat(keystoreWatcher.listenersCount()).isEqualTo(2);
    }

    @Test
    void unwatchesFile_WhenCorrespondingKS_is_GarbageCollected() throws Exception {
        File file = new File("1");
        registerKSWithFile(file);

        System.gc();
        await().pollInterval(1, TimeUnit.SECONDS).until(() -> keystoreWatcher.keystoresCount() == 0);

        // We don't actively monitor a ReferenceQueue,
        // so the KeystoreWatcher only notices when an event for the file is raised.
        keystoreWatcher.fileChanged(new FileChangedEvent(file, MODIFIED));
        verify(fileWatcher).unwatch(file);
    }

    private void registerKSWithFile(File file) throws Exception {
        keystoreWatcher.register(new TestWatchableKeystore(file));

        verify(fileWatcher).start(any());
        verify(fileWatcher).watch(file);
    }

    private KeystoreReloadListener mockListener(KeyStore ks) {
        KeystoreReloadListener listener = mock(KeystoreReloadListener.class);
        when(listener.getKeystores()).thenReturn(Collections.singleton(ks));

        return listener;
    }

    private TestKeyStore createKeyStore() throws Exception {
        KeystoreProperties properties = new KeystoreProperties("PKCS12", ksFile.toFile(), passFile.toFile(), passFile.toFile());

        try (InputStream stream = properties.storeToInputStream()) {
            TestKeyStore ks = new TestKeyStore(new DynamicFileKeystore(), dummyProvider, HotReloadProvider.ALGO_KEYSTORE);
            ks.load(stream, PASSWORD);

            return ks;
        }
    }

    private static class TestWatchableKeystore implements WatchableKeystore {
        private KeystoreProperties keystoreProperties;

        private TestWatchableKeystore(File file) {
            keystoreProperties = new KeystoreProperties("", file, null, null);
        }

        @Override
        public KeystoreProperties getProperties() {
            return keystoreProperties;
        }

        @Override
        public void keystoreFileChanged() {
        }
    }

    private static class TestKeystoreListener implements KeystoreReloadListener {
        private final KeyStore ks;

        public TestKeystoreListener(KeyStore ks) {
            this.ks = ks;
        }

        @Override
        public Set<KeyStore> getKeystores() {
            return Collections.singleton(ks);
        }

        @Override
        public void keystoreReloaded() {
        }
    }

    private static class TestKeyStore extends KeyStore {
        DynamicFileKeystore spi;

        protected TestKeyStore(DynamicFileKeystore keyStoreSpi, Provider provider, String type) {
            super(keyStoreSpi, provider, type);
            this.spi = keyStoreSpi;
        }

    }

}