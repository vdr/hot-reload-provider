package vdr.jsse.demo;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import vdr.jsse.HotReloadProvider;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;
import vdr.jsse.test.SslContextBuilder;
import vdr.jsse.test.TestUtils;
import vdr.jsse.test.engine.Channel;
import vdr.jsse.test.engine.NioClient;
import vdr.jsse.test.engine.NioServer;
import vdr.jsse.test.engine.PlainChannel;
import vdr.jsse.test.engine.SslChannel;

/**
 * Demo of EssSecurity used in TLSv1.2 and TLSv1.3 with and without reload. Uses custom NIO client and server.
 */
public class NioReloadDemo {
	private static final Logger LOG = LoggerFactory.getLogger(NioReloadDemo.class);
	private final SslContextBuilder serverContextBuilder;
	private final SslContextBuilder clientContextBuilder;
	private final Path clientKeyStoreFile;
	private final Path clientPasswordFile;
	private final Path clientKeypassFile;
	private final boolean ssl;
	private final boolean reload;
	private final boolean testPasswordChange;

	public static void main(String[] args) throws Exception {
		try (HotReloadProvider provider = HotReloadProvider.enableLast()) {
			System.out.println("Demo HotReload Provider with NIO SSL Client and Server");
			System.out.println("===============================================");

			System.out.println("=========== Reference PlainText NIO ===========");
			new NioReloadDemo(null, false, false).run();

			System.out.println("===============================================");
			System.out.println("============== TLSv1.2 Reference ==============");
			new NioReloadDemo("TLSv1.2", false, false).run();

			System.out.println("============== TLSv1.2 Reload =================");
			new NioReloadDemo("TLSv1.2", true, false).run();

			System.out.println("============== TLSv1.2 Password Change =================");
			new NioReloadDemo("TLSv1.2", false, true).run();

			System.out.println("===============================================");
			System.out.println("============== TLSv1.3 Reference ==============");
			new NioReloadDemo("TLSv1.3", false, false).run();

			System.out.println("============== TLSv1.3 Reload =================");
			new NioReloadDemo("TLSv1.3", true, false).run();

			System.out.println("============== TLSv1.3 Password Change =================");
			new NioReloadDemo("TLSv1.3", false, true).run();
		}
	}

	public NioReloadDemo(String protocol, boolean reloadNoPasswordChange, boolean reloadWithPasswordChange) throws IOException {
		if(reloadNoPasswordChange && reloadWithPasswordChange) {
			throw new IllegalArgumentException("You can't test reload with password change and reload without password change at the same time.");
		}

		this.ssl = protocol != null;
		this.reload = ssl && reloadNoPasswordChange;
		this.testPasswordChange = ssl && reloadWithPasswordChange;

		clientKeyStoreFile = Files.createTempFile("clientKeyStore", ".p12");
		clientPasswordFile = Files.createTempFile("clientPassword", ".creds");
		clientKeypassFile = Files.createTempFile("clientKeypass", ".creds");
		TestUtils.copyFile("src/test/resources/client1.p12", clientKeyStoreFile.toString());
		TestUtils.copyFile("src/test/resources/password.creds", clientPasswordFile.toString());
		TestUtils.copyFile("src/test/resources/keypass.creds", clientKeypassFile.toString());

		clientContextBuilder = new SslContextBuilder(
				protocol,
				clientKeyStoreFile.toString(), HotReloadProvider.ALGO_KEYSTORE, "confluent", "confluent",
				"src/test/resources/truststore.p12", "PKCS12", "confluent",
				HotReloadProvider.ALGO_KEYMANAGER_X509, HotReloadProvider.ALGO_TRUSTMANAGER_X509,
				HotReloadProvider.NAME, clientPasswordFile.toString(), clientKeypassFile.toString());

		serverContextBuilder = new SslContextBuilder(
				protocol,
				"src/test/resources/server.p12", "PKCS12", "confluent", "confluent",
				"src/test/resources/truststore.p12", "PKCS12", "confluent",
				HotReloadProvider.ALGO_KEYMANAGER_X509, HotReloadProvider.ALGO_TRUSTMANAGER_X509,
				HotReloadProvider.NAME, null, null);
	}

	public void run() throws Exception {
		NioServer server = new NioServer(getServerBuilder());
		server.startInBackground();

		Thread.currentThread().setName("Client");
		NioClient client = new NioClient(getClientBuilder());
		client.start(server.getPort());

		sendReceive(client, "Echo1");

		if (reload) {
			// Trigger a reload
			TestUtils.copyFile("src/test/resources/client2.p12", clientKeyStoreFile.toString());
			System.out.println("Wait for FileChange event to be detected (~ 10sec)");
			await().atMost(20, SECONDS).until(() -> ((SslChannel) client.getChannel()).getContext().getKeyStore().containsAlias("client2"));
		}

		if (testPasswordChange) {
			// Trigger a reload and password change
			TestUtils.updateFile(clientPasswordFile, "notconfluent");
			TestUtils.updateFile(clientKeypassFile, "notconfluent");
			TestUtils.copyFile("src/test/resources/client3.p12", clientKeyStoreFile.toString());
			System.out.println("Wait for FileChange event to be detected (~ 10sec)");
			await().atMost(20, SECONDS).until(() -> ((SslChannel) client.getChannel()).getContext().getKeyStore().containsAlias("client3"));
		}

		sendReceive(client, "Echo2");
		sendReceive(client, "Echo3");

		client.close();
	}

	private void sendReceive(NioClient client, String message) throws IOException {
		LOG.info(">>>> {}", message);
		client.write(message);
		LOG.info("<<<< {}", client.read());
	}

	private Channel.Builder getClientBuilder() {
		return ssl ? getSslClientBuilder() : PlainChannel::new;
	}

	private Channel.Builder getSslClientBuilder() {
		return channel -> SslChannel.client(channel, clientContextBuilder);
	}

	private Channel.Builder getServerBuilder() {
		return ssl ? getSslServerBuilder() : PlainChannel::new;
	}

	private Channel.Builder getSslServerBuilder() {
		return channel -> SslChannel.server(channel, serverContextBuilder);
	}
}