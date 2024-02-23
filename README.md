# HotReload Provider

[JSSE Provider](https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html) supporting hot reload of certificates. 
Designed specifically for projects using [kafka-clients library](https://mvnrepository.com/artifact/org.apache.kafka/kafka-clients) 
or other libraries with deeply embedded NIO Network stack.  

## Build

### Prerequisites

OpenSSL, Java8

If you have `asdf` with java plugin, install the appropriate JVM with

```shell
asdf install
```



### Building

You need to generate some certificate, run

```shell
cd ./src/test/resources; ./create-certs.sh
```

After that, run maven normally:

````shell
mvnw clean install
````

### Demo

[vdr.jsse.demo](./src/test/java/vdr/jsse/demo) package contains several runnable examples. 

## Implementation Guide

Without the provider

![JSSEStackOld](./docs/JSSEStackOld.png)

* No reload capability as the Keystore File is loaded directly by Kafka EngineBuilder

With the provider:

![JSSEStack](./docs/JSSEStack.png)

* Green are the new components.

* Blue are the components recreated when the KeyStore file changes

* White is existing components, not recreated even when the KeyStore file changes.

Key features: 

1. Dynamic reload not affecting the transport side and therefore no performance impact outside the actual reload. 
2. Immediate effect. All Kafka SSL Connections are renegotiated upon reload. 
3. No code handling either keystore files, passwords or network data. Very small security attack surface.

## Usage

HotReload Provider is used like a regular JSSE Provider. It should be loaded in the JVM and then is used indirectly as a SPI for the Keystore, Trust/KeyManager and SSLContext by any library using those components. Usually this is done via configuration but is entirely dependent on the library.

It is recommended that HotReload provider is loaded statically by adding it to the JVM `java.security` properties file.

Specific configuration is provided in order to setup hot reloading for Kafka. 

### 1. Load Provider

Include the maven dependency

```xml
<dependency>
    <groupId>vdr.security</groupId>
    <artifactId>hot-reload-provider</artifactId>
  	<version>1.0.0</version>
    <!-- If static loading, you don't need the jar for building, only for running
         You can download the jar by any mean, but the path of least resistance
         is to include it as a dependency and have maven download it, 
         so it's ready for packaging how you want to. 
      -->
    <scope>runtime</scope>
</dependency>
```

#### Static loading [Recommended]

Make sure the jar is available on the **application classloader**. This means either on the java command classpath argument (`java -cp`) or in the JVM `lib-ext` folder. 

If it is included in a children classloader such as SpringBoot Executable Jar Classloader or WebApp deployment, it cannot be loaded statistically and must be loaded programmatically.  

Add a security provider entry in `$JAVA_HOME/conf/security/java.security`

Eg:

```properties
#
# List of providers and their preference orders (see above):
#
security.provider.1=SUN
security.provider.2=SunRsaSign
security.provider.3=SunEC
security.provider.4=SunJSSE
security.provider.5=SunJCE
security.provider.6=SunJGSS
security.provider.7=SunSASL
security.provider.8=XMLDSig
security.provider.9=SunPCSC
security.provider.10=JdkLDAP
security.provider.11=JdkSASL
security.provider.12=Apple
security.provider.13=SunPKCS11
# Strictly incremental sequence. 
# Different environments will have different number of provider by default.
# Make sure the provider is at the exact last index with no gap. 
# However the provider can be defined anywhere in the file
security.provider.14=vdr.jsse.HotReloadProvider
```

##### Development Environment

In development environment it can be inconvenient to change the JVM settings as it is generally shared between multiple project. In particular, unit testing  this project relies on its capacity to load and unload the provider dynamically while testing.

To avoid such issue, a provider can be declared in an add-on file that is declared in the system property `java.security.properties`

eg: 

```bash
java -Djava.security.properties=/full/path/to/the/additional/extra-java.security ...
```

with `extra-java.security` containing:

```properties
# Same rule about strict incremental sequence. 
# 14 needs to be the last index, no gap.
security.provider.14=vdr.jsse.HotReloadProvider
```



#### Dynamic Loading

Although not recommended, this is the only option if you do not have access to either the Application ClassLoader or the ext-lib folder.

A provider can be loaded dynamically in the code. This should be done as early as possible in your application, ideally in the `main()` method if present. 

eg. Before calling `SpringApplication.run(...)` in a SpringBoot app.

```java
@SpringBootApplication
public class App {
    public static void main(String[] args) {
        HotReloadProvider.enableLast();
        SpringApplication.run(App.class, args);
    }
}
```

### 2. Configure Provider

Provider does not require configuration and provides reasonable defaults.

The following system properties can be set to changed the default behaviour:

```
HotReload.EventBufferWindowMs: >= 0 long, default 1000 
                                 Slow file system and/or slow keystore creation can lead 
                                 a file to be loaded before it has been fully updated.
                                 This setting control the time in ms the keystore will
                                 wait until it reacts on a file change event. 
                                 It will buffer further event in that time window.  
                                 Use 0 to disable.
```

 

### 3. Configure FileWatching Keystore in Kafka

Create the properties file that point to the keystore to monitor.

You can optionally specify `password.location` and the `keypass.location` to point to a file that has the keystore password and keymanager password to support password reloading.

Caution: password stored in file are trimmed.


```properties
location=/Users/Vincent.derijcke/projects/hotreload/certs/producer.jks
keystore.algorithm=JKS
password.location=/Users/Vincent.derijcke/projects/local/certs/password.creds
keypass.location=/Users/Vincent.derijcke/projects/local/certs/keypass.creds
```

Configure Kafka clients to use that file as a `DynamicKeystore`

Additionally configure Kafka clients to use `HotReload` provider for SSL and `ReloadableX509` as KeyManager.

eg: with Spring Kafka this looks like:

```yaml
spring:
  kafka:
    properties:
      ssl.provider: HotReload
      ssl.keymanager.algorithm: ReloadableX509
      ssl.trustmanager.algorithm: ReloadablePKIX
    security:
      protocol: SSL
    ssl:
      trust-store-location: truststore.properties
      trust-store-password: confluent
      key-store-location: producer.properties
      key-store-password: confluent
      key-password: confluent
      key-store-type: DynamicKeystore
```

Note that passwords are ignored if a `password.location` or `keypass.location` are provided in the keystore properties. Otherwise, they would be the password of the underlying keystore.



## Caveats

1. No SSLSocket support
2. There is a dirty trick to link a ReloadableKeyManager to a DynamicKeystore. 
   Since the KeyManager receives a Keystore rather than KeystoreSPI, we abuse the `Keystore#store` method to give enough information about the underlying SPI to match it to an instance of `FileWatcher`
