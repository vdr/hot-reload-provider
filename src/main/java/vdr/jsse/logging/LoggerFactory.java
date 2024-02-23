package vdr.jsse.logging;

import java.io.PrintStream;
import java.time.Instant;
import vdr.jsse.HotReloadProvider;

/**
 * Retrieve a Slf4j Logger, or disable logging.
 */
public final class LoggerFactory {
    /* Package for testing */ static Binding instance;

    static synchronized void init() {
        if (instance == null) {
            // When loaded statically in java.security, HotReloadProvider can be loaded from the AppClassLoader.
            // In application such as Vert.x or SpringBoot, Slf4j is generally loaded in a child class loader
            // and would not be visible from the AppClassLoader.
            // Check instead from the current thread CL, which normally should have the expected visibility in simple app.
            // In WebApp container or Application Server with multiple independent CL hierarchy, this would need review:
            //      In such an environment, maybe a shared slf4j should be made available AND configured withing this,
            //      or check how/if slf4j supports different webapp configuration if slf4j is loaded in a parent CL.
            ClassLoader threadClassLoader = Thread.currentThread().getContextClassLoader();
            if (isSlf4jAccessible(threadClassLoader)) {
                instance = new Slf4JBinding(threadClassLoader);
                getLogger(LoggerFactory.class).info(HotReloadProvider.NAME + " provider detected Slf4j: logging enabled");
            } else {
                instance = new NoopBinding();
                info(HotReloadProvider.NAME + " provider did not detect Slf4j: logging disabled");
            }
        }
    }

    /**
     * Determine if Slf4j API is accessible.
     */
    private static boolean isSlf4jAccessible(ClassLoader classLoader) {
        try {
            Class.forName("org.slf4j.LoggerFactory", false, classLoader);
            return true;
        } catch (Exception e) {
            err("Slf4j not accessible from classLoader [%s]: %s %s", LoggerFactory.class.getClassLoader(), e.getClass().getSimpleName(), e.getMessage());
        }

        return false;
    }

    /**
     * @param message message to log at error level when slf4j is not available.
     */
    private static void err(String message, Object...args) {
        log(System.err, message, args); //NOSONAR Used when there is no logger.
    }

    /**
     * @param message message to log at info level when slf4j is not available.
     */
    private static void info(String message, Object...args) {
        log(System.out, message, args); //NOSONAR Used when there is no logger.
    }

    /**
     * Log method for when there is no slf4j logger.
     *
     * @param out the stream to print to.
     * @param format the message to print, in {@link String#format} format.
     * @param args the argument to print the message.
     */
    private static void log(PrintStream out, String format, Object...args) {
        String message = String.format(format, args);
        out.printf("%s [%s]: %s%n", Instant.now(), Thread.currentThread().getName(), message);
    }


    private LoggerFactory() {
        // Not instantiable
    }

    public static Logger getLogger(Class<?> clazz) {
        init();
        return new Logger(instance.getLogger(clazz));
    }

    public static Logger getLogger(String name) {
        init();
        return new Logger(instance.getLogger(name));
    }

    interface Binding {
        BindingLogger getLogger(Class<?> clazz);
        BindingLogger getLogger(String name);
    }

    public interface BindingLogger {
        /**
         * For logging libraries like Slf4j that supports overloading of FQCN,
         * indicates the boundary of the logging framework for better reporting of logging source class.
         */
        String FQCN = Logger.class.getName();

        void log(BindingLevel level, String message, Object[] args, Throwable t);

        String getName();

        boolean isTraceEnabled();

        boolean isDebugEnabled();

        boolean isInfoEnabled();

        boolean isWarnEnabled();

        boolean isErrorEnabled();
    }

    public enum BindingLevel {
        TRACE, DEBUG, INFO, WARN, ERROR
    }
}
