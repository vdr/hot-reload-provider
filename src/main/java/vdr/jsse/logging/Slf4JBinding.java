package vdr.jsse.logging;

import static java.lang.Class.forName;
import static java.lang.invoke.MethodType.methodType;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.EnumMap;
import vdr.jsse.logging.LoggerFactory.Binding;
import vdr.jsse.logging.LoggerFactory.BindingLevel;

/**
 * Binds logging to Slf4j found in the specified class loader.
 */
class Slf4JBinding implements Binding {
    private static final EnumMap<BindingLevel, Integer> levelMapping = new EnumMap<>(BindingLevel.class);
    private final Class<?> locationAwareClass;
    private final Class<?> loggerFactoryClass;

    private final MethodHandle getLoggerByClass;
    private final MethodHandle getLoggerByName;

    private final MethodHandle loggerGetName;
    private final MethodHandle loggerIsTraceEnabled;
    private final MethodHandle loggerIsDebugEnabled;
    private final MethodHandle loggerIsInfoEnabled;
    private final MethodHandle loggerIsWarnEnabled;
    private final MethodHandle loggerIsErrorEnabled;
    private final MethodHandle loggerLog;

    public Slf4JBinding(ClassLoader classLoader) {
        try {
            loggerFactoryClass = forName("org.slf4j.LoggerFactory", true, classLoader);

            locationAwareClass = forName("org.slf4j.spi.LocationAwareLogger", true, classLoader);
            levelMapping.put(BindingLevel.TRACE, getStaticInteger(locationAwareClass, "TRACE_INT"));
            levelMapping.put(BindingLevel.DEBUG, getStaticInteger(locationAwareClass, "DEBUG_INT"));
            levelMapping.put(BindingLevel.INFO, getStaticInteger(locationAwareClass, "INFO_INT"));
            levelMapping.put(BindingLevel.WARN, getStaticInteger(locationAwareClass, "WARN_INT"));
            levelMapping.put(BindingLevel.ERROR, getStaticInteger(locationAwareClass, "ERROR_INT"));

            MethodHandles.Lookup lookup = MethodHandles.publicLookup();
            Class<?> loggerClass = forName("org.slf4j.Logger", true, classLoader);
            getLoggerByClass = lookup.findStatic(loggerFactoryClass, "getLogger", methodType(loggerClass, Class.class));
            getLoggerByName = lookup.findStatic(loggerFactoryClass, "getLogger", methodType(loggerClass, String.class));

            loggerGetName = lookup.findVirtual(locationAwareClass, "getName", methodType(String.class));
            loggerIsTraceEnabled = lookup.findVirtual(locationAwareClass, "isTraceEnabled", methodType(boolean.class));
            loggerIsDebugEnabled = lookup.findVirtual(locationAwareClass, "isDebugEnabled", methodType(boolean.class));
            loggerIsInfoEnabled = lookup.findVirtual(locationAwareClass, "isInfoEnabled", methodType(boolean.class));
            loggerIsWarnEnabled = lookup.findVirtual(locationAwareClass, "isWarnEnabled", methodType(boolean.class));
            loggerIsErrorEnabled = lookup.findVirtual(locationAwareClass, "isErrorEnabled", methodType(boolean.class));

            Class<?> markerClass = forName("org.slf4j.Marker", true, classLoader);
            MethodType logType = MethodType.methodType(void.class, markerClass, String.class, int.class, String.class, Object[].class, Throwable.class);
            loggerLog = lookup.findVirtual(locationAwareClass, "log", logType);
        } catch (NoSuchFieldException | NoSuchMethodException | IllegalAccessException | ClassNotFoundException e) {
            // We should have checked Slf4j availability before creating this class.
            // Nothing done here should fail
            throw new IllegalStateException(e);
        }
    }

    private Integer getStaticInteger(Class<?> c, String name) throws NoSuchFieldException, IllegalAccessException {
        MethodHandles.Lookup lookup = MethodHandles.publicLookup();

        return invokeGetter(lookup.findStaticGetter(c, name, int.class));
    }

    @Override
    public Slf4jLogger getLogger(Class<?> clazz) {
        return doGetLogger(getLoggerByClass, clazz);
    }

    @Override
    public Slf4jLogger getLogger(String name) {
        return doGetLogger(getLoggerByName, name);
    }

    private Slf4jLogger doGetLogger(MethodHandle getter, Object arg) {
        Object logger = invokeFunction(getter, arg);
        assertInstanceOf(logger, locationAwareClass);

        return new Slf4jLogger(logger);
    }

    private void assertInstanceOf(Object o, Class<?> locationAwareClass) {
        if (!locationAwareClass.isInstance(o)) {
            throw new IllegalArgumentException(o.getClass() + " is not instance of " + locationAwareClass);
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T invokeFunction(MethodHandle handle, Object args) {
        try {
            return (T) handle.invoke(args);
        } catch (Error | RuntimeException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T invokeGetter(MethodHandle getter) {
        try {
            // /!\ Polymorphic invoke - parameter count matters
            // Cannot reuse invokeFunction
            return (T) getter.invoke();
        } catch (Error | RuntimeException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException(e);
        }
    }

    class Slf4jLogger implements LoggerFactory.BindingLogger {
        final Object logger;
        private final MethodHandle getName;
        private final MethodHandle isTraceEnabled;
        private final MethodHandle isDebugEnabled;
        private final MethodHandle isInfoEnabled;
        private final MethodHandle isWarnEnabled;
        private final MethodHandle isErrorEnabled;
        private final MethodHandle log;

        public Slf4jLogger(Object logger) {
            this.logger = logger;

            getName = loggerGetName.bindTo(logger);
            isTraceEnabled = loggerIsTraceEnabled.bindTo(logger);
            isDebugEnabled = loggerIsDebugEnabled.bindTo(logger);
            isInfoEnabled = loggerIsInfoEnabled.bindTo(logger);
            isWarnEnabled = loggerIsWarnEnabled.bindTo(logger);
            isErrorEnabled = loggerIsErrorEnabled.bindTo(logger);
            log = loggerLog.bindTo(logger);
        }

        @Override
        public void log(BindingLevel level, String message, Object[] args, Throwable t) {
            try {
                log.invoke(null, FQCN, levelMapping.get(level), message, args, t);
            } catch (Error | RuntimeException e) {
                throw e;
            } catch (Throwable e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public String getName() {
            return invokeGetter(getName);
        }

        @Override
        public boolean isTraceEnabled() {
            return invokeGetter(isTraceEnabled);
        }

        @Override
        public boolean isDebugEnabled() {
            return invokeGetter(isDebugEnabled);
        }

        @Override
        public boolean isInfoEnabled() {
            return invokeGetter(isInfoEnabled);
        }

        @Override
        public boolean isWarnEnabled() {
            return invokeGetter(isWarnEnabled);
        }

        @Override
        public boolean isErrorEnabled() {
            return invokeGetter(isErrorEnabled);
        }
    }
}
