package vdr.jsse.logging;

class NoopBinding implements LoggerFactory.Binding {
    private static final NoopLogger NOOP = new NoopLogger();

    @Override
    public NoopLogger getLogger(Class<?> clazz) {
        return NOOP;
    }

    @Override
    public NoopLogger getLogger(String name) {
        return NOOP;
    }

    static class NoopLogger implements LoggerFactory.BindingLogger {
        static final String NAME = "NOOP";

        @Override
        public void log(LoggerFactory.BindingLevel level, String message, Object[] args, Throwable t) {
            // NOOP
        }

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public boolean isTraceEnabled() {
            return false;
        }

        @Override
        public boolean isDebugEnabled() {
            return false;
        }

        @Override
        public boolean isInfoEnabled() {
            return false;
        }

        @Override
        public boolean isWarnEnabled() {
            return false;
        }

        @Override
        public boolean isErrorEnabled() {
            return false;
        }
    }
}
