package vdr.jsse.logging;

import static vdr.jsse.logging.LoggerFactory.BindingLevel.DEBUG;
import static vdr.jsse.logging.LoggerFactory.BindingLevel.ERROR;
import static vdr.jsse.logging.LoggerFactory.BindingLevel.INFO;
import static vdr.jsse.logging.LoggerFactory.BindingLevel.TRACE;
import static vdr.jsse.logging.LoggerFactory.BindingLevel.WARN;

import lombok.RequiredArgsConstructor;
import vdr.jsse.logging.LoggerFactory.BindingLogger;

/**
 * Custom logging facade allowing inclusion of ess-security library in project not using Slf4j.
 */
@RequiredArgsConstructor
public class Logger {
    private final BindingLogger binding;

    public String getName() {
        return binding.getName();
    }

    public boolean isTraceEnabled() {
        return binding.isTraceEnabled();
    }
    public void trace(String format, Object... arguments) {
        binding.log(TRACE, format, arguments, null);
    }
    public void trace(String msg, Throwable t) {
        binding.log(TRACE, msg, null, t);
    }

    public boolean isDebugEnabled() {
        return binding.isDebugEnabled();
    }
    public void debug(String format, Object... arguments) {
        binding.log(DEBUG, format, arguments, null);
    }
    public void debug(String msg, Throwable t) {
        binding.log(DEBUG, msg, null, t);
    }

    public boolean isInfoEnabled() {
        return binding.isInfoEnabled();
    }
    public void info(String format, Object... arguments) {
        binding.log(INFO, format, arguments, null);
    }
    public void info(String msg, Throwable t) {
        binding.log(INFO, msg, null, t);
    }

    public boolean isWarnEnabled() {
        return binding.isWarnEnabled();
    }
    public void warn(String format, Object... arguments) {
        binding.log(WARN, format, arguments, null);
    }
    public void warn(String msg, Throwable t) {
        binding.log(WARN, msg, null, t);
    }

    public boolean isErrorEnabled() {
        return binding.isErrorEnabled();
    }
    public void error(String format, Object... arguments) {
        binding.log(ERROR, format, arguments, null);
    }
    public void error(String msg, Throwable t) {
        binding.log(ERROR, msg, null, t);
    }
}
