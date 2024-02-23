package vdr.jsse.utils;

import java.lang.Thread.UncaughtExceptionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import vdr.jsse.logging.Logger;
import vdr.jsse.logging.LoggerFactory;

class DaemonThreadFactory implements ThreadFactory {
    private final Logger log = LoggerFactory.getLogger(DaemonThreadFactory.class);

    private static final AtomicInteger THREAD_COUNTER = new AtomicInteger(0);

    private final UncaughtExceptionHandler exceptionHandler;
    private final String name;

    public DaemonThreadFactory(String name, UncaughtExceptionHandler exceptionHandler) {
        this.exceptionHandler = exceptionHandler;
        this.name = name;
    }

    @Override
    public Thread newThread(Runnable r) {
        Thread thread = new Thread(r);
        thread.setName(name + "-" + THREAD_COUNTER.getAndIncrement());
        thread.setDaemon(true); // do not prevent JVM shutdown
        thread.setUncaughtExceptionHandler(this::onExceptionRestart);


        return thread;
    }
    private void onExceptionRestart(Thread t, Throwable e) {
        if (exceptionHandler != null) {
            exceptionHandler.uncaughtException(t, e);
        } else {
            log.error("Thread {} died after unexpected exception. Check if restarted", Thread.currentThread().getName(), e);
        }
    }
}
