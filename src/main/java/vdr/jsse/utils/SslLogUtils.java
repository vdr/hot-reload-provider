package vdr.jsse.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.stream.Collectors;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import lombok.SneakyThrows;

public abstract class SslLogUtils {
    private SslLogUtils() {
        // Utils class, not instantiable.
    }

    public static String toString(SSLEngine engine) {
        return engine.toString() +
                "(in[" + isDone(engine.isInboundDone()) + "]/out[" + isDone(engine.isOutboundDone()) + ", " +
                toString(engine.getSession()) + ")";
    }

    private static String isDone(boolean done) {
        return printBoolean(done, "DONE", "OPEN");
    }

    public static String toString(SSLSession session) {
        return session.toString() +
                "(" + printBoolean(session.isValid(), "Valid", "Invalid") + ", " +
                "LastAccess:" + Instant.ofEpochMilli(session.getLastAccessedTime()) + ", " +
                "Principal:" + session.getLocalPrincipal() + ", " +
                "Peer:" + getPeerPrincipal(session) + ")";
    }

    private static String printBoolean(boolean bool, String trueValue, String falseValue) {
        return bool ? trueValue : falseValue;
    }

    private static String getPeerPrincipal(SSLSession session) {
        try {
            return session.getPeerPrincipal().toString();
        } catch (RuntimeException | SSLPeerUnverifiedException e) {
            return "ANONYMOUS";
        }
    }

    /**
     * Produce a concise string representation of a certificate, for more readable logging in higher level log level.
     *
     * @param certificate the certificate.
     * @return the string.
     */
    public static String toShortString(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }

        return String.format("x509(subject:%s, issuer:%s, valid(%tF->%tF), fingerprint(SHA1): %s)",
                certificate.getSubjectDN(),
                certificate.getIssuerDN(),
                certificate.getNotBefore(),
                certificate.getNotAfter(),
                getFingerprint(certificate));
    }

    @SneakyThrows(NoSuchAlgorithmException.class) // Will not happen with SHA-1
    public static String getFingerprint(X509Certificate certificate) {
        MessageDigest crypt = MessageDigest.getInstance("SHA-1");//NOSONAR Not a security issue.
                                                                 //        Only used to generate a fingerprint that is consistent
                                                                 //        with many other tools allowing easy comparison for
                                                                 //        humans debugging with the logs.
        try {
            crypt.update(certificate.getEncoded());
            byte[] hash = crypt.digest();
            String[] hex = new String[hash.length];

            for (int i = 0; i < hash.length; i++) {
                hex[i] = Integer.toHexString(Byte.toUnsignedInt(hash[i])).toUpperCase();
                if (hex[i].length() == 1) {
                    hex[i] = "0" + hex[i];
                }
            }

            return String.join(":", hex);
        } catch (CertificateEncodingException e) {
            return "Failed " + e.getMessage();
        }
    }

    /**
     * Produce a concise string representation of a certificate chain, for more readable logging in higher level log level.
     *
     * @param chain the certificate chain.
     * @return the string.
     */
    public static String toShortString(X509Certificate[] chain) {
        return Arrays.stream(chain)
                .map(SslLogUtils::toShortString)
                .collect(Collectors.joining("=>", "[", "]"));
    }

    public static String getSSLExceptionMessage(SSLException e) {
        return printShortStackTrace(e);
    }

    public static String printShortStackTrace(Throwable e) {
        StackTraceElement[] stackTrace = e.getStackTrace();
        String location = stackTrace.length > 0 ? " at " + stackTrace[0] : "";

        Throwable cause = e.getCause();
        String causeMessage = cause != null ? "\nCaused by: " + printShortStackTrace(cause) : "";

        return e + location + causeMessage ;
    }
}
