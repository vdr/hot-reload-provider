package vdr.jsse.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

class SslLogUtilsTest {
    /** Fingerprint pattern, eg: "5C:31:AF:4C:A6:3D:83:7E:80:DF:D8:D7:B7:92:05:ED:EF:44:83:22" */
    private static final String FINGERPRINT_SHA1_PATTERN = "..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..";

    @Test
    @DisplayName("Demo how short certificate logging looks like")
    void examples() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fs = new FileInputStream("src/test/resources/test.p12")) {
            ks.load(fs, "confluent".toCharArray());

            X509Certificate test = (X509Certificate) ks.getCertificate("test");

            System.out.println(SslLogUtils.toShortString(test));

            assertThat(SslLogUtils.toShortString(test)).matches(
                    "x509\\(subject:CN=test.+, issuer:.+CN=ca, valid\\(.+\\), fingerprint\\(SHA1\\): ..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..:..\\)");
        }
    }

    @Test
    void generateProperCertFingerprint() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fs = new FileInputStream("src/test/resources/test.p12")) {
            ks.load(fs, "confluent".toCharArray());

            String fingerprint = SslLogUtils.getFingerprint((X509Certificate) ks.getCertificate("test"));

            assertThat(fingerprint).matches(FINGERPRINT_SHA1_PATTERN);
        }
    }

    @Test
    void supportsNullCertificate() {
        assertThat(SslLogUtils.toShortString((X509Certificate) null)).isNull();
        assertThat(SslLogUtils.toShortString(new X509Certificate[] {null})).isEqualTo("[null]");
    }

    @Test
    void supportsBrokenCertificate() throws CertificateEncodingException {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenThrow(CertificateEncodingException.class);

        assertThat(SslLogUtils.toShortString(certificate)).isEqualTo("x509(subject:null, issuer:null, valid(null->null), fingerprint(SHA1): Failed null)");
    }

    @Test
    void givenSSLException_printSummaryStackTrace(TestInfo info) {
        SSLException e = new SSLException("ssl exception message");
        String actual = SslLogUtils.getSSLExceptionMessage(e);
        // eg: javax.net.ssl.SSLException: ssl exception message at [...]SslLogUtilsTest.givenSSLException_printSummaryStackTrace(SslLogUtilsTest.java:64)"

        String thisClassName = SslLogUtilsTest.class.getName();
        String thisMethodName = info.getTestMethod()
                        .orElseThrow(() -> new IllegalArgumentException("TestInfo does not contain test method information"))
                        .getName();
        assertThat(actual)
                .contains(e.toString())
                .contains(thisClassName)
                .contains(thisMethodName);
    }

    @Test
    void givenSSLExceptionWithCause_printSummaryStackTrace(TestInfo info) {
        Throwable cause = new Throwable("cause exception message");
        SSLException e = new SSLException("ssl exception message", cause);
        String actual = SslLogUtils.getSSLExceptionMessage(e);
        // eg: javax.net.ssl.SSLException: ssl exception message at [...]SslLogUtilsTest.givenSSLExceptionWithCause_printSummaryStackTrace(SslLogUtilsTest.java:82)
        //     Caused by: java.lang.Throwable: cause exception message at [...]SslLogUtilsTest.givenSSLExceptionWithCause_printSummaryStackTrace(SslLogUtilsTest.java:81)"

        String thisClassName = SslLogUtilsTest.class.getName();
        String thisMethodName = info.getTestMethod()
                .orElseThrow(() -> new IllegalArgumentException("TestInfo does not contain test method information"))
                .getName();
        assertThat(actual)
                .contains(e.toString())
                .contains(thisClassName)
                .contains(thisMethodName)
                .contains(cause.toString());
    }
}