package vdr.jsse.test.engine;

import static vdr.jsse.test.engine.TLSRecord.intEnum.find;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Simplified TLS Record parser to extract useful info for logging.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5246">TLS 1.2 RFC</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8446">TLS 1.3 RFC</a>
 * @see <a href="https://tls.ulfheim.net">Every byte of a TLS connection explained and reproduced.</a>
 */
@RequiredArgsConstructor
@Getter
public final class TLSRecord {
    @RequiredArgsConstructor
    enum ContentType implements intEnum<ContentType> {
        invalid(0), // 1.3
        change_cipher_spec(20),
        alert(21),
        handshake(22),
        application_data(23);

        @Getter
        private final int value;
    }

    @RequiredArgsConstructor
    @Getter
    enum ProtocolVersion {
        tls_10(3, 1), /* Can be used in Client Hello */
        tls_11(3, 2),
        tls_12(3, 3),
        tls_13(3, 4); /* Only used in handshake version, TLS 1.3 use {3, 3} for record version */

        private final int major;
        private final int minor;

        static Optional<ProtocolVersion> find(int major, int minor) {
            if (major == 3 && minor >= 1 && minor <= 4) {
                return Optional.of(values()[minor - 1]);
            }
            return Optional.empty();
        }
    }

    @RequiredArgsConstructor
    enum HandshakeType implements intEnum<HandshakeType> {
        hello_request(0), // 1.2
        client_hello(1),
        server_hello(2),
        new_session_ticket(4),   // 1.3
        end_of_early_data(5),    // 1.3
        encrypted_extensions(8), // 1.3
        certificate(11),
        server_key_exchange (12), // 1.2
        certificate_request(13),
        server_hello_done(14), // 1.2
        certificate_verify(15),
        client_key_exchange(16), // 1.2
        finished(20),
        key_update(24),
        message_hash(254);

        @Getter
        private final int value;
    }

    @RequiredArgsConstructor
    enum AlertType implements intEnum<AlertType> {
        close_notify(0),
        unexpected_message(10),
        bad_record_mac(20),
        decryption_failed_RESERVED(21), // 1.2
        record_overflow(22),
        decompression_failure(30), // 1.2
        handshake_failure(40),
        no_certificate_RESERVED(41), // 1.2
        bad_certificate(42),
        unsupported_certificate(43),
        certificate_revoked(44),
        certificate_expired(45),
        certificate_unknown(46),
        illegal_parameter(47),
        unknown_ca(48),
        access_denied(49),
        decode_error(50),
        decrypt_error(51),
        export_restriction_RESERVED(60), // 1.2
        protocol_version(70),
        insufficient_security(71),
        internal_error(80),
        inappropriate_fallback(86), // 1.3
        user_canceled(90),
        no_renegotiation(100), // 1.2
        missing_extension(109),
        unsupported_extension(110),
        unrecognized_name(112), // 1.3
        bad_certificate_status_response(113), // 1.3
        unknown_psk_identity(115), // 1.3
        certificate_required(116), // 1.3
        no_application_protocol(120); // 1.3

        @Getter
        private final int value;
    }

    public static String describe(ByteBuffer ssl, int length) {
        if (length == 0) {
            return "";
        }

        // Peek into the SSL record
        ssl = ssl.duplicate();
        ssl.position(0);
        ssl.limit(length);

        try {
            return TLSRecord.fromBuffer(ssl).stream()
                    .map(TLSRecord::describe)
                    .collect(Collectors.joining("+", "{", "}"));
        } catch (Exception e) {
            return "error";
        }
    }

    public static List<TLSRecord> fromBuffer(ByteBuffer buffer) {
        List<TLSRecord> records = new ArrayList<>();

        while (buffer.hasRemaining()) {
            TLSRecord record = get(buffer);

            if (record != null) {
                records.add(record);
            } else {
                break;
            }
        }

        return records;
    }

    public static TLSRecord get(ByteBuffer buffer) {
        Optional<ContentType> ct = find(ContentType.class, getInt8(buffer));
        Optional<ProtocolVersion> version = ProtocolVersion.find(getInt8(buffer), getInt8(buffer));

        boolean supported = ct.isPresent() && version.isPresent();
        if (supported) {
            int size = getInt16(buffer);
            byte[] fragment = new byte[size];
            buffer.get(fragment);

            return new TLSRecord(ct.get(), version.get(), fragment);
        }

        return null;
    }

    private final ContentType ct;
    private final ProtocolVersion version;
    private final byte[] fragment;

    public String describe() {
        try {
            ByteBuffer b = ByteBuffer.wrap(fragment);
            switch (ct) {
                case alert:
                    return (getInt8(b) == 1 ? "warn" : "fatal") + ":" + intEnum.describe(AlertType.class, getInt8(b));
                case handshake:
                    return "hs(" + describeHandshake(b) + ")";
                case application_data:
                    return "appdata";
                case change_cipher_spec:
                    return "cipher";
                default:
                case invalid:
                    return "invalid";
            }
        } catch (Exception e) {
            return "\n" + printBin() + "\n";
        }
    }

    private String printBin() {
        ByteBuffer buffer = ByteBuffer.allocate(fragment.length + 5);
        putInt8(buffer, ct.getValue());
        putInt8(buffer, version.getMajor());
        putInt8(buffer, version.getMinor());
        putInt16(buffer, fragment.length);
        buffer.put(fragment);

        byte[] bytes = buffer.array();

        StringBuilder message = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(Byte.toUnsignedInt(bytes[i]));
            hex = hex.length() == 1 ? ("0" + hex) : hex;
            message.append(hex);
            if (i > 0 && (i + 1) % 16 == 0) {
                message.append("\n");
            } else if (i > 0 && (i + 1) % 8 == 0) {
                message.append("   ");
            } else {
                message.append(" ");
            }
        }

        return message.toString();
    }

    private String describeHandshake(ByteBuffer b) {
        List<String> handshakes = new ArrayList<>();
        try {
            while (b.hasRemaining()) {
                handshakes.add(intEnum.describe(HandshakeType.class, getInt8(b)));
                int length = getInt24(b);
                b.position(b.position() + length);
            }
        } catch(Exception e) {
            // Heuristic - we can't be sure unless tracking the TLS state,
            // but it's more likely the packet is encrypted than invalid.
            // The first encrypted hs message in a TLS 1.2 handshake is the hs finished message.
            handshakes.clear();
            handshakes.add("encrypted");
        }

        return String.join("+", handshakes);
    }

    private static int getInt8(ByteBuffer b) {
        return Byte.toUnsignedInt(b.get());
    }

    private static int getInt16(ByteBuffer b) {
        return (getInt8(b) << 8) | getInt8(b);
    }

    static int getInt24(ByteBuffer b) {
        return (getInt8(b) << 16) | getInt16(b);
    }

    static void putInt8(ByteBuffer b, int i) {
        b.put((byte)(i & 0xFF));
    }

    static void putInt16(ByteBuffer b, int i) {
        putInt8(b, i >> 8);
        putInt8(b, i);
    }

    public interface intEnum<T extends Enum<T> & intEnum<T>> {
        int getValue();

        static <T extends Enum<T> & intEnum<T>> Optional<T> find(Class<T> c, int value) {
            return Arrays.stream(c.getEnumConstants())
                    .filter(ct -> value == ct.getValue())
                    .findFirst();
        }

        static <T extends Enum<T> & intEnum<T>> String describe(Class<T> c, int value) {
            Optional<T> maybe = find(c, value);

            return maybe.isPresent() ? maybe.get().toString() : ("0x" + Integer.toHexString(value));
        }
    }
}
