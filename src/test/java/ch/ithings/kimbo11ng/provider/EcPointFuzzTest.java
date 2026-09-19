/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.InvalidKeyException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@link EcPointCodec} against input it did not expect.
 *
 * <p>Both entry points read bytes the token supplies, and a token is not a trusted source: a
 * firmware bug, a vendor quirk or a truncated read all arrive here as arbitrary bytes. The contract
 * this suite holds them to is narrow and total — <em>every</em> input either produces a point on the
 * curve or an {@link InvalidKeyException}. Anything else escapes as an unchecked exception through
 * callers that only catch the checked ones, and what should have been "this key will not load"
 * becomes a failure somewhere further out with no mention of the key.
 *
 * <p>The seeds are fixed. A fuzz test that picked a fresh seed each run would fail on somebody
 * else's machine, at a rate nobody could reproduce, and PIT needs the same answer every time.
 * Widening the search is a matter of raising the seed count deliberately, not of running it again.
 *
 * <p>Corpus-guided rather than purely random: bytes off {@code /dev/urandom} are rejected by the
 * length check almost immediately and never reach the parser. The interesting inputs are the ones
 * that look nearly right, so most of these are valid encodings with something bent.
 */
@DisplayName("EC point decoding, fuzzed")
class EcPointFuzzTest {

    /** Enough to explore the shapes below without making the suite noticeably slower. */
    private static final int ITERATIONS = 2000;

    private static final String P256_OID = "1.2.840.10045.3.1.7";
    private static final String P384_OID = "1.3.132.0.34";

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static ECParameterSpec spec(String oid) throws Exception {
        return EcPointCodec.parseCurve(new ASN1ObjectIdentifier(oid).getEncoded());
    }

    /**
     * Asserts the total contract: a point, or {@link InvalidKeyException}, and nothing else.
     *
     * <p>{@code StackOverflowError} and {@code OutOfMemoryError} are deliberately not caught. They
     * are not "the input was bad", they are the parser having been talked into unbounded work, and
     * a test that swallowed them would be hiding the most interesting finding of all.
     */
    private static void assertOnlyInvalidKey(byte[] input, ECParameterSpec spec, String what) {
        try {
            EcPointCodec.decodePoint(input, spec);
        } catch (InvalidKeyException expected) {
            assertTrue(expected.getMessage() != null && !expected.getMessage().isEmpty(),
                    "an operator has to be able to act on this: " + what);
        } catch (Throwable unexpected) {
            fail("decodePoint threw " + unexpected.getClass().getName() + " rather than"
                    + " InvalidKeyException for " + what + " (" + describe(input) + "): "
                    + unexpected.getMessage(), unexpected);
        }
    }

    private static String describe(byte[] input) {
        StringBuilder sb = new StringBuilder(input.length + " bytes:");
        for (int i = 0; i < Math.min(input.length, 24); i++) {
            sb.append(String.format(" %02x", input[i]));
        }
        return input.length > 24 ? sb.append(" ...").toString() : sb.toString();
    }

    /** Valid encodings of the generator, which are the shapes worth bending. */
    private static List<byte[]> corpus(ECParameterSpec spec) throws Exception {
        List<byte[]> seeds = new ArrayList<>();
        byte[] uncompressed = spec.getG().getEncoded(false);
        byte[] compressed = spec.getG().getEncoded(true);
        seeds.add(uncompressed);
        seeds.add(compressed);
        seeds.add(new DEROctetString(uncompressed).getEncoded());
        seeds.add(new DEROctetString(compressed).getEncoded());
        return seeds;
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 5})
    @DisplayName("a bent encoding is refused, never thrown out of")
    void mutatedEncodingsStayChecked(int seed) throws Exception {
        Random random = new Random(seed);
        for (ECParameterSpec spec : List.of(spec(P256_OID), spec(P384_OID))) {
            List<byte[]> seeds = corpus(spec);
            for (int i = 0; i < ITERATIONS; i++) {
                byte[] input = seeds.get(random.nextInt(seeds.size())).clone();
                input = mutate(input, random);
                assertOnlyInvalidKey(input, spec, "a mutated encoding");
            }
        }
    }

    /** One of: flip a bit, change a byte, truncate, extend, or splice two encodings. */
    private static byte[] mutate(byte[] input, Random random) {
        return switch (random.nextInt(5)) {
            case 0 -> {
                if (input.length > 0) {
                    int at = random.nextInt(input.length);
                    input[at] ^= (byte) (1 << random.nextInt(8));
                }
                yield input;
            }
            case 1 -> {
                if (input.length > 0) {
                    input[random.nextInt(input.length)] = (byte) random.nextInt(256);
                }
                yield input;
            }
            case 2 -> java.util.Arrays.copyOf(input, random.nextInt(input.length + 1));
            case 3 -> {
                byte[] longer = java.util.Arrays.copyOf(input, input.length + 1
                        + random.nextInt(8));
                for (int i = input.length; i < longer.length; i++) {
                    longer[i] = (byte) random.nextInt(256);
                }
                yield longer;
            }
            default -> {
                // A length prefix that promises far more than the buffer holds is the classic way
                // to make a DER reader read past its input or allocate on the promise.
                byte[] lying = input.clone();
                if (lying.length > 1) {
                    lying[0] = 0x04;
                    lying[1] = (byte) 0x7F;
                }
                yield lying;
            }
        };
    }

    @ParameterizedTest
    @ValueSource(ints = {11, 12, 13})
    @DisplayName("arbitrary bytes of any length are refused, never thrown out of")
    void arbitraryBytesStayChecked(int seed) throws Exception {
        Random random = new Random(seed);
        ECParameterSpec spec = spec(P256_OID);
        for (int i = 0; i < ITERATIONS; i++) {
            // Lengths around the two the curve accepts, where the length gate stops screening.
            byte[] input = new byte[random.nextInt(140)];
            random.nextBytes(input);
            assertOnlyInvalidKey(input, spec, "arbitrary bytes");
        }
    }

    @Test
    @DisplayName("a DER length header promising more than the buffer holds is refused")
    void truncatedOctetStringHeader() throws Exception {
        ECParameterSpec spec = spec(P256_OID);
        // 0x04 0x82 0xFF 0xFF: an OCTET STRING claiming 65535 bytes, followed by almost none.
        assertOnlyInvalidKey(new byte[] {0x04, (byte) 0x82, (byte) 0xFF, (byte) 0xFF, 0x00, 0x01},
                spec, "an OCTET STRING header promising 65535 bytes");
        // And the indefinite-length form, which has no length at all.
        assertOnlyInvalidKey(new byte[] {0x24, (byte) 0x80, 0x04, 0x01, 0x00},
                spec, "an indefinite-length constructed OCTET STRING");
    }

    @Test
    @DisplayName("an ASN.1 parse that throws unchecked is still reported as a bad key")
    void asn1ParsingExceptionIsNotLetOut() throws Exception {
        ECParameterSpec spec = spec(P256_OID);
        // Found by fuzzing ASN1InputStream directly. A constructed BIT STRING (0x23) of indefinite
        // length (0x80) containing a BIT STRING whose pad-bit count is 0x1b — 27, where DER permits
        // 0 to 7. BouncyCastle answers with ASN1ParsingException, which extends
        // IllegalStateException and so slipped through a catch of IOException and
        // IllegalArgumentException. It reached PublicKeyReader.readEcPublicKey unchecked, where it
        // would abort enumeration of every alias on the slot because of one malformed key.
        byte[] badPadBits = java.util.HexFormat.of()
                .parseHex("238003311b1cb7f55e8e9e25bfbcfc82b9f438637b0fa32e");

        assertOnlyInvalidKey(badPadBits, spec, "a constructed BIT STRING with 27 pad bits");
    }

    @Test
    @DisplayName("a point nested in OCTET STRINGs is not unwrapped twice")
    void doubleWrappingIsRefused() throws Exception {
        ECParameterSpec spec = spec(P256_OID);
        byte[] once = new DEROctetString(spec.getG().getEncoded(false)).getEncoded();
        byte[] twice = new DEROctetString(once).getEncoded();

        // One unwrap is the CKA_EC_POINT convention; a second would mean accepting an encoding no
        // token produces, and with it a whole family of near-miss inputs.
        assertOnlyInvalidKey(twice, spec, "a doubly wrapped point");
    }

    @ParameterizedTest
    @ValueSource(ints = {21, 22, 23})
    @DisplayName("CKA_EC_PARAMS is refused rather than thrown out of, whatever the bytes")
    void curveParsingStaysChecked(int seed) throws Exception {
        Random random = new Random(seed);
        List<byte[]> seeds = List.of(
                new ASN1ObjectIdentifier(P256_OID).getEncoded(),
                new ASN1ObjectIdentifier(P384_OID).getEncoded(),
                new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.7").getEncoded());
        for (int i = 0; i < ITERATIONS; i++) {
            byte[] input = seeds.get(random.nextInt(seeds.size())).clone();
            input = mutate(input, random);
            try {
                EcPointCodec.parseCurve(input);
            } catch (InvalidKeyException expected) {
                assertTrue(expected.getMessage() != null && !expected.getMessage().isEmpty());
            } catch (Throwable unexpected) {
                fail("parseCurve threw " + unexpected.getClass().getName() + " rather than"
                        + " InvalidKeyException for " + describe(input) + ": "
                        + unexpected.getMessage(), unexpected);
            }
        }
    }

    @Test
    @DisplayName("a valid point still decodes, so the checks above are not vacuous")
    void theHappyPathStillWorks() throws Exception {
        // Without this, every assertion above would pass on a decodePoint that refused everything.
        for (String oid : new String[] {P256_OID, P384_OID}) {
            ECParameterSpec spec = spec(oid);
            for (byte[] encoding : corpus(spec)) {
                assertEquals(spec.getG(), EcPointCodec.decodePoint(encoding, spec),
                        "a valid encoding must still decode to the generator");
            }
        }
    }
}
