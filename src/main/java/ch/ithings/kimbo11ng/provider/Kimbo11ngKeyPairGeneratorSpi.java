/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

import ch.ithings.kimbo11ng.p11.P11Slot;
import ch.ithings.kimbo11ng.p11.SessionLease;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CryptokiE;
import org.pkcs11.jacknji11.LongRef;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * KeyPairGenerator over PKCS#11, for callers that reach the token through the JCA rather than
 * through EJBCA's CryptoToken API.
 *
 * <p>Templates come from {@link KeyTemplates}, the same builder the CryptoToken path uses, so the
 * two cannot drift as they previously had.
 */
public abstract class Kimbo11ngKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private static final Logger log = Logger.getLogger(Kimbo11ngKeyPairGeneratorSpi.class);

    protected final P11Slot slot;

    protected Kimbo11ngKeyPairGeneratorSpi(P11Slot slot) {
        this.slot = slot;
    }

    /**
     * Label for keys created through this path; EJBCA relabels via {@code setKeyEntry}.
     *
     * <p>Random rather than derived from the object handle: the handle is not known until after
     * generation, and it has to go into the template so both halves of the pair carry it.
     */
    private static String provisionalLabel() {
        return "generated-" + java.util.UUID.randomUUID();
    }

    KeyPair generate(KeyTemplates.Pair templates, byte[] keyId, String label, String algorithm,
            long mechanism) {
        try (SessionLease lease = slot.borrow()) {
            long session = lease.session();
            CryptokiE ce = slot.ce();
            LongRef pubRef = new LongRef();
            LongRef privRef = new LongRef();
            ce.GenerateKeyPair(session, new CKM(mechanism),
                    templates.pub(), templates.priv(), pubRef, privRef);
            java.security.PublicKey publicKey = "RSA".equals(algorithm)
                    ? PublicKeyReader.readRsaPublicKey(ce, session, pubRef.value())
                    : PublicKeyReader.readEcPublicKey(ce, session, pubRef.value());
            Kimbo11ngPrivateKey privateKey = new Kimbo11ngPrivateKey(algorithm, slot,
                    new P11KeyRef(keyId, label, null), privRef.value());
            if (log.isDebugEnabled()) {
                log.debug("Generated " + algorithm + " key pair: priv=" + privRef.value()
                        + " pub=" + pubRef.value());
            }
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            // ProviderException, not RuntimeException: this is what the JCA contract specifies for
            // a provider-internal failure during generateKeyPair.
            throw new ProviderException("Failed to generate an " + algorithm
                    + " key pair on the token: " + e.getMessage(), e);
        }
    }

    /** RSA. */
    public static final class RSA extends Kimbo11ngKeyPairGeneratorSpi {

        private int keySize = 2048;

        public RSA(P11Slot slot) {
            super(slot);
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            this.keySize = keysize;
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException("Use initialize(int) for RSA");
        }

        @Override
        public KeyPair generateKeyPair() {
            byte[] keyId = KeyTemplates.newKeyId();
            String label = provisionalLabel();
            return generate(KeyTemplates.rsa(label.getBytes(StandardCharsets.UTF_8), keyId, keySize),
                    keyId, label, "RSA", CKM.RSA_PKCS_KEY_PAIR_GEN);
        }
    }

    /** EC. */
    public static final class EC extends Kimbo11ngKeyPairGeneratorSpi {

        private String curveName = "P-256";

        public EC(P11Slot slot) {
            super(slot);
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            switch (keysize) {
                case 384 -> curveName = "P-384";
                case 521 -> curveName = "P-521";
                default -> curveName = "P-256";
            }
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidAlgorithmParameterException {
            if (!(params instanceof ECGenParameterSpec ecSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Expected ECGenParameterSpec, got: " + params.getClass().getName());
            }
            // Rejected here, where the JCA gives us a checked exception the caller can act on.
            // Deferring it to generateKeyPair turns a typo into a ProviderException at a point
            // where the curve name is no longer obviously the cause.
            if (!KeyTemplates.isKnownCurve(ecSpec.getName())) {
                throw new InvalidAlgorithmParameterException("Unknown curve '" + ecSpec.getName()
                        + "'. Accepted spellings are the NIST (P-256), SEC (secp256r1), X9.62"
                        + " (prime256v1) and Brainpool names, or a dotted OID.");
            }
            curveName = ecSpec.getName();
        }

        @Override
        public KeyPair generateKeyPair() {
            try {
                byte[] keyId = KeyTemplates.newKeyId();
                String label = provisionalLabel();
                return generate(KeyTemplates.ec(label.getBytes(StandardCharsets.UTF_8), keyId,
                        curveName), keyId, label, "EC", CKM.EC_KEY_PAIR_GEN);
            } catch (java.io.IOException | RuntimeException e) {
                // generateKeyPair declares no checked exception, so the JCA contract is
                // ProviderException for anything that goes wrong inside the provider. Letting an
                // IllegalArgumentException out instead gives the caller no indication of which
                // provider, or which curve, produced it.
                throw new ProviderException("Cannot encode EC parameters for curve "
                        + curveName + ": " + e.getMessage(), e);
            }
        }
    }
}
