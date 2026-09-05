/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.provider;

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

    protected final CryptokiDevice device;

    protected Kimbo11ngKeyPairGeneratorSpi(CryptokiDevice device) {
        this.device = device;
    }

    /** Label for keys created through this path; EJBCA relabels via {@code setKeyEntry}. */
    private static byte[] provisionalLabel(long handle) {
        return ("generated-" + handle).getBytes(StandardCharsets.UTF_8);
    }

    KeyPair generate(KeyTemplates.Pair templates, String algorithm, long mechanism) {
        try {
            long session = device.getOrOpenSession();
            CryptokiE ce = device.getCe();
            LongRef pubRef = new LongRef();
            LongRef privRef = new LongRef();
            synchronized (device) {
                ce.GenerateKeyPair(session, new CKM(mechanism),
                        templates.pub(), templates.priv(), pubRef, privRef);
            }
            java.security.PublicKey publicKey = "RSA".equals(algorithm)
                    ? Kimbo11ngPublicKey.readRsaPublicKey(ce, session, pubRef.value())
                    : Kimbo11ngPublicKey.readEcPublicKey(ce, session, pubRef.value());
            Kimbo11ngPrivateKey privateKey = new Kimbo11ngPrivateKey(privRef.value(), algorithm,
                    new String(provisionalLabel(privRef.value()), StandardCharsets.UTF_8), device);
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

        public RSA(CryptokiDevice device) {
            super(device);
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
            byte[] label = provisionalLabel(System.nanoTime());
            return generate(KeyTemplates.rsa(label, keyId, keySize), "RSA",
                    CKM.RSA_PKCS_KEY_PAIR_GEN);
        }
    }

    /** EC. */
    public static final class EC extends Kimbo11ngKeyPairGeneratorSpi {

        private String curveName = "P-256";

        public EC(CryptokiDevice device) {
            super(device);
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
            curveName = ecSpec.getName();
        }

        @Override
        public KeyPair generateKeyPair() {
            try {
                byte[] keyId = KeyTemplates.newKeyId();
                byte[] label = provisionalLabel(System.nanoTime());
                return generate(KeyTemplates.ec(label, keyId, curveName), "EC",
                        CKM.EC_KEY_PAIR_GEN);
            } catch (java.io.IOException e) {
                throw new ProviderException("Cannot encode EC parameters for curve "
                        + curveName + ": " + e.getMessage(), e);
            }
        }
    }
}
