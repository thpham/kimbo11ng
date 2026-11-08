/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AltSignatureAlgorithm;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * The BouncyCastle half of the PQC demo: what OpenSSL cannot do yet.
 *
 * <pre>
 * csr      KEY_OUT CSR_OUT SUBJECT_DN ALGORITHM   new key pair and a CSR signed with it
 * sign     KEY CERT DOCUMENT SIGNATURE_OUT        detached CMS signature over DOCUMENT
 * verify   SIGNATURE DOCUMENT ROOT [CA...]        the CMS signature, and its signer's chain
 * chain    ROOT [CA...] LEAF                      PKIX path validation, BouncyCastle doing the maths
 * altsig   ISSUER SUBJECT                         the hybrid alternative signature, with the issuer's
 *                                                 SubjectAltPublicKeyInfo key
 * describe CERT...                                one line per certificate
 * </pre>
 *
 * Every check prints {@code OK <what>} or {@code FAIL <what>: <why>} and sets the exit status, so
 * pqc-check.sh can tabulate it.
 */
public class PqcDemo {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        boolean ok = switch (args[0]) {
            case "csr" -> csr(args[1], args[2], args[3], args[4]);
            case "sign" -> sign(args[1], args[2], args[3], args[4]);
            case "verify" -> verify(args[1], args[2], args[3], tail(args, 4));
            case "chain" -> chain(args[1], tail(args, 2));
            case "altsig" -> altsig(args[1], args[2]);
            case "describe" -> describe(tail(args, 1));
            default -> throw new IllegalArgumentException("unknown command " + args[0]);
        };
        System.exit(ok ? 0 : 1);
    }

    static boolean csr(String keyOut, String csrOut, String dn, String algorithm) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance(algorithm, "BC").generateKeyPair();
        PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(dn), pair.getPublic())
                .build(new JcaContentSignerBuilder(algorithm).setProvider("BC").build(pair.getPrivate()));
        writePem(keyOut, pair.getPrivate());
        writePem(csrOut, request);
        System.out.println("OK " + algorithm + " key pair and CSR for " + dn);
        return true;
    }

    static boolean sign(String keyPath, String certPath, String document, String out) throws Exception {
        PrivateKey key;
        try (PEMParser p = new PEMParser(new FileReader(keyPath))) {
            key = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(
                    org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(p.readObject()));
        }
        X509Certificate cert = cert(certPath);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(new JcaContentSignerBuilder(key.getAlgorithm()).setProvider("BC").build(key), cert));
        gen.addCertificates(new JcaCertStore(List.of(cert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(Files.readAllBytes(Path.of(document))), false);
        Files.write(Path.of(out), signed.getEncoded());
        System.out.println("OK signed " + document + " with " + key.getAlgorithm());
        return true;
    }

    @SuppressWarnings("unchecked") // SignerId is a Selector<X509CertificateHolder>
    static boolean verify(String signature, String document, String root, List<String> cas) throws Exception {
        CMSSignedData signed = new CMSSignedData(new CMSProcessableByteArray(
                Files.readAllBytes(Path.of(document))), Files.readAllBytes(Path.of(signature)));
        for (SignerInformation signer : signed.getSignerInfos().getSigners()) {
            X509CertificateHolder holder = (X509CertificateHolder) signed.getCertificates()
                    .getMatches(signer.getSID()).iterator().next();
            X509Certificate signerCert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(holder);
            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert))) {
                System.out.println("FAIL CMS signature: does not verify");
                return false;
            }
            System.out.println("OK CMS signature by " + signerCert.getSubjectX500Principal()
                    + " (" + signerCert.getPublicKey().getAlgorithm() + ")");
            List<String> path = new ArrayList<>(cas);
            Files.writeString(Path.of(signature + ".signer.pem"), pem(signerCert));
            path.add(signature + ".signer.pem");
            return chain(root, path);
        }
        System.out.println("FAIL CMS signature: no signer");
        return false;
    }

    static boolean chain(String rootPath, List<String> rest) throws Exception {
        X509Certificate root = cert(rootPath);
        List<X509Certificate> path = new ArrayList<>();
        for (String p : rest) {
            path.add(0, cert(p));
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            CertPath certPath = cf.generateCertPath(path);
            PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX", "BC").validate(certPath, params);
            StringBuilder algs = new StringBuilder();
            for (X509Certificate c : path) {
                algs.append(algs.length() == 0 ? "" : ", ").append(c.getSigAlgName());
            }
            System.out.println("OK chain to " + root.getSubjectX500Principal().getName()
                    + " (signatures: " + algs + ")");
            return true;
        } catch (Exception e) {
            System.out.println("FAIL chain: " + e.getMessage());
            return false;
        }
    }

    static boolean altsig(String issuerPath, String subjectPath) throws Exception {
        X509CertificateHolder issuer = holder(issuerPath);
        X509CertificateHolder subject = holder(subjectPath);
        Extension alg = subject.getExtension(Extension.altSignatureAlgorithm);
        if (alg == null) {
            System.out.println("FAIL alternative signature: " + subject.getSubject() + " carries none");
            return false;
        }
        Extension altKey = issuer.getExtension(Extension.subjectAltPublicKeyInfo);
        if (altKey == null) {
            System.out.println("FAIL alternative signature: " + issuer.getSubject()
                    + " publishes no SubjectAltPublicKeyInfo, so nobody can verify it");
            return false;
        }
        PublicKey key = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(SubjectPublicKeyInfo.getInstance(
                SubjectAltPublicKeyInfo.getInstance(altKey.getParsedValue()).toASN1Primitive()));
        boolean valid = subject.isAlternativeSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider("BC").build(key));
        String name = AltSignatureAlgorithm.getInstance(alg.getParsedValue()).getAlgorithm().getAlgorithm().getId();
        System.out.println((valid ? "OK" : "FAIL") + " alternative signature on " + subject.getSubject()
                + " (" + key.getAlgorithm() + ", OID " + name + ")" + (valid ? "" : ": does not verify"));
        return valid;
    }

    static boolean describe(List<String> paths) throws Exception {
        for (String p : paths) {
            X509CertificateHolder h = holder(p);
            X509Certificate c = cert(p);
            Extension alt = h.getExtension(Extension.altSignatureAlgorithm);
            String cn = org.bouncycastle.asn1.x500.style.IETFUtils.valueToString(
                    h.getSubject().getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN)[0]
                            .getFirst().getValue());
            String altSig = alt == null ? "" : "  + " + mlDsaName(AltSignatureAlgorithm
                    .getInstance(alt.getParsedValue()).getAlgorithm().getAlgorithm().getId());
            String altKey = h.getExtension(Extension.subjectAltPublicKeyInfo) == null ? ""
                    : " (publishes its ML-DSA key)";
            System.out.printf("%-28s signed %-27s key %-27s%s%s%n", cn, c.getSigAlgName(),
                    c.getPublicKey().getAlgorithm(), altSig, altKey);
        }
        return true;
    }

    private static String mlDsaName(String oid) {
        return switch (oid) {
            case "2.16.840.1.101.3.4.3.17" -> "ML-DSA-44";
            case "2.16.840.1.101.3.4.3.18" -> "ML-DSA-65";
            case "2.16.840.1.101.3.4.3.19" -> "ML-DSA-87";
            default -> oid;
        };
    }

    private static List<String> tail(String[] args, int from) {
        List<String> list = new ArrayList<>();
        for (int i = from; i < args.length; i++) {
            list.add(args[i]);
        }
        return list;
    }

    private static X509Certificate cert(String path) throws Exception {
        try (InputStream in = new FileInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in);
        }
    }

    private static X509CertificateHolder holder(String path) throws Exception {
        return new X509CertificateHolder(cert(path).getEncoded());
    }

    private static String pem(Object o) throws Exception {
        java.io.StringWriter w = new java.io.StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(w)) {
            pw.writeObject(o);
        }
        return w.toString();
    }

    private static void writePem(String path, Object o) throws Exception {
        try (JcaPEMWriter w = new JcaPEMWriter(new FileWriter(path))) {
            w.writeObject(o);
        }
    }
}
