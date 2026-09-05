/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */
package ch.ithings.kimbo11ng.cli;

import ch.ithings.kimbo11ng.p11.Pkcs11Errors;
import ch.ithings.kimbo11ng.p11.SessionLease;
import ch.ithings.kimbo11ng.profile.AlgorithmEntry;
import ch.ithings.kimbo11ng.profile.PqcMechanismProfile;
import ch.ithings.kimbo11ng.profile.ProfileResolver;
import com.keyfactor.util.keys.CachingKeyStoreWrapper;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CryptokiE;

import java.io.PrintStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * The commands that look at, and remove, objects on the token.
 *
 * <p>{@code listobjects} and {@code listkeypairs} are two views of the same slot and the difference
 * between them is the point. {@code listobjects} is what PKCS#11 holds: every object, by handle,
 * including ones no Java caller will ever see. {@code listkeypairs} is what kimbo11ng publishes to
 * EJBCA: the alias list, built by the same key store SPI the CA reads. A key that appears in the
 * first and not the second is the single most common HSM problem there is — a key pair whose halves
 * disagree on {@code CKA_ID}, or a private key with no public half — and it is invisible from
 * either view alone.
 */
final class ObjectCommands {

    private ObjectCommands() {
    }

    static List<Command> all() {
        return List.of(listObjects(), listKeyPairs(), showObjectAttributes(), deleteObject());
    }

    /** The attributes worth printing for any object, in the order a reader wants them. */
    private static final long[] INTERESTING = {
            CKA.CLASS, CKA.KEY_TYPE, CKA.LABEL, CKA.ID,
            CKA.TOKEN, CKA.PRIVATE, CKA.MODIFIABLE,
            CKA.SENSITIVE, CKA.ALWAYS_SENSITIVE, CKA.EXTRACTABLE, CKA.NEVER_EXTRACTABLE,
            CKA.SIGN, CKA.VERIFY, CKA.ENCRYPT, CKA.DECRYPT, CKA.WRAP, CKA.UNWRAP, CKA.DERIVE,
            CKA.MODULUS_BITS, CKA.VALUE_LEN,
    };

    private static Command listObjects() {
        return Command.sessionLevel("listobjects",
                "Lists every object in the slot with its handle, class, label and id.",
                List.of(),
                (env, args) -> {
                    try (TokenHandle handle = TokenHandle.session(env, args);
                            SessionLease lease = handle.slot().borrow()) {
                        CryptokiE ce = handle.slot().ce();
                        long[] objects = ce.FindObjects(lease.session());
                        PrintStream out = env.out();
                        out.println("Objects in slot " + handle.slot().slotId() + ": "
                                + objects.length);
                        out.println();
                        out.println(row("HANDLE", "CLASS", "KEY TYPE", "LABEL", "ID"));
                        for (long object : objects) {
                            out.println(row(Long.toString(object),
                                    className(ce, lease, object),
                                    keyType(ce, lease, object),
                                    string(ce, lease, object, CKA.LABEL),
                                    hex(ce, lease, object, CKA.ID)));
                        }
                    }
                });
    }

    /**
     * The alias view: what EJBCA will list, built by the key store the crypto token publishes.
     *
     * <p>Deliberately not a re-derivation from {@code C_FindObjects}. Going through the key store is
     * what makes the output an answer to "what will the CA see", including the cases where that
     * answer is "less than you put there".
     */
    private static Command listKeyPairs() {
        return Command.sessionLevel("listkeypairs",
                "Lists the aliases kimbo11ng publishes to EJBCA, with each key's algorithm.",
                List.of(),
                (env, args) -> {
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
                        CachingKeyStoreWrapper keyStore = handle.keyStore();
                        List<String> aliases = Collections.list(keyStore.aliases());
                        Collections.sort(aliases);
                        PrintStream out = env.out();
                        out.println("Aliases in slot " + handle.slot().slotId() + ": "
                                + aliases.size());
                        out.println();
                        out.println(keyRow("ALIAS", "KIND", "ALGORITHM", "KEY LENGTH"));
                        for (String alias : aliases) {
                            if (handle.token().isSecretKey(alias)) {
                                out.println(keyRow(alias, "secret", "-", "-"));
                                continue;
                            }
                            PublicKey publicKey = handle.token().readPublicKey(alias, true);
                            if (publicKey == null) {
                                // A private key whose public half is missing or unreadable. It is
                                // in the alias list and EJBCA will refuse to use it, so saying so
                                // here is the whole value of the command.
                                out.println(keyRow(alias, "key pair", "<no public key>", "-"));
                                continue;
                            }
                            out.println(keyRow(alias, "key pair", publicKey.getAlgorithm(),
                                    keyLength(publicKey)));
                        }
                    }
                });
    }

    private static Command showObjectAttributes() {
        return Command.sessionLevel("showobjectattributes",
                "Prints the PKCS#11 attributes of one object, by handle or by alias.",
                List.of(Opt.arg("object", "<handle>",
                                "Object handle, as printed by listobjects. Decimal or 0x-prefixed."),
                        Opt.arg("alias", "<name>",
                                "Alias; every object whose CKA_LABEL matches is printed.")),
                (env, args) -> {
                    if (!args.has("object") && !args.has("alias")) {
                        throw CliException.usage("Give either --object or --alias.");
                    }
                    try (TokenHandle handle = TokenHandle.session(env, args);
                            SessionLease lease = handle.slot().borrow()) {
                        CryptokiE ce = handle.slot().ce();
                        List<Long> targets = new ArrayList<>();
                        if (args.has("object")) {
                            targets.add(args.requireLong("object"));
                        } else {
                            String alias = args.require("alias");
                            for (long object : ce.FindObjects(lease.session())) {
                                if (alias.equals(string(ce, lease, object, CKA.LABEL))) {
                                    targets.add(object);
                                }
                            }
                            if (targets.isEmpty()) {
                                throw new CliException("No object on the token carries the label '"
                                        + alias + "'.");
                            }
                            // The count matters on its own: a healthy key pair is two objects, and
                            // one is the shape of the most common breakage there is.
                            env.out().println("Objects labelled '" + alias + "': " + targets.size());
                            env.out().println();
                        }
                        for (long object : targets) {
                            printAttributes(env.out(), ce, lease, object);
                        }
                    }
                });
    }

    private static void printAttributes(PrintStream out, CryptokiE ce, SessionLease lease,
            long object) throws CliException {
        List<String> lines = new ArrayList<>();
        for (long type : INTERESTING) {
            String rendered = attribute(ce, lease, object, type);
            if (rendered != null) {
                // jacknji11's L2S drops the CKA_ prefix; the specification's own spelling is what
                // an operator will be reading the vendor documentation against.
                lines.add("  " + InfoCommands.pad("CKA_" + CKA.L2S(type), 24) + " " + rendered);
            }
        }
        // The heading only once every read has come back. Printed first, it appears above nothing
        // when the handle names no object, and a typo then looks exactly like a real object that
        // happens to carry no attributes.
        out.println("Object " + object);
        for (String line : lines) {
            out.println(line);
        }
        out.println();
    }

    /**
     * One attribute, rendered, or {@code null} when the object does not have it.
     *
     * <p>Every read is on its own, rather than one batched {@code C_GetAttributeValue}: asking for
     * an attribute an object does not carry fails the whole batch on most tokens, and a
     * {@code CKA_SENSITIVE} key legitimately refuses several of these. Failing per attribute is what
     * lets the rest of the object still be printed.
     *
     * @throws CliException if the read failed for a reason that is not "this object has no such
     *                      attribute" — a handle that names nothing, or a session that has died
     */
    private static String attribute(CryptokiE ce, SessionLease lease, long object, long type)
            throws CliException {
        CKA value;
        try {
            value = ce.GetAttributeValue(lease.session(), object, type);
        } catch (RuntimeException e) {
            // CKR_ATTRIBUTE_TYPE_INVALID and CKR_ATTRIBUTE_SENSITIVE are not failures: PKCS#11
            // v2.40 §5.7 says so explicitly, and a public key with no CKA_SENSITIVE is the normal
            // case. Everything else is a statement about the object or the session, and reporting
            // it as an absent attribute is what let a dead connection print as a slot full of
            // unlabelled objects.
            if (Pkcs11Errors.is(e, CKR.ATTRIBUTE_TYPE_INVALID)
                    || Pkcs11Errors.is(e, CKR.ATTRIBUTE_SENSITIVE)) {
                return null;
            }
            throw attributeFailure(e, lease, object, type);
        }
        if (value == null || !value.hasValue()) {
            return null;
        }
        if (type == CKA.CLASS) {
            return CKO.L2S(orZero(value.getValueLong()));
        }
        if (type == CKA.KEY_TYPE) {
            return keyTypeName(orZero(value.getValueLong()));
        }
        if (type == CKA.LABEL) {
            return value.getValueStr();
        }
        if (type == CKA.ID) {
            return toHex(value.getValue());
        }
        if (type == CKA.MODULUS_BITS || type == CKA.VALUE_LEN) {
            Long number = value.getValueLong();
            return number == null ? null : number.toString();
        }
        Boolean flag = value.getValueBool();
        return flag == null ? toHex(value.getValue()) : flag.toString();
    }

    /**
     * What to tell the operator about a {@code C_GetAttributeValue} that failed for real, and what
     * to do with the session it failed on.
     *
     * <p>Classified through {@link Pkcs11Errors} rather than by inspecting the message, so a
     * dropped Luna connection lands in the same bucket here as it does in the signing paths. A
     * stale object handle leaves the session usable and the lease is kept; anything the classifier
     * calls retryable or offline means the session or the device is the problem, and returning
     * that session to the pool hands the next borrower a connection the token has already given up
     * on.
     */
    private static CliException attributeFailure(RuntimeException cause, SessionLease lease,
            long object, long type) {
        if (Pkcs11Errors.is(cause, CKR.OBJECT_HANDLE_INVALID)) {
            return new CliException("No object with handle " + object + " on the token"
                    + " (CKR_OBJECT_HANDLE_INVALID). Handles are assigned per session and change"
                    + " when the token is reinitialised — run listobjects to see the ones this"
                    + " slot holds now.", cause);
        }
        Pkcs11Errors.Kind kind = Pkcs11Errors.classify(cause);
        if (kind == Pkcs11Errors.Kind.RETRYABLE || kind == Pkcs11Errors.Kind.OFFLINE) {
            lease.invalidate();
        }
        return new CliException("Reading CKA_" + CKA.L2S(type) + " from object " + object
                + " failed" + Pkcs11Errors.describe(cause) + ". Nothing below this point was read,"
                + " so treat the output above as incomplete rather than as the token's contents."
                + " Check that the HSM is reachable and run the command again.", cause);
    }

    private static Command deleteObject() {
        return Command.sessionLevel("deleteobject",
                "Removes a key by alias, or raw objects by handle.",
                List.of(Opt.arg("alias", "<name>",
                                "Alias to delete, through the crypto token, which removes both "
                                        + "halves of a key pair."),
                        Opt.repeatable("object", "<handle>",
                                "Object handle to destroy, repeatable. Removes exactly that object "
                                        + "and nothing else.")),
                (env, args) -> {
                    if (args.has("alias") == !args.all("object").isEmpty()) {
                        throw CliException.usage("Give either --alias or one or more --object,"
                                + " not both and not neither.");
                    }
                    try (TokenHandle handle = TokenHandle.session(env, args)) {
                        if (args.has("alias")) {
                            String alias = args.require("alias");
                            // Membership first. The key store SPI logs a warning and returns
                            // normally for an alias it does not hold, and log4j is unconfigured in
                            // this tool, so a mistyped alias would otherwise print a deletion that
                            // never happened and exit 0 — the one answer an operator must not get
                            // from a destructive command.
                            if (!Collections.list(handle.keyStore().aliases()).contains(alias)) {
                                throw new CliException("No key on the token under alias '" + alias
                                        + "', so nothing was deleted. Run listkeypairs to see the"
                                        + " aliases this slot publishes, or deleteobject --object"
                                        + " <handle> to destroy a raw object that listobjects"
                                        + " reports.");
                            }
                            boolean secret = handle.token().isSecretKey(alias);
                            handle.token().deleteEntry(alias);
                            env.out().println("Deleted alias " + alias + ": " + (secret
                                    ? "the secret key object on the token."
                                    : "the private key, its public half and any certificate"
                                            + " carried under that alias."));
                            return;
                        }
                        try (SessionLease lease = handle.slot().borrow()) {
                            for (String raw : args.all("object")) {
                                long object = Long.decode(raw.trim());
                                handle.slot().ce().DestroyObject(lease.session(), object);
                                env.out().println("Destroyed object " + object);
                            }
                        }
                        // Handles cached elsewhere in this process now name nothing. Nothing else
                        // runs in a CLI invocation, but the slot is shared with the key store SPI
                        // built during activation, which would otherwise keep answering with them.
                        handle.slot().invalidateHandles();
                    }
                });
    }

    // ---- rendering ----

    /**
     * One row of {@code listobjects}: a handle, then three token-supplied strings.
     *
     * <p>Separate from {@link #keyRow} even though both are four columns and a trailing field.
     * They were one method, and the widths that suit a numeric handle are the wrong ones for an
     * alias — which is how {@code listkeypairs} ended up with a 10-column alias field that every
     * real alias overflowed.
     */
    private static String row(String handle, String className, String keyType, String label,
            String id) {
        return (InfoCommands.pad(handle, 10) + InfoCommands.pad(className, 14)
                + InfoCommands.pad(keyType, 18) + InfoCommands.pad(label, 30) + id).stripTrailing();
    }

    /** One row of {@code listkeypairs}, whose first column is an alias and needs the room. */
    private static String keyRow(String alias, String kind, String algorithm, String keyLength) {
        return (InfoCommands.pad(alias, 24) + InfoCommands.pad(kind, 10)
                + InfoCommands.pad(algorithm, 20) + keyLength).stripTrailing();
    }

    private static String className(CryptokiE ce, SessionLease lease, long object)
            throws CliException {
        String rendered = attribute(ce, lease, object, CKA.CLASS);
        return rendered == null ? "?" : rendered.toLowerCase(Locale.ROOT);
    }

    private static String keyType(CryptokiE ce, SessionLease lease, long object)
            throws CliException {
        String rendered = attribute(ce, lease, object, CKA.KEY_TYPE);
        return rendered == null ? "-" : rendered;
    }

    private static String string(CryptokiE ce, SessionLease lease, long object, long type)
            throws CliException {
        String rendered = attribute(ce, lease, object, type);
        return rendered == null ? "" : rendered;
    }

    private static String hex(CryptokiE ce, SessionLease lease, long object, long type)
            throws CliException {
        String rendered = attribute(ce, lease, object, type);
        return rendered == null ? "" : rendered;
    }

    private static long orZero(Long value) {
        return value == null ? 0L : value;
    }

    /**
     * A name for {@code CKA_KEY_TYPE}, including the post-quantum types jacknji11 does not know.
     *
     * <p>jacknji11 1.3.1 predates the PKCS#11 v3.2 key types, so a real ML-DSA key prints as
     * {@code unknown CKK constant 0x0000004a} — on a tool whose reason to exist is post-quantum
     * keys. The profile tables already carry the mapping, so the family name comes from there.
     *
     * <p>The family, not the algorithm: ML-DSA-44, -65 and -87 share one {@code CKK}, and telling
     * them apart needs {@code CKA_PARAMETER_SET}, whose attribute id is itself profile-dependent.
     * Naming the family is what can be said without guessing, and the numeric value stays on the
     * line so nothing is lost.
     */
    private static String keyTypeName(long ckk) {
        String known = CKK.L2S(ckk);
        if (known != null && !known.toLowerCase(Locale.ROOT).startsWith("unknown")) {
            return known;
        }
        for (PqcMechanismProfile profile : ProfileResolver.available()) {
            for (AlgorithmEntry entry : profile.entries()) {
                if (entry.ckkKeyType() == ckk) {
                    return entry.family() + " (0x" + Long.toHexString(ckk) + ")";
                }
            }
        }
        return known;
    }

    private static String toHex(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return "";
        }
        StringBuilder hex = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * A key length for display, or {@code "-"}.
     *
     * <p>Through the encoded form rather than a cast to {@code RSAPublicKey} and friends: a
     * post-quantum public key is none of the interfaces {@code java.security} defines a length on,
     * and the encoded length is at least an honest number rather than a wrong one.
     */
    private static String keyLength(PublicKey publicKey) {
        if (publicKey instanceof java.security.interfaces.RSAPublicKey rsa) {
            return rsa.getModulus().bitLength() + " bits";
        }
        if (publicKey instanceof java.security.interfaces.ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize() + " bits";
        }
        byte[] encoded = publicKey.getEncoded();
        return encoded == null ? "-" : encoded.length + " bytes encoded";
    }
}
