/*
 * Copyright (c) 2026 Thomas Pham — kimbo11ng
 * SPDX-License-Identifier: Apache-2.0
 */

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Lifts EJBCA Community Edition 9.6's refusal to start when the database holds an HSM crypto token,
 * by emptying the one method that enforces it.
 *
 * <p>{@code StartupSingletonBean.checkHsmTokensNotUsedInCommunityEdition()} throws
 * {@code IllegalStateException} when {@code !isRunningEnterprise() && hasNonCeSupportedTokenTypes()}.
 * Every token type other than Soft and Null counts as unsupported, so a {@code Pkcs11NgCryptoToken}
 * row aborts the deployment. See docs/EJBCA_UPSTREAM_WATCH.md, W1.
 *
 * <p>This rewrites that method to a bare {@code return}, in place, in a copy of the official
 * {@code ejbca-ejb.jar}. Nothing else in the jar is touched: no EJBCA source is rebuilt, so every
 * other class stays byte-identical to what Keyfactor shipped.
 *
 * <p>It refuses to guess. The build fails, rather than the CA failing to start, when:
 * <ul>
 *   <li>the class or the method is not there — the check was renamed or moved;
 *   <li>the method does not call {@code hasNonCeSupportedTokenTypes} — it is no longer the check;
 *   <li>anything else in the class calls {@code hasNonCeSupportedTokenTypes} — a second check would
 *       survive the patch.
 * </ul>
 * It does not see a check added in some other class. {@code hasNonCeSupportedTokenTypes} having a
 * new caller is caught by the image build's own start-up test, not here.
 *
 * <p>Idempotent: a jar whose method is already a bare {@code return} is left as it is.
 *
 * <p>Usage: {@code java -cp asm.jar StartupCheckPatcher.java path/to/ejbca-ejb.jar}
 */
public final class StartupCheckPatcher {

    private static final String ENTRY = "org/ejbca/core/ejb/StartupSingletonBean.class";
    private static final String METHOD = "checkHsmTokensNotUsedInCommunityEdition";
    private static final String DESC = "()V";
    private static final String CHECK_CALL = "hasNonCeSupportedTokenTypes";

    private StartupCheckPatcher() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            fail("usage: StartupCheckPatcher <ejbca-ejb.jar>");
        }
        Path jar = Path.of(args[0]);
        try (FileSystem fs = FileSystems.newFileSystem(URI.create("jar:" + jar.toUri()), Map.of())) {
            Path entry = fs.getPath(ENTRY);
            if (!Files.exists(entry)) {
                fail(ENTRY + " is not in " + jar + ". The class was renamed or moved; find the new"
                        + " home of the check (git grep hasNonCeSupportedTokenTypes) and update this tool.");
            }
            byte[] original = Files.readAllBytes(entry);
            Inspection seen = inspect(original);

            if (!seen.declared) {
                fail("StartupSingletonBean has no " + METHOD + DESC + ". The check was renamed or"
                        + " removed; if removed, this patch is no longer needed, and if renamed,"
                        + " update this tool.");
            }
            if (seen.bodyIsBareReturn) {
                System.out.println("already patched: " + METHOD + " is a bare return in " + jar);
                return;
            }
            if (!seen.callsCheckInMethod) {
                fail(METHOD + " no longer calls " + CHECK_CALL + ". It is not the check this tool"
                        + " was written for; read it before deciding what to patch.");
            }
            if (!seen.otherCallers.isEmpty()) {
                fail(CHECK_CALL + " is also called from " + seen.otherCallers + ". A second check"
                        + " would survive this patch.");
            }

            byte[] patched = rewrite(original);
            Inspection after = inspect(patched);
            if (!after.bodyIsBareReturn || !after.otherCallers.isEmpty()) {
                fail("internal error: the rewritten class does not verify as a bare return");
            }
            Files.write(entry, patched);
            System.out.println("patched " + METHOD + " to a bare return in " + jar
                    + " (" + original.length + " -> " + patched.length + " bytes)");
        }
    }

    private record Inspection(boolean declared, boolean bodyIsBareReturn, boolean callsCheckInMethod,
            List<String> otherCallers) {
    }

    private static Inspection inspect(byte[] classBytes) {
        boolean[] declared = {false};
        boolean[] callsCheck = {false};
        int[] instructions = {0};
        boolean[] onlyReturn = {true};
        List<String> others = new ArrayList<>();

        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                    String signature, String[] exceptions) {
                boolean target = METHOD.equals(name) && DESC.equals(descriptor);
                if (target) {
                    declared[0] = true;
                }
                String where = name + descriptor;
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitInsn(int opcode) {
                        if (target) {
                            instructions[0]++;
                            onlyReturn[0] &= opcode == Opcodes.RETURN;
                        }
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String callee,
                            String calleeDescriptor, boolean isInterface) {
                        if (target) {
                            instructions[0]++;
                            onlyReturn[0] = false;
                        }
                        if (CHECK_CALL.equals(callee)) {
                            if (target) {
                                callsCheck[0] = true;
                            } else {
                                others.add(where);
                            }
                        }
                    }

                    @Override
                    public void visitVarInsn(int opcode, int varIndex) {
                        if (target) {
                            instructions[0]++;
                            onlyReturn[0] = false;
                        }
                    }

                    @Override
                    public void visitJumpInsn(int opcode, org.objectweb.asm.Label label) {
                        if (target) {
                            instructions[0]++;
                            onlyReturn[0] = false;
                        }
                    }

                    @Override
                    public void visitFieldInsn(int opcode, String owner, String field, String d) {
                        if (target) {
                            instructions[0]++;
                            onlyReturn[0] = false;
                        }
                    }

                    @Override
                    public void visitTypeInsn(int opcode, String type) {
                        if (target) {
                            instructions[0]++;
                            onlyReturn[0] = false;
                        }
                    }

                    @Override
                    public void visitLdcInsn(Object value) {
                        if (target) {
                            instructions[0]++;
                            onlyReturn[0] = false;
                        }
                    }
                };
            }
        }, 0);
        return new Inspection(declared[0], declared[0] && instructions[0] == 1 && onlyReturn[0],
                callsCheck[0], others);
    }

    private static byte[] rewrite(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        ClassWriter writer = new ClassWriter(reader, 0);
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                    String signature, String[] exceptions) {
                MethodVisitor out = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!METHOD.equals(name) || !DESC.equals(descriptor)) {
                    return out;
                }
                // A private instance method: `this` is the only local and nothing is pushed, so no
                // stack map frame is needed for a body with no branches.
                out.visitCode();
                out.visitInsn(Opcodes.RETURN);
                out.visitMaxs(0, 1);
                out.visitEnd();
                return null;
            }
        }, 0);
        return writer.toByteArray();
    }

    private static void fail(String message) {
        System.err.println("StartupCheckPatcher: " + message);
        System.exit(1);
    }
}
