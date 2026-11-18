package com.aweimc.j4shell;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Victim-side TCP server - pure JDK, no third-party dependencies.
 *
 * Binds to 127.0.0.1 by default (local lab topology; authorized test environments only).
 *
 * Wire protocol (text lines + one binary body):
 *   C: PING\n                      ->  S: PONG <arm status>\n
 *   C: FIRE <len>\n + <len bytes>  ->  S: HIT shot=N row=R len=A->B\n   (then the JVM dies)
 *                                      or CONTAMINATED shot=N row=R\n
 *                                      or SURVIVED shots=N\n
 *   C: SHUT\n                      ->  S: BYE\n  (graceful exit for negative-control scripting)
 *
 * On FIRE the server runs DualDecodeVictim.fire(): two consecutive single-arg
 * decode(byte[]) calls. If a sentinel length field is corrupted, the HIT reply is
 * sent BEFORE the forced crash - the client receives the reply and then verifies
 * the port is dead, giving a complete evidence chain.
 */
public final class J4ShellServer {

    private final int port;
    private final String bind;
    private final DualDecodeVictim victim;
    private final int shots;
    private String armStatus = "NOT-ARMED";

    public J4ShellServer(int port, String bind, int warm, int gridMb, int shots) {
        this.port = port;
        this.bind = bind;
        this.victim = new DualDecodeVictim(warm, gridMb, shots);
        this.shots = shots;
    }

    public void run() throws Exception {
        armStatus = victim.arm();
        System.out.println("[server] " + armStatus);

        ServerSocket ss = new ServerSocket();
        ss.bind(new InetSocketAddress(bind, port));
        System.out.println("[server] listening on " + bind + ":" + port + " (lab only)");
        System.out.flush();

        while (true) {
            try (Socket s = ss.accept()) {
                s.setTcpNoDelay(true);
                handle(s);
            } catch (Exception e) {
                System.out.println("[server] connection error: " + e);
                System.out.flush();
            }
        }
    }

    private void handle(Socket s) throws Exception {
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        String line = readLine(in);
        System.out.println("[server] cmd: " + line);
        System.out.flush();

        if (line.equals("PING")) {
            write(out, "PONG " + status());
            return;
        }
        if (line.equals("SHUT")) {
            write(out, "BYE");
            System.exit(0);
        }
        if (line.startsWith("FIRE ")) {
            int len = Integer.parseInt(line.substring(5).trim());
            if (len != victim.triggerLen()) {
                write(out, "ERR expect len=" + victim.triggerLen());
                return;
            }
            byte[] buf = victim.recvBuf();
            int off = 0;
            while (off < len) {
                int n = in.read(buf, off, len - off);
                if (n < 0) { write(out, "ERR short-body"); return; }
                off += n;
            }
            System.out.printf("[server] payload received: %d bytes, firing %d single-arg decodes...%n",
                    len, shots);
            System.out.flush();

            DualDecodeVictim.FireResult r = victim.fire(buf);
            if (r.hit && r.lengthHit) {
                // reply first (evidence chain: client receives HIT), then force the crash
                write(out, String.format("HIT shot=%d row=%d len=%d->%d (0x%08X)",
                        r.shot, r.rowIndex, r.oldLen, r.newLen, r.newLen));
                System.out.flush();
                victim.forceCrash(r.rowIndex, r.shot);
                return;   // normally unreachable
            }
            if (r.hit) {
                write(out, String.format("CONTAMINATED shot=%d row=%d", r.shot, r.rowIndex));
                return;
            }
            write(out, "SURVIVED shots=" + r.shot);
            return;
        }
        write(out, "ERR unknown-cmd");
    }

    private String status() {
        return "java=" + System.getProperty("java.version")
                + " triggerLen=" + victim.triggerLen()
                + " probe=" + (victim.isProbed() ? "REPRODUCED" : "none")
                + " ready=true";
    }

    private static void write(OutputStream out, String msg) throws Exception {
        out.write((msg + "\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    static String readLine(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1 && c != '\n') {
            if (c != '\r') buf.write(c);
            if (buf.size() > 4096) break;
        }
        return buf.toString(StandardCharsets.US_ASCII);
    }
}
