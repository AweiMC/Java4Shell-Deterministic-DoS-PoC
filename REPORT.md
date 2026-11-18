# J4Shell-Deterministic-DoS PoC Report — CVE-2026-114938 Derivative: Two Single-Argument Decodes + Humongous Hole Geometry (Client → Server)

> **Recipe name: J4Shell-Deterministic-DoS** (technical description: dual-decode + humongous hole geometry).
> Code package: `com.aweimc.j4shell` · Repository: <https://github.com/AweiMC/Java4Shell-Deterministic-DoS-PoC>
> Test environment: Windows x86-64, Zulu JDK **17.0.20+8** (unpatched, `UseBASE64Intrinsics=true`, `UseAVX=3`, AVX-512 VBMI available), G1 GC.
> All testing was performed on a local loopback (127.0.0.1) lab — see Section 9, Ethics.

中文版：[REPORT_zh-CN.md](REPORT_zh-CN.md)

---

## 1. Derivative claim (what this PoC adds)

CVE-2026-114938 ("Java4Shell"), disclosed by Calif on 2026-11-17, is demonstrated by the
reference PoC (`Pwned-test/cve-2026-114938-java17-PoC`) through the **two-argument**
`decode(byte[], byte[])` overload with an oversized destination array (129-byte trigger,
spill observed at `[98..160)`).

This PoC's derivative recipe **never uses the two-argument API as the weapon**. The only
firing call is the **single-argument `decode(byte[])`** — the entry point real applications
use (HTTP Basic headers, tokens, upload fields) — executed **twice in a row**; combined
with humongous hole geometry (region alignment + tuned trigger length), it upgrades the
community-known "100k-cycle heap-layout lottery" into a **deterministic hit**:

| Aspect | Reference PoC | This derivative |
|---|---|---|
| Firing API | two-arg `decode([B[B)I` | **single-arg `decode([B)[B` ×2** |
| Observation surface | app-provided oversized dst guard buffer | humongous hole layout + sentinel row length fields |
| Hit rate | one-shot demonstration | **deterministic hit within ≤2 shots (measured 5/5: 3 clean-layout runs + 2 release re-verifications)** |
| Outcome | role-bit flip demo | **victim server JVM process death (SIGSEGV + hs_err)** |
| Delivery | single-JVM self-test | **pure-Java Client → Server network topology** |

**Novelty check (2026-11-18)**: Calif's disclosure and public coverage (Upwind, Endor Labs,
Equixly, Qualys, Check Point, Broadcom, FreeBuf) describe crashes and product-specific
heap-layout RCE claims (Keycloak/Jira/Jenkins etc.). **No public record of a
"single-arg decode ×2 + humongous deterministic DoS" recipe was found.** Based on this
non-exhaustive search, the derivative is recorded as "not publicly published".

---

## 2. Vulnerability mechanics (and how the recipe connects)

Trigger shape: `encodedLen = 64k+1..3` with a trailing `=`. The C2-compiled Base64 decode
intrinsic (AVX-512 VBMI path) underflows the output length in the tail fixup,
`bzhiq(-1,-1)` yields an all-ones mask, and `evmovdqub` performs a fixed **64-byte
store** at `[spillStart, spillStart+64)` where `spillStart = (len-1)/4*3`. The
`IllegalArgumentException` is thrown only *after* the write — corruption first,
rejection second.

Single-argument `decode(byte[])` allocates the dst at exactly the logical output length,
so the 62-byte spill lands directly on **adjacent heap objects**. In a plain TLAB
scenario the spill hits free space and is absorbed (previous experiments: 50k cycles,
zero contamination) — which is why the reference PoC needs the two-argument oversized dst.

**This derivative's answer: do not change the write; change the geometry of where it lands.**

---

## 3. Deterministic geometry (Dual-Decode + Humongous), regionSize = 1MB

With `-XX:G1HeapRegionSize=1m` the humongous threshold is 512KB, so dst takes the
region-aligned humongous allocation path — **no TLAB randomness; the landing zone is
fully determined by the length**.

Pick `len = 64k+1` such that dst satisfies both:

```
obj  = dst + 16      ≤ N × regionSize      (fits into N regions)
spillStart + 64      > N × regionSize      (the 64B store crosses the region end)
```

Solution measured (N=2, regionSize=1048576):

| Parameter | Value |
|---|---|
| k | 43690 |
| **len (trigger length)** | **2,796,161 = 64×43690+1** |
| dst = logicalOut(len) | 2,097,122 B |
| obj = dst + 16 header | 2,097,138 B ≤ 2,097,152 (2 regions) ✅ |
| spillStart | 2,097,120 |
| **deterministic crossing** | **2,097,120+64 − 2,097,152 = 32 B** |

The trigger dst exactly fills a 2-region hole, and the last **32 bytes** of the 64-byte
vector store necessarily cross into the next region — the object placed right after the hole.

**Hole layout** (built in `arm()`; a full GC is NEVER performed — compaction would
rearrange the layout and destroy the holes):

```
[recvBuf 2 regions (pinned live)][row0 1 region][filler0 2 regions][row1][filler1]...×100
```

Sentinel rows are `byte[R-16]` (exactly 1 region each, zero-filled). Releasing all
fillers and forcing a young GC turns each filler into a 2-region hole with a sentinel
row immediately after it — no matter which hole the trigger dst fills, the 32-byte
crossing always lands on a sentinel header.

GC pressure must also be **non-humongous** (64KB chunks < 512KB threshold) — a measured
pitfall: pressuring with dead 4MB humongous arrays leaves unpaired holes outside the
layout; a trigger dst landing in one of those corrupts an unrelated dead object's
header instead (run #1: GC thread SIGSEGV reading `0x...699aa671`, the address itself
carrying the 0x9A9A699A fixed-value signature — the DoS still succeeded, but the
evidence chain was unclean).

---

## 4. Topology and code structure

```
Pure JDK, no third-party dependencies
┌────────────────────┐   PING         ┌──────────────────────────────────┐
│   J4ShellClient    │ ─────────────► │   J4ShellServer (victim JVM)      │
│   (attacker)       │   PONG(env)    │  Zulu 17.0.20+8 unpatched         │
│                    │                │  -Xmx768m -XX:G1HeapRegionSize=1m │
│   build trigger    │   FIRE len     │  -Xbatch -XX:ErrorFile=hs_err     │
│   2,796,161 B      │ ─────────────► │                                   │
│   'A'×2796160+'='  │   full TCP     │  arm(): layer-1 self-check (129,  │
│                    │                │   bounded) + recvBuf + grid + fill│
│   read verdict     │   HIT / EOF    │  fire(): ★ single-arg decode ×2   │
│   poll port        │ ◄───────────── │   shot1 → scan → (re-warm)        │
│                    │   port dead    │   shot2 → scan → HIT reply        │
└────────────────────┘                │   → forced OOB read → SIGSEGV     │
                                      └──────────────────────────────────┘
```

| File | Role |
|---|---|
| `src/com/aweimc/j4shell/Payload.java` | trigger geometry math (len / logicalOut / spill range / crossing) |
| `src/com/aweimc/j4shell/DualDecodeVictim.java` | victim core: arm (self-check + layout + C2 fill) / fire (single-arg decode ×2) / forced crash |
| `src/com/aweimc/j4shell/J4ShellServer.java` | TCP server (binds 127.0.0.1 by default); PING/FIRE/SHUT wire protocol |
| `src/com/aweimc/j4shell/J4ShellClient.java` | attack client: delivers the 2.7MB trigger, reads verdict, polls port, renders verdict |
| `src/com/aweimc/j4shell/Main.java` | entry point + standalone bounded `probe` |
| `build.sh` / `build.bat` | compile |
| `run-server.sh|.bat` / `run-server-safe.sh|.bat` / `run-client.sh|.bat` | one-shot scripts (path-independent) |

---

## 5. Reproduction steps

Windows:

```bat
build.bat
run-server.bat     :: terminal A - victim (unpatched JDK 17 + AVX-512 VBMI machine)
run-client.bat     :: terminal B - attacker
```

Linux / macOS (equivalent path-independent sh scripts):

```bash
./build.sh
./run-server.sh    # terminal A
./run-client.sh    # terminal B
```

Negative control (must survive):

```bash
./run-server-safe.sh      # adds -XX:-UseBASE64Intrinsics
./run-client.sh           # expect SURVIVED, client exit code 2
```

Standalone environment check (no network):

```bash
java -cp out com.aweimc.j4shell.Main probe --len 129
# expect: spill=[98..160) oob=62B  REPRODUCED
```

---

## 6. Measured results (all local, 2026-11-18)

### 6.1 Layer-1 self-check (bounded probe, causal prerequisite)

```
java = 17.0.20
len=129 logicalOut=98 spill=[98..160) oob=62B
REPRODUCED - runtime has the layer-1 out-of-bounds write
```

Numbers match the reference PoC exactly (62 bytes, coordinates `[98..160)`).

> **Attribution**: the layer-1 observation technique — two-argument
> `decode(byte[], byte[])` with an oversized destination buffer to expose the
> fixed-value spill — is **adapted from the reference PoC**
> ([Pwned-test/cve-2026-114938-java17-PoC](https://github.com/Pwned-test/cve-2026-114938-java17-PoC)),
> with a bounded 8KB guard buffer added so the probe never touches the live heap.
> It is used for environment detection only; the attack path is single-arg only.

### 6.2 Positive: Client → Server deterministic DoS

| Run | Server | Client verdict | Result | Timing |
|---|---|---|---|---|
| run2 (first clean layout) | Zulu 17.0.20+8 | `HIT shot=2 row=2 len=1048560→-1503028570 (0xA6699AA6)` | **TARGET DOWN**, port verified closed | fire 584 ms |
| run3 | same | `HIT shot=1 row=1 ... (0xA6699AA6)` | **TARGET DOWN** | fire 219 ms |
| run4 | same | `HIT shot=1 row=1 ... (0xA6699AA6)` | **TARGET DOWN** | fire 138 ms |
| Release E2E (`run-*.bat`) | same | `HIT shot=1 row=1 ... (0xA6699AA6)` | **TARGET DOWN** | fire 102 ms |

**5/5 deterministic hits within ≤2 shots: 3 clean-layout runs + 2 release
re-verifications (`run-*.sh` above, `run-*.bat` below), victim JVM dead every time.**

Final release-recipe verification (`com.aweimc.j4shell` package, run-server.sh + run-client.sh):
`HIT shot=1 row=1 len=1048560→-1503028570 (0xA6699AA6)` → **TARGET DOWN**, fire 82 ms;
hs_err forensics show:
`Problematic frame: j com.aweimc.j4shell.DualDecodeVictim.forceCrash(II)V+68`.
Raw run logs are generated locally under `logs/` (gitignored); results are summarized here.

The corrupted value `-1503028570 = 0xA6699AA6` is this build's lookup-table
residual pattern — byte sequence **A6 69 9A A6** on this machine (not a clean
0x9A/0x69 alternation; other builds differ, e.g. Temurin 21.0.13 reportedly
shows 9A 69 …). What matters is the **invariance across inputs**: the pattern
is identical in every measured run regardless of payload tail shape —
deterministic fixed-value write proven, not a random crash.

### 6.3 Crash forensics (hs_err)

Recorded hs_err excerpt:

```
EXCEPTION_ACCESS_VIOLATION (0xc0000005)
Problematic frame:
j  com.aweimc.j4shell.DualDecodeVictim.forceCrash(II)V+68
```

The crash lands exactly on the **deliberately executed out-of-bounds read** after the
sentinel length field was corrupted — evidence chain: **network payload → intrinsic
OOB write → length corruption (HIT reply delivered to client first) → forced OOB read
→ SIGSEGV → hs_err written → port closed (independently verified by client)**.

Note: the very first experiment (layout polluted by humongous noise) also killed the
server with a single network payload, but the crash surfaced in the GC thread
(the eager-reclaim dereference faulted on a dead object header whose bytes
embed the 0x9A9A699A signature) — side evidence that even
without a tuned hole layout, heap corruption under this humongous geometry is
sufficient to kill the JVM.

### 6.4 Controls (negative + fixed build)

| Control | Server config | Self-check | Result |
|---|---|---|---|
| A | `-XX:-UseBASE64Intrinsics` (Zulu 17.0.20+8) | `spill=none (oob=0B)` | `SURVIVED shots=2`, server alive, client exit code 2 ✅ |
| B | **fixed build Zulu 17.0.21.1+2** | `spill=none (oob=0B)`, `probe=none` | `SURVIVED shots=2`, server alive, graceful shutdown ✅ |

Control B details (Zulu 17.70+201-CA, build 17.0.21.1+2-LTS):

```
java = 17.0.21.1
len=129 logicalOut=98 spill=[-1..0) oob=0B
none - runtime patched / intrinsics off / no AVX-512 VBMI
```

Layer-1 spill gone **and** the full network E2E leaves the patched server alive —
the patch is verified end-to-end, not just at the probe level. Client independently
warned `server layer-1 self-check shows NO spill - runtime patched or intrinsics off;
attack will not work` before firing.
Same trigger, same geometry, same flow — only the intrinsic disabled, and nothing hits.
Causality between the OOB write and the JVM death is closed.

---

## 7. Role of the "two decodes" in the measurements

**Firing API confirmation (source level)**: the only decode call on the firing path is
`dec.decode(src)` inside `DualDecodeVictim.fire()` — single-argument
`decode(byte[])` (`DualDecodeVictim.java:131`). The only two-argument
`decode(src, big)` in the project is the layer-1 probe's **bounded measurement**
(spill stays inside an 8KB guard buffer; environment detection only) — it never
participates in the attack. The C2 fill (warmDecode) also uses only single-arg decode.

Structural significance of the recipe: the intrinsic fires only once per compiled
version (it deoptimizes via uncommon trap after triggering), so **a re-warm is mandatory
before a second shot**. This PoC turns "fill → fire → re-fill → re-fire" into a fixed
sequence inside `fire()` — the correct way to chain two decodes, beyond the
reference PoC's single-shot demo.

Measured: run2 hit on shot 2. **Hypothesis (not yet instrumented/verified)**:
after dst1 died, eager reclaim returned its regions to the free list and the
re-warm provided a second deterministic opportunity — this explains the
shot-2 hit but has not been confirmed with heap instrumentation. run3, run4
and both release re-verifications hit on shot 1.

---

## 8. Scope and limitations (honest statement)

**Prerequisites** (this PoC's lab conditions):

1. Unpatched Java 17 line — **all builds ≤ 17.0.21** (independent matrix test:
   Temurin 17.0.21+9 still reproduces, `changedBeyondLogical=62`; plain 17.0.21
   has no "fixed" state, the fixed build is **17.0.21.1**. The *lower* bound of
   the affected range is per the advisory, not independently verified) /
   pre-fix Java 21 line (≤ 21.0.13, fixed 21.0.13.1), x86-64 + AVX-512 VBMI;
2. Victim decode point: **single-arg `decode(byte[])` on a hot (C2-compiled) path with
   attacker-controlled input that can be scaled to ~2.8MB**;
3. The deterministic hit requires the humongous hole layout, actively constructed by the
   victim in `arm()`. On an **unconditioned real application**, every humongous dst is
   still region-aligned and the spill still structurally crosses the region boundary by
   32 bytes — but *what* it hits (live header vs free region) is probabilistic. The
   recipe upgrades the odds from a "100k-cycle lottery" to "every shot deterministically
   crosses a 32-byte high-value boundary"; quantifying multi-shot rates on unconditioned
   apps is future work.

**GC scope**: the vulnerability itself is collector-independent — the intrinsic
out-of-bounds write lives in JIT-generated code and reproduces under any GC
(the layer-1 spill probe passed regardless). The **deterministic recipe,
however, is G1-specific**. It depends on three G1 behaviors: (1) **humongous
objects** (≥ 50% region size) allocated into contiguous region-aligned
addresses; (2) **eager reclaim** of dead humongous objects at young GC
(`G1EagerReclaimHumongousObjects`, default on), which leaves predictable
holes the next humongous allocation fills in FIFO address order; (3) the
region-granular arithmetic in §3 (dst exactly 2 regions with a 32-byte tail
→ guaranteed boundary crossing). Under Serial/Parallel GC there is no
humongous concept and no region-aligned placement, so the "every shot
deterministically crosses 32 bytes" property evaporates — the spill lands
wherever the allocator happened to place dst, i.e. fully probabilistic.
ZGC/Shenandoah are region-based but with different allocation/reclaim
semantics; the §3 geometry was not designed for them. `-XX:G1HeapRegionSize`
is itself a G1-only flag. On unconditioned **G1** applications the recipe's
structural claim still holds (humongous dst is always region-aligned); on
non-G1 collectors this derivative offers no determinism advantage over the
baseline lottery.

**Structural conclusions from prior work remain**: vanilla/modded Minecraft has no
reachable decode surface (cold JIT, exception absorption, zero two-arg call sites,
malformed packets rejected by Netty) — this recipe does not apply to real MC
clients/servers. The victim here is a **purpose-built lab service** validating the
recipe itself.

**Mitigation**: upgrade to 17.0.21.1+ / 21.0.13.1+ / 25.0.5.1+ (fixed builds carry the
`.1` suffix). Interim: `-XX:-UseBASE64Intrinsics` (all architectures) or `-XX:UseAVX=2`
(x86-64 only).

---

## 9. Ethics

This PoC and all code are for **vulnerability research on local/authorized environments
only**. The server binds `127.0.0.1` by default; no third-party hosts, products, or real
users were contacted during testing. The report and code do not constitute exploit
capability against any real product. If disclosing this derivative, follow responsible
disclosure (Oracle/OpenJDK and the original Calif coordination channels first).
