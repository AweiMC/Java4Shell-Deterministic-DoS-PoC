# J4Shell-Deterministic-DoS PoC 报告 —— CVE-2026-114938 衍生：单参双 Decode + Humongous 确定性 DoS（Client → Server）

> **配方名 J4Shell-Deterministic-DoS（技术描述：dual-decode + humongous hole geometry）**。PoC 代码包：`com.aweimc.j4shell`，
> 配套仓库 <https://github.com/AweiMC/Java4Shell-Deterministic-DoS-PoC>。
> 测试环境：Windows x86-64，Zulu JDK **17.0.20+8**（未修复，`UseBASE64Intrinsics=true`，`UseAVX=3`，AVX-512 VBMI 激活），G1 GC。
> 所有测试均在自有本地回环（127.0.0.1）环境完成，见第 9 节伦理声明。

---

## 1. 衍生声明（本 PoC 主张的新点）

Calif 于 2026-11-17 披露的 CVE-2026-114938（Java4Shell），其官方参考 PoC
（`Pwned-test/cve-2026-114938-java17-PoC`）观察越界写的路径是**双参**
`decode(byte[], byte[])` + 超大目标数组（129 字节触发串写入 `[98..160)`）。

本 PoC 的衍生配方：**全程不使用双参 API**，唯一的"射击"解码调用是真实应用里
最普遍的**单参 `decode(byte[])`，连续执行两次**；配合 humongous 洞几何
（region 对齐 + 定制触发长度），把社区已知的"10 万周期堆布局抽奖"
升级为**确定性命中**：

| 对比项 | 官方参考 PoC | 本衍生（Deterministic-DoS 配方） |
|---|---|---|
| 射击 API | 双参 `decode([B[B)I` | **单参 `decode([B)[B` ×2** |
| 观察面 | 应用自留的超大 dst 缓冲带 | humongous 洞布局 + 哨兵行 length 字段 |
| 命中性 | 演示一次写 | **第 1~2 发确定性命中（实测 5/5：3 次干净布局 + 2 次发布版复核）** |
| 结果 | 角色 bit 翻转演示 | **受害服务端 JVM 进程死亡（SIGSEGV + hs_err）** |
| 交付形态 | 单机自测 | **纯 Java Client → Server 网络攻击拓扑** |

**查新（2026-11-18）**：检索 Calif 披露、Upwind、Endor Labs、Equixly、Qualys、
Check Point、Broadcom、FreeBuf 等公开材料，覆盖内容为"崩溃 + 特定产品
（Keycloak/Jira/Jenkins 等）堆布局 RCE 声明"，**未发现"单参 decode ×2 +
humongous 确定性 DoS"配方的公开记录**。基于本轮检索未穷尽所有渠道，
该衍生点暂按"未见于社区发布"记录。

---

## 2. 漏洞机制回顾（与衍生配方的衔接）

触发形状：`encodedLen = 64k+1..3` 且末字节 `=`。C2 编译后的 Base64 decode
intrinsic（AVX-512 VBMI 路径）在尾部 fixup 中输出长度下溢为负，
`bzhiq(-1,-1)` 掩码全 1，`evmovdovu` 固定按 **64 字节定值写**
`[spillStart, spillStart+64)`，`spillStart = (len-1)/4*3`。
写完后 `IllegalArgumentException` 才抛出 —— **先写后拒，破坏已发生**。

单参 `decode(byte[])` 内部按精确逻辑输出长度分配 dst，因此 62 字节越界
直接落在**堆上相邻对象**。纯 TLAB 场景下越界区是空闲空间，破坏被吸收
（此前实验 5 万周期零污染）；这就是官方 PoC 要用双参超大 dst 才能观察的原因。

**本衍生的解法：不改变写入行为，改变写入落点的几何。**

---

## 3. 确定性几何推导（Dual-Decode + Humongous）（regionSize = 1MB）

`-XX:G1HeapRegionSize=1m` 下 humongous 阈值为 512KB，dst 走 region 对齐的
humongous 分配 —— **无 TLAB 随机性，落点由长度唯一决定**。

选 `len = 64k+1` 使 dst 满足两个条件：

```
obj  = dst + 16      ≤ N × regionSize      （能装进 N 个 region）
spillStart + 64      > N × regionSize      （64B 定值写跨过 region 末尾）
```

实测解（N=2，regionSize=1048576）：

| 参数 | 值 |
|---|---|
| k | 43690 |
| **len（触发串长度）** | **2,796,161 = 64×43690+1** |
| dst = logicalOut(len) | 2,097,122 B |
| obj = dst + 16 头 | 2,097,138 B ≤ 2,097,152（2 region）✅ |
| spillStart | 2,097,120 |
| **确定性跨界量 crossing** | **2,097,120+64 − 2,097,152 = 32 B** |

即：触发 dst 恰好填满一个 2-region 的洞，64 字节向量写的**尾部 32 字节
必然**跨过 region 边界，打中洞后第一个对象。

**洞布局**（arm 阶段构造，全程绝不做 full GC —— compaction 会重排布局毁洞）：

```
[recvBuf 2 regions（常驻）][row0 1 region][filler0 2 regions][row1][filler1]...×100
```

哨兵行 `byte[R-16]` 每个正好占 1 region、全 0；释放全部 filler → young GC
eager-reclaim（不做 compaction，相邻性保留）→ 每个洞恰好 2 region 且**洞后
必是哨兵行** → 无论 dst 填进哪个洞，跨界 32B 必打中某个哨兵行的对象头。

GC 施压也必须用**非 humongous** 小块（64KB < 512KB 阈值）—— 这是实测踩过
的坑：用 4MB humongous 死数组施压会在布局外留下无法配对的洞，触发 dst
落进那种洞后越界写打中的是其他死对象头（第 1 轮实验：GC 线程在
`0x...699aa671` 处 SIGSEGV，地址直接带着 0x9A9A699A 定值签名 —— DoS 依然
成立，但证据链不干净）。

---

## 4. 网络拓扑与代码结构

```
纯 Java，无第三方依赖（JDK 17 直跑）
┌────────────────────┐   PING         ┌──────────────────────────────┐
│   J4ShellClient        │ ─────────────► │   J4ShellServer（受害 JVM）        │
│   (攻击端)          │   PONG(环境)    │  Zulu 17.0.20+8 未修复        │
│                    │                │  -Xmx768m -G1HeapRegionSize=1m │
│   构造触发串         │   FIRE len     │  -Xbatch -ErrorFile=hs_err    │
│   2,796,161 B      │ ─────────────► │                               │
│   'A'×2796160+'='  │   完整走 TCP    │  arm(): 层一自检(129,有界)      │
│                    │                │   + recvBuf + 网格 + 装填 + 成洞 │
│   读回包            │   HIT / EOF    │  fire(): ★ 单参 decode ×2      │
│   轮询端口          │ ◄───────────── │   shot1 → 扫描 → (重装填)       │
│                    │   端口死亡      │   shot2 → 扫描 → HIT 回包       │
└────────────────────┘                │   → 强制越界读 → SIGSEGV+hs_err │
                                      └──────────────────────────────┘
```

| 文件 | 职责 |
|---|---|
| `src/com/aweimc/j4shell/Payload.java` | 触发几何公式（len/logicalOut/spill 区间/跨界推导） |
| `src/com/aweimc/j4shell/DualDecodeVictim.java` | 受害核心：arm（自检+布局+装填）/ fire（单参 decode ×2）/ 强制崩溃 |
| `src/com/aweimc/j4shell/J4ShellServer.java` | TCP 服务端（默认只绑 127.0.0.1），PING/FIRE/SHUT 线协议 |
| `src/com/aweimc/j4shell/J4ShellClient.java` | 攻击客户端：投递 2.7MB 触发串、读回包、轮询端口、裁决 |
| `src/com/aweimc/j4shell/Main.java` | 入口 + 独立 `probe` 有界自检 |
| `build.bat` / `run-server.bat` / `run-server-safe.bat` / `run-client.bat` | 一键脚本 |

---

## 5. 复现步骤

```bat
cd /d D:\AIAGENT\CVE_TEST\J4Shell_DoS
build.bat

:: 终端 A —— 受害服务端（未修复 JDK 17 + AVX-512 VBMI 机器）
run-server.bat

:: 终端 B —— 攻击客户端
run-client.bat
```

Linux / macOS（等价 sh 脚本，路径无关）：

```bash
./build.sh
./run-server.sh          # 终端 A
./run-client.sh          # 终端 B
```

负对照（应存活）：

```bat
:: 终端 A 换用
run-server-safe.bat        :: = 追加 -XX:-UseBASE64Intrinsics
:: 终端 B 不变 —— 预期 SURVIVED，客户端退出码 2，服务端存活
```

独立环境自检（无需网络）：

```bat
java -cp out com.aweimc.j4shell.Main probe --len 129
:: 预期：spill=[98..160) oob=62B, REPRODUCED
```

---

## 6. 实测结果（全部本机实测，2026-11-18）

### 6.1 层一自检（有界探测，因果前提）

```
java = 17.0.20
len=129 logicalOut=98 spill=[98..160) oob=62B
REPRODUCED — runtime has the layer-1 out-of-bounds write
```

与官方 PoC 数字完全吻合（62 字节、坐标 `[98..160)`）。

### 6.2 正向：Client → Server 确定性 DoS

| 轮次 | 服务端 | 客户端回包 | 裁决 | 用时 |
|---|---|---|---|---|
| run2（干净布局首测） | Zulu 17.0.20+8 | `HIT shot=2 row=2 len=1048560→-1503028570 (0xA6699AA6)` | **TARGET DOWN**，端口关闭实证 | fire 584ms / 全程 1.09s |
| run3 | 同上 | `HIT shot=1 row=1 len=1048560→-1503028570 (0xA6699AA6)` | **TARGET DOWN** | fire 219ms |
| run4 | 同上 | `HIT shot=1 row=1 len=1048560→-1503028570 (0xA6699AA6)` | **TARGET DOWN** | fire 138ms |
| 发布版 E2E（bat 脚本，已存档） | 同上 | `HIT shot=1 row=1 len=1048560→-1503028570 (0xA6699AA6)` | **TARGET DOWN** | fire 102ms（`evidence/e2e-bat-client-output.txt`） |

**5/5 确定性命中（≤2 发内）：3 次干净布局 + 2 次发布版复核（上表 bat 一行 +
下方 sh 脚本复核），受害 JVM 每次死亡。**

一键脚本端到端验证（最终发布版，`com.aweimc.j4shell` 包，run-server.sh + run-client.sh）：
`HIT shot=1 row=1 len=1048560→-1503028570 (0xA6699AA6)` → **TARGET DOWN**，fire 82ms，
取证 `evidence/hs_err_victim-SIGSEGV.log`：`Problematic frame: j com.aweimc.j4shell.DualDecodeVictim.forceCrash(II)V+68`。
证据文件归档在 `evidence/`（probe 输出、E2E 客户端/服务端实录、hs_err、负对照实录）。

污染值 `-1503028570 = 0xA6699AA6` 是该 build 的查找表残值图样——本机字节序为
**A6 69 9A A6**（并非干净的 0x9A/0x69 交替；跨 build 不同，如 Temurin 21.0.13
据称呈 9A 69 …）。真正要证明的是**跨输入不变性**：该图样在全部实测轮次中
与载荷尾部形态无关、完全一致 —— 定值写实锤，非随机崩溃。

### 6.3 崩溃取证（hs_err）

最终发布版取证 `evidence/hs_err_victim-SIGSEGV.log`：

```
EXCEPTION_ACCESS_VIOLATION (0xc0000005)
Problematic frame:
j  com.aweimc.j4shell.DualDecodeVictim.forceCrash(II)V+68
```

崩溃精确落在哨兵行 length 字段被定值污染后**主动执行的越界读**上 ——
证据链：**网络载荷 → intrinsic 越界写 → length 字段污染（HIT 回包先送达
客户端）→ 强制越界读 → SIGSEGV → hs_err 落盘 → 端口关闭（客户端独立验证）**。

另：初版（布局含 humongous 噪声）第 1 轮同样一发网络载荷打死服务端，但
崩溃发生在 GC 线程（eager-reclaim 读到被污染的死对象头，故障地址
`0x000001bd699aa671` 内嵌 0x9A9A699A 签名）—— 侧面证明即使不配洞，
该配方在 humongous 几何下的堆破坏也足以击杀 JVM。

### 6.4 对照组（负对照 + 修复版）

| 对照 | 服务端配置 | 自检 | 结果 |
|---|---|---|---|
| A | `-XX:-UseBASE64Intrinsics`（Zulu 17.0.20+8） | `spill=none (oob=0B)` | `SURVIVED shots=2`，服务端存活，客户端退出码 2 ✅ |
| B | **修复版 Zulu 17.0.21.1+2** | `spill=none (oob=0B)`、`probe=none` | `SURVIVED shots=2`，服务端存活，优雅退出 ✅ |

对照 B 细节（`evidence/fixed-jdk-probe-output.txt`、
`evidence/fixed-jdk-e2e-server.txt`、`evidence/fixed-jdk-e2e-client.txt`），
Zulu 17.70+201-CA (build 17.0.21.1+2-LTS)：

```
java = 17.0.21.1
len=129 logicalOut=98 spill=[-1..0) oob=0B
none - runtime patched / intrinsics off / no AVX-512 VBMI
```

层一溢出消失，且完整网络 E2E 打完后修复版服务端仍然存活——
补丁有效性从 probe 到 E2E 两层闭环验证。客户端开火前独立告警
`server layer-1 self-check shows NO spill - runtime patched or intrinsics off`。

同一触发串、同一几何、同一流程，仅关 intrinsic 即完全不命中 —— 越界写
与 JVM 死亡的因果关系闭环。

---

## 7. "两次 Decode" 在本轮实测中的角色

**触发 API 确认（源码级）**：射击路径唯一的解码调用是 `DualDecodeVictim.fire()`
中的 `dec.decode(src)` —— 单参 `decode(byte[])`（`DualDecodeVictim.java:131`）。
全项目仅有的两参 `decode(src, big)` 出现在层一探测器的**有界测量**中
（溢出留在 8KB 缓冲带内，仅作环境检测），不参与攻击。装填（warmDecode）
同样只用单参 decode。

> **出处归属**：双参 `decode(byte[], byte[])` + 超大目标数组来观察越界写的
> 技术**参考自官方 PoC**
> （[Pwned-test/cve-2026-114938-java17-PoC](https://github.com/Pwned-test/cve-2026-114938-java17-PoC)），
> 本项目在其基础上加了 8KB 有界缓冲带使探测不伤堆。该双参用法仅用于
> 环境检测；攻击路径全程单参。

- run2：shot 1 未命中（dst 落点受初版布局残差影响），**shot 2 命中** ——
  【假说，尚未插桩验证】补射机制（dst1 死亡 → eager-reclaim 重新成洞 →
  重装填 C2）提供了第二次确定性机会，该解释成立与否需堆插桩证实；
- run3/run4：shot 1 首发即命中。

单参双 Decode 配方本身还有一层结构意义：intrinsic 每编译周期只有一发
（触发后 uncommon trap 反优化），**必须重新装填才能再射** —— 本配方把
"装填→射击→再装填→再射击"做成 fire() 内的固定序列，这就是"连续两次
Decode"的正确打开方式，也是官方单发演示之外的工程化补全。

---

## 8. 适用面与局限（如实陈述）

**成立的前提**（本 PoC 的实验条件）：

1. 未修复的 Java 17 线——**全部 ≤ 17.0.21 的构建**（独立矩阵实测：
   Temurin 17.0.21+9 仍可复现，`changedBeyondLogical=62`；plain 17.0.21 不存在
   "已修复"状态，修复版是 **17.0.21.1**。区间*下限*据公告声称、未经独立实测）/
   Java 21 修复前线（≤ 21.0.13，修复版 21.0.13.1），x86-64 + AVX-512 VBMI；
2. 受害 JVM 的解码点：**单参 `decode(byte[])` 在热路径（C2 编译）上执行
   攻击者可控、长度可放大到 ~2.8MB 的输入**；
3. 确定性命中依赖 humongous 洞布局 —— 本 PoC 在受害端 arm 阶段主动构造。
   在**未做布局条件化的真实应用**中，dst 每次分配仍然 region 对齐、
   越界写仍然结构性跨界 32B（这部分是确定性的），但跨界后打中"活对象头"
   还是空闲 region 是概率性的 —— 本配方把命中概率从"10 万周期抽奖"
   提升为"每发必跨界的 32B 高价值写"，多发改决率的量化留待后续工作。

**GC 适用范围**：漏洞本身与 GC 无关——intrinsic 越界写存在于 JIT 生成代码中，
任何收集器下都能复现（层一溢出探测不受 GC 影响）。但**确定性配方仅限 G1**，
依赖三项 G1 行为：(1) **humongous 对象**（≥ region 一半大小）分配在连续、
region 对齐的地址上；(2) young GC 时的 **eager reclaim**（
`G1EagerReclaimHumongousObjects`，默认开）会把死掉的 humongous 对象回收成
可预测的"洞"，下一个 humongous 分配按地址顺序填入；(3) §3 的 region 粒度
算术（dst 恰好 2 region + 尾差 32B → 必然跨界）。Serial/Parallel GC 没有
humongous 概念、也没有 region 对齐分配，"每发确定性跨界 32B"的性质消失，
溢出落点完全取决于分配器恰好把 dst 放哪——退化为纯概率事件。ZGC/Shenandoah
虽是 region 式但分配/回收语义不同，§3 的几何未针对它们设计；
`-XX:G1HeapRegionSize` 本身就是 G1 专属参数。对未条件化的 **G1** 应用，
本配方的结构性结论仍然成立（humongous dst 恒 region 对齐）；在非 G1
收集器上，本衍生相对基线抽奖没有任何确定性优势。

**不改变已知的结构性结论**：Minecraft 原版/模组包线协议无可达解码面
（此前实测：冷 JIT、异常吸收、双参 0 处、畸形包被 Netty 拒绝四层吸收），
本配方不适用于真实 MC 客户端/服务端 —— 本 PoC 的受害端是**编排好的
实验性服务**，用于验证配方本身。

**缓解**：升级 17.0.21.1+ / 21.0.13.1+ / 25.0.5.1+（版本号带 `.1` 后缀才算修复）；
临时：`-XX:-UseBASE64Intrinsics`（跨架构）或 `-XX:UseAVX=2`（仅 x86-64）。

---

## 9. 伦理声明

本 PoC 及全部代码**仅用于漏洞研究与自有/授权测试环境**。服务端默认只绑定
`127.0.0.1`；测试全程未接触任何第三方主机、产品或真实用户。报告与代码
不构成对任何真实产品的利用能力；如需披露衍生配方，建议遵循负责任披露
流程（先报 Oracle/OpenJDK 与 Calif 原始协调渠道）。
