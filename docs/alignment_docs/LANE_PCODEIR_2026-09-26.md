# LANE PCODEIR — P-code→IR 现有工作精读（Ghidrall 论文 + Patchestry + Pcode2C）

> 日期 2026-09-26 | 车道 PCODEIR（纯研究零 src 零 commit；网络调研+读主仓背景，报告落 /dev/shm）
> 前置输入：LANE_RELIT_2026-09-26.md（杠杆地图）、.slim/deepwork/stage-bisect-e2e.md 尾部（IR 感知层讨论背景：我们的 SSA+恢复层管线，增强轨=IR 收敛纲领，MLIR 为备选）。
> 方法：滑铁卢论文 PDF 直接下载全文精读（65 页，pdftotext 后逐段读毕）；Patchestry `git clone --depth 1`（HEAD 4acddb4，2026-06-07）源码精读+fixture 解剖；Pcode2C 博客全文精读。所有结论标注来源（论文章节/印刷页码、仓库文件路径、commit）。
> 诚实纪律：读不到/没读的部分如实标注（§七）；worker 无失败重试需求（三次网络抓取一次重定向后全成功）。

---

## 〇、执行摘要（TL;DR）

1. **root 的预判全部证实**：三个工作都**不做类型/结构恢复**——提升只换基座不填信息。唯一的例外是 Patchestry 的**惯用法局部尺寸推断**（memset/memcpy/recv/read/strncpy 参数位→buffer 尺寸，确定性小表，可直接偷）和 Ghidrall 的 Ghidra 伪码**表示层修复**（调用约定传播/全局合并/栈布局）。
2. **SSA 处理的决定性事实**：三个工作**无一自己重建 SSA，也无一保留 SSA**。Ghidrall/Ghidra-to-LLVM 发射全内存形态 IR（寄存器=全局变量、局部=alloca、**输出零 phi 节点**——论文全文 grep "phi" 零命中），把 SSA 构造整体甩给 LLVM mem2reg；Patchestry 在 Java 序列化器里就把 MULTIEQUAL/COPY/INDIRECT "挖矿"回命名变量（de-SSA），再走 Clang AST→CIR→LLVM。**我们已有 heritage SSA 是严格更强的位置**——可偷的不是"怎么建 SSA"而是"LLVM pass 免费菜单"作为增强轨清单。
3. **高层 pcode 切点被独立验证两次**：Ghidrall（"Decompilation Data Structures"=反编译器内部数据结构、伪 C 发射前的状态）与 Patchestry（DecompInterface simplificationStyle="decompile" + PcodeOpAST + LocalSymbolMap）选的是**同一个切点**——正是我们 printc 前的 IR 形态。root 的"我们的 printc 前的 IR 就是高层 pcode 形态"判断获得两个独立先例背书。
4. **MLIR 备选路径收到高价值负结果**：任务书假设 Patchestry="P-code MLIR 方言+翻译，LLVM 18 集成"。实测：其 `pc` MLIR 方言是**遗迹**（~250 行 .td，仅被自己的注册文件引用，不在生产路径），生产路径=Clang AST→**ClangIR(CIR)**→LLVM（vendored LLVM **22.1.4** fork 分支 `patchir-llvmorg-22.1.4`，非 18）。该领域经费最充足的团队（Trail of Bits+ARPA-H）试过 pcode MLIR 方言后放弃、改押 C 语义基座——**我们的"自有 SSA 上做 IR 收敛层（主）+MLIR 备选"排序被验证为正确**，且 MLIR 备选应降级为"文本导出选项"（直接发 .ll 更便宜更标准）。
5. **首推三件可偷**（§四）：① Patchestry JSON schema 作为我们高层 pcode 的序列化契约（switch 三路恢复元数据/taken-not_taken/DECLARE_* 伪指令族）；② Ghidrall 单 struct 栈策略（86.08% 实测最优的栈/帧对象表示，GEP 重建层的参照形态）；③ Pcode2C 式逐字 C 发射作为**确定性行为差分 oracle sidecar**（RELIT 的 Decompile-Diverge 行为门禁的非 LLM 版本，我们 emitter 基建直接可挂）。

---

## 一、逐工作档案

### A. 滑铁卢论文（一手：PDF 全文，uwspace bitstream c90b61a3，文件名 Toor_Tejvinder.pdf）

**基本信息**：Tejvinder Singh Toor, "Decompilation of Binaries into LLVM IR for Automated Analysis", MASc thesis, University of Waterloo ECE, 2022。导师 Arie Gurfinkel（SeaHorn 作者）；读者 Mahesh Tripunitara / Werner Dietl。65 页。两个工具：Ghidra-to-LLVM（低 P-code 反汇编级 lifter，PoC 级）+ Ghidrall（反编译数据结构 lifter，主工作量）。评估：Ghidrall 对 McSema（DynInst 前端）功能性保持 **86.08% vs 71.13%**（+15pp），平均输出 LOC 61.1 vs 3417.6（97 个 Pharos 测试程序×O0/O1/O2×goal/nongoal）[论文章 5.2，印 pp.36-38]。

**A1. Ghidra-to-LLVM（低 P-code 路线）** [论文章 3]

- 管线：Ghidra headless 插件 → 中间 XML（函数签名+逐指令 pcode+寄存器/内存引用表）→ Python llvmlite 提升器 → .ll。
- **映射表** [表 3.3.1，印 p.18]：`COPY`→load/store 对；`LOAD/STORE`→load/store（按 varnode 尺寸定 iN）；`BRANCH/CBRANCH`→br/cond-br；`CALL`→`call void @f()` **无参数**（参数走栈！调用约定残迹全部机器仿真化）；`RETURN`→ret void；`INT_EQUAL`→icmp；`INT_ADD`→add；`BOOL_XOR`→xor i1。
- **flags 处理**：flags=寄存器空间 varnode，提升为 i1 全局变量（`@"CF" = internal global i1 0`）；寄存器=按尺寸 i8/i64 全局；内存引用=全局 [印 fig 3.3.1b]。
- **机器仿真**：每函数 1MB `alloca i8` 栈+RSP 全局；**每条汇编指令地址=一个基本块**（块内是该指令的 pcode 序列），fall-through 隐式恢复 [印 p.17]。
- **类型**：无推断。SanitizeOp 桥接尺寸/指针性差异（P-code 不区分指针/整数，LLVM 要求显式）；指针性靠"对照已知架构寄存器表"猜（RSP/RIP→i8*）[算法 5]。
- 仓库现状：toor-de-force/Ghidra-to-LLVM，**242 星/23 fork，钉死 Ghidra 9.1.1（2019），休眠**；社区 fork LukeSerne/Ghidra-to-LLVM（13 星）在做"补全缺失 pcode 算子"——证明原版算子覆盖不全 [websearch 一手 GitHub 页]。

**A2. Ghidrall（主工具：反编译数据结构路线）** [论文章 4]

- 切点：修改 Ghidra 反编译器本体，暴露"Decompilation Data Structures"——伪 C 发射前的内部状态。**论文明确没做 High P-code 层工具**："No tool was developed for High P-Code as the markers are not directly translatable to LLVM IR" [印 p.4]；High P-code 五算子表 [表 2.2.1]：MULTIEQUAL=phi、INDIRECT=隐式修改标记、PTRADD/PTRSUB/CAST。反编译数据结构="same as High P-Code but have INDIRECT operations removed"+函数参数/局部/栈信息 [§2.2.3 印 p.7]。
- rizin 驱动调用图恢复（从入口闭包+剪枝系统/插桩函数）[算法 8]。
- **四个修复级子阶段** [§4.3]：全局恢复（xpath 跨函数合并全局变量引用）；**调用约定恢复**（声明侧 arity 优先于调用点 arity，传播+修复不匹配——"declaration is typically closer to being accurate"）；**局部函数栈恢复**（三种策略，见下）；指令提升。
- **三种栈策略** [fig 4.3.1 + 表 5.2.1/5.2.2，实测 97 程序]：
  - (a) 朴素：每局部变量独立 `alloca`（Ghidra 数组裂解问题原样保留）→ 83.16%；
  - (b) **单 struct**：一个 LLVM struct（padding 填缝隙保持相对索引）+GEP 字段访问 → **86.08% 最优**；
  - (c) 字节寻址大数组：`alloca [999999 x i8]`+GEP+bitcast → 82.99%（最差，lifting 失败少但验证失败多）。
  - 关键发现：含数据结构的测试在 (a) 下全部 lifting 失败（"sequentially defined data arranged in same order"假设不成立）；(b) 的优势主要来自 lifting 失败 30→8 [印 pp.28-30, 36-37]。
- **映射表** [表 4.3.1，印 p.30]：与 Ghidra-to-LLVM 同表 + `PTRSUB A,3`→`gep`；PIECE/SUBPIECE 走特殊栈恢复；**CALL 有真参数**（调用约定恢复后）；flags 已被反编译器消化不存在。
- **SSA：零 phi**（论文全文及附录 vuln.ll 无一处 phi——所有值经全局变量/alloca/GEP-load-store 流动）；"Simplification passes are performed later on by LLVM optimization passes" [印 p.17]。
- SeaHorn 验证闭环：INT_RAND→nd()、path_goal→verifier.error() [表 5.1.2]；密码挑战自动解出非预期第二解 "enveysw" [§5.1]。
- 仓库现状：toor-de-force/Ghidrall（fork 自 rizinorg/rz-ghidra），**13 星/3 fork/6 issues，2021 年后休眠** [websearch 一手 GitHub 页]。

### B. Patchestry（一手：clone@4acddb4 源码+fixture+docs 精读）

**基本信息**：Trail of Bits（lifting-bits org）二进制**补丁**框架，ARPA-H 资助。**86 星/5 fork/25 open issues/184 closed PR**，HEAD 2026-06-07，PR #289 到 2026-09-18 仍活跃 [websearch 一手 GitHub org 页]。规模：C++ ~49,720 行（lib+include+tools）+ Java ~9,691 行 + 104 个 JSON lit fixture（含 CVE 实例：cve_2016_6563/cve_2018_18732/cwe121…）。

**真实管线** [docs/system_data_flow.md，仓库自有文档]：

```
Ghidra Java 脚本(PatchestryDecompileFunctions + PcodeSerializer 6245 行)
  → 高 P-code+类型+CFG+switch 元数据 JSON（DecompInterface, simplificationStyle="decompile"）
  → patchestry_ghidra(JSON 反序列化→内存类型化 pcode/CFG 模型)
  → patchestry_ast(pcode op→Clang 表达式; CGraph=显式 CFG; SNode=结构化控制流)
  → Clang AST 发射 → CIR(ClangIR) → LLVM IR / pretty-printed C
```

- **Ghidra 侧序列化器**（PcodeSerializer.java）：消费**反编译完成的 HighFunction**（PcodeOpAST + LocalSymbolMap + getJumpTables）[grep 亲证 :96/:1961/:6167 + PatchestryDecompileFunctions.java:324-327]。做四件超出"导出"的事：
  1. **de-SSA 挖矿**：`mineForVarNodes` 注释原文——"mining them from `MULTIEQUAL`, `COPY`, and `INDIRECT` operations, which exist to encode SSA form, as well as to represent control-flow barriers in terms of data flow dependencies" [:2681-2690]。SSA 机具在 Java 侧坍缩回命名变量。
  2. **惯用法局部尺寸推断**：`inferLocalSizesFromCalls` —— memset{0,2}/memcpy{0,1,2}/memmove/bzero/recv{1,2}/recvfrom/read{1,2}/pread/strncpy{0,1,2}/strlcpy/send{1,2}/sendto/write{1,2} 参数位→buffer 尺寸表 [:1015-1150]。**确定性、可整体搬运**。
  3. **三路 switch 恢复**：(1) JumpTable.getLabelValues() 权威 → (2) symbol/INT_EQUAL 启发 → (3) 失败则整段省略 switch_cases 让消费端兜底 [:4614-4641 注释]；输出 switch_input/switch_cases/fallback 边。
  4. **伪指令族**：P-CODE 无 ADDRESS_OF → 自加 `ADDRESS_OF` + `DECLARE_PARAMETER/DECLARE_LOCAL/DECLARE_TEMPORARY` + `LZCOUNT/TAIL_CALL` [include/patchestry/Ghidra/Pcode.def 全表+ :2670-2679 注释]。
- **JSON schema**（fixture 亲解剖，subpiece.json/buf_write.json）：顶层 {architecture, id, format, functions(按地址键), globals, types}；函数 {name, is_intrinsic, type(return/parameter_types 引用类型表), basic_blocks(键 `ram:ADDR:N:basic`), entry_block}；块 {operations(pN→op), **ordered_operations(显式序)**}；op {mnemonic, type, size, inputs:[{type, kind, operation/…}]}；**值引用=定义点 SeqNum**（`ram:0800f28a:66:1`）；kind ∈ parameter/constant/temporary/local/global/function；CALL 带 target{function 地址, is_variadic, is_noreturn}+has_return_value；CBRANCH 带 taken_block/not_taken_block；类型表 {name, size, kind=integer/undefined/composite/enum}。
- **结构化**：CGraph→SNode 后是 **goto 消不动点管线**（SNodePostPasses.cpp 7,879 行）：EliminateGotoToNextLabel/InlineResidualGotos/ConvertGotoToBreakContinue/ConvertGotoToReturn/AbsorbFallthroughIntoElse/ScopeifyIfGotos/标签复制家族（DuplicateSwitchCaseTargets 等 ~30 个 pass，每个保证"至少消除一个 goto"的终止度量）[grep 亲证 :892-:7414]。**非 Ghidra 路线也非 SAILR 路线**——经典 goto 消去学派。
- **C 清理**：ClangEmitterPostPasses.cpp 7,985 行（二元算符合并/逗号算子/守卫折叠加族）。
- **`pc` MLIR 方言 = 遗迹**：include/patchestry/Dialect/Pcode/PcodeOps.td 162 行——func/block/instruction 嵌套+reg/mem/var/const varnode op+~13 个标量算子+branch/cbranch/call/return/load/store；全 `AnySignlessInteger` 无类型安全；**无 MULTIEQUAL/INDIRECT/PTRADD/PTRSUB/CAST，缺大多数算子**；grep 亲证仅被自身三个注册文件引用，生产路径不经过它。`--emit-mlir` 实际输出=CIR 跑完 `populateCIRToLLVMPasses` 后的模块 [Codegen.cpp:152-165 亲读]；`--emit-cir`=原 CIR；`--emit-llvm`=`lowerDirectlyFromCIRToLLVMIR`。
- **Contracts 方言**：静态 MLIR 属性（contract.static），补丁/验证元数据随降级链携带，不发运行时代码 [ContractsDialect.hpp + docs/GettingStarted/patch_specifications.md]。
- **LLVM 集成**：vendored submodule 指向 fork 分支 `patchir-llvmorg-22.1.4` [vendor/llvm-project/CMakeLists.txt:17-22 亲读]——**LLVM 22.1.4 带 ClangIR**，非任务书假设的 18。
- **验证配套**：patchir-klee-verifier / patchir-seahorn-verifier 工具+KLEE libc 模型+QEMU 固件运行时验证（whole-function replacement→patcherex2 字节改写→qemu-system-arm）[test/qemu-firmware-runtime + lib/patchestry/klee]。
- **在飞演化信号**（PR 标题，2026-09）：`--emit-instructions`（逐指令 raw P-code+反汇编导出）[#289]、`feat(llm): Tier 2 structured-C loop checked by -validate-pcode`+`strip stack canary boilerplate` [#172 系]——LLM 辅助与验证回路仍是活跃方向。

### C. Pcode2C（一手：博客全文 2026-09-25 更新版 + github.com/philzook58/pcode2c）

- 定位：**低 pcode→C 的逐字翻译**，目标=把二进制语义放进现货 C 验证器（CBMC/ESBMC）做翻译验证，**明确不是反编译**（"resulting C has a direct mapping to the original assembly"）。
- 形态：**解释器特化**（Futamura 投影的pretty-print 版）：`CPUState{reg[], unique[], ram[], pc}` 字节数组；每个 pcode op=一个 helper 宏调用（`COPY(dst,8,src,8)`/`INT_LESS(reg+0x200 /*CF*/,1,...)`），varnode=数组内指针；**控制流=`for(;;) switch(state->pc)` 每指令地址一个 case**；flags=1 字节寄存器 varnode 无特判；常量=`&(int64_t){0x0L}` 复合字面量取址。
- 类型：全无（字节粒度 helper 动态尺寸）。SSA：全无（机器状态仿真）。结构恢复：全无。
- 博客明示哲学：C 作为验证 IR 的三优点（现货验证器/可直接 gcc 编译+fuzz/工程师可读）；CBMC "radically underutilized"；块级只 unroll 基本块不逐指令（对 BMC 友好）。
- 相关引用（博客 TODO 节）：niconaus/pcode-interpreter（"A Formal Semantics for P-Code"）——正式语义路线，登记不展开。

---

## 二、问题单逐项回答

### a. pcode 算子→IR 指令映射表；LOAD/STORE/分支/调用约定残迹/flags；类型怎么给？

| 维度 | Ghidra-to-LLVM（低 pcode） | Ghidrall（反编译数据结构） | Patchestry（高 pcode JSON→Clang） | Pcode2C（低 pcode→C） |
|---|---|---|---|---|
| LOAD/STORE | `load/store iN`，varnode 尺寸定 iN | 同左+GEP（PTRSUB→gep） | 机械提升为 Clang 解引用表达式；CIR 降级成 LLVM load/store/GEP | helper 函数按字节数组 memcpy 语义 |
| 分支 | 每汇编指令=1 bb；br/cond-br | 块=基本块；br/cond-br | CBRANCH 带 taken/not_taken_block；CGraph→SNode 结构化 | `switch(pc)` 逐指令 case |
| **调用约定残迹** | **不恢复**——CALL 无参数，全走栈（机器仿真） | **恢复**——声明侧 arity 传播到全部调用点+修复 | **继承 Ghidra 反编译器成品**（FuncProto/LocalSymbolMap） | 不恢复（CALL=pc 跳转+状态副作用） |
| **flags** | i1 全局变量，逐 op 显式计算 | 已被反编译器消化，不存在 | 已被反编译器消化 | 1 字节 reg 数组槽，逐 op 显式计算 |
| 类型 | 尺寸整数+指针性猜测（对照架构寄存器表） | Ghidra typeref 照搬（无推断） | Ghidra 类型表全量（builtin/composite/enum）+惯用法尺寸推断 | 全无（字节流） |

来源：论文表 3.3.1/4.3.1+算法 5；PcodeSerializer.java:1015-1150；博客示例输出。

### b. 高层 pcode 的处理——Ghidrall 用哪个？高层 pcode 到 LLVM 更接近编译器 IR 吗？

- Ghidrall 用的是**反编译器内部数据结构**（=高 pcode 减 INDIRECT+参数/局部/栈信息），**不是** High P-code 中间层——论文明确跳过后者因"markers 不可直接翻译"[印 p.4]。Patchestry 实质同切点（DecompInterface 全程跑完）。
- **是的，显著更接近编译器 IR**：flags 消失（INT_SLESS/BOOL_* 已折叠进布尔值流）、真变量名/类型/参数存在、每函数一个栈帧而非全机器仿真、CALL 有真参数。论文数字直接佐证：同表映射下 Ghidrall 86.08% vs 低层路线无法评估（"not developed to the same standard"）+ McSema（低层路线工业版）71.13%，且输出小 56 倍。
- **对我们的落点**：我们 printc 前的 IR（SSA+varmap+结构化完成态）比 Ghidrall 的输入还靠后一层（他们还要自己做调用约定修复和栈恢复——这两件我们的 fspec/varmap 域已完成对齐）。增强轨以"我们的高层 pcode"为输入面=站在两个先例的肩上且起点更高。

### c. SSA 处理（关键可偷点）——他们重建 SSA 吗？LLVM 现成 pass 链能替我们做多少恢复？

- **三个工作无一重建 SSA，也无一保留 SSA**：
  - Ghidra-to-LLVM/Ghidrall：发内存形态 IR（全局+alloca+load/store），输出零 phi（论文全文 grep 亲证零命中）；SSA 构造完全甩给 LLVM（"Simplification passes are performed later on by LLVM optimization passes"，印 p.17）。
  - Patchestry：Java 侧 mineForVarNodes 把 SSA 机具坍缩回命名变量后才导出；Clang CFG→CIR→LLVM 链里的 mem2reg 由 clang 侧常规管线完成。
- **LLVM pass 链能替"低层形态"做多少**（Ghidrall 实证的间接答案）：从全内存形态出发，mem2reg+SROA+instcombine+SCCP+GVN+ADCE 一条 O1/O2 链能把机器仿真形态收敛回接近高 pcode 的形态——这正是 Ghidrall 与 McSema 的 15pp 差距的另一面（Ghidrall 起点高，所以不需要深优化就能过验证）。
- **对我们的判定**：这个"可偷点"对我们的**正典路径不可用也不需要**（我们有 heritage SSA，且跑 LLVM pass 会摧毁 oracle 对齐）。真正的可偷=**pass 菜单作为增强轨 IR 收敛层的候选算子清单**（mem2reg↔我们已有的 SSA 规范化/SCCP↔常量折叠/instcombine↔表达式规范化/GVN↔公共子表达式/ADCE↔死代码），以及"内存形态作为可验证中间落点"这一表示策略（见 §四-2）。

### d. 类型/结构恢复——root 预判"提升只换基座不填信息"证实还是证伪？

**证实，含两个可偷的边缘例外**：
- Ghidra-to-LLVM：零恢复（尺寸+指针猜测）。
- Ghidrall：**修复** Ghidra 的表示缺陷而非推断——调用约定传播（声明 arity 权威化）、全局变量跨函数合并（Ghidra 逐函数反编译不保全局一致性）、单 struct 栈布局（把 Ghidra 裂解的数组按相对索引重装）。这些是"Ghidra 输出卫生学"，与 RELIT 的 TRex/STRide 推断层完全正交。
- Patchestry：类型=照搬 Ghidra 类型库；例外=**惯用法尺寸推断表**（d 项唯一真正的推断增量，确定性、13 个 libc 函数）。
- Pcode2C：零。
- 结论：**pcode→IR 提升线全部不填类型信息——type_match 洼地（RELIT 首推 TRex/STRIDE）在 pcode→IR 文献里没有竞争者，护城河③判断维持**。

### e. Patchestry MLIR 方言设计——op 集/类型系统/降级路径/成熟度

- **op 集**：~16 个（func/block/instruction 容器 + const/reg/mem/var varnode + copy/popcount/bool_negate + int_add/sub/less/equal/sborrow/sless/and + branch/cbranch/call/return/store/load）。**缺**：全部浮点、INT_MULT/DIV/REM/移位/XOR/OR/NEGATE/2COMP/zext/sext/PIECE/SUBPIECE/CAST/PTRADD/PTRSUB/BRANCHIND/CALLIND/CALLOTHER/MULTIEQUAL/INDIRECT。
- **类型系统**：4 个 varnode 身份类型（const/reg/mem/var）+ 操作全用 `AnySignlessInteger`——**无语义类型检查**，是句法层而非语义层。
- **降级路径**：不存在（方言没有到 LLVM dialect 的 lowering 被实现/使用）；生产降级链=Clang AST→CIR（clang/CIR Dialect）→populateCIRToLLVMPasses→LLVM IR [Codegen.cpp 亲读]。Contracts 方言只做属性随链携带。
- **成熟度评估**：框架本体工程严肃（104 CVE/firmware fixture、QEMU 运行时验证、KLEE/SeaHorn 双验证器、184 closed PR、ToB+ARPA-H），但 **pcode MLIR 方言本身=放弃的实验**（遗迹证据：仅自引用+op 覆盖 ~20%+无类型安全+无 lowering）。可借鉴的是其 **JSON schema 与 Clang 发射 know-how**，不是方言。

### f. 可偷方案清单 —— 见 §四。

---

## 三、对我们的架构定位校验

| 他们的组件 | 我们的对应物 | 状态对比 |
|---|---|---|
| Ghidra 反编译器（Ghidrall/Patchestry 的输入） | **就是我们移植的主体** | 我们=基座本身；他们=基座的消费者 |
| Ghidrall 调用约定传播 | fspec/domain PARAMID/IMPORTSIG/CURLWIRE/CSPEC2 系 | 我们已对齐 oracle（更严） |
| Ghidrall 全局恢复 | CSPEC-GLOBAL-APPLY/TYPESEED/SYMDB 已落地 | 同上 |
| Ghidrall 单 struct 栈 | varmap/RangeHint 域（Ghidra 原生路径） | **正典路径我们走 Ghidra 原生；单 struct=增强轨备选形态** |
| Patchestry 三路 switch 恢复 | jumptable.rs+SwitchNorm（Ghidra 原生） | 同上；其三路兜底可作残差族交叉验证 |
| Patchestry SNode goto 消去 | blockaction（Ghidra 原生）+SAILR-PORT（增强轨在飞） | 不偷；pass 分类学可供 SAILR merge 决策参考 |
| Pcode2C 逐字 C | 无对应 | **新可偷件**（行为 oracle sidecar） |
| LLVM/MLIR 基座 | 无（自有 IR） | 见 §五 MLIR 成本重估 |

**核心校验结论**：pcode→IR 文献的两条严肃路线（Ghidrall 论文、Patchestry 工程）都是"Ghidra 之上加一层验证/补丁消费者"——**没有人用 LLVM/MLIR 重写反编译器主体**。我们的 Ghidra 1:1 移植+oracle 门禁路线在该文献域内无先例竞争者；增强轨（IR 收敛层）是这些工作没做的空白层。

---

## 四、可偷方案清单（按优先级）

### ① Patchestry JSON schema → 我们高层 pcode 的序列化契约（工作量：小）

- **偷什么**：字段设计——函数按地址键/type 引用类型表/basic_blocks 显式 ordered_operations/**值=定义点 SeqNum 引用**/inputs{type,kind}/CBRANCH taken_block+not_taken_block/switch_input+switch_cases+fallback 三路元数据/DECLARE_PARAMETER-LOCAL-TEMPORARY+ADDRESS_OF 伪指令族/CALL target{is_variadic,is_noreturn}+has_return_value。
- **为什么**：增强轨（SAILR 层/TRex 类型层/行为差分 harness）需要稳定输入契约；该 schema 经 104 个 CVE/固件 fixture 磨过；我们的 stage 投影/emitter 基建（v1.2.1 格式、drillobserve）已有 80% 字段，补 switch/branch/DECLARE 元数据即完整。
- **注意**：我们的投影格式已有身份键协议（oracle commit/指纹），新契约应作为投影格式的**增强面**而非替代。

### ② Ghidrall 单 struct 栈策略 → GEP 重建层的参照形态（工作量：零——是设计决策不是代码）

- **偷什么**：栈/帧对象表示为"一个 struct+padding+GEP 字段引用"（86.08% vs 字节数组 82.99% vs 朴素 83.16% 的实测排序）。Ghidrall 的失败模式清单同样可偷：(a) 朴素 per-var alloca 在"数据结构被相对索引"时全灭；(c) 字节数组 lifting 失败最少但**验证**失败最多（语义精度损失在下游爆）。
- **为什么**：增强轨 GEP 重建/类型层需要落点表示；单 struct 是文献唯一有 A/B 实测排序的选项，且与 LLVM GEP 天然同构。
- **边界**：正典路径维持 Ghidra 原生 varmap（对齐铁律）；单 struct 仅作为增强脸/LLVM 发射脸的帧表示。

### ③ Pcode2C 逐字 C 发射 → 确定性行为差分 oracle sidecar（工作量：中）

- **偷什么**：解释器特化形态（CPUState 字节数组+helper 宏+switch(pc)）——同一函数发两版 C：我们的反编译 C + pcode2c 式逐字 C，同 harness 同输入跑，diff 行为。
- **为什么**：RELIT 首推件 2"三重门禁 best-of-N 选择器"需要行为差分验收层；Decompile-Diverge 证明了可编译性≠语义保持。pcode2c 版本是**非 LLM、确定性、每次都同输出**的行为基准——比 LLM driver 合成便宜且可进 CI。我们已有 raw pcode（SLEIGH 全 Rust 化后原生可得）与 emitter 基建。
- **注意**：CBMC 有界（unwind）性质决定它是回归信号不是完备证明；按其博客哲学用作"fuzz+BMC 双通道"。

### ④ LLVM pass 菜单 → IR 收敛层候选算子清单（工作量：零——是清单）

- mem2reg（↔SSA 规范化）/SROA（↔栈槽去物化，我们 restart 语义已做）/SCCP（↔常量传播）/instcombine（↔表达式规范化）/GVN（↔公共子表达式）/ADCE（↔死代码）。Ghidrall 实证了"内存形态+O 级链"可达 86% 功能保持——增强轨按 pass 语义逐个映射到我们自有 IR 变换，**不引入 LLVM 依赖**。

### ⑤ Patchestry 惯用法尺寸推断表（工作量：小）

- 13 个 libc 函数×参数位→buffer 尺寸（memset/memcpy/memmove/bzero/recv/recvfrom/read/pread/strncpy/strlcpy/send/sendto/write）。确定性、无 ML、直接挂 varmap 增强面。与我们 LibcSignatureTable 通道（IMPORTSIG）天然汇流。

### ⑥ Patchestry 三路 switch 兜底模式（工作量：零——交叉验证策略）

- JumpTable 权威→启发→**失败时诚实省略元数据让消费端兜底**。对我们 SwitchNorm 残差族（SWITCH-GOTO/CASE-TAIL 系）是现成的分层兜底设计参照。

### 不偷清单（有据）

- **Patchestry 结构化**（goto 消去 7.9k 行）：我们正典=Ghidra blockaction（护城河①），增强=SAILR（学术+实证更强）；goto 消去是第三条路线，引入只增加 best-of-N 候选维护成本。
- **`pc` MLIR 方言**：遗迹，勿抄。
- **Ghidra-to-LLVM 的栈传参/无参 CALL**：机器仿真残迹，我们已有真调用约定。

---

## 五、MLIR 备选路径接入成本重估

1. **证据修正**：Patchestry（该方向唯一认真做过 MLIR 的团队）的 pcode 方言=遗迹；其生产路径选了 **ClangIR(CIR)=C 语义 MLIR 基座**，代价是 vendored LLVM 22.1.4 fork（ClangIR 尚未进主线稳定面）。这构成对"pcode 方言直接 MLIR 化"路线的**负面先例**。
2. **Rust 侧现实**：无生产级 Rust MLIR 绑定（melior 绑定 crate 活跃度/覆盖面不足以承载方言开发）；进程内 MLIR 需要 C++ FFI+LLVM 构建链——与我们"纯 Rust 构建链刚收官（SLEIGH 三阶段）"的方向冲突。
3. **重估结论**：
   - **主路径确认**：自有 SSA 上做 IR 收敛层（root 原案）——正确且无先例竞争。
   - **MLIR 备选降级为文本导出选项**：若增强轨需要 MLIR/LLVM 生态消费者（KLEE/SeaHorn 类验证、mlir-opt 工具链），最便宜路径=**从我们的高层 pcode 直接发 .ll 文本**（值引用/类型/CFG 我们全有，Ghidrall 的映射表 3.3.1/4.3.1 即现成发射规范）——绕过方言开发与 FFI，一次性 emitter 工作量。
   - 若未来真要方言：先发 LLVM dialect（标准、消费者多），自定义方言只在"LLVM dialect 表达不了"的语义（如 MULTIEQUAL 显式化）出现时再议。

---

## 六、对 IR 感知层设计的修订建议（供 root 排 MB19 后车道时参考）

1. **输入面定义**：增强轨统一输入="printc 前高层 pcode"的序列化形态（我们的投影格式+Patchestry 式 switch/branch/DECLARE 扩展字段）。SAILR-PORT/TRex/STRIDE/行为 harness 全部吃同一契约——避免每个增强件各自发明导出。
2. **帧表示**：GEP 重建层的栈/帧对象落点采用单 struct 形态（证据：Ghidrall 实测排序），正典路径不动。
3. **验证闭环**：行为差分层用 pcode2c 式逐字 C 作确定性基准（非 LLM），与 best-of-N 三重门禁汇流；CBMC/fuzz 双通道进 CI 而非终审。
4. **pass 映射表**：IR 收敛纲领的"算子从哪来"问题用 LLVM pass 菜单回答（§四-④ 映射表），每个增强 pass 标注"对应 LLVM pass+在我们 IR 上的等价变换+option-gated 开关"。
5. **不引入**：进程内 MLIR/LLVM 依赖（构建链代价+负先例）；.ll 文本导出作为唯一 LLVM 生态接口。
6. **文献空位确认**：pcode→IR 文献没有类型恢复、没有反编译器本体重写、没有 oracle 对拍方法论——我们的三条护城河在该域无先例竞争者；增强轨优先级排序（SAILR→TRex→选择器）不受本报告影响，只补充了契约/形态/验证三块零件。

---

## 七、诚实纪律记录

1. **论文**：65 页 PDF 全文获取并精读（redirect 后直链下载成功）；pdftotext -layout 提取 2,216 行全部读完。页码引用按印刷页码（PDF 页=印刷页+12）。**Ghidra 版本坑**：论文系于 Ghidra 9.1.x 时代（Ghidra-to-LLVM README 亲证），其"High P-code"描述与 12.0.4 有演进差（如当时表 2.2.1 未列 MULTIEQUAL 以外细节）——结论按"当时行为"引用，未假定与 12.0.4 逐字一致。
2. **Patchestry**：clone --depth 1（单 commit 4acddb4，2026-06-07）；**未构建**（vendored LLVM submodule 未初始化，全量构建估计 GB 级+小时级，超出车道预算）——所有运行时行为声明来自其自带 lit fixture 的 RUN 行（仓库自标 tested）与 docs，未亲跑。6,245 行 Java 序列化器与 7,985 行后处理 pass 为**代表性精读+定向 grep**，非逐行读完（MULTIEQUAL/INDIRECT 挖矿、switch 三路、惯用法推断、CALL 处理四处核心机制逐段亲读）。
3. **Pcode2C**：博客全文精读（2,947 词）；**仓库未 clone**（博客明示 WIP，pcode.h 不完整——按 WIP 引用）。
4. **websearch 侧频道质量注记**：star 数等来自搜索聚合镜像（多镜像一致：~84-87 星），GitHub 官方 API 未直连；数量级可信，非精确值。
5. **未读部分如实标注**：Patchestry 的 KLEE/SeaHorn verifier 工具源码、patch-runtime、firmwares/ 目录（只读了目录结构与 docs）；论文附录 B vuln.ll 全文（已抽样确认零 phi）；GhiHorn（论文相关工作节提及的 pcode→SMT 路线，登记未展开——与 RELIT 的 D-LiFT SMT 信号同域，留待需要时深挖）。
6. 任务书"worker-failure 先重试再归因"：本轮三次抓取（PDF 重定向一次/Patchestry clone/博客）均一次成功，无重试事件。

## 八、来源索引

- 论文 PDF：https://dspacemainprd01.lib.uwaterloo.ca/server/api/core/bitstreams/c90b61a3-7edf-48ac-a03c-2373c4b18db2/content（本地 /tmp/opencode-smartfetch/Toor_Tejvinder.pdf + thesis.txt）
- Ghidrall 仓库：github.com/toor-de-force/Ghidrall（fork of rizinorg/rz-ghidra）；Ghidra-to-LLVM：github.com/toor-de-force/Ghidra-to-LLVM；社区 fork：LukeSerne/Ghidra-to-LLVM
- Patchestry 本地 clone：/dev/shm/rugra-tests/pcodeir/patchestry@4acddb4（关键文件：docs/system_data_flow.md、scripts/ghidra/util/PcodeSerializer.java、include/patchestry/Dialect/Pcode/PcodeOps.td、lib/patchestry/Codegen/Codegen.cpp、lib/patchestry/AST/{OperationStmt,SNodePostPasses,BuildSNodeFromRegion}.cpp、test/patchir-decomp/*.json）
- Pcode2C 博客：philipzucker.com/pcode2c/（2026-09-25 更新）；仓库 github.com/philzuck58/pcode2c
- 官网：lifting-bits.github.io/patchestry（MLIR Tower/CIR 叙事）
- 收尾动作：/dev/shm/rugra-tests/pcodeir/patchestry clone 按任务书于车道收尾时删除（报告先行落盘）。
