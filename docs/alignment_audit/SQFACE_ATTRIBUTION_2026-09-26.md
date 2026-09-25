# SQATTR 车道归因报告 — sq 面（sasquatch 第四语料）残差族深归因 @ master efc28f4a（2026-09-26, ora 只读归因）

**任务**：sq 面残差族深归因（后续 wave 规格底稿）。零 src 改动；诊断产物在 `/dev/shm/rugra-tests/sqattr/`。

## 0. 口径、指纹与 fresh 基线（任务①）

- **基线 commit**：master `efc28f4a`（worktree 干净亲验）；oracle = Ghidra 12.0.4 锁定 `e40ed130`（ghidra/ 目录亲在）。
- **构建**：`CARGO_TARGET_DIR=/dev/shm/rugra-targets/sqattr cargo build --profile fast-release --example gen_decompile`（本 session 亲建，1m07s，0 error）。
- **跑法**：`RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=600 <gen_decompile> /usr/local/bin/sasquatch`（sha256 `5d1eb6d076cfdc9baeead8360b5281d9f3f157a1ccdffe0bc38b27902e6c0ad3`，GEN4 选型沿用）；
  对拍 `python3 tools/compare_ghidra.py <out> tests/golden/ghidra_sq_1204.direct-runner.c --base 0 --summary-only`。
- **工件**：`/dev/shm/rugra-tests/sqattr/sq_mirror_master_efc28f4a.{c,err}`（2289777 字节，805 函数输出）。

| 指标 | GEN4 首测（9d027a33） | DBLHI 后（42938d57+1） | **本测（efc28f4a）** |
|---|---|---|---|
| ok / 总单元 | 804/810 | 805/810 | **805/810**（5 非 ok 见下） |
| skeleton | 15848 | 15889 | **7838** |
| defects | 0 | 0 | **0** |
| numbering | 7 | 7 | **7**（仅 GetOptimumEjRjS2_，--one 680 亲验） |
| 骨架恒等函数 | 423/804 | — | （compare 未出该数；族分布见 §1） |

**官方门禁判定（verify_mirror_gate.sh --corpus sq，本 session 亲跑，工件 /tmp/rugra-mirror-gate.ttcdlJ）**：
`MIRROR-GATE[sq] FAIL: skeleton=7838/22639 defects=0 numbering=7 matched=805/805 health=fail` —
skeleton 7838≤22639 ✓ / defects 0 ✓ / matched 805≥floor 805 ✓（新 floor 立住）；numbering=7→FAIL（硬断言，绑 GEN4-SQ-DUPDECL-NUMBERING-0001，根因已钉 §3）+ health ok=805/810→FAIL（PRETTYFLUSH 2→SQATTR-PENDINGBRACE-IDENTITY-0001 + sqnullt 待并 3）——总 FAIL=承重态不变，绑定票由四票演化为：DUPDECL+PENDINGBRACE 两张已具修法规格的 P1 + sqnullt 待合并。

5 非 ok 单元（输出函数头集 vs golden 函数头集差，亲验）：`LzmaEnc_CodeOneBlock.part.0`（NULLLOCALTYPE）+ `read_inode_1`/`read_inode_3`（MERGE-FORCEDINTERSECT）——三者均待 wt/sqnullt（948974df）合并消除；`TestRemoveDescendant`×2 克隆（PRETTYFLUSH panic，§4 根因已钉）。

骨架 15889→7838 的 −8051 归因：F5IF（preferComplement BFS 断流修复，已并）消 BRANCH-INVERT 主体（§2）+ 后续车道（union 指针臂 e94c3640、F7NAME 94e89d82 等）的累积收敛。GEN4 票面 "post-F5IF 9281" 为 F5IF 合并时点值，本测含更多已并车道。

## 1. 族分拣 fresh 数字（hunk 分类器，7838 行全分类，零 OTHER 泄漏）

分类器：`/dev/shm/rugra-reports/hunk_family_quant_gen4.py`（GEN4 原版，tools path 补齐后本 session 亲跑）。

| 族 | 行数 | 函数数 | GEN4 时 | 变化 |
|---|---|---|---|---|
| CAST-SHAPE | 2617 | 176 | 3866/177 | −1249 |
| OTHER（栈槽物化主导） | 2203 | 226 | ~2804/223 | −601 |
| SWITCH-GOTO | 1135 | 46 | 2100/51 | −965（归并 MSTRUCT-SWITCHGOTO） |
| OPNAME-LEAK（ZEXT） | 851 | 28 | 1968/26 | −1117 |
| UNAFF-EXTRAOUT | 555 | 27 | 782/31 | −227（归并 GENSMOKE-S4/S2） |
| CAST-TEMP-HOIST | 180 | 13 | 1651/30 | −1471 |
| LOOPSHAPE | 154 | 11 | 442/16 | −288（归并 MSTRUCT-FORSPLIT） |
| CMP-ORIENT | 128 | 6 | 511/14 | −383 |
| TYPE-SPELL | 14 | 5 | 4/2 | +10（GetOptimum 档位混入，随 DUPDECL §3） |
| WARNING-FACE | 1 | 1 | 339/189 | −338（GLOBALOVERLAP-PROXY 修复已并） |
| **BRANCH-INVERT** | **0** | **0** | **1381/3** | **族灭绝**（§2） |

ZEXT 泄漏总量亲测：Rugra 107 处 `ZEXT\d+(`（golden 0）；独立 cast 语句 `V = (cast)V;`：Rugra 774 vs golden 928（**−154 = Rugra 过度内联的直接计数证据**，§2.1）。

## 2. BRANCH-INVERT 复测（任务②）——**族灭绝，关闭归 F5IF**

- **复测对象**：GEN4-SQ-BRANCH-INVERT-0001 的 1345 行主力 `_ZN9NCompress5NLZMA8CDecoder8CodeSpecEj`（--one 405）。
- **实测**：`--func` skeleton **39 行**（1345→39，−97%），defects=0/numbering=0。逐行核对 **0 个取反+体交换形态**（`if(V < X){A}else{B}` 双侧取向已一致；39 行全落：CONCAT31 融合 ~35 行（§2.1 CASTFUSE-A）+ 声明序 churn ~4 行（STACKSLOT 域））。
- **全语料佐证**：分类器 0 hunk 命中 BRANCH-INVERT（原 3 函数）。
- **归因**：收敛主体归 HTTPDMAIN-F5-IFELSE-RETEST-0001（wt/f5if 的 structure_children Goto/MultiGoto BFS 断流修复——CR-F5IF 要求的复测结论：**预判成立，1345 行族基本全自愈**）。
- **残量处置**：无独立残量；39 行改挂 CASTFUSE/STACKSLOT 票。**GEN4-SQ-BRANCH-INVERT-0001 建议关闭**（TODO 板本 lane 更新）。

## 2.1 CASTFUSE 族深归因（任务③重点，CAST-SHAPE 2617 + CAST-TEMP-HOIST 180 = 2797 行 = 最大未开采池）

分桶器把"任一侧含 cast 的 hunk"全丢进 CAST-SHAPE——**不是单一根因**。抽样（CodeSpec/GetLongestMatch×3 克隆/read_inode_2/GetOptimum）分解为四个子族，机制互相独立：

### 子族 A：explicit/implied 标记分歧（语句链 vs 融合表达式）——主成分

**形态**（CodeSpec 亲样，Rugra one_405.c:106 vs golden:32724-32729）：
- oracle：`iVar9 = CONCAT31(Var4,xVar7);`（**独立语句落到命名变量**，后被读 2 次：`= iVar9;` 与 `| iVar9 << 8`）
- Rugra：`*(uint4 *)(param_1 + 0x84) = CONCAT31(Var4,xVar7);`（融合进 store），第二读另走 `(int4)(unkint3)Var4`（子族 C 叠加）

**决定性机制**（双侧亲读）：
- oracle 打印层变量化开关 = `Varnode::isImplied()`：`PrintLanguage::recurse()`（printlanguage.cc:197-226）对 `vn->isImplied()` 走 `defOp->getOpcode()->push(this,defOp,op)` 内联，否则 `pushVnExplicit` 落符号。
- 标记由 **ActionMarkImplied**（coreaction.cc:3416-3455，深度优先后序；`checkImpliedCover` :3376-3414 = LOAD 跨 STORE / CALL 跨 CALL / inflateTest 三门）+ **Merge::markImplied**（merge.cc:1595-1605，置 implied + 输入 coverdirty）决定；不过门即 `setExplicit()` 落命名变量。
- **多读者不可能 implied**（内联会复制表达式）——oracle 的 iVar9（2 读者）必然 explicit。
- Rugra 侧：ActionMarkImplied 移植在 coreaction.rs:5055（apply）/4879（check_implied_cover，三门齐）/merge.rs inflate_test；printlanguage recurse 等价物在 printc RPN 通道。
- **计数证据**：独立 cast 语句 774 vs 928（−154）——Rugra 系统性把 oracle 落变量的中间值内联掉。

**根因候选（待 IR 级 fixture 钉死，二选一或并存）**：
1. Rugra 某标记路径放行了多读者 varnode（descend_iter 快照时机或 explicit 回退缺失）；
2. Rugra 的 IR 在标记时点读者数<2（时序差异：某 Action 在 MarkImplied 之后改写了读者结构）。
**修法规格**：`--one 405` 单函数 fixture，dump CONCAT31 输出 vn 的 (readers 数, is_implied, is_explicit, cover) 双侧对照（oracle 用 golden_dump_1204 加同名 printf；Rugra 临时探针），先钉 1 vs 2 再动核心。
**写域**：`src/coreaction.rs`（ActionMarkImplied/checkImpliedCover）+ `src/merge.rs`（inflate_test/markImplied）——**机制 C 白名单（merge 核心），commit 须附 Cross-Review**。
**优先级**：**P1**（单族最大收益 ~1500-2000 行量级，含 CAST-TEMP-HOIST 全部 + CAST-SHAPE 主成分）。

### 子族 B：cast 插入形态（ActionSetCasts/castStandard）

GetLongestMatch 亲样：Rugra `V = V + (long)V;`（多一枚 cast）vs oracle `V = V + V;`；`V = (uint4)(uint1)((V ^ V) >> LIT);` 双层 cast 链 vs oracle 语句链。写域 `src/coreaction.rs:5175+`（ActionSetCasts）+ cast.cc:340-470 对照。P2（随 A 的 fixture 一起钉）。

### 子族 C：ZEXT/unkint opname 泄漏 = **元类型中毒，非 printc 缺臂（票面根因证伪）**

- GEN4-SQ-ZEXT-OPNAME-0001 票面称"printc 的 ZEXT 渲染臂缺失"——**亲读证伪**：RPN 臂在 printc.rs:2818-2845（RPN 分派）与 :17411-17444（op_int_zext），忠实走 `cast_strategy.is_zext_cast(out_def_facing, in_read_facing)`（cast.cc:453-470 的移植：out∈{UINT,INT} ∧ in∈{UINT,BOOL} 才 opTypeCast）。
- 泄漏 = 门返回 false：`uVar7 = ZEXT48((uint4)uStack_68 & param_1[0x305]);`（mirror 输出 :5134）——AND 输出或 ZEXT 输出元类型非 UINT（xunknown 中毒），与 MIRROR_RESIDUAL F-TYPE 同判（"SEXT48 是 metatype 中毒的派生症状"）；`(int4)(unkint3)Var4`（unkint3 = CONCAT 部件类型未解析）同根。
- **修域改判**：`src/varmap.rs`/类型传播域（GENSMOKE-S2/VARMPOISON 车道系），非 printc。printc 写域释放。
- 107 泄漏位点的函数分布：GetOptimum 双克隆 20、LzmaDecoderCode/CodeReal/DecodeReal2 23、GetLongestMatch 族 11、WriteEndMarker 10、squashfs_opendir_1 6。
- **验收更新**：ZEXT\d+ →0 的前提 = 类型传播收敛；printc 侧零独立工作量。P1（但归并既有类型票，不新开 printc 票）。

### 子族 D：杂项小族（已在 MIRROR_RESIDUAL 登记，sq 面再现）

- ARRCAST `(xunknown1(*) [LIT])` vs `(xunknown1 [LIT]*)`（GetLongestMatch 等）——F-ARRCAST。
- CODENAME `== (code *)LIT` vs `== _ZN6NPat3H...GetIndexByteEi`（pushPtrCodeConstant 断线）——F-CODENAME。

## 2.2 OTHER 桶（2203 行/226 函数）= STACKSLOT-MATERIALIZE 票面维持

read_inode_2/GetOptimum 亲样维持 GEN4 判断：中链值栈槽物化（oracle 复用单一高层变量、Rugra 中途物化 `uStack_XX`）+ 栈符号分型（`axStack_cb [LIT]` vs `xStack_cb`）+ 声明序 churn。写域 varmap.rs ScopeLocal 晋升（票面不变，数字更新 2804→2203）。**P2**。

## 3. DUPDECL-NUMBERING 深挖（任务④a）——根因 =  legacy 文本补偿层的声明注入臂

**现象**（--one 680 亲测，numbering=7）：`int4 iVar16;`（顶部 mirror 档）之后，函数体**中部**（one_680.c:798-816，`do {}` 循环体内）冒出整块 canon 档声明 `int iVar16; int iVar19; … char *piVar23; char *piVar33; long uVar14; …`——同函数两套档位拼写、同名重复声明。

**发射流取证**（本 session FWDLOG 仪器，`/dev/shm/rugra-tests/sqattr/fwd680.log`，28483 条 Emit 调用）：`begin_var_decl` 全部 88 次集中在流首 16-646 行——**printc 作用域声明通道只发射了一次、位置正确**。中块**不是** printc 发的。

**根因**（prettyprint.rs 亲读）：`post_process_output_legacy` 的**声明回填/注入臂**：
- `flush_func_remove_unused`（:2959）与 backfill 注入臂（:2500-2580，`out.push(format!("{}{}{}{};", indent_str, ty, join, m))`，前缀猜型 `lVar/uVar→long`、`iVar/bVar→int`、`piVar/pcVar→char *`）+ uVarNNN 注入（:3083 `format!("  int {};", mname)`）。
- 注入判据的**declared 探测只认 canon 拼写**（`int `/`long `/`char ` 头，:945/:1888 等）——mirror 档的 `int4 /uint4 /int8 /xunknown8 ` 声明行全部不被识别 → 已声明符号被当 missing → 前缀猜型重声明（=档位混入 + 重复声明双症状）；
- 插入锚点 `last_decl_idx` = "最后一个被识别的声明行"——识别失败时锚点落到函数体中部的伪声明形线条上 → **中块**。
- PRINTC-LEGACY-DECL-DUP-0001（canon 面）已修过 2-token join 形态；mirror 档拼写是**未覆盖的同类洞**。

**oracle 对照**：emitScopeVarDecls（printc.cc:2518-2575）一次性顶部发射；direct-runner golden **零注入声明**；golden GetOptimum 自身的 `piVar2×2/iVar16×2`（.part.0 golden:48694-48695）是 oracle 侧 scope 双符号怪癖（另案，不构成本族主体）。Rugra 顶部块无此重复——oracle 怪癖是否需要复现**独立低优先级跟踪**（不阻塞 numbering=0）。

**修法规格**（P1，便宜且独立）：mirror 面整体跳过注入臂——这些是 canon 面 self-containment 补偿（POSTFIX-RETIRE-0001 W0 域，oracle 零对应物），direct-runner golden 无注入行；具体=doc_function→post_process 链路携带 face 信号（driver 侧 `RUGRA_GEN_MIRROR` 已在 env，passes 内一次 lazy 读取即可）或在 `flush_func_remove_unused`/backfill 入口早退。**写域 `src/prettyprint.rs`+`docs/api/prettyprint.md`**（非机制 C 白名单）。次选（canon 面保注入）：declared 探测补 mirror 拼写 + 锚点回退函数首。
**验收**：sq 面 numbering=0 + GetOptimum 中块消失 + canon 双脸字节恒等（curl/httpd 不回退）+ 四面 ZEXT 等族数字不升。

## 4. PRETTYFLUSH 2 panic 深挖（任务④b）——根因 = PendingBrace 传输丢失对象身份，双重 close 炸空 indentstack

**现象**：`TestRemoveDescendant` 双克隆（--one 609/620）确定性 panic：`prettyprint.rs:3946:56 called Option::unwrap() on a None`，栈 = doc_function→scan→advanceleft→print_token（TokenBreak 相对缩进臂 `indentstack.last().unwrap()`）。oracle golden 同函数 107 行全跑通=同输入下 oracle 栈永不空。

**取证链**（本 session 全新仪器法，零 src 改动）：
1. 仓库外 probe（/dev/shm/rugra-tests/sqattr/probe，复刻 gen_decompile run_one + 可换 emitter）：EmitNoMarkup 直跑成功 → 结构树 dump（trd609_tree.txt）+ NoMarkup 输出（probe609.c）拿到——输出文本括号 19/19 平衡、但 else 体缺 `{` 多语句直排；
2. trait 调用级计数 emitter（begin/end 全类配对追踪）：**调用序列完全平衡**（final 0/0/0，从未负）→ 排除 printc 调用不对称；
3. **FwdEmit 转发器**（包住真 EmitPrettyPrint，逐调用落盘）+ 转发 `pending_brace_fired` → panic 复现且流被捕获（fwd609b.log，1366 条至 panic）；
4. **MiniOppen 复放器**（Python 忠实复刻 prettyprint.cc:541-1243 Oppen 协议逐 token 重放该流）→ **同点复现空栈失败**，ring 记录铁证：
   - 调用 626 与 823 两处：`print("goto code_r0x…;") → cancel_pending_print → close_brace_indent → close_brace_indent`——**同一枚已发射的 pending brace 被关了两次**；
   - 每次 double-close = 一枚多余 `drop_indent`；函数尾 `close_brace_indent(函数体)` 的 drop 吃掉 `func_b` 组、`end_function` 的 end 再弹空 → 尾部 bump_t(size=999999) 强制断行提交时 `indentstack.back()` 于空栈 → 3946 panic。

**双侧根因**（逐字行号）：
- **oracle 有对象身份**：printc.cc:2882 `PendingBrace pendingBrace(option_brace_ifelse);`（**每次 emitBlockIf 调用一枚栈对象**，printc.hh:351-361 ctor indentId=-1）；:2885 `setPendingPrint(&pendingBrace)`（装指针）；:2900 `hasPendingPrint(&pendingBrace)` = prettyprint.hh:457 **`pendPrint == pend` 身份判定**（只取消"自己那枚还挂着"的 brace，产出 else-if 合并）；:2946 `pendingBrace.getIndentId() >= 0`（**只有发射过这枚对象的调用方才关它**）；emitPending（prettyprint.hh:1129-1136）先清槽再回调。
- **Rugra 丢了身份**：prettyprint.rs:3758-3762 pending 槽 = 全局 `Option<BraceStyle>` + `pending_brace_fired: bool`（**无 token**）；printc.rs:5831 `installed_pending_brace = is_set(PENDING_BRACE)`（**继承来的 mod 旗标**，非本调用对象——else 子 If 继承父的 PENDING_BRACE 后，子调用也认领这枚 brace）；:5858 `has_pending_print()`（bool，无身份）；:5897-5898 IFGOTO 路径 `cancel + if installed && fired → close`（oracle :2914-2917 的 goto 路径**无 cancel**，直落 popMod+身份 close）；:5949 尾部同全局旗标 close——**子和父对同一枚已发射 brace 各关一次**。
- 另注：oracle end/end_indent pop 有守卫（prettyprint.cc:641/647 `throw LowlevelError("indent error")`，fail-closed 整函数失败）；Rugra `pop()` 静默吞、死在下一个 tokenbreak 的 unwrap——MIRROR3-PRETTYFLUSH-FAILCLOSED-0001 登记的"错误路径 fail-closed 分歧"仍成立，但 sq 2 panic 的**首要根因是本条身份丢失**（正流即炸，非错误路径）。

**修法规格**（P1）：给 pending 槽加身份 token——`set_pending_brace(style) -> BraceId`（每次调用 fresh id）；`has_pending_print_id(id)`/`pending_brace_fired_id(id)` 按 id 查询；printc emit_structured_if 每调用生成自己的 id，三处判定（:5858 取消、:5897-5898、:5949 关闭）全部改 id 门；IFGOTO 路径的多余 `cancel_pending_print()`（oracle 无此调用）随身份化后删除或改 id 门。**写域 `src/prettyprint.rs`（Emit trait 三方法签名扩展）+ `src/printc.rs`（emit_structured_if）+ 对应 docs/api**。trait 签名扩展波及 emit 实现类（NullEmit/EmitNoMarkup/EmitPrettyPrint/CountingEmit 类 fixtures）——机械跟进。非机制 C 白名单（printc/prettyprint 不在清单），但属主管线打印层，建议 CR。
**验收**：609/620 双克隆 rc=0 + 与 golden defects=0/numbering=0（golden 107 行参照）+ sq 面 ok 805→807（合并 sqnullt 后 810/810 的最后缺口）+ canon/legacy 三面恒等 + probe609.c 观察到的"else 体缺 `{` 多语句直排"形态同步消失（double-close 的 NoMarkup 侧症状）。

## 5. 修复优先级与依赖图（建议 root 裁决）

```
PENDINGBRACE-IDENTITY（printc+prettyprint，独立，2 panic + NoMarkup else 形态）
DUPDECL 注入门控（prettyprint legacy 层，独立，numbering=7→0）── 二者无写域冲突，可并行
wt/sqnullt 合并（root 待办）── 消 3 非 ok 单元
   └─> 三者收口后 sq 面 810/810 + numbering=0 → 面转绿、ceiling 可重钉（7838 基础上）
CASTFUSE-A fixture（coreaction/merge，机制 C）── 单函数 IR dump 钉"多读者 implied"根因
   └─> 修 ActionMarkImplied/inflate_test → CASTFUSE-A/B ~2000 行 → CAST-SHAPE/TEMP-HOIST 主收敛
ZEXT/unkint（varmap 类型传播，归并 GENSMOKE-S2/VARMPOISON 系）── 107 位点随类型收敛自愈
STACKSLOT（varmap ScopeLocal）2203 行、SWITCH-GOTO（MSTRUCT）1135、CMP-ORIENT 128 → 既有票续作
```

## 6. 复现配方（全指纹）

- fresh 基线：§0 命令（golden sha256 `52108b823002d0d03bdc914f0133ccf6488683ea73e552afa527443b402ee143` 沿用 10723b01，未动）。
- 分类器：`python3 /dev/shm/rugra-reports/hunk_family_quant_gen4.py <mirror.c> tests/golden/ghidra_sq_1204.direct-runner.c`。
- BRANCH-INVERT 复测：`--one 405` + `compare --func _ZN9NCompress5NLZMA8CDecoder8CodeSpecEj`。
- PRETTYFLUSH repro：`RUGRA_GEN_MIRROR=1 <gen_decompile> /usr/local/bin/sasquatch --one 609|620`；取证链 4 步产物在 /dev/shm/rugra-tests/sqattr/{probe609.c,trd609_tree.txt,bal609.err,fwd609b.log,replay.py}。
- DUPDECL repro：`--one 680` + `compare --func _ZN9NCompress5NLZMA8CEncoder10GetOptimumEjRjS2_`；注入块=one_680.c:798-816。

**只读合规**：本车道零 repo src/改动；repo 内仅新增本报告与 TODO_BOARD 票据更新。
**落位声明（root 协调 2026-09-26）**：主仓 mid-merge（MERGEPCS）期间本车道**不做 git commit**——两件交付物以未提交态留主仓（TODO_BOARD 票行 + 本报告 untracked），待 root 在 MERGEPCS 落地后核对存活并补提交（建议 message：`docs: sq face residual family deep attribution (SQATTR lane)`）。
