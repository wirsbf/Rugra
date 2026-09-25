# LANE REPORT — FL elsefix (HTTPD-FULLEMPTY-ELSE-0001 修复)

- Branch: wt/elsefix @ <commit-hash> (基=亲父 a57da535 亲测)
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-elsefix(主)+sb-elsefix-base(亲父基线)
- Oracle: Ghidra 12.0.4 e40ed130(HEAD==tag 校验过;oracle 探针链接 sb-drill 的锁版本 libdecomp.a)
- 写域: `src/disasm/x86_lift.rs`(lifter,车道域内)+`docs/api/disasm/x86_lift.md`+TODO 行;
  blockaction/printc/coreaction 零改动(车道假设"结构化器/打印层"双双证伪)。

## 0. TL;DR

**缺陷性判定:真缺陷**(双侧 golden 均无空 else;oracle 同输入结构=proper if)。
**根因(一句话)**:iced lifter 把直接分支目标提升为 **8 字节 ram varnode**,相邻
目标互相重叠 → Heritage 范围细化(refineRead/refineWrite,heritage.cc:390-414/474-494)
拆分重组出 PIECE 链残骸,死 PIECE 落进仅含 jmp 的基本块 → `BlockBasic::isDoNothing`
hasOnlyMarkers(block.cc:2578)不过 → 块不被 ActionDoNothing 移除 →
ruleBlockIfElse(blockaction.cc:1416)合法地把幸存块包成 else 臂 → `else {}`。
**修复**:三处目标 8→1 字节(oracle newCodeRef 形,funcdata_varnode.cc:222-233)。

## 1. 复现与判定(任务①)

- 基线复现(a57da535,MAX_FUNCS=840):ap_parse_uri L16 / ap_invoke_handler L57
  各 1 处 `else {\n}`;全量 L2 = **37939/2/0**。
- golden 对照(direct-runner):两函数均**无** else(条件真臂=循环,假边直落 join)。
- oracle 直跑探针(oracle_blocktree.cc,锁 12.0.4):**bblocks 里根本没有 0x34335
  块**——BB0(0x34314-33)假边直连 BB3(0x3434a);最终结构树 If 只有 cond+Whiledo
  两臂(proper if,无 else 臂)。

## 2. 归因链(任务②,双侧证据)

1. oracle raw 探针(post-followFlow):`goto 0x34335`(jmp-only 块)**在 Ghidra
   原始 CFG 里同样存在**;CBRANCH/BRANCH 目标输入=**ram 空间 size=1** varnode
   (`[target-space=ram offset=0x34344 size=1]`)→ 1 字节目标互不重叠 →
   heritage read-only range 走 guard/setActiveHeritage→renameRecurse 输入晋升
   即止,**零 PIECE**;jmp-only 块只含 BRANCH → donothing 移除 → proper if。
2. Rugra drill(RUGRA_STAGE_DRILL):目标为 **ram:8** → 0x34340/0x34344/0x3434a
   等 8 字节目标互相重叠 → heritage 细化产出 `concat` PIECE 链
   (`u0x10000038 = concat(ram:0x3434c:6, ram:0x3434a:2)`@0x34335 等);
   donothing 探针实证:块@0x34335 ops=`[CPUI_PIECE@34335, CPUI_BRANCH@34335]`
   → hasOnlyMarkers 不过 → 块幸存 → if-else 包裹 → else 空体打印
   (printc 侧 emitBlockIf 忠实 printc.cc:2926-2944,无过错)。
3. 结构化器/打印层假设证伪:两侧规则/打印逻辑同构,唯一分歧=lifter 目标形态。

## 3. 修复(任务③)

`src/disasm/x86_lift.rs` 三处:`VarnodeRaw::new(AddressSpace::Ram, target, 8)`
→ `(…, 1)`:cmovcc 内部 `goto inst_next`(:1849)/`jmp imm`(:4681)/`jCC imm`
(:4746)。CALL 目标不动(oracle=fspec 空间独立域)。注入层 phase1 本就每输入
fresh varnode → 1 字节不重叠,与 oracle 生命周期一致(read-only→输入晋升)。

## 4. 验收(全部亲测,fast-release,终二进制)

| 门禁 | 基线(a57da535) | 修复后 | 判定 |
|---|---|---|---|
| httpd 全量 L2 vs direct-runner | 37939/**2**/0 | **37867/0/0** | defects 2→0 ✓ skeleton −72 只降 ✓ 双跑逐字节恒等 ✓ |
| httpd 门禁面 29 fns(canonical) | 2225/0/0 | **2148/0/0** | −77,0/0 保持 ✓ |
| curl E2E(canonical) | 2152/0/0 | 逐字节==基线 | 零影响 ✓ |
| 三投影(RUGRA_MIRROR=1) | MATCH×3 | **MATCH×3** | next_url/match_url/parseconfig ✓ |
| cargo test --lib 串行 | 1677/18 | **1677/18** | 同集,18 全预存 ✓ |
| annotation/refs 检查 | — | 全过 | ✓ |

## 5. 产物清单

- /dev/shm/rugra-tests/sb-elsefix/:oracle_blocktree{,.cc}(双侧结构/裸 pcode
  探针)、oracle_ap_{parse_uri,invoke_handler}.{c,stderr}、rugra_ap_parse_uri.drill、
  probe_donothing.stderr、httpd_full_{base,fix,final}.c、httpd_gate_*、curl_{base,fix,final}.c、
  m_*.projection、failures_{base,fix}.txt
- 基线 worktree /dev/shm/rugra-worktrees/elsefix-base(a57da535,对照专用)

## 6. 未决移交

1. cmovcc 内部 `goto inst_next` 在 Ghidra 是指令内相对分支(findRelTarget 路
   径),Rugra 物化为绝对 ram:1——当前无双侧差异证据(投影 MATCH),若未来
   drill 级逐 op 对拍出现差异,查此点。
2. CALL 目标 ram:8 vs oracle fspec 注记(独立预存形态差,callspec 链消费中,
   不在本 lane 域;若 PLT 密集函数出现同族 PIECE 残骸,改法同款 size/空间)。
