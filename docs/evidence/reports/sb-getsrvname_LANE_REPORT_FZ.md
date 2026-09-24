# LANE REPORT — FZ getsrvname (HTTPD-FULLEMPTY-ELSE-0001 residual 收口)

- Branch: wt/getsrvname @ 970b2ecc (基=亲父 720551db 亲测)
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-getsrvname(主)+sb-getsrvname-base(亲父基线)
- Oracle: Ghidra 12.0.4 e40ed130(HEAD==tag;oracle_blocktree 探针复用 sb-elsefix 的
  锁版本二进制,直跑同输入)
- 写域: `src/prettyprint.rs`(P6 声明行判据,补偿层内封堵)+`docs/api/prettyprint.md`
  +TODO 行;blockaction/printc/coreaction/lifter **零改动**(FL 同族假设在本例证伪)。

## 0. TL;DR

**缺陷性判定:真缺陷**(双侧 golden 均无空 else;oracle 同输入 else 臂有实语句)。
**根因(一句话)**: prettyprint P6 单用内联的**声明删除谓词**
`contains(" uVarN;")` 把尾置裸变量的**使用行**(`… = uVar5;` / `return uVar5;`)
误判为声明一并清空——inline 臂先删赋值行、再把唯一使用行当声明删空
(decl 检查先于 replace_word 且 continue 短路)→ else 臂双行全灭 → `else {}`。
**修复**: 新增 `is_declaration_line` 真声明行判据(纯类型头+整行尾匹配+
语句关键字黑名单),inline/dead-elim 两臂统一换用。
**里程碑: httpd 全量 470 函数 defects 归零**。

## 1. 复现与判定(任务①)

- 基线复现(720551db,MAX_FUNCS=840):ap_get_server_name L21 `else {\n}`;
  全量 L2 = **38672/1/0**(panic=0 TIMEOUT=0 settling=0)。
- golden 对照:direct-runner golden L12958-12978 该 if 无空 else(else 臂有
  apr_pstrdup 两语句);oracle_blocktree(锁 12.0.4)同输入直跑:输出与 golden
  同形,structured tree If[BB2 cond, BB3 then, BB4 else],else 臂 BB4 非空。
- oracle CFG 关键事实:**无 jmp-only 块**(11 块全有实 ops;BB4 结尾 jmp 但有
  5 实 ops)——FL 的 PIECE 残骸/ActionDoNothing 机制在本例**不适用**。

## 2. 归因链(任务②,双侧+逐层探针)

1. oracle 直跑探针(oracle_blocktree,复用 sb-elsefix 锁版本二进制):
   结构树/裸 pcode 全取证(见 §1)。
2. Rugra drill(RUGRA_STAGE_DRILL):BB4 的 CALL `RAX = call i0x2aee0(...)`
   在 activereturn(stage 297)后无任何死亡记录(`**`),存活至终态;
   STORE@0x38029 同样存活。
3. RUGRA_DUMP_FUNC 树转储:sblocks = List[If0[BB0, If1[BB1, If2[BB2,BB3,BB4]]],
   Else If5[Cond(Or(BB5,BB6)&&BB7), BB8], BB9] —— 与 oracle 同形,else 臂=BB4。
4. examples 侧临时探针(已撤):bblocks BB4 ops=16,树 Copy 包装原块;
   op 终态 CALL out=RAX implied=**false** ndesc=1,STORE 无 skip 标志。
5. src/printc.rs 临时逐 op 追踪(RUGRA_FZDBG,已撤):主 pass 对 BB4 的
   CALL/STORE **确实走到 emit_statement**(dead/marker/nonprint/noret/branch/
   implied 全 false)。
6. src/prettyprint.rs 临时快照(RUGRA_FZRAW,已撤):**pre-postprocess 文本
   else 臂本已打印两行**:
   `uVar5 = apr_pstrdup(*puVar2,…);` + `*puVar2 + 0xb = uVar5;`。
   RUGRA_POSTFIX_STATS:该函数 **P6=3 突变(31→30 行)**。
7. 凶手确认:P6 inline 臂 `t.contains(" uVar5;")` 命中使用行
   `*puVar2 + 0xb = uVar5;`(尾置裸变量+分号)→ 当声明删空 + continue 短路
   掉 replace_word → 赋值行(inline 删)+使用行(误判删)双灭 → 空 else。
   结构化器/打印层/IR 层全链清白。

## 3. 修复(任务③)

`src/prettyprint.rs`:
- 新增 `is_declaration_line(t, var_name)`(RUGRA-GLUE,补偿层 helper):
  整行尾匹配 `<head> uVarN;` + head 字符集仅 `[A-Za-z0-9_* ]`(纯类型头,
  无 `=`/`(`/`)`/`,`/运算符)+ 语句关键字黑名单(return/goto/break/continue/
  case/default 不得作为 head token)。
- P6 inline 臂与 dead-elim 臂的声明删除统一换用该判据;使用行落
  `replace_word` 正常内联为 `*puVar2 + 0xb = apr_pstrdup(…);`。

## 4. 验收(全部亲测,fast-release,亲父 720551db 双 worktree 对照)

| 门禁 | 基线(720551db) | 修复后 | 判定 |
|---|---|---|---|
| httpd 全量 L2 vs direct-runner | 38672/**1**/0 | **38726/0/0** | defects 1→0 ✓(全量 defects 归零);skeleton +54=**55 条 P6 静默吞掉的真实语句恢复**(apr_pstrdup/apr_array_make 调用、全局/指针 STORE、`x^x` 清零;base/fix 逐行 diff 全为 restored 类,11 删除全空白),方向=语句恢复,文本形态仍异(printc STORE 臂缺括号拼写=既有骨架差);双跑逐字节恒等 ✓ |
| httpd 门禁面 29 fns(canonical) | 2698/0/0 | **2698/0/0** | 恒等(受影响函数均门外)✓ |
| curl E2E(canonical) | — | **逐字节==亲父基线** | P6 谓词变更 curl 零命中 ✓ |
| 三投影(RUGRA_MIRROR=1) | MATCH×3 | **MATCH×3** | next_url/match_url/parseconfig.constprop.0 stage+snapshot identical ✓ |
| gcc 审计 per-function 集 | 101 OK/369 FAIL | **同集恒等** | 恢复语句未新增 gcc 失败(int8 族预存)✓ |
| cargo test --lib 串行 | 见终报 | 同集 | 见终报 ✓ |
| annotation/refs 检查 | — | 全过 | ✓ |

## 5. 未决移交

1. `*ptr + off = value;` 缺括号 STORE 地址拼写(printc.rs STORE 臂,2002 行
   field_access 未命中时 `*` + 裸加法地址)——skeleton 既有差,非 defect 类,
   未单独立项(属 printc 域,若 FQ3/FY2 修 STORE 渲染可顺带消)。
2. P6 在 httpd 全量的静默吞语句面=55 处(本修复全恢复);POSTFIX-RETIRE-0001
   退役 P6 时以本判据行为为基线,防止退役回退该封堵。
3. `x ^ x` 未折叠为 0(param_5 = param_5 ^ param_5 恢复后可见)——上层化简
   RuleXorZero 域既有缺口,非本 lane。

## 6. 产物清单

- /dev/shm/rugra-tests/sb-getsrvname/:oracle_ap_get_server_name{.c,.stderr}
  (锁版 oracle 直跑)、rugra_ap_get_server_name.drill、httpd_full_{base,fix,fix2}.c、
  httpd_gate_{base,fix}.c、curl_{base,fix}.c、m_{next_url,match_url,parseconfig}
  .projection、fzdbg/fzraw/postfix/rugra_dumpfn*.stderr(探针记录,探针代码已撤)
- 基线 worktree /dev/shm/rugra-worktrees/getsrvname-base(720551db,对照专用)
