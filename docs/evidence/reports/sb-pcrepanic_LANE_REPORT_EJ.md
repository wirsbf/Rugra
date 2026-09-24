# LANE REPORT — EJ pcrepanic (PCRE-EXEC-PANIC-0001 根因定位)

- Branch: wt/pcrepanic @ effa7390 (基=亲父 effa7390 亲测;**零 src 改动**,写域 varnode.rs 未动——根因在 ruleaction.rs 非本 lane 域,按占线纪律只登记)
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-pcrepanic(主)+sb-pcrepanic-base(基线复现/正控)
- Oracle: Ghidra 12.0.4 e40ed130(已验 HEAD=tag)

## 0. TL;DR

**不变式破坏点(一句话)**:`RuleSubRight::apply_op` lump 臂(ruleaction.rs:12685)用
`op_unset_input(op,0)` 冒充 Ghidra `data.opUnlink(op)`(ruleaction.cc:7285=funcdata_op.cc:179-193
全量销毁)——被肢解的 SUBPIECE 槽0=共享 null_slot_sentinel 仍活,二次匹配时 sentinel 被当真
varnode 传入 `op_set_input` 获 live descend;SetCasts::cast_input 再对该 free sentinel 插 CAST,
`add_descend` 第二读者触发 varnode.rs:2565 panic(=忠实 Ghidra varnode.cc:336 throw,断言无罪)。

- HEAD(effa7390)pcre_exec **不 panic**(468/470 ok;httpd 全量 lump 臂触发 0 次,DQ/EE 上游
  改动使该输入不再落入 lump 路径)——**地雷仍在**,任何两次落入 lump 臂的语料即复现。
- 修复 spec(一行,载体已存在)已在 **bf3f5064 正控验证**(见 §4)。
- 登记:`RULEACTION-SUBRIGHT-UNLINK-0001`(P1,待派即修)+`HTTPD-FULLEMPTY-ELSE-0001`(P2)+
  `TYPEPROP-NONSETTLING-HTTPD-0001`(P2)。

## 1. 复现与栈(bf3f5064,EG2 panic 确定性复现)

- 复现命令(EG2 仪表盘形态):`RUST_BACKTRACE=full MAX_FUNCS=840 httpd_decompile`
  (release 版 strip=true 无符号;fast-release(strip=false)拿栈)。
- 结果:bf3f5064 = 467 ok + pcre_exec panic(每跑必现,3/3);effa7390 = 468 ok 零 panic
  (release+fast-release 双跑,排除 codegen/调度偶然)。
- panic 栈(probe 产物 httpd_full_basebf3.stderr.log):
  `add_descend ← op_set_input ← ActionSetCasts::cast_input ← ActionSetCasts::apply/perform
  ← ActionRestartGroup ← worker thread`——panic 点是**消费端**,不是破坏点。

## 2. 根因链(三层探针,全部产物在本目录)

- probe1/2(varnode.rs add_descend 注记 first-free-add registry):异常 vn =
  **null_slot_sentinel(Ram|0|0|0,size=0,ci=0,flags=仅COVERDIRTY)**;首读者 =
  RuleSubRight 新建的 INT_RIGHT(start=0x78ed0);registry 回溯首挂栈 =
  `RuleSubRight::apply_op → op_set_input → add_descend`。
- probe3(funcdata.rs new_op/op_unset_input + op.rs mark_alive 按 0x78ed0 过滤生命周期):
  ①UNSET SUBPIECE time=14275 slot=0 parent=**true**,栈=RuleSubRight lump 臂
  (ruleaction.rs:12685,Ghidra 同位是 opUnlink=销毁);②二次应用:NEWOP→ALIVE
  INT_RIGHT **sentinel_slots=[0]**,栈=RuleSubRight op_insert_before——证 a=sentinel 被当真
  varnode 装入新 op。
- 语义核对(Ghidra 逐行):varnode.cc:330-340 addDescend throw(Rugra panic 忠实,禁放宽);
  varnode.cc:1316-1327 makeFree **允许 free-with-descend 瞬态**(descend 由 replace:1343
  特判保留,cc:334 只拦"加第二读者");funcdata_op.cc:179-193 opUnlink=opUnsetOutput+全
  opUnsetInput+opUninsert(**op 死亡**);funcdata.rs:4924 op_unlink 忠实载体已在;
  coreaction.cc:2655-2715 castInput 无 NULL 守卫(Ghidra 侧活 op NULL 槽=不可能态);
  transform/placeInputs 对 NULL 的 cc:107 早退语义(Rugra 共享 sentinel ptr_eq 等价)。

## 3. HEAD(effa7390)门禁+投影(本 lane 亲测,零 src 改动=即亲父基线)

| 门禁 | 数字 | 判定 |
|---|---|---|
| curl E2E vs canonical | **2593/0/0** | ==任务预期 ≈2593(EE +32 已含) |
| httpd 门禁面(29 fns) | **2335/0/0**(双跑恒等) | ≈预期 2337(2 行差,0/0 达标;EE lane 自报 2337 为其分支树,合并后 2335) |
| httpd 全量 L2 vs direct-runner | 37542/**2**/0 | 2 defects=ap_parse_uri(L16)/ap_invoke_handler(L57)空 else,EG2 发现仍在,已登记 |
| pcre_exec 全量 | **不 panic**,468/470 ok | 缺 2=ap_build_cont_config/ap_log_rerror(类型传播不收敛,已登记) |
| next_url/match_url/parseconfig 三投影 | **MATCH×3**(stage_bisect --v1 exit 0) | 保持;**方法论**:必须 `RUGRA_MIRROR=1` 正典 bundle;`RUGRA_FLOW_MIRROR=1` 单件差 1 op(@SNAP2 718 vs 717)致 ordinal-2 假分歧(已用 joinstop MATCH 树 6b4ca15a 对照证实为环境件差异) |

## 4. 修复 spec 与正控(bf3f5064+一行修,fast-release 全量)

```rust
// ruleaction.rs RuleSubRight::apply_op lump 臂(12684-12686)
- fd.op_unset_input(&working_op_ref, 0);
+ fd.op_unlink(&crate::op::PcodeOpRef(op_arc.clone()));   // cc:7285 data.opUnlink(op)
```

正控结果(basefix.stderr.log / rugra_httpd_full_basefix.c):
- `Free varnode` panic **0 次**(未修 bf3f5064 基线 3/3 必现)——panic 链闭合。
- pcre_exec 不再 panic,转归 `WARNING: Type propagation algorithm not settling` 中止
  (bf3f5064 预存独立缺陷,TYPEPROP-NONSETTLING-HTTPD-0001 同族;HEAD 侧 pcre_exec 已正常
  完成,见 §3)。ok 计数 467==基线(pcre_exec 两种失败模式均计入 470-467-2)。
- 修复 spec 对 HEAD 的预期:三门禁恒等风险低(lump 臂 HEAD 全量触发 0 次),但任何触发
  lump 臂的语料输出会变(被肢解 op 不再泄漏)→差分需 ## Differential。

## 5. 产物清单(本目录;结论已录 TODO_BOARD 四行 + 本报告归档 /dev/shm/rugra-reports/sb-pcrepanic/)

- httpd_full.stderr.log / httpd_full_fr.stderr.log(effa7390 release/fast-release 双跑)
- rugra_httpd_full.c / rugra_httpd_full_fr.c(全量输出)
- httpd_full_basebf3.stderr.log(bf3f5064 panic+全栈)/ probe1-3.stderr.log(探针)
- rugra_curl_v2.c / rugra_httpd_gate.c(门禁)/ m_*.projection+mbisect_*.txt(三投影 MATCH)
- basefix.stderr.log + rugra_httpd_full_basefix.c(bf3f5064+修复正控)
- bisect_*{,_ee6007,_6b4ca15a}*.txt(方法论误用 FLOW_MIRROR 单件的 ordinal-2 假分歧证据链)

## 6. 未决移交

1. RULEACTION-SUBRIGHT-UNLINK-0001 待派即修(P1;修后 pcre_exec/同形语料输出可能变化→差分
   需 ## Differential)。
2. HTTPD-FULLEMPTY-ELSE-0001 / TYPEPROP-NONSETTLING-HTTPD-0001(L2 backlog,修域未归因)。
3. httpd 门禁面 2335 vs EE lane 自报 2337 的 2 行差:EE 分支树(6007e957)vs 合并树
   (effa7390=DQ+EE)合并效应,量级在 ≈ 内且 0/0;如需逐行归因归 root(疑 DQ×EE 合并的
   set_varnode_properties/LoadGuard 交互,非本 lane 域)。
