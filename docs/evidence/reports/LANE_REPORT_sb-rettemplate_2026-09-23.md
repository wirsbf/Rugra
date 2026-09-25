# LANE REPORT — DU: RET-OP3-0001(wt/rettemplate)2026-09-23

- 基线: master 94f3bf58;交付 commit: **52b016f1**(wt/rettemplate)
- Oracle: Ghidra 12.0.4 e40ed130(sleigh_specs/x86-64.sla 锁定语言文件)

## RET 模板真身(锁定 .sla 探针 oneInstruction 一手 dump)
- `ret`(C3)= 三 op:`LOAD reg:0x288(RIP):8 <- const:0x3:8(ram spaceid), reg:0x20(RSP):8`
  → `INT_ADD RSP <- RSP, 8` → `RETURN <- RIP`
- `ret imm16`(C2)= 四 op:同 LOAD + `INT_ADD +8` + `INT_ADD +zext(imm16)`(imm=0x8000
  实测 const 0x8000:8 零扩展;pop 尺寸 bump 是独立第二个 INT_ADD)+ RETURN
- 旧 Rugra 发射裸 `RETURN <- const:0`(单 op,非 oracle 形态;其注释"对齐 ia.sinc"与
  DL 的 CALL 发现同族被 .sla 实测推翻)

## 门禁(全部亲测)
| 门禁 | 结果 | 判定 |
|---|---|---|
| curl E2E vs ghidra_curl_1204 | 124 函数 skeleton **2665** / defects 0 / numbering 0(main=605/getparameter=748/next_url=103/match_url=76) | ✅ ==任务书 2665,双 MATCH 保持 |
| httpd E2E vs ghidra_httpd_1204 | 29 函数 skeleton **2331** / defects 0 / numbering 0 | ✅ ==任务书 2331,双 MATCH 保持 |
| 亲父 Differential(94f3bf58) | curl sha256 ce12468c…、httpd sha256 55bd2076… 双侧字节级恒等(diff 0 行) | ✅ 零漂移 |
| lift fixture 逐 op 对拍 | ret/ret 0x8/ret 0x8000 三形态 op 序列(op/输出/输入/顺序)vs sla_probe 全同 | ✅ MATCH×3 |
| lib 测试 serial --test-threads=1 | child 18 失败 == 父基线亲测 18,child-only 失败集空(并行 ±5 波动=预存 FFI 顺序态 flaky,父基线同样波动) | ✅ 无新增 |
| hook 四件套 | gate_health OK / doc_sync OK / annotations --all OK / refs --all --strict OK;机制 A 4/4 | ✅ |

## 提交内容(5 文件,+108/−6)
- src/disasm/x86_lift.rs:lift() 'ret' 臂三 op 化(RIP LOAD/INT_ADD +8/RETURN[RIP],
  C2 追加 INT_ADD +zext(imm16))
- src/funcdata.rs:test_seq_mov_add_ret_alignment 手写计数 11→13(写域波及披露:
  仅一个 #[test],与 w-scopefix 租约区域零重叠)
- docs/api/disasm/x86_lift.md + docs/api/funcdata.md + docs/TODO_BOARD.md(RET-OP3-0001 行 done)

## 未决问题(转 orchestrator)
1. **RC1(CALL 三 op)未并入 master**:本 lane 独立实现 RET(未 cherry-pick b00bf54d,
   避免 RC1 的 httpd 2667 回归(CALLSPEC-0001 未落)破坏本 lane 门禁)。两改动同 arm
   不同分支,合并冲突面极小。
2. **test_seq_mov_and_shl_ret_alignment 预存失败**:master 94f3bf58 亲测 2/2 失败
   (期望形态停在 FLAG-PCODE 之前的 6-op COPY 链)= funcdata 测试债,归 funcdata 域。
3. **retf(CB/CA 远返回)**:仍 `_ => {}` 未实现臂(既有,P-code 完整性遗留)。
4. TODO_BOARD:621 行冲突矩阵 "x86_lift.rs=w-sse" 陈旧(wt2/sse 已并入 HEAD),建议 root 清理。
5. lib 测试 FFI 顺序态 flaky 族(funcdata alignment/ssa_rename/varnode equate,
   serial 18 稳定/并行 ±5)——预存基础设施问题,未登记 TODO,建议 root 立案。

## 产物(/dev/shm/rugra-tests/sb-rettemplate/)
sla_probe/{Cargo.toml,src/main.rs}(可重跑探针)、sla_probe_out.txt、
lift_fixture/{Cargo.toml,src/main.rs}、lift_fixture_out.txt、
curl_{parent,after}.{c,err}、curl_after.compare、httpd_{parent,after}.{c,err}、
httpd_after.compare、libtest_{parent,child}_serial*.txt、x86_lift.rs.child、commit_msg.txt

## 接手复验(2026-09-23,fixer-2,全部亲测自 commit 52b016f1 干净树)

前任会话在 commit 后丢失;本复验自干净 worktree(HEAD=52b016f1,git status 空)重建并重跑全部门禁:
- example 构建:cargo build --release --example {curl,httpd}_decompile EXIT=0(5m17s,
  指纹未变 no-op 复核;前一轮全量 cargo build --release EXIT=0 4m45s)
- curl E2E EXIT=0:124 函数 skeleton 2665/defects 0/numbering 0(main=605/
  getparameter=748/next_url=103/match_url=76),输出与 lane 工件字节级相同
- httpd E2E EXIT=0:29 函数 2331/0/0,输出与 lane 工件字节级相同
- next_url 投影 bisect:kind= MATCH,335 stages/96457 ops(vs baseline_8144a7bf.projection)
- match_url 投影 bisect:kind= MATCH,340 stages/80385 ops(vs curl.match_url.oracle.projection)
- cargo test --lib test_seq_mov_add_ret_alignment:1 passed/0 failed(serial)
- 注:master 后续并入 DV debugproto(2614)与本 lane 正交,未交互,数字==亲父基线
- 回收:/dev/shm/rugra-tests/sb-rettemplate 已清;B2 fixture+复验证据归档
  /dev/shm/rugra-reports/sb-rettemplate-fixtures/;/dev/shm/rugra-targets/sb-rettemplate
  留 root merge 后清扫(AGENTS.md 回收纪律)
