# Lane EW (wt/emitterhang) — HTTPD main stage-emitter 确定性死锁：根因定位与修复

- 日期: 2026-09-23 (Asia/Shanghai)
- worktree: /dev/shm/rugra-worktrees/emitterhang, branch **wt/emitterhang**（基 wt/chainmerge@736982f2）
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-emitterhang（fast-release）
- **修复 commit: 5aaf4ae40b778f86ca4679d673bba7521954f93f**（wt/emitterhang，待 root 集成）
- TODO: HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001 行结案 + -0002 行登记（同 commit）

## 1. 冻结点（一句话）

worker 线程自死锁于 `ActionSetCasts::cast_input` double-cast 臂（coreaction.cc:2680-2684 对应
Rust 臂）：if-let scrutinee 临时读锁（in_vn）贯穿臂体，臂内 `op_set_input` 的 opUnsetInput 腿
写锁 OLD slot 输入（= in_vn 本身）→ 同线程读→写 futex 互等，CPU idle 永久冻结
（输出 76745763B / 76745730B 两轮合并态逐字节确定；default 模式 <1s 正常）。

gdb 双采样（setsid + gdb-as-parent 绕 ptrace_scope=1，SIGINT 前向）：
```
Thread 2 worker:
#2 std::sys::sync::rwlock::futex::RwLock::write_contended
#3 rugra::funcdata::Funcdata::op_set_input        ← funcdata.rs:2235 old_vn.write() (erase_descend)
#4 rugra::coreaction::ActionSetCasts::cast_input  ← coreaction.rs:5198 if-let 读锁存活处
#5 ActionSetCasts::apply / #6 perform / #10 emit_stage_projection
```
证据: /dev/shm/rugra-tests/sb-emitterhang/r3/（r3.gdb.txt 双采样、r3.tasks、r3.ps、冻结投影）。

## 2. 引入 commit（链上逐 commit emitter main bisect 实锤）

| commit | 内容 | emitter main |
|---|---|---|
| b00bf54d (DL RC1) | x86_lift CALL push 三 op 模板 | ✅ 6s 完成 |
| **fb935792 (DL RC2)** | **httpd cspec-backed Architecture 挂载** | ❌ **20s 冻结 (76731680B)** |
| 5430c1ad (DL 合流) | RC1+RC2 | ❌ 冻结（=RC2 尺寸） |
| 736982f2 (round2 合并态) | × master 983e0fc9 | ❌ 冻结 (76745763B) |

归因：RC2 的 cspec 类型让 httpd main 的 IR 首次出现“implied CAST 且 prev 类型 == ct”形态
到达该臂——**锁缺陷是更早潜伏的 Rust 侧锁卫生问题，RC2 只是内容触发器**（master 两树无
cspec 挂载故 emitter 完成不是因为没这个 bug，而是数据从未进该臂）。证据: bisect.*/ 子目录。

## 3. 根因与修复形态

- Ghidra coreaction.cc:2655 castInput 单线程裸指针：cc:2680 先完整读 `vn->getDef()->getIn(0)`
  进 vnin，cc:2682 `data.opSetInput(op,vnin,slot)` 无锁直写——无死锁可能。
- Rugra 镜像处把该读写进 if-let scrutinee 表达式，scrutinee 临时值（含 RwLockReadGuard）
  生命周期延至整个 if-let 块尾 → op_set_input 内 `old_vn.write().unwrap().erase_descend()`
  （old_vn == in_vn == op 当前 slot 输入）自死锁。
- **修复（src/coreaction.rs 1 hunk，语义零变化）**：prev 提取改 `let prev_cast_input = ...;`
  先绑定（读锁随 let 语句结束释放），再 `if let Some(prev) = prev_cast_input`。读序仍=
  cc:2680（先完整读 def 输入、后 opSetInput）。
- 同函数其余读锁点核查：5225 `else if in_vn.read()...is_constant()` 为普通 if 条件（条件内
  即释放，常量臂高频路径从未死锁的运行事实佐证）；5178 lone_descend / 5241 高类型读均为
  语句级临时值——本臂是唯一 scrutinee 形态点。

## 4. 验收（wt/emitterhang@5aaf4ae4）

| 项 | 结果 |
|---|---|
| emitter 模式 httpd main | ✅ **3s 完成**（294 @BEGIN、`stage emitters done`、78MB 完整投影；修复前 >600s 冻结） |
| default curl 全语素 | **逐字节 == 修复前树**（cmp eq2_curl_r2.c 零差异）+ 门禁 **2512/0/0** |
| default httpd 全语素 | **逐字节 == 修复前树**（cmp eq2_httpd_r2.c 零差异）+ 门禁 **2539/0/0** |
| 三投影（RUGRA_MIRROR=1 全家 env） | next_url / match_url / parseconfig.constprop.0 **非 META diff=0 全 MATCH**（META 4 行=side/producer 身份行，按定义差异） |
| 机制 B 差分门禁（coreaction 白名单） | defects=0 + numbering=0 双语素，无未解释缺陷 |
| 机制 C | ActionSetCasts=主管线 Action——交叉复核待 root 集成（本修复纯锁生命周期重排，无算法/顺序/比较键变化；default 语素逐字节回归为最强旁证） |

产物: /dev/shm/rugra-tests/sb-emitterhang/{r3, bisect.*, verify/, repro.sh, bisect_probe.sh, verify.sh}。
worktree 与 target 目录保留至 root 集成后回收（/dev/shm/rugra-targets/sb-emitterhang）。

## 5. root 集成输入

1. wt/emitterhang = wt/chainmerge@736982f2 + 5aaf4ae4（单 commit，3 文件：src/coreaction.rs
   1 hunk + docs/api/coreaction.md + docs/TODO_BOARD.md），无冲突面（chainmerge 之后链侧/
   master 侧均未再动 castInput 该臂）。
2. 建议并入链合并序列：EQ2 §11 的“(b) stage-emitter main 死锁作为并车前置”由本车道解除；
   ap_fini_vhost_config +106 与 GOLDEN-CONTRACT-PUSHABSORB-0001 仍开放（不在本 lane 域）。
3. 机制 C 复核（若 root 要求 APPROVE 块再并）：复核点=coreaction.rs 5214 附近 let 绑定后
   读序与 cc:2680-2682 一致性 + 无其他 scrutinee 读锁点。
