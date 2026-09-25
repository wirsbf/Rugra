# LANE REPORT — GG2 / wt-smallfns (sb-smallfns)

**Lane**: GG2 续跑（配额墙中断，接手同 worktree 双驱动 WIP）
**Branch**: `wt/smallfns` @ **af6c5ee2**（亲父 00829949；master 已前移，数字以亲父为准，合并交 root）
**Worktree**: /dev/shm/rugra-worktrees/smallfns；CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-smallfns
**Oracle**: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b（golden corpus 差分口径；机器重启后 /tmp oracle 环境未重建，无新 oracle 侧运行）

## 零差函数清单（严格字节：头部注释 + 函数体 diff=0）

| # | 语料 | 函数 | 备注 |
|---|------|------|------|
| 1 | curl 0x103410 | `__do_global_dtors_aux` | completed_8061 + (undefined*)0x0 cast + __dso_handle |
| 2 | curl 0x103450 | `frame_dummy` | 前代 ledger-body/共享返回修复后收零 |
| 3 | curl 0x104960 | `main_init` | `return CURLE_OK;` |
| 4 | curl 0x104970 | `main_free` | unknown-model 警告形 |
| 5 | curl 0x103c50 | `SetHTTPrequest`(.part.0) | `*store != HTTPREQ_UNSPEC` |
| 6 | curl 0x104a00 | `hugehelp` | 六字面量 + 警告形 |
| 7 | curl 0x104f70 | `glob_url` | 头部 116B ledger 尺寸 |
| 8 | httpd 0x12b7fa | `switchD_00154265::default` | 头部 image-base |
| 9 | httpd 0x12b804 | `switchD_00177493::default` | 同上 |
| 10 | httpd 0x12b80e | `switchD_0017766d::default` | `undefined8` 返回 |

## 族归类

1. **枚举常量族**（main_init/SetHTTPrequest；getparameter 顺带 −6）：
   `TypeOpReturn::getInputLocal`（typeop.cc:883-897）缺失覆写 → RETURN 输入播种不到
   proto 输出枚举类型；DWARF 枚举缺 ENUMTYPE 旗标；printc Enum 元类型落默认 cast 臂。
   修：typeop.rs:230 fd-form 覆写 + varnode.rs:315 RETURN 臂（fd 穿线）+
   debugproto.rs:1670 旗标 + printc.rs:1558/15628 Enum 臂（exact-member else 整数）。
2. **未锁返回类型族**（httpd default#3）：ActionOutputPrototype 简表（size→byte/int/long）
   违铁律 1.4 → 重写为 coreaction.cc:4765 端口（getFirstReturnOp→updateOutputTypes）+
   fspec.rs:1596 None→getBase(size,TYPE_UNKNOWN) 折叠（undefined8 oracle 见证）。
3. **程序符号族**（__do_global_dtors_aux）：worker ELF OBJECT 扫描漏点→下划线与
   st_size==0 跳过（completed.8061 顽固、__dso_handle 缺名）；GOT PTR_ 槽未 typelock
   （比较 0x0 无 (undefined*) cast）；头注释 base-0/ELF 尺寸 ≠ golden image-base/ledger。
4. **前代 WIP 收编**（已核证保留）：op.rs create 即注册 code-list；printc opStore 双打印
   （cc:500-518）；maptable end 序键（rangemap.hh:100-102）；DWARF-NAME-PRECEDENCE/
   strip_gcc_suffix；DWARF-VOID-UNKNOWN-MODEL；httpd loader/stringmgr/lea-codeptr。

## 三门禁（亲父 00829949 基线 = sb-smallfns/{curl,httpd}_base.c 10:12 运行档）

| 门禁 | 亲父 | 终态 | 判定 |
|------|------|------|------|
| curl 全量差分 | 1970 / 0 / 0 | **1701 / 0 / 0** | 过；逐函数零回退（41 fn 改善） |
| httpd 差分 | 1960 / 0 / 0 | **1781 / 0 / 0** | 过；本代零回退 +5 改善* |
| gcc 审计 curl | 102 OK / 22 FAIL | **103 / 21** | 过（新 2 FAIL=枚举名 undeclared，golden 同形 parity；glob_set/_init 修复） |
| gcc 审计 httpd | 7 / 22 | **8 / 14** | 过 |
| cargo test --lib | — | 18 失败 = master 预存集逐名一致 | 过（零新增） |
| 五投影 | — | MATCH ×5（非 META 逐字节） | 过 |

\* ap_vhost_iterate_given_conn 48→50 vs 亲父：session-start 快照（前代 WIP 态）同值 50，
即前代遗留非本代引入；函数深残（UNRECOVERED_JUMPTABLE/IR 面），绑 RESIDMAP 族。

## 工具变更

`tools/compare_ghidra.py::match_functions` 头部地址双向归一（addr / addr−base /
addr+base / by_name 末选）：image-based 头形态下旧 by_addr 单形态使 44 组
PLT-thunk↔EXTERNAL 同名对错配（假 +5×44 回归）；base-0 头输入行为不变。

## 残余/交接

- 机制 C Cross-Review：**PENDING**（coreaction/typeop 主管线面，待独立 agent，root 集成门）。
- curl 尾 PLT-thunk `/* WARNING: Unknown calling convention */` 缺失族仍开
  （PLTSTUB-WARNLOSS-0001 域，本 lane 未动）。
- getparameter −6 来自枚举族顺带，非本 lane 验收面。

## 产物回收

- /dev/shm/rugra-tests/sb-smallfns/：保留 curl_final.c / httpd_final.c / commit_msg.txt /
  perfn_*.txt / strict_diff.sh；清 proj/（~100MB 投影）与中间 v2/v3/gg2 档。
- /dev/shm/rugra-targets/sb-main-check（master 侧测试探针 target）已删除；
  sb-smallfns target 留待 root 集成后统一回收。

---

# 追记：CR29 返工交付（26109524）

**件④两修**：
1. fspec.rs 空表臂：clear_unlocked_output 委托（仅清锁标志）→ 真 store->
   clearOutput() 语义（return_type 无条件复位 void 基类型，fspec.cc:3389-
   3395/3262-3270）；af6c5ee2 Evidence 的"clear(void)"断言已修正。
2. printc.rs 枚举两臂：接 TypeEnum::get_matches（datatype.rs:3223-3290
   a1bcaea6 既有移植）完整表示——`A`/`B|A`（贪心自最大命名值，namemap 反向
   同序）/`~A`/`~(B|A)`/`>> n`（amount 无符号 4 字节）；无表示回退无符号整数
   （cc:1685 硬编码 false 含 enum_int）；删"无 getMatches"假注释。

**件①②③附带条件**：typeop/varnode/coreaction 锚行 883→901 族修正（slot0=
907-908、getOutputType=918、失配=919-920）；登记 PROTOSTORE-SIZELOCK-
UPGRADE-0001（locked+TYPE_UNKNOWN 态升级路径缺口，含 fspec.rs:1608 合流
解除条件）。

**验证**：curl 1701→**1697**/0/0（getparameter 473→469）、httpd 1781/0/0；
10 目标严格零差保持；逐函数零回退（vs af6c5ee2 与亲父）；gcc 103/21、8/14
持平；五投影 MATCH ×5；单测稳定失败集 17 全 ∈ master 并集（minimal_
alignment 族并行漂移 master 侧同现，18↔21，非本 diff 引入），新增
enum_match_text/enum_rep_text 两单测过（shift 形态 rep 直驱）。

**Commit**: `26109524`（wt/smallfns @ af6c5ee2 之上）。CR30 待重审件④两子项。
