# LANE REPORT — EO2 typesettle（TYPEPROP-NONSETTLING-HTTPD-0001 修复）

- Branch: wt/typesettle @ 2030b576（基=亲父 175511c2 亲测）
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-typesettle；写域实际落地=examples 两驱动+docs（src 零改动）
- Oracle: Ghidra 12.0.4 e40ed130（已验 HEAD=tag）

## 0. TL;DR

**不收敛机制（一句话）**：httpd/单函数驱动的 Architecture 未挂 TypeFactory，`Funcdata::spacebase()`
（funcdata.cc:230-269 的忠实移植）无法给 sp 输入 typelock `TypePointer→TypeSpacebase`，
`RulePtrsubUndo` 的 `isPtrsubMatching` 恒真防线（ruleaction.cc:7138 → TypeSpacebase::getSubType
无符号命中的 1 字节 TYPE_UNKNOWN 兜底，type.cc:2963-2966）失效，于是
`annotateRawStackPtr`（varmap.cc:386-408）的 `PTRSUB(sp,#0)` 注解被
`ptrsubundo→identityel→propagatecopy→earlyremoval` 五连环每轮拆净、下一轮再注解，
mainloop rule_repeatapply 永不达不动点 → 15s TIMEOUT。

## 1. 定位链（工件在本目录与 /dev/shm/rugra-tests/sb-typesettle/）

1. 工件读数：ap_build_cont_config(273/840)/ap_log_rerror(302/840) 均为
   `WARNING: Type propagation algorithm not settling` 后 **TIMEOUT (>15s)**（非 panic）；
   其余 14 个同警告函数正常完成 → 挂死在警告之后的管线尾部。
2. gdb（setsid+进程组 SIGINT，绕 ptrace_scope=1）双采样：自旋线程分别命中
   `Heritage::heritage` / `ActionMultiCse::apply` → 非单一内层循环，是 mainloop 级不收敛。
3. RUGRA_STAGE_DRILL 阶梯（1.33M DEBUG 记录）尾部：每轮 mainloop 固定五连变更
   `restructure_varnode → ptrsubundo → identityel → propagatecopy → earlyremoval`，
   振荡 op=`0x41e68:41498`（`u… = r0x20(i) -> #0x0` 每轮重建→拆净，净零变化）。
4. 逐环对照 oracle：五规则本体、TypeSpacebase::get_sub_type、is_ptrsub_matching、
   propagatecopy 守卫全部忠实；分歧行=spacebase() 的 typelock 腿被
   `if let Some(types) = arch…` 跳过。临时探针（已撤）实证点火时
   `sb=true, tl=false, vtype=Int`；curl 驱动有 set_types（curl_decompile.rs:1914-1939）
   而两驱动缺 → curl 收敛、httpd 两函数振荡的完整解释（振荡还需"裸 sp 被非加性 op 读"
   形态，故仅 2/470 触发）。

## 2. 修复（照 oracle Architecture::init 链）

- `examples/httpd_decompile.rs`：tracked_context_architecture 补
  TypeFactory::new(8) + cspec data_organization 解码（architecture.cc:1269）+
  setup_sizes（:1350）+ arch.set_types（=curl 驱动同款；oracle buildTypegrp :1398 无条件）。
- `examples/rugra_decompile_func.rs`：同款最小挂载（此前完全无 Architecture）。
- src 零改动；临时探针（ruleaction.rs/funcdata.rs 各一段 eprintln）已撤，git diff 干净。

## 3. 验收（全部亲测，release 构建）

| 门禁 | 数字 | 对比基线（亲父 175511c2=EJ lane 亲测） |
|---|---|---|
| 两函数单函数跑 | 双双收敛 exit=0，警告 0 | 修前 TIMEOUT（>15s 挂死） |
| httpd 全量 | **470/470, 零 TIMEOUT**；警告 16→5（余 5 均能完成=对齐"仅警告"语义） | 468/470 |
| httpd 全量 L2 vs direct-runner | **37677/2/0** | 37542/2/0（+135=两函数 0→产出；defects 恒 2=既有空 else 家族，无新增） |
| curl E2E vs canonical | **2593/0/0** | 恒等（与 EJ 工件仅 2 行 `} while` 格式差=dd22aba5 基线树演化，非本修） |
| httpd 门禁面（29 fns） | **2225/0/0** | 2335/0/0（skeleton −110=指针类型传播激活贴近 golden typed-store 形态；0/0 保持） |
| 三投影 | **MATCH×3**（next_url/match_url/parseconfig.constprop.0，stage+snapshot identical） | 保持 |

## 4. 新暴露移交

1. `PRINTC-BADSPACEBASE-RENDER-0001`（P3）：修后 sp 输入获真实类型态，门禁面 3 处
   `BADSPACEBASE *in_register_00000020` 声明泄漏（golden 零此形态）；printc/varmap=EK2
   占用域，登记不写。
2. `HTTPD-DRIVER-ARCH-INIT-0001`（P3）：httpd 驱动仍缺 set_register_xref/set_commentdb/
   archid 三件（curl 侧有）；独立于收敛根因，不扩 scope。
3. 两函数输出与 oracle golden 仍有大形态差（粗糙参数/BADSPACEBASE/未消化 op）——
   收敛≠对齐，属既有 L2 长尾（golden：299/328 字节成熟形态）。

## 5. 产物清单

- /dev/shm/rugra-tests/sb-typesettle/：httpd_full_fix.{c,stderr}（全量）、
  httpd_gate_fix.{c,stderr}、curl_fix.c、fix_ap_*.c（单函数）、m_*.projection、
  bisect_*.txt、drill 尾段样本 drill_tail.txt、gdb 采样 intdump*.txt
  （abcc_drill.txt 1.4GB 与过程样本已按回收纪律清除）
- 本目录：LANE_REPORT_EO2.md + 门禁/单函数/投影/bisect 关键工件
