# Lane EH2 — CR4 REJECT 返工终报（BOOMATTR r2）— 2026-09-23

branch `wt/boomattr` @ **1c7bde2b**（= 13f080fd r1 + CR4 三修正；full hash
`1c7bde2b93e43b1efa8539c9ed117ea03277095a`，投影 producer 行已自证）
oracle: Ghidra 12.0.4 `e40ed130` | CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-boomattr
write-set: `src/coreaction.rs` + `src/funcdata.rs` + docs（TODO_BOARD/api 两份）；fspec.rs 未动

## 0. 交接纠偏（过程记录）

- 前会话（配额墙中断）实际已完成 src 修正并跑完 r2 门禁，仅剩提交动作；
  commitmsg 的 `Rugra:` 行缺 `:<line>` 被 evidence checker 拒——即真实断点。
- 本会话（EH2）：不采信任何声明，本人重读 oracle（coreaction.cc:4784-4830、
  funcdata_varnode.cc:486-537、action.cc:285-330、varnode.cc:1831-1945）逐条
  复核后，修复 message 行并提交；全部门禁以 r3 重建二进制独立复跑。

## 1. CR4 三修正确认

| # | CR4 判定 | 修正 | 本人核对锚点 |
|---|---|---|---|
| M1 | 重叠扩展内循环升序不含自身，偏离 oracle | `input_vns[..=idx].iter().rev()`（含自身降序） | coreaction.cc:4794 `*iter++` 越过当前 → cc:4803 `iter2=iter` → cc:4805-4807 `--iter2; vn=*iter2` 首访当前自身再降序到首输入；varnode.cc:1836-1837 证 beginDef(input)=def_tree 输入类按 location 升序 ⇒ rev 切片逐字镜像 |
| M2 | count 通道静默缺失 | `count: i32` 字段 + cc:4826 每次 adjust +1 + `take_count_delta`(mem::take) | **接上了既有等效机制，无降级、无 TODO**：src/action.rs:338-339 `state.count += take_count_delta()` → :345-352 `lcount<count → issue_warning+count_apply+=1` → :357 repeat 门，逐字镜像 oracle action.cc:298+；该通道为框架既有（38 个 Action 已接：coreaction.rs:10340/6354、condexe.rs:1776、blockaction.rs:88…），apply 返回保持 0（cc:4828） |
| M3(次要) | adjust_input_varnodes 三处 `throw LowlevelError` 被静默 continue | 收集成员资格=起始偏移∈[addr,endaddr]（beginDef/endDef Address 序）；尾部越界→`Error::Lowlevel("Cannot properly adjust input varnodes")`（cc:505-506）；`!isInput‖sz<=size`→`Error::Lowlevel("Bad adjustment to input varnode")`（cc:512-514；`sa<0` 经 gather 起点保证不可达，代码注释声明） | funcdata_varnode.cc:494-531 逐行对照 ✓ |

## 2. 三门禁（r3 本会话独立复跑；r3 输出与 r2 逐字节相同 = 确定性自证）

| 门禁 | r3 数字 | vs r1 基线 | r3 vs r2 |
|---|---|---|---|
| curl default（vs canonical 1204） | **2684/0/0**（124 函数） | 同（2684/0/0） | cmp 零差异 |
| curl RUGRA_MIRROR vs canonical | **4064/0/0** | 同 | cmp 零差异（亦=r1 逐字节） |
| curl RUGRA_MIRROR vs direct-runner | **3118/0/0**（117 函数） | 同 | cmp 零差异 |
| httpd RUGRA_MIRROR vs 1204 | **2099/0/0**（28 函数） | 同（≤2104 ✓） | cmp 零差异 |
| cargo test --lib | 1650 pass/**18 fail**/5 ignore | 18 fail=r2 基线集 ±1 flaky 排列（add_rax_imm↔ssa_single_block，**两者 solo 均过**=已知并行 flaky 族） | 无新增 |
| LowlevelError 触发 | **0**（default+MIRROR+httpd stderr grep） | 同 | — |

master 侧参考（root 提供）：master 175511c2 = 2593/2335、EK 待并 = 2516/2335。
本链 default 2684 高于 master 侧系**链基差**（wt/dupdecl 链 + f2string 输入面扩大 +
canonical(DWARF) vs 镜像(裸 BFD) 契约差 GOLDEN-CONTRACT-PUSHABSORB-0001，root 裁决
开放中，见 LANE_EH §4 残差④）；链内自身为 2689→2684（r1 修复 -5），r2→r3 零漂移，
defects/numbering 全 0。

## 3. 双投影（r3 新生成，producer 行自证 commit=1c7bde2b）

- next_url：vs sb-oracle 锁定 oracle 投影 **仅 META 身份 4 行**（side/producer）→ **MATCH**
- match_url：同上 **仅 4 行** → **MATCH**
- r3 vs r2 投影：仅 producer tree-hash 1 行（13f080fd→1c7bde2b），stage 体零差异。

## 4. M1 链式跨骑触发差异：**零**

- 证据：default/MIRROR/httpd 三输出 r3↔r2↔r1 逐字节相同（cmp 零差异）+ 双投影 stage 体
  零差异 ⇒ 本语料（curl 124 + httpd 28 函数）**无 ≥2 步向下扩展链**场景。
- 论证：单重叠扫描对方向不敏感（同一重叠无论升序降序都会被吸收）；只有同趟扫描内
  "高位输入下扩 vdata.offset → 更低位输入变为跨骑"的链式场景才使升序/降序产生可观察
  分歧——逐字节相同即证明未发生。该修正消除的是 CR4 判定的**潜伏语义雷**，非本语料
  可观察差异。

## 5. 残差（不变，r1 Differential ①②③④ 继续有效）

①BOOMATTR-INSTACK-SYMATTACH-0001（P2，print/参数符号吸附域）；②TypeFactory 未知类型
命名轨道（undefined8 vs xunknown8）；③body 级=master 既有；④canonical 契约差=
GOLDEN-CONTRACT-PUSHABSORB-0001（root 裁决开放）。

## 6. 移交

- **CR6 复审请求（机制 C，root 派发）**：主管线 Action 改动，对象 commit **1c7bde2b**。
  复核者须自读 coreaction.cc:4784-4830、funcdata_varnode.cc:486-537、action.cc:285-330、
  varnode.cc:1831-1945 对照 commit Evidence 块；重点：M1 遍历方向逐字性（iter2=iter
  含自身降序 + def_tree 序）、M2 count 通道等价性主张（action.rs:338-345 ↔
  action.cc:298）、M3 错误契约三站点与 sa<0 不可达论证。
- 工件：/dev/shm/rugra-tests/sb-boomattr/（r3_*.{c,err}、r3.*.projection、
  failures/r3_failures.txt、commitmsg_r2.txt）；target 目录保留至 root 集成后回收。
