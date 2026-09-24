# Lane EH wt/boomattr — curl +1488 爆炸归因与自函数参数恢复修复 — LANE REPORT 2026-09-23

branch `wt/boomattr`（/dev/shm/rugra-worktrees/boomattr）
= wt/dupdecl@ea71b739（DL RC1+RC2+DP RC3+EC dupdecl 链尖）
+ **cherry-pick 4c53bfeb**（f2string RuleLoadVarnode addrtied 修复，爆炸复现必要件）
+ **13f080fd**（本 lane 交付）

oracle: Ghidra 12.0.4 e40ed130 | CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-boomattr

## 1. 爆炸分解表（第一步交付：top 函数清单与形态分类）

复现口径：RUGRA_MIRROR（库级 BFD 单函数契约——4073 的真实口径，非 default 全分析模式）。
基线（链+f2string，无本 lane 修复）= **4071/0/0** vs canonical golden，unaff_=64。

| 函数 | diff(canonical) | 形态 | 修复后 |
|---|---|---|---|
| main | 911 | 签名塌缩 19 参 raw long 型（每个 used 输入一参） | 909，**2 参 RDI int+RSI int8** |
| glob_set | 190 | body 级（master 既有） | 190 不变 |
| next_url | 144 | 签名塌缩 4 参（含 RBX 4 字节读！）+ unaff 26 | 144，**1 参**，unaff 26=26 oracle 同数 |
| match_url | 133 | 签名塌缩 3 参 | 134，**2 参**（+1=见 §4 残差①） |
| glob_range/myprogress | 108/106 | myprogress 6 参塌缩；余 body 级 | 不变 / **5 参** |
| glob_word | ~335 | 9 参塌缩 | **5 参**（DR oracle 逐形同） |

形态占比（爆炸主体）：**签名塌缩/raw 参化=本 lane 修复对象**；unaff_ 增量=canonical(DWARF)
vs 镜像(裸 BFD) 契约差 + 未合并 high 命名族（direct-runner oracle 同样 26 个 unaff_）；
body 级差异=master 既有残差（default 模式 main=581 同函数族）。

## 2. 根因一句话

`ActionUnjustifiedParams`（fullloop）旧实现是自创 raw 兜底——对每个"未匹配声明参数且有
后代"的输入 varnode 直接造 `param_N`/long 参数（DBG 探针：next_url 的 4 参来自
off=0x18/4B RBX、0x28 RBP、0x38 RDI、0xa0 R12），`ActionInputPrototype`（fixateproto）
旧实现只在参数为空时全量 raw 化；二者都不是 oracle 的 possibleInputParam 门 +
ParamActive trial + deriveInputMap 恢复链——f2string addrtied 修复扩大输入面后该兜底
把未合并 high（RBX/RBP/R12…）全部升参，即 SB-F2STRING-ADDRTIED-PARAMRECOVERY-0001。

## 3. 修复内容（commit 13f080fd）

- coreaction.rs：ActionInputPrototype::apply 按 coreaction.cc:4707-4763 全量重写
  （possibleInputParam 门、def 序 trial 注册、unref/used 物化、updateInputTypes/
  NoTypes、clearDeadVarnodes）；ActionUnjustifiedParams::apply 按 cc:4784-4828 全量
  重写（unjustifiedInputParam+adjustInputVarnodes 重justified，永不造参）；
  bank_has_input_intersection GLUE（varnode.cc:1536-1554）。
- fspec.rs：FuncProto::resolve_model/derive_input_map/unjustified_input_param 新增；
  update_input_types None-fold+param_<n> 默认名；update_input_no_types 全量。
- funcdata.rs：adjust_input_varnodes 空间感知化（旧 spaceless 实现把 304B 合并输入
  落 Ram 空间打印 auRam 巨型输入——修复后 default 模式 match_url 的 DWARF 锁定
  URLGlob 栈容器 adjust 与 oracle 同形）。
- **varmap.rs 零改动**（任务疑点"ScopeLocal 参数条目/RangeHint 参数判定"被实证排除：
  栈参数符号/paramrange 链工作正常，缺口全在 coreaction/fspec 侧）。

## 4. 三门禁（诚实）

1. curl（RUGRA_MIRROR, fast-release）：canonical **4071→4064/0/0**；direct-runner
   golden（同契约 oracle）**3149→3118/0/0**；签名形态全恢复（main 2=2、next_url 1=1
   unaff 26=26、match_url 2=2、myprogress 5=5、glob_word 5=5、_start 3=3）。
   default 模式 2683→2684/0/0（vs 链尖 2689 = -5）。
2. httpd（RUGRA_MIRROR）：**2099/0/0** ≤ 2104 基线 ✓（-5）。
3. next_url/match_url 双投影 vs sb-oracle 锁定 oracle 投影：逐 stage **MATCH**
   （仅 META side/producer 身份 4 行）。
4. cargo test --lib：18 失败=基预存同集（b8031069 A/B 复核，含并行 flaky solo-pass
   子集），无新增失败。
5. 残差：①BOOMATTR-INSTACK-SYMATTACH-0001（P2）default 模式大栈参数 adjust 后
   in_stack_00000008[304] 声明未吸附参数符号（EC 残差②同族，print/符号吸附域）；
   ②未知类型命名轨道 undefined8/unkbyte1 vs oracle xunknown8/xunknown1（TypeFactory 域）；
   ③body 级（main 909 等）master 既有；④canonical 大数=契约差，root 裁决项
   GOLDEN-CONTRACT-PUSHABSORB-0001 开放中。

## 5. 移交/登记

- **机制 C 复核请求**：coreaction 主管线 Action 改动（inputprototype/unjustparams），
  请求独立 cross-review（复核者自读 coreaction.cc:4707-4828 对照 commit Evidence 块）；
  varmap 核心算法零改动，varmap C 通道 N/A。
- **funcdata.rs 域重叠登记**：adjust_input_varnodes 与 EE 车道（master 树 funcdata 域）
  登记重叠，无活冲突（TODO 板 EH 行已声明 write-set 扩展）。
- 产物：/dev/shm/rugra-tests/sb-boomattr/（对拍脚本+前后输出+双投影）；
  target 目录 /dev/shm/rugra-targets/sb-boomattr 保留至 root 集成后回收。
