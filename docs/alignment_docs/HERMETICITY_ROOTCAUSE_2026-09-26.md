# HERMETICITY 根因裁决报告 — PAREVAL-DETERM-HERMETICITY-0001（2026-09-26，Lane HERMIT）

> 车道 wt/hermit（基=master 0e2c87d5）；oracle=Ghidra 12.0.4 锁定 commit e40ed130。
> 姊妹文档：`docs/alignment_docs/PARALLELIZATION_DESIGN_2026-09-26.md`（wt/pareval，
> 已并 master a6822ae8）§2.5 为本缺陷的并行化视角；本文档为根因+裁决+修复的权威记录。
> 车道终报（含门禁原始输出）：`/dev/shm/rugra-reports/LANE_HERMIT_2026-09-26.md`。

## 1. 缺陷现象（PAREVAL PoC 门禁抓获，HERMIT 复现确认）

sqlite3 `shell_exec`（3967B 输入）同函数同输入在同一进程内因**前置反编译函数集合不同**
产生两个字节变体（现 master 尺寸 38519B；PAREVAL 证据期 38491B，master 前进所致，
现象同构）：

- **变体 A** fnv `4110e793cfd7eef9` / md5 `78c3ba8c`
- **变体 B** fnv `1e655d11f680b997` / md5 `208dad82`
- 唯一文本差异：`pppppbVar20 = (byte *****)0x0;` 与 `param_2 = (byte *****)0x0;`
  两条相邻零赋值语句互换（输出 652/653 行）。

剂量实验（前置集 {k..5} 后 shell_exec，单进程主线程）：k5:A k4:A k3:B k2:B k1:A
k0:A（HERMIT 复现；PAREVAL 证据期 k5:B k4:A k3:A k2:B k1:A k0:A——**非单调**）。
HERMIT 新增观察：**同协议跨进程可翻转**（--dump 协议下 k3 一进程 B、另一进程 A）
——ASLR 参与扰动，强指向地址序通道。串行同样受害（非并行引入，并行只是暴露面）。

## 2. 根因（文件:行级污染链）

**定位方法**：给车道探针（`examples/hermit_probe.rs --dump`）加"参考运行自身全状态
转储"——主线程剂量梯跑 shell_exec 后，从**产出该文本的同一 Funcdata** 转储全部基本块
（索引/出边/全 op：SeqNum addr+time+opcode+输入输出）与结构树全走。同剂量不同变体的
两份转储 diff（归一化 iop 空间裸指针偏移后）：

- 块 021（0x33ce1）两条影子 COPY `COPY Unique:100010e2:8 = Const:0` /
  `COPY Unique:100010ea:8 = Const:0` **创建序/块内位序完全一致**；
- 但 0x33e71 处两个 MULTIEQUAL 的输入 0 接线互换：
  变体 B 进程 `ME(Rb8)←e2, ME(R90)←ea`；变体 A 进程 `ME(Rb8)←ea, ME(R90)←e2`；
- 名字按 ME 目标恒定（ME(Rb8) 的影子印作 `param_2`，ME(R90) 的印作 `pppppbVar20`），
  故 temp→ME 分配序翻转直接表现为两条打印语句互换；
- 4 字节族零 COPY 的 SeqNum time 同样置换（26323/26326/26327/26325 ↔
  26325/26322/26323/26327）= 同机制多实例。

**污染链**（Rugra → Ghidra 对照）：

1. `src/coreaction.rs` `ActionConditionalConst::collect_reachable`：phi 边向量旧表示
   `Vec<(usize, usize)>`，元素 0 = `Arc::as_ptr(op_arc) as usize`（op 的**裸堆地址**）。
2. `phi_node_edges.sort()` 按元组序 = **按堆地址排序**。
3. `handle_phi_nodes` 按此序对每条断连 phi 边调 `place_copy`（cc:4200-4222 形：
   `new_op` + `new_unique_out`（**fresh unique temp 从 Funcdata uniq 计数器分配**）
   + 分支前 `op_insert`）→ **temp 分配序 = 块内插入序 = 最终打印语句序 = 堆地址序**。
4. 堆地址受进程内前置反编译的分配历史扰动（非单调剂量响应）+ ASLR 扰动（跨进程翻转）。

**Ghidra oracle 语义（亲读）**：`collectReachable`（coreaction.cc:4090）
`sort(phiNodeEdges.begin(),phiNodeEdges.end())` 的比较器是
`PcodeOpNode::operator<`（**expression.hh:41-48**）：

```cpp
if (op != op2.op)                       // 指针只做相等性检查
  return (op->getSeqNum().getTime() < op2.op->getSeqNum().getTime());  // 排序键=SeqNum time
if (slot != op2.slot) return (slot < op2.slot);
return false;
```

`handlePhiNodes`（coreaction.cc:4299-4333）按排序后序迭代调 `placeCopy`。
**Ghidra 的边处理序=SeqNum time 序=逻辑确定序**；Rugra 旧端口把排序键换成了堆地址
——这是移植缺陷，非 oracle 行为。

## 3. oracle 裁决（决定性，前次会话完成，HERMIT 复核协议）

锁定 oracle 环境 `/tmp/rugra-ghidra-bfd-2.38`（binutils 2.38 BFD），runner
`hermit_oracle_1204`（BfdArchitecture + registerBfdFunctionSymbols + registerPltStubs
+ decompileFunction，golden_dump_1204 协议；源码与构建脚本归档
`/dev/shm/rugra-tests/hermit/`，重建配方 `build_hermit_oracle.sh`）。

三模式矩阵（函数集与剂量语义逐字复刻 Rugra PoC：largest-first truncate(8) 跳过病态
idx 8/24/30 后地址序，shell_exec=f006）：

| 模式 | 含义 | 结果 |
|---|---|---|
| solo ×3 | 新进程只解 shell_exec | fnv `0x9cf3421e9e9cd852` / 39257B 恒定 |
| dose k=5..0（+重复 k2/k0） | **一个 BfdArchitecture 全程共享**（Ghidra 控制台形态） | 同上恒定 |
| dose-arch k=5/2/0 | 每函数新 BfdArchitecture（Rugra isolated 形态） | 同上恒定 |

全部 13 跑 md5 `421ce710db36a43971d8cae24b5f8587`。**裁决：oracle 在共享与隔离两种
Architecture 形态下均封闭（单变体）→ Rugra 双变体是对齐缺陷**（非"oracle 也非封闭"
的文档化情形）。

**方向验证**：oracle 输出（oracle/dose-k0.c:643-644）该处语句序为
`ppppuVar18 = (uint1 *****)0x0;` 先、`param_2 = (uint1 *****)0x0;` 后——与 Rugra
变体 A 同序。修复后 Rugra 确定性收敛到变体 A=**朝 oracle 方向**。

## 4. 修复（src/coreaction.rs，空闲域直接修）

`phi_node_edges` 表示 `Vec<(usize, usize)>` → `Vec<(PcodeOpRef, usize)>`（Arc+slot）：

- `sort_by` 按（SeqNum time, slot）逐字镜像 `PcodeOpNode::operator<`
  （ptr_eq 相等检查 → time 比较；同 op → slot 比较）；
- `binary_search_by` 成员测试用同序比较器（cc:4106 `binary_search` 镜像）；探针 time
  提升出闭包——外层 `op` 读守卫存活，防同锁再入死锁；
- `handle_phi_nodes` 直接持 Arc 按排序后序迭代（去掉旧 alivelist 裸指针 O(n) 线性
  找回；Ghidra 无存活过滤，且 push（cc:4413/4424）→handle（cc:4459-4464）窗口内
  零 op 销毁，propagateConstant 亲核）；
- `place_multiple_constants`（死代码，见 §6 缺口）同步新类型签名，行为零变化。

## 5. 验证

- **剂量实验**：k=0..5 全部恒等 fnv `4110e793…`（变体 A），k=6（首跑 typedef 闩锁
  面，见 §6）除外；**双进程复跑一致**（ASLR 不再影响）。
- **IR 全量转储**：7 剂量 × 2 进程的 IR 转储，归一化 iop 地址后**单一 md5**
  `e8ff397a…`——完全封闭。
- **语句序**：k3（修复前=变体 B）现输出 `pppppbVar20` 先 `param_2` 后=oracle 序。
- canon 双语料/镜面四面/bank/cargo test --lib/三门禁/sqlite3 1385 面：见车道终报
  `/dev/shm/rugra-reports/LANE_HERMIT_2026-09-26.md`（本缺陷修复仅重排 ActionConditionalConst
  影子 COPY 放置序，凡地址序恰等于 time 序的函数输出不变）。

## 6. 残差与登记票

1. **CONDACT-FLOWTOGETHER-LEG-0001**（P2，新票）：oracle `handlePhiNodes` 的
   `flowTogether`（cc:4174-4235）+`placeMultipleConstants`（cc:4236-4254）腿在 Rugra
   端为死代码（无调用者）——多条断连边流共一常量时应放单一共享 COPY，Rugra 一律
   各放独立 COPY（输出形态偏差）。预存缺口，非 HERMIT 引入；本修复仅同步签名。
2. **CONDACT-IOP-PTRFACE-AUDIT-0001**（P3，新票）：Rugra iop 空间偏移=op Arc 裸指针
   （Ghidra 同为 C++ 指针值，编码形态同族）；本缺陷中该通道证伪（归一化后零结构差异），
   但"iop 偏移被当排序键"的同类模式审计义务登记在票。
3. **typedef 进程闩锁**（已知设计非缺陷）：`src/printc.rs:21` 进程级 latch 使
   Ghidra 风格 typedef 前导块每进程只发射一次（模拟 Ghidra 全文档一次性）——k6（首跑）
   有前导块、后续剂量无。golden 门禁已归一化（compare_ghidra.py 剥 typedef 行），
   PoC 逐函数比较不受影响；严格逐函数封闭语义下的豁免已在
   PARALLELIZATION_DESIGN §2 确定性协议中声明。
4. PAREVAL 嫌疑通道 (a) TypeFactory 单例、(b) iop Arc::as_ptr 在**本缺陷**中证伪
   ——双变体唯一 IR 结构差异在 ActionConditionalConst phi 边分配，TypeFactory 单例
   争用仅是性能面（PAREVAL-PHASE1-LAND-0001 域）。

## 7. 并行化封闭性协议结论（并入 PARALLELIZATION_DESIGN 结论）

1. **根因既除，per-worker 进程隔离不再是正确性必需**：缺陷是"排序键=堆地址"这一
   单点移植偏差，修复后边处理序=SeqNum time 序（逻辑确定），同进程多函数反编译
   恢复铁律 2.1 进程模型前提。
2. **仍建议保留 per-worker 进程隔离作为防御层**：本缺陷证明"Rust Arc 地址渗入排序键"
   是可发生、难察觉、仅被差分门禁抓获的缺陷类。建议后续对全部 `Arc::as_ptr` 位点
   做排序键审计（CONDACT-IOP-PTRFACE-AUDIT-0001 已开首票）。
3. **PoC 门禁预期**：修复后 `examples/pareval_poc.rs` sqlite3 面（skip 8/24/30）
   应全 GREEN（shell_exec 双变体消除）；该验收归 PAREVAL-PHASE1-LAND-0001。
4. **判定准则沉淀**：任何"同函数同输入多字节变体"缺陷，第一步做**参考运行自身
   全状态转储 diff**（不重跑不换线程——ladder 重跑与线程栈都会扰动被观察通道，
   trA/trB→vA/vB 迭代的教训），归一化已知无语义的裸指针面（iop 偏移）后再看结构
   差异；本例 30 分钟内从"两个变体"收敛到"哪两条 op 接线互换"。
