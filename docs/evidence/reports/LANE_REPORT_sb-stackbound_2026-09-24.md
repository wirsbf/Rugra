# LANE REPORT — VARMAP-STACKBOUNDARY-0001 (wt/stackbound)

- worktree: /dev/shm/rugra-worktrees/stackbound, branch wt/stackbound
- base: master **bc22461d**(亲父,FL 车道 commit;curl 2152/0/0、httpd 2148/0/0 亲测基线,工件=/dev/shm/rugra-tests/sb-elsefix/{curl_final,httpd_gate_final}.c)
- commit: **4f4c9d78**(varmap: live ScopeLocal channel for stack spacebase subtype queries;含 ## Alignment Evidence + ## Differential + Cross-Review 请求)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b(锁树 ✓,annotation/refs/evidence hook ✓,gate health ✓)
- 产物: /dev/shm/rugra-tests/sb-stackbound/(discrim/ 判别实验+after/ 验证+analysis/);target: /dev/shm/rugra-targets/sb-stackbound/(增量缓存留复核)

## ① 判别实验结论(FH 存档的两假设裁决)

仪器化 oracle 载具(discrim/discrim_dump.cc:stage_projection 同款断点游走+@BEGIN 序数逐字对齐
归档投影 402 事件 ✓),在 ord150(oppool2 pre-apply)dump:

- **(A) 成立**:oracle 活跃 ScopeLocal = `[48@-616][256@-568(line)][264@-312][8@-48]`;
  `getSubType(-567)` 命中 256B 数组@-568 → newoff=1;`nearestArrayedComponentBackward(-567)`
  → offBefore=1∈[0,256),arrayHint(=biggestNonMultCoeff=1)==1 接受 → **extra=1**。
  (机制链:spacebase size=0 → -567 整体入 nonmultsum,查询偏移即 -567。)
- **(B) 证伪(该位点)**:op 35c4:406/35cf:412 的 ptr facing 均 plain `PTR→SPACEBASE`
  (isFormalPointerRel=false)——rel 播种不参与 ord150;TYPEOP-PTRREL-FACING-0001 行已更新结论。
- **边界前提修正**:oracle ord150 中管线图与 rugra **同形**(264 合并段@-312 同在);
  golden 的 outline[256]+prevblock/thisblock unresolved 是后续轮次形态——
  VARMAP-STACKBOUNDARY-0001 原登记的 "restructure/RangeHint 边界差是 ord150 馈入缺口" 不成立,
  **varmap.rs 零改动**;终局文本差(outline[256] vs [264])是另一现象(后续轮次/打印层,未随本行处理)。

## ② 交付(type.cc:2935-2945 getMap local 臂的 Rust 所有权镜像)

- `TypeFactory::live_local_scopes` registry + `get_type_spacebase` 构造期 `entry().or_insert_with()`
  立即挂接共享句柄(空 ScopeLocal=oracle 首趟 restructure 前可观察态;缓存类型永不 stale)。
- `TypeSpacebase.fd` 重定义(stubs::Funcdata 死占位 → `Option<Arc<RwLock<ScopeLocal>>>`);
  `get_map` → `SpacebaseMap` 枚举(Local guard | Global 快照);`get_sub_type` Local 臂 =
  `ScopeLocal::find_container_entry(space,off,1,None)`(queryContainer null-usepoint 忠实移植,只收 addrtied)。
  local-frame 判定 `!localframe.is_null()`(legacy Address 无 space,is_invalid() 对真入口恒真;
  global spacebase 恒 frame 0)。
- `Funcdata::publish_scope_to_spacebase` + ActionRestructureVarnode 每趟发布钩子(coreaction.rs:1678)。

## ③ myprogress 新状态 + 门禁(基线=亲父 bc22461d 亲测)

| 门禁 | 结果 | 基线 | 判定 |
|---|---|---|---|
| myprogress 投影 bisect | 首分歧 **150 → 399**(`universal:setcasts` count 5vs6;±1 拆分族全解;残余登记 MYPROGRESS-SETCASTS-ORD399-0001) | ord150 | ✅ 后移 |
| myprogress `--func` 文本 | **64**(数组元素类型开始打印 `undefined1[256] auStack_238`,贴近 oracle `bool line[256]`) | 65 | ✅ 方向 |
| parseconfig 投影 | 与亲父指纹 **MATCH**(ord186 族未动——前向吸附归 FC 的 RULEARITH-SPACEBASE-ARRAYSNAP-0001) | 同指纹 | ✅ 无回归 |
| next_url / match_url 投影 | **MATCH ×2**(stage+snapshot identical) | MATCH | ✅ |
| curl E2E 124 fn | **2150/0/0**(−2 = myprogress 65→64 + match_url 50→49 双改善;其余 122 函数字节稳定) | 2152/0/0 | ✅ 改善 |
| httpd E2E 29 fn | **2148/0/0,字节级==基线** | 2148/0/0 | ✅ |
| gcc 审计 | curl 82OK/25FAIL、httpd 6OK/23FAIL ==基线 | 82/25,6/23 | ✅ |
| test --lib(串行) | 18 failed == 已知集零新增(1682 passed) | 18 | ✅ |
| 双跑确定性 | curl/httpd 字节恒等 ×2 | — | ✅ |

## ④ 机制 C 复核请求(交付声明)

写域邻接 varmap 核心算法白名单(ActionRestructureVarnode 钩子 + 馈入 varmap 域可观察面),
commit **4f4c9d78** 请求独立 cross-review,重点:
1. 构造期立即挂接是否杜绝"缓存类型带 stale/无句柄 local frame"(registry entry().or_insert_with 语义);
2. `find_container_entry(space,off,1,None)` ≡ `queryContainer(addr,1,nullPoint)` 的 addrtied-only 语义;
3. 发布时机覆盖管线中 spacebase 查询前的全部 ScopeLocal 图变异(restructure 完成点 vs oracle 动态解析);
4. `!is_null()` local-frame 判定 vs Ghidra `isInvalid()` 在无 space legacy Address 形态下的等价性论证;
5. Differential 块内 −2 改善的逐函数归因(myprogress/match_url)。

复核期间只读;批准后由 reviewer 在集成提交加 `## Cross-Review: APPROVE`。

## ⑤ 跨车道协同(登记于 TODO_BOARD)

- **RULEARITH-SPACEBASE-ARRAYSNAP-0001(FC)**:其修复三件之③(getMap 动态化)已由本行交付;
  FC 剩余 = datatype.rs 两 walk(nearestArrayedComponent*,rebase 时 get_map/get_sub_type 已重写)
  + ruleaction.rs calc_subtype 两臂 hint≠0 接线;parseconfig ord186 验收仍归 FC。
- **TYPEOP-PTRREL-FACING-0001**:判别实验结论已写入该行(该位点 rel 路径不参与;行保持 OPEN 待 rel 创建链出现)。
- **MYPROGRESS-OPPOOL2-CONSTSPLIT-0001**:喂入缺口(a) FIXED、(b) 判别结论回填;剩余=arrayHint≠0 忠实路径(FC)。

## 回收

- 本目录(discrim/dump.150.txt+载具源码、after/、analysis/、commitmsg.txt)保留至复核与 root 集成;
  discrim/ 的 oracle 解包树与 tar 已清(可由锁树重建),dbg 探针产物已删;
- /dev/shm/rugra-targets/sb-stackbound/ 增量缓存留待 root merge 后按纪律清扫。
