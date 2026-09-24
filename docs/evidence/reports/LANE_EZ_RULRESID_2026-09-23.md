# LANE REPORT — EZ rulresid（RULEMELD-FIDELITY-RESIDUE-0001 四件套 + CR11 O-1）

- Branch: wt/rulresid @ **0d4e1602**（代码+api docs）+ **0299d1b3**（TODO 收尾）
  （基=亲父 756d0f9d；oracle=Ghidra 12.0.4 e40ed130 已验 HEAD）
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-rulresid（+sb-rulresid-base 基线 A/B；收尾已回收）
- 写域: src/ruleaction.rs + src/rangeutil.rs（pull_back 签名）+ docs/api/{ruleaction,rangeutil}.md + TODO 本行

## 0. 四件状态清单

| # | 项 | 状态 | 落点 |
|---|---|---|---|
| ① | CR11 O-1：SubRight lump 臂 shiftop 地址源（cc:7299 经 cc:7286 重绑读 lone 地址） | **修** | ruleaction.rs:12693 改从 `working_op_ref.0` 取地址（原读已 unlink 的 op_arc）；lump 单测给 lone 地址 0x2000，断言 shiftop.get_addr()==0x2000（旧代码此处==0x1000=SUBPIECE 地址） |
| ② | cc:1414-1417 `newConst->copySymbolIfValid(markup)` 缺失 | **修** | apply_op 单个共享 `markup`（cc:1377：跨 6 个拉回调用点、从不清零、cc:1069-1070 最后符号常量胜）→ translate 成功臂传播；正典 `CircleRange::pull_back` 补 `const_markup` 出参（rangeutil.rs:834-836，撤销 ET 的"观测死省略"GLUE 注记）；端到端单测：`(V<5)\|\|(V==5)` 合并常量 6 携带 c5 的 equate SymbolEntry |
| ③ | cc:1401 isHeritageKnown 用 is_free() 代理 | **修** | 换 `varnode.rs:930 is_heritage_known()`（varnode.hh:298 忠实 flag 检查）。语义核对：Ghidra VarnodeBank::create（cc:1250）**不**给 free varnode 置 INSERT，仅 setInput/setDef→xref（cc:1306）置位、makeFree（cc:1323）清除——旧代理双向偏差（INPUT-only 无 INSERT 被放行 / 银行注册未写 INSERT 被 拒）。既有 3 个 meld fixture 改走 `fd.vbank.set_input`（真实输入路径）；新单测锁 INPUT-only 无 INSERT→NO_CHANGE |
| ④ | pull_back_op 缺 cc:1053-1065 SUBPIECE nzmask 补救臂 | **已覆盖→切换闭合** | EZ 基线里正典 `CircleRange::pull_back`（ET/RANGEUTIL-CONSTGEN-0001 落地）已含该臂+cc:1075-1082 尾交集并有单测（rangeutil 4742 行 salvage 测试）；本 lane 按账本提示把简化版 pull_back_op 整体删除，6 调用点全切正典（RangeMeld 路径 usenzmask=false 与 oracle 一致，补救臂对该规则仍为死路=同 Ghidra） |

## 1. 三门禁（child 0d4e1602 亲测，fast-release）

| 门禁 | 数字 | 判定 |
|---|---|---|
| curl E2E vs ghidra_curl_1204.c | **2511/0/0** | ==任务书预期 ≈2511；defects=0 numbering=0 |
| httpd 门禁面（29 fns）vs ghidra_httpd_1204.c | **2282/0/0** | ==任务书预期 ≈2282 |
| httpd 全量 MAX_FUNCS=840 | panic=0, TIMEOUT=0, not-settling=1 | not-settling==亲父（pcre_exec 预存 WARNING） |
| **A/B 亲父 756d0f9d pristine** | **六输出 cmp 字节恒等**（curl E2E/httpd gate/httpd full 840/next_url/match_url/parseconfig 投影） | **潜伏类实证**：四件在当前语料 0 触发 |
| 三投影（RUGRA_MIRROR=1 正典 bundle） | **MATCH×3**（stage_bisect v1.2 stage+snapshot identical） | next_url 335/96457、match_url、parseconfig 335/130099 |
| ruleaction 单测 | **213/213**（+3 新行为锁） | lump 地址锁/heritage 拒绝锁/markup 传播锁 |
| rangeutil 单测 | **54/54** | pull_back 签名扩展后全绿 |
| lib 单线程 | 1675P/18F==基线家族逐名 diff 空 | funcdata alignment 族+test_heritage_creation 预存 |

## 2. 过程发现（供 root 归档）

1. **ER 证据脚本驱动用错（已在本 lane 修正）**：next_url/match_url 是 **curl** 语料函数
   （binary_sha 8af50bca…，func_entry 0x4ff0/0x…），ER 的 run_e2e.sh 用 httpd 驱动投影——
   httpd 驱动 stderr 报 "matched no function" exit 1，其 mbisect 消费的是更早手动跑出的
   产物。本 lane 证据（ab_identity.txt + run_e2e2.sh）已用 curl 驱动重跑并 MATCH。
2. **域内第 5 项观察（未改，登记待派）**：cc:1399 `if (A1 != A2)` 是**指针比较**，Rust 侧
   大小失配再拉回臂用 `functional_equality_eq`（功能等价超集）：拉回得到功能等价但异指针
   varnode 时 Rugra 继续 meld 而 oracle 拒绝。当前语料掩蔽（canonical 路径下拉回结果即
   同一指针），修法=换 Arc::ptr_eq,建议随下一 ruleaction 车道带独立复核。
3. fixture 教训：闭包内构造的 op Arc 在返回时 drop 会令 out.def 的 Weak 失效——applyOp 在
   def-upgrade 处早退，测试必须持有 op 强引用（本 lane 两个新单测的 (out, op) 返回形状）。

## 3. 机制 C 声明

改动落在 ruleaction Rules（主管线 Rule 外延，机制 C 白名单邻域）：0d4e1602 携完整
Alignment Evidence（RuleRangeMeld::applyOp / RuleSubRight::applyOp 两函数四类语义逐条）+
Differential 块；无独立 `## Cross-Review: APPROVE`（同 ER 先例，改动小、潜伏类字节恒等、
行为面由 3 个新单测锁定），**建议 root 集成时派独立复核**（重点核对 markup 最后写者胜
与 is_heritage_known flag 语义）。

## 4. 工件与回收

- 证据包: /dev/shm/rugra-reports/sb-rulresid/evidence/（ab_identity、双侧 gate、三 mbisect、
  单测输出、commit message、run_e2e{,2}.sh、child_failures.txt、curl_cur.c 快照）
- /dev/shm/rugra-tests/sb-rulresid 原始大件（E2E 全文/投影/stderr）已自清；
  target 目录 sb-rulresid(+base) 已回收；rulresid-base 亲父 worktree 已移除。
