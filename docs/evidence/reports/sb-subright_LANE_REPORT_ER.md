# LANE REPORT — ER subright (RULEACTION-SUBRIGHT-UNLINK-0001 修复落地)

- Branch: wt/subright @ **7474ef57**(代码+api docs)+ **c4019e53**(TODO 收尾)
  (基=亲父 50d6f5f0;oracle=Ghidra 12.0.4 e40ed130 已验 HEAD)
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-subright(+sb-subright-base 基线 A/B;target 回收留 root)
- 写域: src/ruleaction.rs + docs/api/ruleaction.md(机制 B 白名单;TODO 行同 c4019e53)

## 0. TL;DR

1. **一行修正落地(7474ef57)**:RuleSubRight::apply_op lump 臂
   `fd.op_unset_input(op,0)` → `fd.op_unlink(&PcodeOpRef(op_arc.clone()))`
   (=ruleaction.cc:7285 `data.opUnlink(op)`;funcdata_op.cc:179-193=unset output+
   全部 inputs+uninsert,op 死亡)。与 EJ bf3f5064 正控形态逐字一致。
2. **附带死锁修复(EJ 正控未覆盖,本 lane 单测钉死)**:lump 臂入口
   `if let Some(lone) = outvn.read().unwrap().lone_descend()` 的 scrutinee 临时读守卫
   活到整个 if-let 体,而 op_unlink→op_unset_output→make_free_prevalidated 对同一
   outvn 取写锁 → 同线程 std RwLock 非重入=确定性死锁(修复前单测 60s+ 挂起复现;
   提升为独立 let 后 0.00s 通过)。EJ 正控的 httpd 15s per-fn 超时机制会把该死锁
   掩盖成 TIMEOUT 计数,故 bf3f5064 "0 panic" 对死锁维度无效。
   **同形存量(未触碰,建议登记)**:coreaction.rs:5605、dynamic.rs:911 同为
   if-let scrutinee 守卫形态——体内若写锁同一 varnode 即同类死锁。
3. **输出恒等证明**:A/B 亲父 50d6f5f0 pristine worktree(/dev/shm/rugra-worktrees/
   subright-base,已回收)三输出 curl/httpd 门禁/httpd 全量(MAX_FUNCS=840)全部
   **BYTE-IDENTICAL**——当前语料 lump 臂 0 触发的经验证明;httpd 全量 22 条
   not-settling 警告==亲父基线(预存,TYPEPROP-NONSETTLING-HTTPD-0001 家族)。

## 1. 单测(ruleaction 模块 210/210 含新增)

test_rule_subright_lump_unlinks_original_subpiece:SUBPIECE(c=4,outvn 4B,a 8B,
lone=INT_RIGHT const-shift 8)命中 lump 臂;断言:返回 CHANGE;原 op DEAD(出
alivelist/output=None/全槽 sentinel);lone→SUBPIECE 读 newout+const0 无 null 槽
残留;唯一 INT_RIGHT shiftop 读 a+const d=40(c*8+8)。修复前该用例死锁挂起。

## 2. 三门禁+三投影(修复树 7474ef57,fast-release,亲测)

| 门禁 | 数字 | 判定 |
|---|---|---|
| curl E2E vs ghidra_curl_1204.c | **2512/0/0** | ==亲父预期(EN ②行 −4 已含);defects=0 numbering=0 |
| httpd 门禁面(29 fns)vs ghidra_httpd_1204.c | **2335/0/0** | ==亲父实测(A/B 字节恒等);任务书 ≈2286 为过时数字 |
| httpd 全量 MAX_FUNCS=840 | **panic=0,TIMEOUT=0**,pcre_exec 完成(471/840 DECOMP) | 地雷拆弹成立;pcre_exec 不再 panic |
| httpd 全量 not-settling | 22 条==亲父基线 | 预存(TYPEPROP backlog 家族),非本修复引入 |
| next_url/match_url/parseconfig.constprop.0 投影 | **MATCH×3**(stage_bisect --v1 exit 0) | RUGRA_MIRROR=1 正典 bundle;oracle 投影=sb-ord191×2+sb-parseconfig×1 |
| ruleaction 单测 | **210/210** | 含新增死锁回归用例 |
| A/B 亲父 50d6f5f0 | curl/门禁/全量 **BYTE-IDENTICAL×3** | 0 触发=输出恒等,经验证明 |

## 3. 未决移交

1. **同形 scrutinee-guard 存量**:coreaction.rs:5605 / dynamic.rs:911(体内写锁
   同一 varnode 即同类死锁;建议 root 登记新 TODO)。
2. HTTPD-FULLEMPTY-ELSE-0001 / TYPEPROP-NONSETTLING-HTTPD-0001(L2 backlog,
   EJ 已登记,非本 lane 域)。
3. 机制 C 解读:ruleaction Rules 属"主管线 Rule"外延,7474ef57 无独立
   Cross-Review:APPROVE 块(改动小且带四类语义 Evidence),建议 root 集成时派
   独立复核。
4. 任务书 httpd ≈2286 与实测 2335 的出入:亲父实测=A/B 字节恒等=2335,
   2286 疑为 master(9cfd7adb/EI 并入)树数字,归 root 归因。

## 4. 工件

- 证据包:/dev/shm/rugra-reports/sb-subright/evidence/(ab_test.log、
  mbisect_×3、curl_gate/httpd_gate.txt、unit_tests.txt、commit_msg.txt)
- 原始大件(/dev/shm/rugra-tests/subright)已自清;target 目录
  (/dev/shm/rugra-targets/sb-subright 与 sb-subright-base)按指令留 root 回收。
