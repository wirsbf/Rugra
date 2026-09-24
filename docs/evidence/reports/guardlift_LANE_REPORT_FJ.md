# LANE REPORT — FJ guardlift (LOCKHYGIENE-SCRUTINEE-FAMILY-0001 死锁家族收官)

- 日期: 2026-09-23 (Asia/Shanghai)
- worktree: /dev/shm/rugra-worktrees/guardlift, branch **wt/guardlift**
  (基=亲父 master **aaa1ab1d**;oracle=Ghidra 12.0.4 e40ed130 已验 HEAD)
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-guardlift(fast-release;
  base A/B 树=/dev/shm/rugra-worktrees/guardlift-base @ aaa1ab1d 已回收)
- 写域: `src/coreaction.rs` + `src/dynamic.rs` + `docs/api/{coreaction,dynamic}.md`
- Commits: **dc977085**(两处+同函数姊妹 scrutinee 守卫提升+4 单测+普查登记)
  → **84050b2a**(dynamic.cc:667 skip-op 无 output corner 修正+回归单测)

## 0. TL;DR

1. **账本末两处潜伏 scrutinee 守卫提升落地(dc977085,照 ER/EW 模板)**:
   - coreaction.rs `mark_explicit_unsigned` lone 臂(cast.cc:38-71,ER 时代行 5605,
     FD 后 5634):`if let Some(lone)=outvn.read().unwrap().lone_descend()` scrutinee
     读守卫活到体尾→体内写锁 outvn 即自死锁(现体内只读=潜伏)。
   - dynamic.rs `gather_first_level_vars` slot<0 臂 lone_descend(cc:663)
     + slot>=0 臂 get_def(cc:677,同函数同形姊妹,本 lane 普查发现一并提升)。
   - 均提升为语句级 let(owned `Option<Arc<_>>` 提前 drop 不可观测),读序逐点不变。
2. **全库同形普查:52 处生产位点,零新潜伏**(单行 51+多行 1[typeop.rs:1023];
   12 处体内含写调用逐一人工核验,写目标全部为异对象——0 处写锁 scrutinee
   本体)。底稿=evidence/scrutinee_census{.txt,_VERDICTS.md}。
3. **顺带行为修正(84050b2a)**:gather_first_level_vars slot<0 臂 skip-op 无
   output 时旧码穿透到尾部 push 泄漏 pre-skip vn;Ghidra dynamic.cc:667 是
   `if(vn==0) continue;`——补 let-else continue+回归单测。
4. **验证全绿**:A/B 亲父 aaa1ab1d pristine 树——curl/httpd 门禁/httpd 全量
   三输出 **BYTE-IDENTICAL**;三投影仅 META producer 行差(按定义);
   三门禁 defects=0/numbering=0(curl 124/124,httpd 29/29;httpd 全量
   MAX_FUNCS=840 panic=0 TIMEOUT=0);三投影 stage_bisect --v1 vs 锁定
   oracle **MATCH×3**;coreaction:: 60/60+dynamic:: 22/22(5 新),lib 单线程
   1682P/18F==基线家族。

## 1. 提升形态(两处+姊妹)

```rust
// 旧(scrutinee 守卫活到体尾):
if let Some(lone) = outvn.read().unwrap().lone_descend() { /*body*/ }
// 新(守卫随 let 语句释放,读序不变):
let lone_descend = outvn.read().unwrap().lone_descend();
if let Some(lone) = lone_descend { /*body*/ }
```

RUGRA-GLUE 注释引家族三先例(ER SubRight/EW castInput/EM3 cover_dirty)+
对应 cc 行号;lone_descend/get_def 均返回 owned `Option<Arc<_>>`(varnode.rs:2218/
2491),提前 drop 不可观测。

## 2. 单测(5 新,潜伏点的可确定性钉法)

潜伏点生产体内无写锁,无法如 ER 在生产路径复现死锁;按"生产调用形状复刻+
10s 超时线程"钉死提升后形态:

| 测试 | 锁定 |
|---|---|
| test_mark_explicit_unsigned_lone_arm_semantics | SUBPIECE lone→false 无 unsignedprint;INT_ADD lone→true+flag(untyped 常量报 UNKNOWN=unsigned-family,正控须另一侧 INT 类型——cc:56 other-side gate) |
| test_mark_explicit_unsigned_lone_arm_guard_released_before_body | 生产调用形状+体内写锁 outvn:scrutinee 形态自死锁,提升后 0.00s 完成 |
| test_gather_first_level_vars_not_attached_skip_op | skip-op CAST 重定向收集到 nv;非 skip ZEXT 保留 vn |
| test_gather_first_level_vars_skip_op_without_output_contributes_nothing | dynamic.cc:667 corner:output-less skip-op → varlist 空(84050b2a) |
| test_gather_first_level_vars_scrutinee_guard_released_before_body | 同上守卫释放钉法(vn 写锁入体) |

## 3. 三门禁+三投影+单测(修复树 84050b2a,fast-release,亲测)

| 项 | 结果 |
|---|---|
| A/B vs 亲父 aaa1ab1d | curl.c/httpd_gate.c/httpd_full.c **BYTE-IDENTICAL×3**;三投影 non-META diff=0(仅 producer 行) |
| curl E2E vs ghidra_curl_1204.c | 124/124 matched,**defects=0 numbering=0**(skeleton 2203) |
| httpd 门禁面 vs ghidra_httpd_1204.c | 29/29 matched,**defects=0 numbering=0**(skeleton 2239) |
| httpd 全量 MAX_FUNCS=840 | **panic=0 TIMEOUT=0** not-settling=1==base,exit=0 |
| next_url/match_url/parseconfig 投影 | stage_bisect --v1 **MATCH×3**(curl 驱动,按 EZ 勘误;oracle bundle=sb-ord191×2+sb-parseconfig) |
| coreaction:: / dynamic:: | 60/60、22/22(含 5 新) |
| lib 单线程 | 1682P/18F==基线家族(funcdata alignment 族 17+test_heritage_creation,逐名一致) |

## 4. 机制 C 声明(coreaction 域)

coreaction.rs 改动位于 ActionSetCasts 主管线 Action 附属函数
(mark_explicit_unsigned,经 cast_input 调用),但为纯锁生命周期重排零分支
语义变化——A/B 三输出字节恒等+三投影 MATCH 为最强旁证。无独立
`Cross-Review: APPROVE` 块,建议 root 集成时随 EW(castInput 同函数族)一并派
独立复核。dynamic.rs 不在机制 C 白名单。

## 5. root 集成输入

- wt/guardlift = aaa1ab1d + dc977085 + 84050b2a(两 commit,5 文件:
  src/coreaction.rs、src/dynamic.rs、docs/api/{coreaction,dynamic}.md、
  docs/TODO_BOARD.md[ER 行后插 FJ 家族收官行])。
- 冲突面:coreaction.rs mark_explicit_unsigned 区域与 dynamic.rs
  gather_first_level_vars 区域自 ER(7474ef57 时代)以来无其他 lane 触碰。
- 证据=/dev/shm/rugra-reports/guardlift/(本报告+evidence/);
  原始大件(投影×6/三 C 输出×2 树)已自清,基线 worktree 与其 target 已回收;
  lane worktree 与 /dev/shm/rugra-targets/sb-guardlift 留 root 集成后回收。
