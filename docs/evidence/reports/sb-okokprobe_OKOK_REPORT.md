# MERGE-COPYNOISE-OKOK-0001 探查报告(CR-CE 条件①)

日期:2026-09-22。Rust 探针基线:master **df9febd9**(worktree 快照;调查期间 master 又前进到
a58091e5,未影响本探针)。oracle:Ghidra 12.0.4 **e40ed130**(repo ghidra HEAD 与
variable.cc md5 `c1c2e3e0…` 核对相等)。只读调查,**repo 零改动**;全部探针在
/dev/shm/rugra-tests/sb-okokprobe/ 独立副本,env 门控(RUGRA_OKOKPROBE)。

## 0. 一句话结论

**假阴性对(Rust intersection=false 而 oracle=true)计数 = 0(双侧实证)。**
残差(CE 时 93,本探针基线 84)不含相交测试假阴性;主因是 same-high 打印侧家族(+44)
与"intersection 可并但从未尝试/他级门槛"域(+33)。**UNTEDINTERSECT 不必升级 P1,
维持 P3,但 merge.rs:41-44 的"分支不可达"辩护注释已被证伪,需勘误。**

## 1. 结构性差异清单(读双侧源码,先于探针)

### 1.1 Rust `MergeTypeIntersectCache::intersection` vs oracle `HighIntersectTest::intersection`

- oracle variable.cc:1166-1201:① `a==b→false`+updateHigh 脏检查/缓存命中;
  ② `intersectList(…,2)`+逐块 `blockIntersection`;③ **variable.cc:1188-1197:
  `!res && aTied!=bTied → testUntiedCallIntersection(tied,untied)`**;④ 双向写缓存。
- Rust merge.rs:280-310 `intersection`(探针版 wrapper+`intersection_raw`):①②④与
  oracle 逐条对应(update_high merge.rs:57=variable.cc:1148;block_intersection
  merge.rs:140=variable.cc:998)。**③ 整体缺失。**
- merge.rs:41-44 辩护注释称 speculative guards 拒绝 addrtied 侧故分支不可达。该断言
  只对 `mergeTestSpeculative`(merge.cc:232-233)成立;CE 修复后 cache 的调用闭包
  含 `merge_test_with_list`(merge.rs:1780 = merge.cc:1657,mergeOp 路径,前置仅
  mergeTestRequired),而 mergeTestRequired(merge.cc:102-166)**不拒单侧 addrtied 对**
  (仅双 addrtied 不同地址 :111-114 及 input×addrtied :118-134)⇒ 结构上可达。
  **oracle 实测:main 管线期分支进入 146 次 ⇒ "不可达"辩护证伪**(见 §3)。

### 1.2 缺失分支的依赖件在 Rust 的现状(= 移植面,全未做,对应 P3 工作量)

- `testUntiedCallIntersection`(variable.cc:1072-1083):tied `isPersist`→false;
  tiedVarnode `hasNoLocalAlias`→false;否则 `untied->getCover().intersect(affectingOps,vn)`。
- `StackAffectingOps`(merge.cc:63-89):populate = 全部 CALL specs 的 op + 有效 STORE
  guard 的 op;`affectsTest`:STORE→`loadGuard.isGuarded(vn addr)`(无 guard→true),
  CALL→恒 true。
- `Cover::intersect(PcodeOpSet,rep)`(cover.cc:342-378):op 集按 (block index,
  SeqNum order) 排序(cover.cc:627-652);cover 块 `contain(op)&&boundary(op)==0`
  → affectsTest。
- Rust:HighVariable `is_persist/is_addr_tied/get_tied_varnode`(variable.rs:1273/
  1278/1017)、`has_no_local_alias`(varnode.rs:2153)、`CoverBlock::contain/boundary/
  get_u_index`(cover.rs:284/310/271)已在;**`Cover::intersect(opset,vn) 未移植**
  (cover.rs 无 opset 变体);`MergePersistentState.stack_affecting_ops`(merge.rs:417-425)
  存在但无生产填充路径(注释自认)。

### 1.3 极性约定(避免术语漂移)

oracle merge.cc:1664:`if (testCache.intersection(a,high)) return false;` ⇒
**intersection=true 阻断合并**,false 才可并。本报告「假阴性对」= 任务口径:
Rust=false 而 oracle=true(Rust 视为可并,oracle 视为相交)。

## 2. 探针方法(双侧,可复现)

- **Rust 侧**(本目录 `wt/`,repo rsync 快照 + ghidra symlink,env `RUGRA_OKOKPROBE`):
  - `MergeTypeIntersectCache::intersection` 包 wrapper:每次调用记
    `[OKOKSEE] a b res at ap ai bt bp bi`(管线期可达性 + Rust 判定)。
  - `pub fn okok_final_probe`(merge.rs,probe-only):管线后对 main 每个 alive COPY 的
    (high_out,high_in) 终态判定:`rust =` 新建空 cache 的 `intersection`;
    `oracle =` rust **或** 缺失分支的 oracle 等价复刻(persist/no-local-alias 门 +
    `okok_affecting_ops`(calls+有效 STORE guards,(block,order) 排序)+
    `okok_cover_intersects_opset`(cover.cc:342 的逐 op 等价实现)+
    `okok_affects_test`(merge.cc:78-89));另记 `req =` `merge_test_required`
    归因。curl_decompile.rs 在 `db.perform_action("decompile")` 后 env 门控调用。
  - 运行:`RUGRA_OKOKPROBE=1 RUGRA_OKOKFUNC=main ./target/fast-release/examples/
    curl_decompile --rugra-selected-function main`(3.5s;探针只进 /dev/shm 副本)。
- **oracle 侧**(`oracle_cpp/` = sb-impliedfold runner 树 rsync,md5 与锁定 oracle 相等;
  `oracle_okokprobe.cc` = oracle_copyprobe_1204.cc 改造):
  - variable.cc 本地副本在分支处插桩:每次进入记 `[OKOKBRANCH] tied={space:off:sz}
    persist= nla= untied_inst= cross=`,**cross 由真 testUntiedCallIntersection 算出**
    (无重实现风险)。
  - main() 在管线后用本地 `Merge` 实例对每个 alive COPY 记 `[OKOKFINAL] … oracle=
    probeIntersection(oh,ih) req= probeMergeTestRequired(oh,ih)`(真代码路径,
    含缺失分支)。
  - 构建:make libdecomp.a(EXTRA=)+ g++ -std=c++11(bfd_root=/tmp/rugra-ghidra-bfd-2.38,
    spec_root=/home/ls/Rugra/sleigh_specs,binary=examples/curl)。运行 0.45s。

## 3. 结果

### 3.1 oracle 真分支行为(main)

| 观测 | 数值 |
|---|---|
| 管线期 `[OKOKBRANCH]` 进入次数 | **146** |
| 管线期 `cross=1`(testUntiedCallIntersection=true) | **0** |
| 终态 census(OKOKFINAL-BEGIN 后)分支进入 | 120 |
| 终态 `cross=1` | **0** |
| 门分布(146 次):persist=1(全局,地址强制即占位) | 14 |
| 门分布:persist=0&nla=0 但 cover 不跨 call(no-cross) | 132 |
| affecting set | 107 = 106 calls + 1 有效 STORE guard |

⇒ **oracle 在 main 的全部 266 次真分支求值中从未翻转结果**:缺失分支在本语料不可能
制造任何 Rust=false/oracle=true。

### 3.2 Rust 终态判定(main,318 个存活 COPY;CE 时 327,df9febd9 的两个
symbol-tail commit 使其降 9)

| 类 | 数量 | 对应 oracle(main, 234) |
|---|---|---|
| same-high(同 HighVariable 对) | **91** | 47 |
| diff-high, rust=0(可并,非 intersection 阻断) | 187(106 no-cross + 77 not-mixed + 4 persist) | 154(o=0) |
| diff-high, rust=1(cover 相交阻断) | 38(35 req=0 双重阻断 + 3 req=1) | 33(o=1:23 req=0 + 10 req=1) |
| diff-high, rust=0 & req=0 | 2 | 0 |
| **rust=0 且 oracle=true(假阴性方向)** | **0** | — |

- Rust 侧 oracle 等价复刻:112 个 mixed-tied 对全部求值(108 no-cross/4 persist/
  含 2 req=0),**0 翻转**,与 oracle 侧 266 次真求值 0 翻转一致(双侧独立证据)。
- 管线期 Rust `[OKOKSEE]` 23881 次:true 仅 157;branch-reachable(res=0 且
  mixed-tied)333 次(含终态 112)——可达性成立,但等价复刻下无一翻转为 true。
- affecting set 差:Rust 105 = 105 calls + 0 stores vs oracle 107 = 106+1(1 个
  call spec 差 + 1 个有效 STORE guard 缺)。**非承重**:oracle 用更全的集合也全部
  cross=0。可作低优先观察项登记。

### 3.3 残差归因表(84 = 318 − 234;CE 时 93 = 327 − 234)

| 残差成分 | Δ(Rugra−oracle) | 域 |
|---|---|---|
| same-high COPY | **+44** | 打印侧/junk-COPY 家族(PRINTC-CONDBLOCK-JUNKOPS-0001 域);双侧全为 o0/i0 explicit |
| diff-high 可并(intersection=0)且 required 放行却未并 | **+33** | **候选生成/管线顺序/adjacent 级门槛域**(非 intersection 域) |
| diff-high cover 阻断 | +5 | intersection 域但方向为 Rust=true(过严),非假阴性 |
| diff-high rust=0&req=0 | +2 | required 域边缘 |
| 其中 implied 牵连(diff-high rust=0/req=1):Rust 60(13/28/19)vs oracle 15 | +45 细分 | MarkImplied/implied 打印域(与 +33/+44 部分重叠的细切) |

**312 对基线口径修复**(copynoise lane):其"basic 双过仍未合并(ok/ok)312 对"在 CE
修复后的语义等价物 = 本探针 rust=0/req=1 的 187 对(intersection 已不再是阻断项);
后续追踪应锚定"候选生成/顺序/adjacent 域",不应再记在 intersection 名下。

## 4. 判定与登记建议

1. **MERGE-COPYNOISE-OKOK-0001:关闭,判定=无假阴性**(双侧独立证据:oracle 真分支
   266 求值 0 翻转 + Rust 复刻 112 对 0 翻转)。CR-CE 条件①回答:93(现 84)残差
   **不含**相交测试假阴性。
2. **UNTEDINTERSECT:维持 P3,不升级 P1/P2。**理由:结构可达但本语料(含 httpd 同
   族的 curl 主干)empirically 零翻转;触发前提窄(tied 非 persist=栈对象、有本地
   别名指针、untied cover 严格跨界包含 call/STORE)。升级条件建议写明:任一语料
   oracle 侧 `cross=1` 出现 >0 次,即升 P2。
3. **新增文档勘误 TODO(低优先,docs-only):merge.rs:41-44** 的"unreachable in this
   call closure"表述改为"reachable via mergeOp/mergeTest path(oracle main 实测 146
   次);empirically non-decisive on locked corpora;port deferred(P3,含
   Cover::intersect(PcodeOpSet,Varnode) 与 StackAffectingOps::populate 两个未移植件)"。
   该注释现状违反机制 D(cited-line 语义与实测不符)精神,但不影响行为。
4. **观察项(可选登记,P3):affecting set 差**(Rugra 105+0 vs oracle 106+1:1 个
   call spec 差、1 个有效 STORE guard 缺)——只在将来真做 UNTEDINTERSECT 移植时
   承重。
5. 残差 +44(same-high)继续归 PRINTC-CONDBLOCK-JUNKOPS-0001/junk-COPY 家族;
   +33 归候选生成/顺序域(建议新登记 MERGE-COPYNOISE-CANDGEN-0001 或并入既有
   管线顺序 TODO)。

## 5. 可复现清单(本目录)

- `wt/`:Rust 探针 worktree(rsync 快照 + ghidra symlink;probe 改动:
  merge.rs intersection wrapper + okok_* 五函数 + curl_decompile.rs OKOK hook)。
- `oracle_cpp/`:oracle 本地副本(variable.cc 分支插桩 + merge.hh/cover.hh probe
  accessor;仅这 3 处偏离 e40ed130)。
- `oracle_okokprobe.cc` / `oracle_okokprobe`:oracle 探针源与二进制。
- `oracle_main.c` / `oracle_main.stderr.log`:oracle main C 输出与探针日志
  (OKOKBRANCH 146 + OKOKFINAL 234 + COPYSTATE/HIGHCENSUS)。
- `rugra_main.c` / `rugra_main.stderr.log`:Rust main 输出与探针日志
  (OKOKSEE 23881 + OKOKFINAL 318)。
- `rugra_pairs.txt` / `oracle_pairs.txt`:终态对键(space:off:sz→…)计数。
