# LANE REPORT — MERGEBATCH18（23 支已交付分支串行零丢失并入 master + 双 CR 条件套用 + 四棘轮重钉 + 集成验证 + 回收——史上最大批）2026-09-26

- 车道：root 集成（主仓 /home/ls/Rugra，基 = master `9ac04ade`，终态 = `b5248f0c` 已 push）
- oracle：Ghidra 12.0.4 `e40ed130`（gate health OK 全程亲验；hook = .githooks 版本化，pre-commit + commit-msg 全程绿）
- 阵容：23 支按任务书冲突面分组序串行（组1 docs/tools → 组2 fixture/repin → 组3 src 修复流 → 组4 CR 条件重批）；在飞 typeunion/printc0004（MB19）全程未动亲核

---

## ① 23 支 hash 表（合并序 = 冲突面分组序；全部 --no-ff merge commit；每支三点 diff 陈旧筛查=写域内零域外）

| # | 分支 | tip（回收前） | merge commit | 冲突面 | 解决方式 |
|---|---|---|---|---|---|
| 1 | wt/perfbench | `fd172434`（6 commits） | `337e314e` | 无 | 自动合并；DUALSLEIGH 层① 后记转入 PERF_BENCH 表（双车道交接条件） |
| 2 | wt/phaseland | `236cc286`（5 commits） | `59399fe7` | TODO_BOARD（TF-SINGLETON 旧行 vs TFSINGLE 已交付行） | HEAD 权威（DONE-STEP1+PERARCH-0002 两行）+ PHASE1LAND 协同注记四点全文并入 0002 行（零丢失） |
| 3 | wt/globrepin | `d880e019`（6 commits,230 文件） | `a5138801` | 无 | 自动合并；**refs/inputs/globrepin-sla-\* 14 refs 合并后+回收后双重亲证在场**（B 族 gc 根因防复发关键条件） |
| 4 | wt/stackfold | `a83f8868` | `e7a9beff` | 无 | 自动合并；census 9/0 双侧重观察重钉 |
| 5 | wt/typeopfix | `87c2b2a6` | `70001134` | 无 | 自动合并 |
| 6 | wt/typeop0001 | `2506b20c`（3 commits） | `4e5a7995` | docs/api/typeop.md（同锚双新增节） | 双节 union 全保（typeopfix 节+typeop0001 节）；**typeop.rs 函数区不相交 union 亲证**：双侧改动集共存（canonical 臂族 11 引用+propagate_add/AddZero 17 引用），union 树 cargo check 绿 |
| 7 | wt/bytelane | `9fe9b5b5` | `f59a0ff5` | 无 | 自动合并；**机制 C 如实注记**（见 ③） |
| 8 | wt/dynhash | `447bbc9b`（2 commits） | `d4ebed3f` | 无 | 自动合并 |
| 9 | wt/storeloadfwd | `17c74b9d`（2 commits） | `01248814`（amend） | TODO_BOARD（同锚双新增节） | 首解 git add -A 误入 marker→amend 修复；KUNABUGS/CR-FSPECDEIN/DYNHASH/STORELOADFWD 四节全保 |
| 10 | wt/copytrim | `a0bd359b` | `6f644835` | 无 | 自动合并 |
| 11 | wt/database7 | `7aa92fab` | `fbb48770` | 无（registry 全文件 1-space 重排自动并入） | 1-space 非正典问题留给 #12 一并正典化 |
| 12 | wt/varmapdecode | `f0fd0627`（2 commits） | `bde1abfa` | fixture_registry（#222×#222 同位 append） | **程序化 union=223 条双保全**+varmap_decodewrap 追加于 database_resid7 后+全文件 indent=2 正典重序列化（MB17 惯例）+S1 prose 当场修 |
| 13 | wt/kunaub2 | `ea409630`（4 commits） | `66f0f204`（amend） | TODO_BOARD | 同 #9 教训 amend 修复；双侧新增节 union 全保 |
| 14 | wt/hermeticity | `fb41ac55` | `6887af84` | 无 | 自动合并 |
| 15 | wt/typingpx | `2b000faa`（3 commits） | `b4c45a7a` | 无 | 自动合并 |
| 16 | wt/retaddr | `00d8a1b3` | `1d7c86eb` | TODO_BOARD（同票行新旧两版） | update-in-place：分支根因钉死行（超集）取代 HEAD 陈旧行+新 TYPESEED 票随行 |
| 17 | wt/b29condexe | `5ad87cbe` | `0a4bf42b` | 无 | 自动合并 |
| 18 | wt/curlfam | `65e34b80` | `f9cc7eee` | TODO_BOARD（HELPF 行+交叉核对行） | 混合 union：HELPF 行取 HEAD（b29 DONE 超集）；交叉核对行取分支版（item③ 修正归因=本车道交付；其余 6 项两侧逐字同） |
| 19 | wt/blockrwlock | `0b19788a` | `a4fe9224` | 无 | 自动合并 |
| 20 | wt/strfold | `afa83950`（3 commits） | `0a118d19` | 无 | 自动合并 |
| 21 | wt/dualsleigh | `d0caceee` | `ec6f3019` | TODO_BOARD（尾部同锚） | 双侧新增节 union 全保 |
| 22 | wt/sleighp3 | `ef8209f2`（11 commits） | `59f64f6e` | stackslot runner（双侧同修）+TODO 两处 | runner 取 HEAD 措辞（同修同义）；TODO：CURLCANON 块取 HEAD 超集，PHASE3 行取分支 DONE、STACKFOLD 行取 HEAD DONE（车道指示"DONE 为终态"）；**dualsleigh×sleighp3 union 亲证**：sleigh_ffi ENGINE_LOADS+新 raw-op API 共存、sleigh_lift from_ctx+七新 API 共存、四向 example union 编译绿 |
| 23 | wt/fspecdein | `ed1c2481`（4 commits） | `8ac3f7f0` | coreaction.md+TODO_BOARD | 双侧新增节 union；TODO 取 HEAD 全量+仅收分支 FSPEC-DEINDIRECT DONE 行（分支陈旧 SUBZEXT 行被 HEAD DONE 行取代） |

集成期追加：`ba6e670e`（B2 repin 波 4 runner+stackslot runner glue 修复）、`87142de3`（棘轮重钉）、`b5248f0c`（波次账本）。

## ② 陈旧内容筛查（每支三点 diff）

23 支 `git diff master...wt/<b> --stat` 全部落在各自车道终报声明写域内，零域外文件，零陈旧树病——逐支亲核（merge commit message 的 Merge-side verification 节）。23 支 tip 均为 master HEAD 祖先（merged=YES 全亲证）。

## ③ 双 CR 条件套用记录

### CR-VARMAPDECODE（APPROVE 5/5 MATCH）— merge `bde1abfa`
- message 附 `## Cross-Review: APPROVE` 块（覆写语义 varmap.cc:479-486 逐字/ATTRIB 133/134 恒等+5 触点 1:1/B2 fixture 独立复现 sha cf1ff3b4/canon fresh 双侧恒等/1808P 独立复跑）。
- **S1 修**：registry 描述 "Eight cases"→"nine cases"（union 时当场修，9-case 扩展后 prose 陈旧）。
- **S2 注记**：两处错误通道行号微漂（marshal.cc:275→276 throw 行；:421→425 AttributeId 形 throw），消息文本逐字正确+fixture 实证，仅记录。
- **S3 票**：`MARSHAL-READBOOL-0001`（P3）登记——read_bool_attr 缺失 lock 返 false vs oracle 抛+值域 t/1/y vs "1"/不敏感 true，生产不可达（writeBool 恒写 true/false）。
- **S4 票**：`DATABASE-DECODESCOPE-WRAPHOOK-0001`（P3）登记——decode_scope wrapping 分支丢属性不分发钩子，master 既有形态+零生产调用方。

### CR-FSPECDEIN（APPROVE 5/5 MATCH）— merge `8ac3f7f0`
- message 附 APPROVE 块（三臂逐句/fspec 生产 hook 逐句/model 绑定偏离有据/B2 6/8+2 失配诚实/canon 中性交叉印证）。
- **-R2/-R3 票绑定保持**：核验 CALLSPEC-0001 账下登记在场。
- **F-A**：`FSPECDEIN-TRANSFERLOCKED-STACK-0001` 票在场（TODO-BOOK 预登记）+ **fspec.rs 过期注释当场修**（机制 E 亲读 fspec.cc:5100-5180 本 session 回执在案）——注释从"Rugra 未暴露 getSpacebaseRelative"改为如实状态"方法已随本车道 commit_new_inputs（cc:5154 镜像）在场，本臂未接线仍走保守 early-Err，行为半边在票"；comment-only 零行为（cargo check 绿）。
- **F-B**：`FSPECDEIN-LATERESTRICT-LOCKED-FIXTURE-0001` 覆盖票核验在场。
- **registry 留 root 串行**：`deindirect_arms_1204` 登记 #224+顺手兑现 typingpx 的 PENDING-ROOT-REGISTER 条件（`typingpx_pxname_1204` #225），共 225 条。
- F-C/F-D 发现项记录无动作（单 model 等价/语料不可达）。
- 附：两条陈旧 OPEN 行（FSPEC-DEINDIRECT-TRIGGER P1/PERF-DUAL-SLEIGH 排队行）加收口注记指向各自 DONE 行。

### 机制 C 白名单如实注记（非 CR 支）
- **bytelane**（`f59a0ff5`）：实际改动文件 `src/double_precis.rs` **不在机制 C 文件白名单**（heritage\*/jumptable/blockaction/condexe\*/varmap 核心/merge）；车道按"主管线 Rule"广义条款自挂 Cross-Review: PENDING，**无独立 CR 终判**。行为证据=rule_doublein_arithgate_1204 B2 投影 MATCH+sq −158 逐函数归因+canon 双字节恒等。CR 债记录于本报告，root 后续裁量（补 CR 或以 B2 门禁为准）。注：该 fixture 的 Rust twin/metadata 入库但 runner 为车道迭代形态未入库（同 typeop0001 先例的 root 重钉面，归 SLEIGH-RETIREE-FLEET-REPIN 族）。
- **storeloadfwd**（`01248814`）：heritage.rs 在白名单但改动为纯注释刷新（可执行零 delta，fixture sha 重建前后不变亲证），无算法改动→不触发 CR 义务，如实注记。

## ④ 四棘轮重钉记录

| 面/对象 | 旧值 | 新值 | 依据 | 门禁实测 |
|---|---|---|---|---|
| httpd mirror ceiling | 156 | **98**（floor 29 不动，pinned ba6e670e） | typingpx fresh-DB 落地（ap_fini 51→7，px/x 清零） | **98/98 精确命中** PASS（staleness guard 抓 ratchet commit 后重链复验） |
| sq mirror 现态记账 | 4481 | **4323**（ceiling 7500/floor 810 不动） | bytelane −158（read_inode_1 −98+read_inode_3 −60 逐函数对合） | **4323/7500 PASS** 810/810 |
| B2 runner（varmapdecode/database7） | lane 态 Cargo sha+base | merge 态（commit/tree+Cargo.toml/lock sha） | src 文件逐字节未动（仅 Cargo 被 sleighp3/strfold 移动），观察重跑 MATCH 重建 | 9 case+19 case MATCH |
| B2 runner（dynhash） | crate tree 7b4cad6a | **c1e8f428**（三形态全钉：runner var commit+metadata crate tree/cargo blobs/runner sha） | 同上 | **10 case 全 MATCH** |

（typeop0001 runner 为 current-tree 形免钉，141 record MATCH 直接复验；MB18-RATCHET-REPIN-0001 头注三面注记入 mirror_gate_baselines.tsv。）

## ⑤ 集成验证数字表（fresh fast-release build 1m30s；canon curl user 68.1s / httpd 54.7s——dualsleigh −16% 兑现）

| 门禁 | 数字 | 判定 |
|---|---|---|
| canon curl | **157/0/0**（Matched 124，md5 51cc85d2） | **预期 200−18−25=157 精确命中**；helpf 29→4（b29）+boolcast −18（curlfam）叠加零回退 |
| canon httpd | **311/0/0**（Matched 34，md5 f5a05fd5） | = sleighp3 预测；**+82 归因逐函数复算验证**：ap_pregsub 19→122（blockaction F5 +103）/ap_no2slash 10→22+ap_make_dirstr_prefix 0→12+ap_stripprefix +2（varmap 域 +28）/main +2 vs 真收敛 −49（ap_fini −13/ap_init −11/strcasecmp+strcmp −9/update_vhost_from_headers −6/ap_parse_vhost_addrs、ap_update_vhost_given_ip 清零等）——与 sleighp3 报告同构（−45/+127 口径差=main/stripprefix 归类），**块/varmap 域本批已释放，归后续收敛票非本批回退**；0 panic/0 timeout，pcre_compile jumptable 3 行=预存 |
| 机制 B 差分 | =canon 本体（白名单多触碰：printc/coreaction/database/varmap/cast/constseq），双语料 defects=numbering=0 | 过；sleighp3/fspecdein/typingpx 各 merge commit Differential/Evidence 块在案 |
| 镜面 curl | **58**/65·74/74 | PASS（恒等基线） |
| 镜面 httpd | **98**/98·29/29 | PASS（重钉 ceiling 精确命中；typingpx 兑现+sleighp3 mirror 门保持） |
| 镜面 vsh | **15**/16·71/71 | PASS |
| 镜面 sq | **4323**/7500·810/810·numbering=0 | PASS（bytelane 兑现，现态记账） |
| 镜面 sqlite | **26833**/26833·1385/1385 | PASS（genwire 棘轮保持复验） |
| projection bank | **391/391** | PASS |
| cargo test --lib | **1813P/0F/5I**（1818 running） | =1805+27−19 **逐车道精确对账**：typeopfix +4/typeop0001 +9/database7 +1/varmapdecode +3/kunaub2 +3/hermeticity +2/typingpx +1/curlfam +2/blockrwlock +2/sleighp3 −19（被删模块测试 9+6+4） |
| 三门禁+gate health | annotations 96 文件/refs --all --strict/corpus 0 违规 2 allowlisted/oracle=e40ed130 | 全绿（disasm 模块退役后 96 文件计数） |
| .sla 三元门禁 | Rust slacomp：sla sha **406bfa48**（==MB14 pin）/484937B/inflated 2e36b32d | OK |
| B2 抽查（7/7） | varmapdecode 9 case MATCH/dynhash 10 case MATCH/typeop0001 141 record MATCH（sha 2daf410c）/constseq 77 行 MATCH/database7 19 case MATCH/stackfold census 9/0 PASS/kunaub2 pagecopy 3/3 PASS | 全 MATCH；bytelane fixture 无入库 runner 如实注记 |
| gcc 审计 | curl **104OK/20FAIL==基线**（fail 名集=预存未声明类型族）；httpd **16OK/13FAIL**（15/14→一函数随收敛转绿） | 改善向零回退 |
| globrepin refs | refs/inputs/globrepin-sla-\* **14 refs** 合并后+回收后双重亲证在场 | B 族 gc 根因防复现兑现 |

## ⑥ result/ 回流

- curl_cur.c → md5 **51cc85d2**（157 态=新基线）；httpd_cur.c → md5 **f5a05fd5**（311 态=新基线）。

## ⑦ 回收（双核验后执行，回收后全零亲证）

- **23 worktree**（/dev/shm/rugra-worktrees/{23 支}）+ **23 分支**（tip 与各道终报全对上）+ **18 target 目录**（perfbench/phaseland/globrepin/stackfold/typeop0001/bytelane/copytrim/database7/varmapdecode/varmapdecode-base/kunaub2/hermeticity/typingpx/retaddr/b29condexe/curlfam/strfold/dualsleigh；typeopfix/dynhash/storeloadfwd/blockrwlock/sleighp3/fspecdein 车道自清无残留）全清。
- 双核验：23 支 merged=YES（ancestor）+ dirty=0（全支 0 脏）先行亲证；globrepin refs 保活亲证**后**清其 target。
- **在飞未动**：typeunion/printc0004（MB19）worktree+target+分支亲核在场。
- /dev/shm 600G：572G used → 496G（105G free）；mb18 集成 target 最后自清。
- 注意：波次账本 .slim/deepwork/stage-bisect-e2e.md 此前为 gitignored 未跟踪态，本批首次 `git add -f` 入库（b5248f0c，2132 行全量）。

## ⑧ 过程事故与教训（如实）

1. **两次冲突 marker 误入 commit**（storeloadfwd 92508ff4→01248814、kunaub2 66f0f204）：`git merge; git add -A; git commit` 单命令链在 UU 冲突时盲 add——均当场发现（markers grep）+ union 解析 + `--amend` 修复 + union 完整性亲证（四节/三节计数）。后续分支全部先查 UU 再 add。
2. **stackslot runner glue 融合 bug**（ba6e670e 修复）：sleighp3 冲突块的 HEAD 侧尾行无换行边界，union 后注释与 `stage_root=` 赋值粘连成注释行→unbound variable；分离后 census 9/0 复验 PASS。教训：hunk 边界粘连是 TODO/注释冲突的机械风险，runner 类文件 union 后必须语法级 smoke。
3. 两次机制 A 红词拒收（"faithful mirror"/"ported"）——措辞改写后过，hook 工作正常。

## ⑨ 遗留移交

1. **ap_pregsub +103（blockaction F5 族）+ varmap 域 +26**（ap_no2slash/ap_make_dirstr_prefix/stripprefix）：canon httpd 311 的持有域分歧暴露面——两域本批已释放，下一波收敛车道即收（sleighp3 报告预告"收敛后 httpd canon 预期回落"）。
2. BYTELANE CR 债（③节）+ rule_doublein_arithgate runner 入库重钉（SLEIGH-RETIREE-FLEET-REPIN 族）。
3. COREACTION-BOOLMINT-FACTORY-UNIFY-0001（curlfam 登记，coreaction 域已释放可派）。
4. GLOBREPIN 移交五项（B2 状态策略门 ~10 面/typefactory_needsres/环境供给 71 面/onion 尾 ~40 面/主仓 tools chmod 755）不变在案。
5. typeunion/printc0004 排 MB19。
