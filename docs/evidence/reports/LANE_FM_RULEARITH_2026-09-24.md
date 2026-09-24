# Lane FM 终报 — RULEARITH-SPACEBASE-ARRAYSNAP-0001 (wt/rulearith)

- worktree: /dev/shm/rugra-worktrees/rulearith, branch wt/rulearith
- 基线: master **06034903**(亲父,三门禁 2152/0/0 + 2225/0/0 亲测口径,FL 合并前一刻)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- 日期: 2026-09-24; commit **26ffb3c2**(基 06034903,单 commit);
  CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-rulearith
- 证据: /dev/shm/rugra-tests/sb-rulearith/(gp/myprogress/parseconfig/next_url/
  match_url 五投影+bisect、curl/httpd E2E 全文与 summary、commit_msg.txt)

## 三件落地清单

1. **datatype.rs**(`+626`):`SpacebaseMap<'a>`(getMap 动态投影:
   `Local(Option<&ScopeLocal>)`/`Global(Option<&Arc<Scope>>)`)+
   `ArrayedComponent`(newoff/elSize 全精度)+`TypeSpacebase::
   get_sub_type_in_map`/`nearest_arrayed_component_forward_in_map`/
   `nearest_arrayed_component_backward_in_map`(type.cc:2947/2971/3020)
   +自由函数 `nearest_arrayed_component_forward/backward`(type.cc:188/201
   基类+1669/1698 TypeStruct 覆写的虚分派形态;与 ruleaction.rs
   RulePtrsubUndo 的布尔版并存,职责不同)+
   `spacebase_local_query_container`(database.cc:2250 同构:最小包含/
   严格小于竞争/恰等早退/null usepoint 仅 addrtied)+
   `get_sub_type` 的 byteToAddress 方向修正(乘→除,space.hh:523,ws=1 恒等)。
2. **ruleaction.rs**(`+254`):`AddTreeState::has_matching_sub_type`
   (ruleaction.cc:6064-6107 全量:arrayHint==0 直查/backward sizeAddr 门/
   forward/双 miss 回退/距离+0x1000 惩罚/tie→backward/uint4 截断)
   +`spacebase_map`(查询点活跃解析:fd 入口==localframe→`fd.scope`
   (live ScopeLocal),否则全局腿;**关键坑:Rugra legacy Address 无
   space→`is_invalid()` 恒真,frame 判别改"全零 sentinel=全局,非零=引用
   函数"**——Ghidra isInvalid=default-constructed 的观察等价)
   +calc_subtype SPACEBASE/STRUCT 两臂接 addressToByte/byteToAddress
   换算(ruleaction.cc:6286-6313)。
3. **typefactory.rs**(注释):构造期全局 scope 快照角色收窄为 getMap
   全局腿;localframe 查询不再读(签名/去重键不变)。

## ord 新状态(五投影 bisect)

| 投影 | 父状态 | FM 后 | 判定 |
|---|---|---|---|
| getparameter 双投影 | 首分歧 **ord186**(0x4f0 vs 0x4e8) | 首分歧 **ord209**(oppool1 count 29 vs 32) | **ord186 后移 ✓**,吸附点快照逐字节==oracle |
| myprogress 双投影 | 首分歧 **ord150** | 首分歧 **ord173**(oppool1 count 7 vs 10) | **ord150 后移 ✓**;文本 `-0x239→-0x238+1` 吸附形态=oracle |
| parseconfig 双投影 | 首分歧 ord186(同指纹) | **MATCH** | 同指纹分歧消失 ✓ |
| next_url 双投影 | MATCH | **MATCH** | 保持 ✓ |
| match_url 双投影 | MATCH | **MATCH** | 保持 ✓ |

探针实证(已还原,RUGRA_DBG_SPACEBASE):gp oppool2 时点 map=Local(Some),
-0x4f0 查询 forward 吸附 undefined1[1192]@-0x4e8 **extra=-8**(=oracle),
-0x4f8/-0x4e8 backward 命中 extra=0(=oracle),miss 位点 extra=0。

## 三门禁 + 文本方向(亲父 06034903 基线)

| 门禁 | 数字 | 基线 | 判定 |
|---|---|---|---|
| curl E2E | **2155/0/0** | 2152/0/0 | +3=三条新暴露 InferTypes 不收敛警告行(file2string/gp/match_url),全部已归因(见残差);defects/numbering 双 0 |
| httpd E2E | **2225/0/0** | 2225/0/0 | 恒等 ✓ |
| --func getparameter | **533** | 任务基线 743(FK 父 summary 行 532) | **−210 只降**(+1=警告行) |
| --func myprogress | **65** | 任务基线 67(FK 父 65) | 只降/= ✓ |
| gcc 审计 | 82 OK / 25 FAIL | 82/25 | ==父 |
| 单测 | 新增 2 过;serial 18-19 失败 | 父=预存 flaky 族+heritage_creation@master | 失败集单跑通过/集数波动=flaky,零新增 |

match_url 文本同时向 oracle 分解形态靠拢:`&0x60+iVar6`(monolithic)→
`&0x8+iVar6+0x58`(base+field),对应 golden `glob.pattern[i].content.*`
的吸附分解(缺符号名附着=既有 print 域差距,非本修复范围)。

## 残差登记(新 TODO)

`RULEARITH-POSTADSORB-CONVERGE-0001`(P2):吸附正确化暴露的收敛残差——
①投影域 gp ord209/myprogress ord173 oppool1 count +3,Rugra fullloop
迭代多于 oracle(gp 587 stages vs 371);②E2E plain-run 三函数
InferTypes ≥7 遍不收敛警告。oracle 同 op 形态可收敛→残差属 Rugra
InferTypes/fullloop 既有分歧被暴露,调查入口=drill oppool1 逐规则
count 对拍+InferTypes 翻转对象。已登记 TODO_BOARD 636 行。

## 机制 C 复核请求

ruleaction.rs=主管线 Rule 白名单,datatype.rs spacebase 查询族=行为
承载面。commit 26ffb3c2 附完整 `## Alignment Evidence`(四类语义
4/4)。请独立 reviewer 复核,重点:
1. `spacebase_local_query_container` 的 (start,i) 降序扫描 vs Ghidra
   (last,subsort) 多重集逆向遍历的 tie 等价性(重构图为无交叠分区,
   size-1 查询答案唯一;交叠+uselimit 片段场景的推导)。
2. `spacebase_map` 帧判别(全零 sentinel vs is_invalid 语义差)。
3. uint4 截断/0x1000 惩罚/tie→backward 三个细节的行级对照
   (ruleaction.cc:6097-6105)。
4. forward walk 的容器末 nextAddr=addr+size/ws 与回绕检查次序
   (type.cc:2997-3001)。

## 回收

- worktree 保留(待 root 集成+机制 C 复核);/dev/shm/rugra-targets/
  sb-rulearith 保留(root 复验增量缓存)。
- 证据件保留 /dev/shm/rugra-tests/sb-rulearith/:五投影+bisect txt、
  curl/httpd E2E 全文+summary+逐函数 cmp、gp_dbg.stderr(探针实证,
  探针代码已从源码还原,commit 内容=无探针终态)、commit_msg.txt、
  run_gates.sh/run_e2e.sh。
- result/curl_cur.c 已回流(worktree 内,gitignored)。
