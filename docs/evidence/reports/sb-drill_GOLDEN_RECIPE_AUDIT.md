# GOLDEN_RECIPE_AUDIT — regen 配方 vs Lane AT 正典捕获配方,只读审计

- Lane: BA(golden 再生配方审计)
- 日期: 2026-09-22
- 工作目录: /home/ls/Rugra(只读,repo 零改动;全部实验产物在 /dev/shm/rugra-tests/sb-drill/recipe-audit/)
- 触发背景: Lane AT 广播(TODO_BOARD.md L55-61)——oracle per-application DEBUG 流依赖早期堆分配序列;argv 相对/绝对形态决定性选择两变体(next_url records=1019 vs 1014);ASLR 使大函数几乎逐跑翻转。正典捕获配方=**相对 argv + `env -i` + `setarch -R`**(repo-root cwd),且广播明言"所有 oracle 捕获 lane(golden regen/fixture)必须采用同配方,否则可能钉住不同确定性变体"。
- 审计对象: `tools/regen_ghidra_golden.py`(1358 行,全文已读)及其产物 `tests/golden/ghidra_{curl,httpd}_1204*.c` + provenance。

---

## §1 regen_ghidra_golden.py 现用调用形态(全文精读结论)

### 1.1 正典路径(path 1,headless)——golden 唯一生成者

`run_headless_import()`(regen_ghidra_golden.py:680-709)构造的调用:

| 维度 | 实际形态 | 与正典配方的偏差 |
|---|---|---|
| **argv 形态** | **全绝对**:`analyzeHeadless` = `/tmp/rugra-ghidra-1204-headless/dist/ghidra_12.0.4_DEV/support/analyzeHeadless`(DEFAULT_HEADLESS,:61-63);`-import examples/curl` 用 `REPO_ROOT/"examples"/"curl"` 绝对路径(:83, :689-695) | ❌ 非"相对 argv" |
| **env** | `os.environ` **全继承**(仅删 `LD_PRELOAD`,:681),再 prepend JAVA_HOME/PATH(:682-684) | ❌ 非 `env -i` |
| **setarch** | **无**——ASLR 开启 | ❌ 无 `-R` |
| **cwd** | `tempfile.mkdtemp(prefix="rugra-golden-headless-<t>-")`——**每次随机的 /tmp 目录**(:720, :698;mkdtemp 随机后缀长度固定,分配尺寸稳定) | ❌ 非 repo-root,且逐跑不同 |

命令模板(:688-695):
```
<abs>/analyzeHeadless <workdir>/ghidra-project golden_regen \
  -import <abs>/examples/curl -scriptPath <workdir> \
  -postScript ghidra_decompile_all.py <workdir>/headless-out.c -deleteProject
```

### 1.2 golden 生成路径:**整树一次生成**(非逐函数)

- 单个 analyzeHeadless 进程 import 二进制 → 跑完整 Java 默认分析(loader/PLT/references/demangler/DWARF,无选项覆盖)→ postScript `tools/ghidra_decompile_all.py` 在**同一 JVM/同一 DecompInterface 会话**里按 Java `FunctionManager.getFunctions(True)`(地址序)顺序反编译全部函数,逐函数 `/* ---- 0xADDR: NAME (SIZE bytes) ---- */` 块写单文件(ghidra_decompile_all.py:36-53,30s/函数超时)。
- curl 有 `determinism_rerun: True`(:91):完整独立二次 headless import,比对 byte_identical;**httpd `determinism_rerun: False`**(:103)——httpd golden 无逐字节确定性复跑记录。
- provenance 记录(curl,tests/golden/ghidra_curl_1204.provenance.json):`determinism.byte_identical=true`(22.2s/21.9s 两跑,**在 ASLR 开启下取得**)。

### 1.3 补充路径(path 2,direct-runner)——非正典 golden(补充产物)

`run_mode()`(:913-915):argv 同样**全绝对**(runner=workdir 内绝对路径,spec_root=`REPO_ROOT/sleigh_specs` 绝对,binary 绝对);`subprocess.run` 无 `env` 参数 → **全继承** os.environ;无 `cwd` → 继承调用者 cwd;**无 setarch**。
生成路径与 headless 相反:**逐函数 hermetic 进程**("one" 模式,每函数新进程+新 Architecture,ThreadPoolExecutor 并行,:971-985);provenance `runner.mode: "one (per-function hermetic process)"`。12 函数抽样复跑 byte-identical(curl 与 httpd 均为 12/12,unstable=[])。

### 1.4 小结(一句话)

**regen 两路径的调用形态 = 绝对 argv + env 全继承 + 无 setarch + 随机 /tmp cwd(headless)/继承 cwd(direct-runner),与 Lane AT 正典配方(相对 argv + env -i + setarch -R + repo-root cwd)四维全部相悖;但两路径的 provenance 都记录了 ASLR 开启下的跨进程 byte-identical 复跑(curl headless 全量 ×2 + 两语料 direct-runner 各 12 函数抽样)。**

---

## §2 敏感性结构论证:C 文本(printC)vs DEBUG 流的敏感面

### 2.1 DEBUG 流为什么敏感(敏感机制在**中间行为层**)

- DEBUG 采集机制本身是**程序序确定的**:`Funcdata::debugModCheck/debugModPrint`(funcdata.cc:1010-1057)按首次触碰顺序把修改过的 op 追加进 `modify_list`(vector),帧内无任何哈希/指针序。因此 **records 计数差(1019 vs 1014 / 4762 vs 4763)= Action/Rule 修改序列的真实行为分歧**,不是诊断噪音、不是指针打印(AT 的帧行文是 SeqNum/地址文本,无裸指针)。
- 行为分歧的载体:管线里存在**堆地址值敏感的 tie-break**。本审计锁定 12.0.4 树中仅存的显式指针对比点:`TypeCode::compareDependency` 对参数/返回 Datatype **"Compare pointers directly"**(type.cc:2874 `param < opparam`、:2883 `otype < opotype`)。它经 `DatatypeCompare`(type.hh:306-311)决定 `TypeFactory::tree`(DatatypeSet)的排序/去重;**匿名 code 类型默认同名 "code"**,两个同尺寸匿名 TypeCode 的相对序完全由参数类型指针的堆地址决定 → 堆序敏感。与 ASLR 观测吻合:brk 堆与 mmap 区块的**跨区相对地址**随 ASLR 独立随机 → 同序列分配下同区内相对序稳定(解释 argv/形态今天不翻转),跨区序逐跑翻转(解释"大函数几乎逐跑翻转"——函数越大间接调用/类型越多,命中年概率越高)。
- 本机今天实测:该机制仍活着——curl main DEBUG 流在 abs argv+全 env+ASLR on 下 3 跑出现 4762/4763 两种 records;setarch -R 后 5 跑恒 4763。

### 2.2 C 文本的容器全貌(逐容器定性,12.0.4 锁定树)

| C 文本要素 | 决定容器(锁定源) | 顺序键 | 堆序敏感? |
|---|---|---|---|
| golden 文件内函数块序(headless) | Java `FunctionManager.getFunctions(True)` | 地址 | ❌ 确定性 |
| golden 文件内函数块序(direct-runner) | `collectFunctions` + `std::sort`(regen FIXTURE_CPP :343-380,镜像 ifacedecomp.cc) | (offset,name) | ❌ 确定性 |
| 语句/表达式序 | PcodeOpBank(SeqNum=pc+uniq 时间序,address.hh:154;obank 有序表) | SeqNum(顺序计数器) | ❌ 确定性 |
| Varnode 迭代(局部/命名/类型传播的根序) | `VarnodeLocSet`/`VarnodeDefSet`(varnode.hh:52/55)——**12.0.4 已把指针比较注释掉换成 `getCreateIndex()`**(varnode.cc:34-87,`// return (a < b); // compare pointers` 原文尚存) | addr/size/flags/SeqNum/createIndex | ❌ 确定性(Ghidra 官方去 ASLR 化改造点) |
| 跨空间地址序 | `Address::operator<`(address.hh:375-393) | 空间 **index**(非指针)+offset | ❌ 确定性 |
| 符号表迭代/全局符号声明 | `SymbolMap`=rangemap<SymbolEntry>(database.hh:164)、`SymbolNameTree`=set 按名(database.hh:373)、`ScopeMap`=map<uint8,Scope*> 按 id(database.hh:439) | 地址/名字/id | ❌ 确定性 |
| 类型工厂查重/命名 | `TypeFactory::tree`(DatatypeSet)+`nametree`(DatatypeNameSet,type.hh:772-773),comparator=compareDependency→**id 兜底**(type.hh:306-320) | 名/尺寸/结构,终局 id | ⚠️ 仅 TypeCode 角落见 2.1 |
| struct/union 字段序 | `vector<TypeField>` 按 offset(type.hh:511/546) | offset | ❌ 确定性 |
| 变量命名计数器 | varmap/ScopeLocal 内计数器,遍历 RangeHint `stable_sort`(varmap.cc:1078) | offset | ❌ 确定性 |
| 全库唯一 unordered 容器 | `marshal.hh:22-27` `unordered_map<string,uint4>`(AttributeId/ElementId 查表)——**仅点查(marshal.hh:690/706),从不迭代** | 字符串 | ❌ 无法泄漏顺序 |
| 其余全部 set/map/rangemap/list/vector | grep 全树:无第二处指针序容器、无 `std::sort` 裸指针比较器(fspec.cc:1924 为成员值比较、cover.cc:240 为 int4 比较、merge.cc:597 为 BlockVarnode 值类型) | 值键 | ❌ |

### 2.3 敏感面差异结论(结构论证)

- **DEBUG 流**记录的是**中间修改序列**——管线上任何一个地址敏感 tie-break(§2.1)在任何一轮的任何一次开火差都直接可见(records 计数变)。
- **C 文本**只消费**最终 fixpoint**(obank/符号表/类型终态),其序列化面(§2.2)全部值序。地址敏感 tie-break 只有在**改变 fixpoint 本身**时才会泄漏进 C 文本;若分歧只改变中间路径(多/少一次可收敛的规则修改)而 fixpoint 唯一,C 文本不变。
- 因此 golden 的敏感面 = {fixpoint 是否唯一} × {TypeCode 指针角落是否被命中并改写终态},**严格小于** DEBUG 流的敏感面。唯一结构性残余风险 = §2.1 的 TypeCode 角落(重匿名函数指针类型的语料才可能命中)。

---

## §3 实证(本机今日全跑通,全部产物在 /dev/shm/rugra-tests/sb-drill/)

复用 sb-drill 已建好的锁定 oracle 树(build/locked-cpp,git-archive 自 e40ed130,-DOPACTION_DEBUG)编译 regen 内嵌的 `golden_dump_1204` fixture(从 FIXTURE_CPP 原样提取;`opactdbg_active` 仅经 `debugEnable()` 置位且 fixture 从不调用——funcdata.hh:595/602,funcdata_op.cc:27-30 守卫已核实——**define 在不开 debug 时零行为差**)。

### 3.1 DEBUG 流对配方/ASLR 的响应(预建 drill runner,`@DONE` records 计数)

| 目标 | 形态 | 结果 |
|---|---|---|
| curl next_url | 绝对 argv+全 env+ASLR on ×3 | 1019/1019/1019 |
| curl next_url | 正典(相对 argv+env -i+setarch -R)×2 | 1019/1019 |
| curl next_url | 绝对 argv+仅 setarch -R / 仅 env -i / repo cwd | 全 1019 |
| curl main | 绝对 argv+全 env+ASLR on ×3 | **4762,4763,4763(ASLR 翻转!)** |
| curl main | 正典 ×3 / 绝对+setarch -R ×2 | 恒 4763 |
| httpd main | 绝对 argv+ASLR on ×4;正典 ×2 | 恒 6583(=广播钉定值) |

注:**AT 广播的 argv 形态二变体(1019 vs 1014)今日不可复现**——所有形态(next_url)均 1019;今天存活的翻转维度是 ASLR(curl main)。1014 的触发条件疑与当时构建/env 内容相关,归 Lane AT 域,本审计仅记录不可复现事实。

### 3.2 C 文本对配方/ASLR 的响应(golden_dump_1204 "one" 模式逐函数 JSON "text" 字段)

| 目标 | 跑法 | 结果 |
|---|---|---|
| curl next_url | 正典 ×1 vs 绝对+ASLR on ×3 | **4 份 C 文本 byte-identical**(sha256 全等 ba5fc429…) |
| curl main | 正典 ×2 vs 绝对+ASLR on ×6 | **8 份 C 文本 byte-identical**(e328bf69…)——**与 3.1 中 main DEBUG 流 4762↔4763 翻转同条件同期,DEBUG 翻了 C 文本没翻** |
| httpd main | 正典 ×2 vs 绝对+ASLR on ×3 | **5 份 C 文本 byte-identical**(size 3062 全等) |

### 3.3 与入库 golden 的字节级对账

- curl direct-runner golden:next_url 块、main 块 = 本次重建产物 **MATCH**(逐字节,行数 104/104、543/543)。
- httpd direct-runner golden:main 块 **MATCH**(逐字节)。
- 即:**今日用正典配方重生成的 C 文本与现库 golden(当初用绝对 argv+env 继承+ASLR on 生成)完全同字节**。

### 3.4 复验命令(留档)

```bash
# 预建(drill 树已存在时跳过): bash tools/build_stage_drill_oracle.sh
G=/dev/shm/rugra-tests/sb-drill/recipe-audit/golden_dump_1204   # 本审计已编译好
cd /home/ls/Rugra
# 正典形态 C 文本:
env -i PATH=/usr/bin:/bin setarch -R $G one sleigh_specs examples/curl 44 /dev/shm/a.json
# 现用 regen 形态 C 文本(可重复多次,期间 ASLR 会翻转 curl main 的 DEBUG 流):
$G one /home/ls/Rugra/sleigh_specs /home/ls/Rugra/examples/curl 44 /dev/shm/b.json
python3 -c "import json,hashlib;print(hashlib.sha256(json.load(open('/dev/shm/a.json'))['text'].encode()).hexdigest())"
# DEBUG 流翻转对照(同条件):
for i in 1 2 3; do STAGE_DRILL_FUNC=main STAGE_DRILL_ADDR=0x25a0 \
  /dev/shm/rugra-tests/sb-drill/build/stage_drill_1204 /home/ls/Rugra/sleigh_specs \
  /home/ls/Rugra/examples/curl 2>/dev/null | tail -1; done   # 观察 records=4762↔4763
```

---

## §4 结论:golden 是否需要重钉/加配方注记

1. **不需要重钉**。三层证据闭环:(a) §3.3 正典配方重生成 = 现库 golden 逐字节;(b) §3.2 C 文本对配方四维(argv/env/setarch/cwd)与 ASLR 全部不变,包括 DEBUG 流正在翻转的 curl main;(c) provenance 自带的 ASLR-on byte-identical 复跑(curl headless 全量 + 两语料 direct-runner 12/12)。现库 golden(ghidra_curl_1204.c/ghidra_httpd_1204.c 及 direct-runner 版)钉住的不是某个"堆序变体",C 文本层面无变体之分。
2. **结构性残余风险**(登记即可,不动 golden):TypeCode::compareDependency 指针兜底(type.cc:2874/:2883)是 12.0.4 唯一存活的地址序决策点;若未来语料命中"多同名匿名 code 类型且 fixpoint 被改写"的角落,C 文本理论上可翻。当前语料(curl/httpd)未见。
3. **建议加固 regen**(下轮触碰 tools/regen_ghidra_golden.py 时顺带,非紧急):① headless/direct 两路径加 `setarch -R`(Linux)+ cwd 钉定;② provenance schema 增 `invocation` 字段(argv_form/env_mode/aslr/cwd 指纹);③ httpd `determinism_rerun` 改 True(headless dist 目前因重启丢失,重建后首个 --regen 即补上);④ 脚本头部注记正典配方,与 AT 广播对所有捕获 lane 的统一要求对齐——虽实证表明 golden 敏感面不受此影响,统一配方可整类消除"钉住不同确定性变体"的怀疑成本。
4. **DEBUG 流捕获 lane(drill/fixture)与 golden lane 敏感面不同**:前者必须严格守正典配方(AT 广播成立,records 是行为敏感量);后者(C 文本)对配方不敏感(本审计实证+结构论证)。两 lane 的配方统一是"降低系统性风险"而非"golden 已被污染的补救"。

---

## §5 登记建议(供 root 落板,本 lane 不改 repo)

- **新 TODO ID 建议**: `GOLDEN-RECIPE-HARDEN-0001`(P3)
  - 状态: OPEN(登记即结,本审计为证据)
  - write-set: `tools/regen_ghidra_golden.py` + `docs/TODO_BOARD.md` 行;可选 `docs/VERIFICATION_GUIDE.md` 注记
  - 内容: §4.3 四项加固(setarch -R / provenance invocation 指纹 / httpd determinism_rerun=True / 头部正典配方注记)
  - 验收: 改后 `--check` 全绿;重建 headless dist 后跑 `--regen` 双跑 byte-identical 且 provenance 记录 invocation 指纹
  - 证据: 本报告(路径见下)+ /dev/shm/rugra-tests/sb-drill/recipe-audit/ 全部产物
- **给 Lane AT 的回流**: argv 形态选择 1019/1014 两变体今日(本机构建 03:19)不可复现(所有形态=1019);今日活跃翻转维度=ASLR(curl main 4762↔4763);候选机制载体=TypeCode::compareDependency 指针兜底(type.cc:2874/2883,跨 brk/mmap 区相对序随 ASLR 翻转、同区序稳定,与全部观测吻合)。1014 变体触发条件请 AT 侧用当时构建复核。
- **不改 golden、不改 regen、不改任何 repo 文件**(本 lane 只读约束,已遵守)。

---

*报告完。产物目录: /dev/shm/rugra-tests/sb-drill/recipe-audit/(golden_dump_1204 二进制、list.json、{nu,m,h}_{canon,aslr}*.json 共 17 份逐函数 JSON、golden_dump_1204.cc 提取件)。*
