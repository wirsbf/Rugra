# KUNA 上游 UB 六项对照复检（KUNAUB 车道，2026-09-26）

> **任务**：竞品 kuna（Ghidra 引擎 Rust 移植，pin 2026-06 master）UB 账本报告的 6 个上游 Ghidra
> 潜在 UB，逐条对照 Rugra 的锁定 oracle（12.0.4，tag `Ghidra_12.0.4_build`，commit
> `e40ed13014025f82488b1f8f7bca566894ac376b`）与本仓 Rust 移植态，给出分类与裁决。
> **本车道只读 `src/`，未改任何源码**；修复票另派车道。
>
> **oracle 锁定核验**：worktree `ghidra/` symlink → `/home/ls/Rugra/ghidra`，HEAD detached at
> `e40ed13014`（= 12.0.4 build）✓。
>
> **master 差分证据**（判定 kuna 2026-06 pin 与 12.0.4 代码是否同体，`git log master --not
> e40ed130` 逐文件）：
> - `rangemap.hh`：唯一后续 commit `792e529e7a`（GP-7080，**2026-07-20**，晚于 kuna pin），
>   仅**新增** `find_first_after/find_last_before`，`erase/zip/unzip/insert` 零改动；
> - `opbehavior.cc`：唯一后续 commit `402d10d6cc`（GP-2493 bitfield），未触及除法族；
> - `memstate.cc/.hh`、`opcodes.cc`、`xml.cc`、`pcodeparse.y/.cc`：**12.0.4 后零 commit**。
> ⇒ 六项 UB 所在代码在 12.0.4 与 kuna pin 间**逐字节同体**；`NOT-IN-1204` 计 **0/6**。
>
> **分类法**：`SAME-UB-MIRRORED`（12.0.4 有 + Rugra 镜像）／`RUST-DIVERGES`（Rust panic 或行为
> 异 → crash 族风险）／`NOT-IN-1204`（12.0.4 干净）。本复检对"Rugra 未镜像且安全"的情形补记
> 第四态 `RUGRA-SAFE`（12.0.4 有 UB、Rust 侧结构免疫，无 crash 风险，不开修复票）。

---

## 总表

| # | kuna 账本条目 | 12.0.4 存在性 | Rugra 形态 | 分类 | 票 |
|---|---|---|---|---|---|
| K1 | `opcode_name[]` 越界 @ CPUI_MAX | ✅ 潜伏（无 in-tree 触发者） | enum + 穷尽 match，结构免疫 | RUGRA-SAFE | 无（记录） |
| K2 | `INT64_MIN / -1` SIGFPE | ✅ 主管线可达 | 全路径 Rust panic（除法溢出恒 panic） | SAME-UB-MIRRORED | **KUNAUB-SDIV-0001**（P2） |
| K3 | XML `convertCharRef` 溢出 | ✅ | 镜像 i32 累加；release=回绕（=C++ de facto），debug=panic | SAME-UB-MIRRORED | **KUNAUB-CHARREF-0001**（P3） |
| K4 | `rangemap::erase` dangling read | ✅ **ASan 实证 heap-use-after-free** | 游标+serial 重设计，stale → `None` | RUGRA-SAFE | 无（记录） |
| K5 | `MemoryBank` page-copy 越界 | ✅（默认 getPage/setPage 死修剪） | 镜像同一死修剪 + slice panic；当前无调用方 | RUST-DIVERGES（潜伏） | **KUNAUB-PAGECOPY-0001**（P3） |
| K6 | pcode snippet 关键字排序违规 | ✅（`"||"` 先于 `"abs"`，二分双双 miss） | 表序+算法逐字节镜像，行为等价 | SAME-UB-MIRRORED | **KUNAUB-IDENTS-PIN-0001**（P3） |

---

## K1 — `opcode_name[]` 数组越界 @ CPUI_MAX

**① 12.0.4 定位**：`opcodes.cc:29-48` `static const char *opcode_name[]` 恰 74 项
（`"BLANK"`..`"LZCOUNT"`，索引 0..73）；`opcodes.hh:130` `CPUI_MAX = 74`。
`opcodes.cc:60-64 get_opname(OpCode opc)` **无边界检查**直接 `return opcode_name[opc]`——
`opc == CPUI_MAX` 时读越界指针（静态存储区相邻数据当 `char*` 解引用，UB）。
**存在性**：✅（潜伏形态）。in-tree 唯一 `CPUI_MAX` 产出源是 `get_booleanflip`（opcodes.cc:94，
非比较 op 返回 `CPUI_MAX`），而全部调用方均先检查（`funcdata_op.cc:1295`、`expression.cc:206`、
`printc.cc:2395`、`ruleaction.cc:5529` 都是判等/比较用法，不喂 `get_opname`）；XML 侧
`marshal.cc:586 writeOpcode` 的 `opc` 来自已初始化 `PcodeOp::code()`。⇒ 12.0.4 主管线
**不可达**，属"缺护栏"潜伏 UB（kuna 应是在移植中把 `CPUI_MAX` 当哨兵值传名查询时踩到）。

**② Rugra 形态**：`src/opcodes.rs:18-92` `enum OpCode`（含 `CPUI_MAX = 74` 变体）；
`name()`（opcodes.rs:96 起）为**编译器穷尽性 match**，`OpCode::CPUI_MAX => "MAX"`
（opcodes.rs:172）——类型系统使数组式越界不可能；`from_i32`（opcodes.rs:181）返回
`Option`，调用方（ruleaction.rs:105/338/4882、pcodeparse.rs:1576、funcdata.rs:7105）全部
`filter_map`/`match` 消费。**结构免疫，无 panic 路径**。

**③ 裁决**：`RUGRA-SAFE`。oracle 侧 UB 输入（喂 `CPUI_MAX` 给 get_opname）没有已定义的
可观测行为可匹配；Rugra 的 `"MAX"` 命名仅是 Rust 形态自然产物，且该输入在双侧主管线均
不可达。**不开修复票**；记录于此防止未来有人"补数组镜像"反向引入 K1。

---

## K2 — `INT64_MIN / -1` SIGFPE（除法溢出）

**① 12.0.4 定位**：`opbehavior.cc:507-517 OpBehaviorIntSdiv::evaluateBinary`——
仅守 `in2 == 0`（:510-511 抛 `EvaluationError("Divide by 0")`），随后
`intb num/denom`（:512-514，`intb`=int64）。`num = 0x8000000000000000`、`denom = -1`
（sizein=8 时可构造）→ x86-64 `idiv` 溢出 → **SIGFPE 进程崩溃**（非 C++ 异常，不可捕获）。
同族：`opbehavior.cc:529-539 OpBehaviorIntSrem::evaluateBinary`（`val % mod`，INT64_MIN % -1
同样 SIGFPE）；`OpBehaviorIntDiv/IntRem`（:499/:519，无符号）无此问题。
**主管线可达性**：`RuleCollapseConstants::applyOp`（ruleaction.cc:3853，:3865）→
`PcodeOp::collapse`（op.cc:453，:466 binary 臂）→ `evaluateBinary`——常量折叠路径直通；
catch 的只有 `LowlevelError`（ruleaction.cc:3866），SIGFPE 穿透。模拟路径同理
（emulate.cc:232、emulateutil.cc:61/181）。⇒ 反编译含常量折叠型
`INT64_MIN s/ -1` / `INT64_MIN s% -1`（8 字节）输入的函数 → Ghidra 12.0.4 **进程崩溃**。

**② Rugra 形态**：全部求值路径汇聚到同一批 i64 除法：
- 主管线：`ruleaction.rs`（RuleCollapseConstants）→ `op.rs:1154 PcodeOpRef::collapse`
  → `typeop.rs:4165 evaluate_binary` → `opbehavior.rs:163 pub fn evaluate_binary`（safe
  `Option` 版）→ `CPUI_INT_SDIV` 臂 **opbehavior.rs:188-196**：
  `let sres = num / denom;`（i64）；`CPUI_INT_SREM` 臂 **opbehavior.rs:205-213**：
  `let sres = val % modulus;`；
- trait 版（Emulate/注入桥）：`opbehavior.rs:1350-1358`（`num / denom`）、`:1398-1408`
  （`val % modulus`）同形。
Rust 语义：**整数除法/取余溢出在任何 profile 恒 panic**（不受 `overflow-checks` 开关管辖）——
`attempt to divide with overflow` unwind。⇒ 同输入下 Rugra panic 崩溃，oracle SIGFPE 崩溃：
**崩溃对崩溃，机制不同**（SIGFPE=内核信号杀进程；panic=可 unwind 的 Rust panic）。

**③ 裁决**：`SAME-UB-MIRRORED`（crash↔crash 镜像，机制相异）。oracle 在该输入上没有
"成功反编译"的输出可对拍——两侧都是崩溃，行为等价层面可辩护；但 panic 文本与信号形态
不同，且若宿主用 `catch_unwind` 包裹则 Rugra 变成"可继续的失败"而 oracle 是硬死——
存在**服务化场景下的可观测分歧**。开票 **KUNAUB-SDIV-0001**（P2）：裁决选项
(a) 维持 panic（最贴近 SIGFPE，零改动）或 (b) 改抛 LowlevelError 走 `opMarkNoCollapse`
软失败（主动分歧，需 roadmap 记录）。复现构造见票面。

---

## K3 — XML `convertCharRef` 溢出

**① 12.0.4 定位**：`xml.cc:2337-2360 convertCharRef(const string &ref)`——
`int4 val` 累加器，`val *= mult; val += cur;`（:2356-2357）**有符号 int 溢出 UB**，
无位数上限、无值域校验；非法字符按 `10+ref[i]-'A'/'a'` 折算（scanner 侧
`xml.cc:2151 XmlScan::scanCharRef` 已限制 token 为 `[0-9a-fA-F]`/`[0-9]`，故字符域安全，
风险只在**长数字串**）。构造：`&#x1111111111111;`（≥9 位十六进制）→ 溢出。C++ de facto
（x86-64 gcc/clang -O2）静默回绕，截断为单字节进字符流（grammar `$$ = convertCharRef(...)`
后 `*lvalue += (char)`）。**存在性**：✅。

**② Rugra 形态**：`src/marshal.rs:1261-1285 convert_char_ref`——逐行镜像：i32 `val`，
`val *= mult; val += cur;`（:1280-1281）；`push_reference_char`（marshal.rs:1292-1296）
镜像 `(char)` 截断。Rust 语义：`overflow-checks=on`（debug/测试 profile 默认）→
**panic**（multiply with overflow）；release/fast-release → **确定性回绕**（有定义）。
scanner 域限制同样镜像（marshal.rs:1074-1098 `scan_char_ref`，十六进制/十进制域）。
⇒ release 行为 = C++ de facto（回绕一致）；debug 构建在对抗输入（长 `&#x..;` 串，来源=
伪造的 spec/XML/cpool 文件）下 panic。

**③ 裁决**：`SAME-UB-MIRRORED`（release 口径行为等价；debug 口径多出 panic 族）。
开票 **KUNAUB-CHARREF-0001**（P3）：改 `wrapping_mul/wrapping_add` 使 debug=release=
de-facto-C++，消除 debug-only 分歧且不动 release 语义。

---

## K4 — `rangemap::erase` dangling read（erase 后读已释放节点）

**① 12.0.4 定位**：`rangemap.hh:281-326 erase(list-iterator)`；`rangemap.hh:168
erase(const_iterator) { erase(iter.getValueIter()); }`；`rangemap.hh:123 getValueIter()`
读 `(*iter).getValue()`（rangemap.hh:92）。**循环删除后同记录迭代器变悬垂**：一条 record
跨多个 sub-range 时在 multiset 里有**多个** `value == v` 的 AddrRange 节点（头注释
rangemap.hh:97-100 明示"同一 recordtype 会被迭代器多次访问"）；`erase` 的 do-循环
（:302-316 `tree.erase(low++)`）删光该记录全部节点（该删除惯用法本身合法）。此后任何
**先前收集的、指向同 record 已删节点的 PartIterator** 再喂 `erase(const_iterator)` /
解引用 → `getValueIter()` 读已释放节点 → heap-use-after-free。次要潜伏点：`zip()`
（rangemap.hh:177-188）首个 while 无 `iter != tree.end()` 护栏（本 lane 推演两处调用点
在容器不变量下不可达 end，但属缺护栏形态）。
**实证（本 lane，oracle 头原样编译，g++ -fsanitize=address,undefined）**：
随机 insert/erase 序列 30 seed 全数命中：
```
ERROR: AddressSanitizer: heap-use-after-free  READ of size 8
  #0 rangemap<Rec>::AddrRange::getValue()  rangemap.hh:92
  #1 rangemap<Rec>::PartIterator::getValueIter()  rangemap.hh:123
  #2 rangemap<Rec>::erase(PartIterator)  rangemap.hh:168
freed by:
  #8 rangemap<Rec>::erase(std::_List_iterator<Rec>)  rangemap.hh:304   ← tree.erase(low++)
```
触发形状 = "同 record 的第二个 PartIterator 在该 record 经另一 PartIterator 删除后再用"
（erase(const_iterator) 重载天然诱导该模式）。**存在性**：✅（kuna 描述与实证逐字吻合）。

**② Rugra 形态**：`src/rangemap.rs` 为 Vec+serial 重设计（非 multiset 镜像）：
- `RangeMapCursor { owner_generation, part_serial }`（rangemap.rs:101；owner_generation
  为实例身份号，构造时取全局原子序号 rangemap.rs:236——非变更计数）；
- `resolve_cursor`（rangemap.rs:557-566）：serial 在 parts 里 `position` 不到 → `None`；
  part serial 单调递增不回收（`allocate_part` rangemap.rs:288-289）——**被删节点的
  stale cursor 必然解析为 None**，槽位被新 part 占据也不会误配；
- `erase_at`（rangemap.rs:546-554）/`record_at_cursor`（:588）/`cursor_is_valid`（:582）
  全走 `Option`，无 unsafe、无 panic。
C++ 中"UB 输入"（stale PartIterator 再用）在 Rugra = 干净的 `None`；C++ 中"合法输入"
（指向未删 record 的迭代器跨删除使用）在 Rugra = serial 仍在 → 正常解析（比
multiset 迭代器失效语义更宽，无过度失效）。

**③ 裁决**：`RUGRA-SAFE`（oracle-UB 输入 → Rust 有定义的 `None`；无 crash 族风险，
无静默错删）。oracle 在该输入上的可观测行为是 ASan 崩溃/未定义内存读，不存在需要对拍
的已定义输出；Rust 返回 `None` 是可辩护分歧（且是唯一健全选择）。**不开修复票**；
登记防止未来"multiset 忠实化"重构反引入 K4。

---

## K5 — `MemoryBank` page-copy 越界

**① 12.0.4 定位**：默认实现 `memstate.cc:93-123 getPage` / `:136-171 setPage` 的
头部修剪条件写错对象：`if (startalign < addr)`（getPage :113 / setPage :153）——
`addr` 是 getChunk/setChunk（:335-359 / :302-327）传入的**页对齐**地址，而错位量在
`ptraddr = addr + skip`（:97/:140）上；`startalign = ptraddr & ~(wordsize-1) ≥ addr`
恒成立 ⇒ **头部修剪恒为死代码**。`skip % wordsize != 0` 时首迭代多拷 `skip mod wordsize`
个请求范围之外的字节，`res += sz` 累计超发 → **读/写越界 caller 缓冲区至多 wordsize-1
字节**（getPage 尾部 `memcpy(res,ptr,sz)` 越界写、setPage :161 `memcpy(ptr,val,sz)`
越界读），且内容整体错位。**受影响面**：仅未覆写 getPage/setPage 的 bank =
`MemoryHashOverlay`（memstate.hh:130-141，只覆写 find/insert；用于 emulation/standalone，
emulate.hh:448-449、sleighexample.cc:261-262 实例化）；`MemoryImage`（memstate.cc:386-399）
与 `MemoryPageOverlay`（:476-493/:502-525）自覆写且正确处理 skip。主管线（Ghidra GUI
decompiler）用 page overlay 族，不走默认实现。**存在性**：✅（潜伏于仿真/standalone 面）。

**② Rugra 形态**：`src/memstate.rs:140-180 get_page` / `:187-240 set_page` 镜像同一
死修剪（`if startalign < addr`，memstate.rs:164 / :202），但载体是 `Vec<u8>`/slice：
`res[out_pos..out_pos + sz].copy_from_slice(...)`（:172）与
`&val[val_pos..val_pos + sz]`（:218）在 `out_pos+sz > size` 时 **panic（slice range
out of range）**。复现推演（ws=8）：`get_chunk(0x1001, size=8)` → 第二迭代
`res[8..9]` 越 len-8 → panic。**当前可达性：零**——`get_chunk/set_chunk` 在
src/examples/bin 全域无调用方（仅 memstate.rs 内定义；MemState 被 emulate.rs:24,44,61
使用但只走 word 级 get_value/set_value）。⇒ 镜像 bug 形 + panic 替代静默越界 + 当前死路。

**③ 裁决**：`RUST-DIVERGES`（**潜伏**panic-on-call；oracle 同输入是静默堆越界——比
panic 更危险，故 Rust 形态实为安全方向，但 panic 语义与 oracle 的"越界写成功继续跑"
不等价，均无已定义 oracle 行为可对拍）。开票 **KUNAUB-PAGECOPY-0001**（P3）：
在票面裁决前**冻结调用方引入**；裁决选项 = 维持 panic（记录）或对齐
`MemoryImage::getPage` 的显式 skip 语义（`startalign < ptraddr`，属按意图修复、与
oracle-as-written 分歧，需 roadmap 记录）。

---

## K6 — pcode snippet 关键字排序违规（排序不变量破坏）

**① 12.0.4 定位**：`pcodeparse.y:228-295`（生成件 pcodeparse.cc 同体）：注释自称
"Sorted list of identifiers" 的 `PcodeLexer::idents[]` 46 项中，**索引 8 `"||"`
（0x7C,0x7C）先于索引 9 `"abs"`（0x61..）**——`'|'=124 > 'a'=97`，任何字节序语义下均
逆序（唯一违序对）。`findIdentifier`（pcodeparse.y:278-295）对此表做**二分查找**
（`str.compare`，无符号字节字典序）。本 lane 以脚本逐字复刻该二分实测：
**`"||"` 与 `"abs"` 均返回 -1（双双 miss）**，其余 44 项可达。后果：`PcodeLexer::
getNextToken`（pcodeparse.y:579-586）对一切 identifier 态 token（含 special2 产出的
双字符操作符）走 `findIdentifier`，miss → 返回 STRING——即 **pcode snippet 里
`a || b` 与 `abs(x)` 无法用作关键字**（`||` 降级为标识符 token → 语法错误；`abs`
被当符号名查 tree/sleigh）。受影响面：仅 `PcodeSnippet`（pcodeparse.y 自带 parser，
服务 `inject_sleigh.cc:387` 手工 callfixup/callotherfixup snippet、ifacedecomp 控制台）；
SLEIGH 编译器本体走 slghscan.l，不受影响。**存在性**：✅（静默误词法，非内存 UB；
"kuna 违反容器排序不变量"表述与实测一致）。

**② Rugra 形态**：`src/pcodeparse.rs:403 PCODE_IDENTS`（`IDENTREC_SIZE=46`，
pcodeparse.rs:36）**逐字节镜像表序**：`"||"`（:437-439）在 `"abs"`（:441-443）之前；
`find_identifier`（pcodeparse.rs:594-）同二分算法 ⇒ **同样的双双 miss，行为与 oracle
等价**。⚠ 已有测试 `test_idents_table_sorted`（pcodeparse.rs:4577-4590）刻意只校验
字母前缀子序列有序，`test_find_identifier_hits`（:4592-4604）skip(10) 放过 `"abs"`，
其注释（:4596-4598）断言 *"Ghidra's lexer never calls findIdentifier for [abs] — abs
is matched by the state machine"*——**该归因是错的**（pcodeparse.y:582 对一切
identifier 态 token 均查表；真正原因是排序逆序导致的 miss），虽然结论（miss）与
实测一致，但错误注释会诱导后人"修好表序"或"补 abs 状态机匹配"，反而制造分歧。

**③ 裁决**：`SAME-UB-MIRRORED`（行为等价镜像，无需修复）。开票
**KUNAUB-IDENTS-PIN-0001**（P3）：钉死 `"||"`/`"abs"` 双 miss 为 oracle 正典行为
（回归测试），并订正错误注释，防未来"好心排序"破坏等价。

---

## 方法与证据索引

| 证据 | 位置 |
|---|---|
| oracle commit 核验 | worktree `ghidra/` → `/home/ls/Rugra/ghidra` @ `e40ed13014` |
| master↔12.0.4 逐文件差分 | `git log master --not e40ed130 -- <file>`（本 lane 亲跑，结论见头部） |
| K4 ASan 实证 harness | 本 lane 运行于 /dev/shm/rugra-tests/kunaub（已按车道纪律清理；栈帧与触发条件已内嵌本文 K4 节） |
| K6 二分 miss 实测 | 对 pcodeparse.y:229-276 表逐字复刻 `findIdentifier`（pcodeparse.y:278-295）模拟，输出：miss = `['||', 'abs']`，违序对 = `[8]/[9]` |
| K2/K3/K5 Rust 语义判定 | Rust 语言规范：除法/取余溢出恒 panic（不受 overflow-checks 管辖）；`overflow-checks=on` 时乘/加溢出 panic，release 回绕（有定义） |

（车道终报：`/dev/shm/rugra-reports/LANE_KUNAUB_2026-09-26.md`）
