# B4 — Architecture-owned StringManager（RulePtrsubCharConstant × PrintC 共用）只读审计

只读审计报告，2026-08-24。Oracle：Ghidra 12.0.4 tag `Ghidra_12.0.4_build`，commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。仓库 `/home/wirs/DEV/Rugra`（只读：未修改任何
仓库文件、未运行 cargo）。本报告对应 hugehelp 根因第 4 步
（`docs/alignment_docs/THREE_FUNCTION_HANDOVER_2026-08-24.md` §3.1 第 4 条）。

---

## 0. 一句话结论

Ghidra 的解是**一个 Architecture 拥有的、以完整 Address 为键、正/负结果都缓存的
StringManager**：Rule（`ruleaction.cc:7375`）与 PrintC（`printc.cc:1537`）问同一个对象，
负缓存保证非法地址只读一次 image。Rugra 的 `stringmanage.rs` 已有近似骨架但
（a）`isString` 不触发读取、（b）读法/缓存语义偏离、（c）生产 Architecture 从不构建它、
（d）rule 侧用 `string_table` 冒充 readonly 守卫、（e）print 侧 `push_ptr_char_constant`
是打 `"<str>"` 的 stub——五个缺口叠加导致 hugehelp 六个 puts 全部打裸 hex
（`result/curl_cur.c:1131-1140`）。hugehelp 六地址的真实判定证据：**三个"非法"地址在
NUL 终止符之前含 Latin-1 软连字符 0xAD（非法 UTF-8/非法 ASCII 字符集字节），三个
"合法"地址是纯 ASCII 且 NUL 在 3354–10329 字节处**——golden（GUI/GhidraStringManager
语义）据此给出 `&DAT_*` ×3 + 截断字符串 ×3。

---

## 1. Ghidra 共享模型（全部函数体已读）

### 1.1 所有权与生命周期

- `Architecture::stringManager`（architecture.hh:203）裸指针成员；`Architecture::init`
  经纯虚 `buildStringManager`（architecture.cc:1401，architecture.hh:308）构建；析构
  delete（architecture.cc:221-222）；encode/decode 随 Architecture 序列化
  （architecture.cc:482、519）。
- 两个实现，maximumChars 都固定 **2048**：
  - 独立/SLEIGH：`SleighArchitecture::buildStringManager` → `new StringManagerUnicode(this,2048)`
    （sleigh_arch.cc:247-251）。自己读 loadimage。
  - GUI/服务：`ArchitectureGhidra::buildStringManager` → `new GhidraStringManager(this,2048)`
    （ghidra_arch.cc:365-369）。`GhidraStringManager::getStringData`
    （string_ghidra.cc:42-54）把 (addr, charType 名+id, maxBytes=2048) 经
    `ELEM_COMMAND_GETSTRINGDATA` 发给 Java（ghidra_arch.cc:780-810），Java 回 UTF8 字节 +
    isTrunc 标志——**检测由 Java 侧完成，2048 只是返回截断界**。

### 1.2 缓存键形态与正/负缓存

- 键 = **完整 `Address`（space+offset）**：`map<Address,StringData> stringMap`
  （stringmanage.hh:48；map 按 space 后 offset 排序）。`StringData{bool isTruncated;
  vector<uint1> byteData}`（stringmanage.hh:43-47），byteData 为 UTF8。
- **负缓存**：`StringManagerUnicode::getStringData`（stringmanage.cc:427-475）先查 map
  （430-435 命中直接返回）；**未命中先在 map 里占坑空条目（437 `stringMap[addr]`，438
  isTruncated=false）再尝试读取**——opaque 编码（441-442）、loadimage 不可用
  （DataUnavailError，465-467）、找不到终止符（455-457）、编码非法（469-471）全部
  `return stringData.byteData`（空）→ **失败结果与成功结果一样留在缓存里**，同地址二次
  询问零 image 读取。`isString`（166-172）＝ `getStringData(...).empty()` 取反。
- **内部字符串**：`registerInternalStringData`（185-199）对 CALLOTHER(string_data) 场景把
  字节注册到**常量空间**地址：`calcInternalHash`（95-105）＝
  `addr.getOffset() ^ (CRC32(bytes, init 0x7b7c66a9) << 32)`，键 =
  `getConstant(hash)`；编码非法返回 0。

### 1.3 读取、阈值与 truncate 语义（StringManagerUnicode）

- **增量读**：do-while 每次 `loadFill` 32 字节（449-460），每块查 `hasCharTerminator`
  （277-291：按 charsize 对齐的连续全零块）；累计上限 maximumChars=2048 字节——
  超限时把最后一块裁到恰好 2048（452-454），已到 2048 仍无终止符 → 返回空
  （455-457 "Could not find terminator"）。
- **编码校验**：终止后 `checkCharacters(testBuffer, curBufferSize, charsize, bigend)`
  （469，实现 324-339）逐 codepoint 校验（`getCodepoint` 347-410：UTF8 前缀链、UTF16
  代理对、UTF32、>0x10FFFF/代理区非法）；numChars<0 → 负缓存空返回（470-471）。
- **赋值/截断**：`assignStringData`（66-86）：`charsize==1 && numChars<maximumChars` →
  **原样整块拷贝**（含终止符及所在 32 字节块的尾部填充，69-72）；否则 writeUnicode
  翻译/截断 + 显式补 NUL（73-84）。`isTruncated = (numChars >= maximumChars)`（85）。
  打印端截断标记：`printc.cc:1548-1549` `...\" /* TRUNCATED STRING LITERAL */`。
- **注意（对 B4 决定性）**：在 StringManagerUnicode 语义下，**任何 NUL 不在前 2048 字节
  内的字符串都是负结果**。hugehelp 六个地址到 NUL 都 >3354 字节，若 golden 由该实现
  产生，六个应全是 `&DAT_*`；golden 实际后三个是字符串 → **golden 走的是
  GhidraStringManager/Java 语义**（检测不受 2048 限制，仅返回截断到 2048+isTrunc；
  golden 字面量解转义后 ≈2048 字符 + `/* TRUNCATED STRING LITERAL */` 佐证）。

### 1.4 两个消费者

- **Rule 侧**：`RulePtrsubCharConstant`（ruleaction.cc:7323-7403；注册
  coreaction.cc:5703，cleanup 组）。守卫链：in(0) 读类型是 TYPE_PTR→TYPE_SPACEBASE
  （7358-7361）；in(1) 常量（7363-7364）；输出 getTypeDefFacing 是 TYPE_PTR 且
  ptrto `isCharPrint()`（type.hh:218，chartype|utf16|utf32|opaque_string）
  （7365-7369）；`TypeSpacebase::getAddress`（type.cc:3061-3071 → `resolveConstant`
    translate.cc:628-641）算 symaddr；`scope->isReadOnly(symaddr,1,usepoint)`
  （7371-7373；Scope::isReadOnly＝queryProperties 查 `Varnode::readonly` 标志，
  database.cc:1796-1801）；**`data.getArch()->stringManager->isString(symaddr,basetype)`
  （7375）不过则原样保留 PTRSUB**。通过后：输出非 addrForce → 遍历后代尝试
  `pushConstFurther`（7379-7391；PTRADD slot0 + 常量索引 → 折成常量 COPY，7323-7340），
  全部成功才 `opDestroy`（7392-7394）；否则 PTRSUB → 常量 COPY + `updateType(outtype)`
  （7395-7401）。
- **Print 侧**：`pushConstant` TYPE_PTR 分支（printc.cc:1778-1790）ptrto isCharPrint →
  `pushPtrCharConstant`（1698-1720）：val≠0 → `glb->resolveConstant(defaultDataSpace,
  val, ct->getSize(), point, fullEncoding)`（1707）→ `symboltab->getGlobalScope()->
  isReadOnly(stringaddr,1,Address())`（1709）→ `printCharacterConstant`（1534-1553）：
  **`glb->stringManager->getStringData(addr, charType, isTrunc)`（1537-1541）**，空 →
  false；宽字符前缀 `L`（1543-1544，charsize>1 且非 opaque）；`escapeCharacterData`
  （printlanguage.cc:498-511，charsize 固定 1，遇 NUL/-1 停）；isTrunc → `...\" /*
  TRUNCATED STRING LITERAL */`。CALLOTHER display_string 也走同一入口
  （printc.cc:694-712，内部字符串的 const-hash 地址）。
- **共享要点**：两个消费者不维护各自的字符串缓存；print 询问的地址与 rule 判定过的
  地址是同一个 Address 键，负缓存让 print 阶段零重复读取。`isString` 的 charType 参数
  即 rule 的 basetype（决定 charsize 与 opaque 早退）。

### 1.5 四类决定性语义核对表（StringManager 侧）

| 类别 | Ghidra 证据 |
|---|---|
| 引用/输出参数 | `getStringData` 返回 `const vector<uint1>&`——**缓存内部向量的引用**（非拷贝）；`isTrunc` 是 out bool（433/439/473 三处写）；map 条目一经写入对后续查询稳定（430-435 早退）。`StringData&` 由 `stringMap[addr]` 就地改写（437、472）。 |
| 循环边界/遍历顺序 | 读循环 do-while（449-464）：块大小 32；`newBufferSize > maximumChars` → 裁到 2048；`amount==0` → 出口；每块 `hasCharTerminator` 后 `curBufferSize=newBufferSize` 再判循环。encode 遍历 map 升序（209，space 后 offset）。 |
| 计数器/累加器 | `curBufferSize` 单调累加（444-463）；`writeUnicode` 的 `count`（40、48-49）达到 maximumChars 即 break（截断）；`checkCharacters` 的 `count` 遇 NUL 停（331-337）。三者互不共享、不重置跨调用。 |
| 排序/比较键 | map 键＝完整 Address（address.hh operator<：space 序再 offset 序）；`isCharPrint` 等值判断（type.hh:218）；终止符判定＝charsize 对齐全零块（280-289）；无 tie-break。 |

---

## 2. hugehelp 六地址预期分类（含字节级依据）

二进制 `examples/curl`（PIE，golden 基址 0x100000；第三 LOAD vaddr==file offset）。
`hugehelp` @0x4a00（84B，`examples/curl_decompile.rs:106`）。六个 puts 实参均为 .rodata
字符串**起始**（各地址前 1–7 字节均为 0x00 填充，已核）。逐地址实测
（file offset==低 16 位，`xxd`/python 验证）：

| 地址(VA) | 到 NUL 长度 | NUL 前非 ASCII 字节 | 首个 ≥0x80 偏移/上下文 | 预期分类 |
|---|---|---|---|---|
| 0x107180 | 10272 (NUL@0x99a0) | **9 个 0xAD** | +0x5ac：`vol\xad\nume` | **非法** → isString=false → PTRSUB 保留 → `puts(&DAT_00107180)`（golden:2196） |
| 0x1099a8 | 10284 (NUL@0xc1d4) | **18 个 0xAD** | +0x184：`opera\xad\ntion` | **非法** → `puts(&DAT_001099a8)`（golden:2197） |
| 0x110c1d8 | 10340 (NUL@0xea3c) | **12 个 0xAD** | +0x18d：`sec\xad\nond` | **非法** → `puts(&DAT_0010c1d8)`（golden:2198） |
| 0x10ea40 | 10284 (NUL@0x1126c) | **0** | — | **合法** → rule 折 COPY typed const → 字符串字面量，**截断**（10284>2048 → isTrunc）→ golden:2199 `"\\n   or specify them with the -u flag li…specifi..." /* TRUNCATED */` |
| 0x111270 | 10329 (NUL@0x13ac9) | **0** | — | **合法** → 截断字符串（golden:2216 段，`--dump-header headers…`） |
| 0x113ad0 | 3354 (NUL@0x147ea) | **0** | — | **真实数据判定=合法**（纯 ASCII 到 NUL；3354>2048 仍截断）→ 截断字符串（golden:2237 段，` check the other way around…`） |

依据行号：
- 判"非法"：`getCodepoint` UTF8 分支 stringmanage.cc:363-391——0xAD 满足
  `(val&0x80)!=0` 且不匹配 c0/e0/f0 任何前缀 → **391 return -1** → `checkCharacters`
  324-339 返回 -1 → 负缓存空（470-471）→ `isString`=false（166-172）→
  `RulePtrsubCharConstant::applyOp` 7375 `return 0`（PTRSUB 保留）→ 打印侧
  `printCharacterConstant` 空缓冲 return false（1541-1542）→ `&DAT_*` 符号。
  （GUI 路径等价：Java 侧 ASCII 字符集不含 0xAD，且需 NUL 终止——0xAD 之前无 NUL。）
- 判"合法/截断"：纯 ASCII 全部 codepoint<0x80 合法；NUL 终止成立；golden 字面量
  解转义后 ≈2048 字符 + `/* TRUNCATED STRING LITERAL */`＝`printc.cc:1548-1549` 的
  isTrunc 消费点 → maximumChars=2048（ghidra_arch.cc:368）只作用于**返回截断**。
- **实现分叉警报**：native `StringManagerUnicode` 的终止符搜索被 2048 上限封顶
  （stringmanage.cc:452-457）——六个地址 NUL 均 >3354 字节，**该实现下六个全是负结果**，
  与 golden 后三个矛盾。证明 golden 由 GhidraStringManager（Java 检测、2048 只截断返回）
  产生。Rugra 生产管线（无 Java）要复现 golden 分类，manager 的**检测**语义必须对齐
  GhidraStringManager 契约（字符集合法 + NUL 终止，检测不设 2048 界；返回截断 2048 +
  isTrunc），而 1:1 的 StringManagerUnicode 移植保留给 native 对拍（其 2048 界行为本身
  也要被双侧 fixture 锁定，见 §5）。这是 B4 最重要的一条架构决策，不能含糊。

---

## 3. Rugra 差异表（双侧行号）

| # | 差异点 | Ghidra (file:line) | Rugra (file:line) | 性质 |
|---|---|---|---|---|
| 1 | `isString` 只查缓存不触发读取：Ghidra isString → 虚 getStringData（读 image + 负缓存）；Rust 基类 `is_string` 仅 `string_map.get`，而 rule 侧拿的正是基类 `Arc<RwLock<StringManager>>` → 生产永不命中 | stringmanage.cc:166-172 / 427-475 | stringmanage.rs:303-310；ruleaction.rs:11307-11311 | **根因 A**（rule 侧守卫永远 false → 永不折叠） |
| 2 | 读法：Ghidra 32 字节增量 + 每块查终止符 + DataUnavailError→空 + 先占坑（负缓存）；Rust 一次性 `load_fill(2048*charsize)`，checkCharacters 与 has_char_terminator 顺序颠倒，无 opaque 早退 | stringmanage.cc:437-467 / 441-442 | stringmanage.rs:453-495（467-471 一次读；473-482 先 checkCharacters 后 terminator） | 语义偏差（见 §1.3；>2048 串与段尾行为不同） |
| 3 | byteData 内容：Ghidra charsize==1 && numChars<max 存**含终止符所在 32 字节块**的整块；Rust 存满 2048 原始字节（打印等价、缓存内容/encode 不等价） | stringmanage.cc:69-72 + 449-472 | stringmanage.rs:257-259 + 467-472 | 观察面差异 |
| 4 | 缓存键：Ghidra 完整 Address（space+offset）；Rust `BTreeMap<u64,…>` 丢 space（ram 与 const 空间内部串可撞键） | stringmanage.hh:48 | stringmanage.rs:275 | 键形态缺口 |
| 5 | `registerInternalStringData`/`calcInternalHash`（CRC32^offset<<32，const 空间键，非法返 0）缺失；`get_internal_string` 自造 `addr\|charsize<<56` 哈希且键到 op 地址 | stringmanage.cc:95-105,185-199 | funcdata.rs:6767-6815（代码内已标 RUGRA-GAP） | 内部字符串路径缺口（D3 邻接） |
| 6 | Architecture 不构建 manager：`string_manager` 恒 None（无生产 caller），类型是基类而非 Unicode/Ghidra 变体，未挂 loader | architecture.hh:203、architecture.cc:1401、sleigh_arch.cc:247-251、ghidra_arch.cc:365-369 | arch.rs:538、662、2264-2268；生产 driver 无 `set_string_manager` | **根因 B**（没有共享对象可共用） |
| 7 | rule readonly 守卫被 string_table 顶替（"是已知字符串"冒充"只读"——语义恰好相反方向） | ruleaction.cc:7371-7373；database.cc:1796-1801 | ruleaction.rs:11294-11301 | 守卫错位 |
| 8 | rule 缺 removeCopy 分支：无 isAddrForce 检查、不遍历后代 pushConstFurther、永不 opDestroy（`push_const_further` 为死代码）；类型用 get_type() 而非 getTypeReadFacing(op) | ruleaction.cc:7379-7401 / 7358 | ruleaction.rs:11228-11257（死）、11262-11324 | 变换不完整 |
| 9 | print：`push_ptr_char_constant` stub 打 `"<str>"`；`push_constant_typed` Pointer 臂不走 ptr-char/code 分派直接 default cast；TRUNCATED 标记无处产生 | printc.cc:1744-1790、1698-1720、1534-1553 | printc.rs:9090-9093、10755-10762 | **根因 C** |
| 10 | print 用 Funcdata `string_table` 快照（含 80 字符 "(continues)"、子串扫描等 Ghidra 无的行为）；curl driver 的 string_table 抽取 `is_ascii()||FFFD` 过滤**保留含 0xAD 的串**（把 0xAD 丢掉的清洗串）——与 oracle 分类直接冲突 | 无对应物 | printc.rs:7785-7812、7905-7925、4165-4169；curl_decompile.rs:2550-2571 | 非 Ghidra adapter，须退役 |
| 11 | CALLOTHER display_string 恒打 `"badstring"` | printc.cc:694-712 | printc.rs:8444-8452 | 内部字符串打印缺口 |
| 12 | `resolveConstant`/`Scope::isReadOnly` 已有 1:1 地基但无此消费点 | translate.cc:628-641；database.cc:1796-1801 | translate.rs:1679-1710（未接线到 ptr-char 常量）；database.rs readonly 标志存在（:44、1351、2761-2766） | 地基可用、缺接线 |

已对齐确认（无需重写）：`write_utf8`/`read_utf16`/`get_codepoint`/`check_characters`/
`has_char_terminator`/`write_unicode` 的逐 codepoint 语义（stringmanage.rs:28-244 ↔
stringmanage.cc:124-410）；`assign_string_data` 的 isTruncated 判定（:268 ↔ :85）。

---

## 4. 移植方案（write-set + 租约冲突）

### 4.1 目标形态

1. `Architecture` 独占拥有 `Arc<RwLock<StringManagerUnicode>>`（不是基类），构造时挂
   loadimage、maximumChars=2048（对齐 sleigh_arch.cc:250）。E2E 语义开关：为复现
   golden 的 >2048 正结果，manager 需实现 GhidraStringManager 契约（检测=NUL 终止 +
   字符集合法、不设 2048 检测界；返回=2048 截断 + isTrunc）——以真实 loadimage 字节为
   数据源。1:1 的 StringManagerUnicode（2048 界）行为同时保留并双侧锁定（§5 F7）。
   两者的选择必须在 `ALIGNMENT_ROADMAP.md`/commit Evidence 里显式声明为 GhidraStringManager
   对齐（ghidra_arch.cc:365-369 + Java 契约），不得默默发明第三种语义。
2. rule 侧（ruleaction.rs：applyOp 守卫链重写）：
   - `getTypeReadFacing` → TYPE_PTR→TYPE_SPACEBASE；outvn `getTypeDefFacing` → char-print ptrto；
   - symaddr 经 `TypeSpacebase::getAddress` 等价物（现 spacebase 基址=装载基址的假设需
     换成真实 `resolve_constant`，translate.rs:1679）；
   - readonly 改查 Database/`Varnode::readonly`（database.rs 既有标志），删除
     string_table 代理（ruleaction.rs:11294-11301）；
   - isString → 共享 manager（含负缓存语义）；补 isAddrForce + 后代 pushConstFurther
     遍历 + 全成则 opDestroy（ruleaction.cc:7379-7401），激活现有死代码
     `push_const_further`。
3. print 侧（printc.rs）：
   - `push_constant_typed` Pointer 臂接 `push_ptr_char_constant` 真身：resolveConstant +
     globalScope isReadOnly + `print_character_constant`（共享 manager getStringData；
     `L` 前缀、escapeCharacterData 等价物、TRUNCATED 标记三件套，printc.cc:1534-1553）；
   - `op_callother` DISPLAY_STRING 分支经 const-hash 地址走同一 `print_character_constant`
     （printc.rs:8444-8452 的 `"badstring"` 恒真值退役为失败分支）；
   - doc_function 快照模式：`fd.arch.string_manager` 以 Arc clone 进 PrintC（与
     printc.rs:6076-6077 的 cpool/userops 同款——这就是 fbf3266 `PtrCharDataSource` 想用
     注入解决的问题的正解：**直接共享 Architecture 的 manager，不再建 PrintC 私有缓存**）。
4. driver（examples/curl_decompile.rs）：构建真实 loadimage 供 manager；string_table
   仅供 legacy 回归，生产字符串路径切到 manager（§3 #10 的清洗串必须退役，否则
   0x7180/0x99a8/0xc1d8 会被错误打成串）。
5. funcdata.rs `get_internal_string` 的哈希换成 `calc_internal_hash`（CRC32，crc32.rs 已
   有）+ const 空间键（依赖 #5；与 exact-piece 租约串行）。

### 4.2 write-set 与租约冲突（实测 TODO_BOARD 2026-08-24）

| 文件 | 改动 | 冲突/约束 |
|---|---|---|
| `src/stringmanage.rs` | 修 isString/读法/键形态/负缓存/内部串哈希 | 无现行租约；但 `TYPEOP-LOCALTYPE-DISPATCH-0001` **D3 producer/string 的 write-set 已列 `src/{flow,arch,stringmanage,coreaction,ruleaction,printc}.rs`** —— B4 实质就是 D3 字符串切片，必须挂在 D3（或其子 ID）下认领，避免双 claim |
| `src/arch.rs` | manager 类型换 Unicode 变体 + build 接线 | 与 `FLOW-PROGRAM-METADATA-INGEST-0001`(BLOCKED)、`CSPEC-TEXT-INGEST-0001`(READY)、`TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001` 的 write-set 相交 → 串行协商 |
| `src/ruleaction.rs` | applyOp 守卫链 + removeCopy 臂 | **被 `TYPEFACTORY-EXACTPIECE-CALLERS-0001`（IN_PROGRESS，a2@wt-myfwrite-splitdatatype）占用 → 必须等释放**（write-set 显式含 ruleaction.rs） |
| `src/funcdata.rs` | get_internal_string 哈希修正 | 同上租约含 funcdata.rs → 串行 |
| `src/printc.rs` | pushPtrCharConstant/printCharacterConstant/TRUNCATED/快照 | 与 `PRINT-SIGNATURE-0001`(IN_PROGRESS root)、`PRINTC-FORMAT-0001`(REVIEW)、`PRINT-TYPED-CONSTANT-CLOSURE-0001`(BLOCKED——其描述"production leaf 必须携带 …readonly/StringManager"即本片 print 半边) 相交 → 建议作为 PRINT-TYPED-CONSTANT-CLOSURE-0001 的执行波或其子任务，串行占印 |
| `examples/curl_decompile.rs` | loadimage/manager 构造 + string_table 降级 | D3 write-set 已列；与 FLOW worker 改造（同文件）串行 |
| docs/api/{stringmanage,arch,ruleaction,printc,funcdata}.md | 同 commit 更新 | pre-commit 强制 |
| `tests/oracle/…`（§5）+ runner | 双侧 fixture | 仿 fbf3266 三件套结构 |

门禁：`src/printc.rs`、`src/ruleaction.rs` 都在机制 B 白名单 → curl 差分 +
`## Differential`；`src/ruleaction.rs` 在机制 C 核心白名单 → 独立 Cross-Review。
commit 含 align/port 字样 → 机制 A Evidence 块（§1.5 即底稿）。

### 4.3 fbf3266 可复用性评估

`fbf326600ed31fcbfbf593020bbab6accb096124`（**不在 HEAD**，dangling）：
- 可复用（质量高）：双侧 fixture 骨架 `tests/oracle/printc_ptrchar_constant_1204.cc`
  —— 用**真实生产 Ghidra 对象**（`StringManagerUnicode(this,2048)`、Database readonly
  Range、ContextResolver、真实 `pushVnExplicit`），14 条记录覆盖 valid/invalid-0xAD/
  负缓存重复/非只读/null/子串/上下文分辨 + loader readCount（证明同地址只读一次）。
  Rust 侧 runner/metadata 同样可搬。rpn `read_slot` 捕获（slot_of_input）与
  `typed_constant_literal` 的分派形状也可搬。
- 必须改：其 Rust 侧把 32 字节扫描/UTF-8 校验/**PrintC 私有 `ptr_char_string_cache`**
  都放进了 printc.rs——共享模型下这些必须上移到 Architecture-owned manager
  （PrintC 只消费 getStringData）；其 `PtrCharDataSource` 注入边界应退化为
  `fd.arch.string_manager` 快照；生产从未安装 adapter（A/B 零变化的原因），新版要装。
- 其 fixture 需扩：byteData 原始内容观察（§3 #3 的块舍入差异现在测不到）、rule 侧
  applyOp 双侧记录、rule→print 共享缓存的 readCount 证明、>2048 长串的
  StringManagerUnicode 负结果锁定。

---

## 5. Fixture 设计（双侧观察面）

双侧 = 锁定 12.0.4 C++（fbf3266 的 FixtureArchitecture 模式）vs Rust 同输入。观察面
必须覆盖：**正/负缓存条目、字节内容、打印文本**三族。

| Case | 输入 | 双侧观察面（逐字节比对） |
|---|---|---|
| F1 合法短串 | ram:0x2000 `alpha\0`（readonly），CALL in1 typed const (char*)0x2000 | print 文本 `"alpha"`；stringMap[0x2000] 存在、isTrunc=false、byteData=`61 6c 70 68 61 00`+块内填充至 32B（Ghidra 块舍入语义，stringmanage.cc:69-72）；loader readCount(0x2000)==1 |
| F2 非法 0xAD | ram:0x2100 `b\xad\0` | print 失败 → 默认 cast/hex（或 &DAT）；**负缓存条目存在且 byteData 空、isTrunc=false**（437+470-471）；readCount(0x2100)==1 |
| F3 重复询问（正/负各一） | F1/F2 地址二次 render | 输出不变；readCount 不增（**负缓存决定性证据**） |
| F4 非只读 | ram:0x2200 可写区合法串 | pushPtrCharConstant false（printc.cc:1709）→ cast+hex；manager 未被查询或查询与否按 Ghidra 实测记录 |
| F5 null + 上下文分辨 | val=0；val=0x40@usepoint0x5000/0x5008（ContextResolver） | `NULL`（option_NULL）或 cast 形态；两个 usepoint 得到不同 stringaddr（translate.cc:628-641 分派） |
| F6 宽字符/多字节 | UTF16 `L` 串 / 含 é 的 UTF8 串 | `L"..."` 前缀（printc.cc:1543-1544）；UTF16→UTF8 转换 byteData |
| F7 **>2048 长串** | 5000 字节纯 ASCII + NUL | StringManagerUnicode 侧：**空结果 + 负缓存**（452-457 2048 界）——双侧锁定该实现行为；生产 GhidraStringManager 契约（检测不限 2048、返回 2048+isTrunc）另以 E2E golden 差分验证（NO_ORACLE for Java-side, 对拍 `tests/golden/ghidra_curl_1204.c --func hugehelp`） |
| F8 截断标记 | 2100 字节纯 ASCII + NUL | numChars>=2048 → byteData=2048 字符 + isTrunc=true → `..." /* TRUNCATED STRING LITERAL */`（printc.cc:1548-1549） |
| F9 **rule 侧 applyOp**（新增，fbf3266 无） | PTRSUB(spacebase, const 0x2000)，输出 (char*)，readonly 区 | rule fire：op→COPY+typed const（ruleaction.cc:7395-7401）；PTRADD 后代被 pushConstFurther 折叠（7323-7340）；非法 0x2100：op 原样（7375 return 0）；isAddrForce 输出：removeCopy=false 保 COPY；混合后代：有不可折后代 → op 保留 |
| F10 **rule→print 共享缓存**（B4 核心） | 先跑 rule（F9 场景）再 print 同一地址 | print 阶段 loader readCount 不增（同一 Address 键命中 rule 写入的条目）；打印文本与 rule 折叠状态一致（字符串）或一致保留 `&DAT_*` |
| F11 内部字符串 | getInternalString 字节串 | registerInternalStringData 哈希逐字节一致（CRC32^offset<<32，const 空间键）；CALLOTHER display_string 打印（printc.cc:707）vs `"badstring"` 失败分支 |
| F12 键形态 | ram:0x2000 与 const:0x2000 两键 | map 两条独立条目（space 参与键，stringmanage.hh:48） |

E2E 验收：
```bash
cargo run --release --example curl_decompile   # 产出 result/curl_cur.c
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func hugehelp -v
```
预期：六 puts → `&DAT_00107180`/`&DAT_001099a8`/`&DAT_0010c1d8` + 三个 2048 字符
TRUNCATED 字符串（golden:2196-2262 逐字对齐）；`&DAT_*` 命名依赖 Database 符号层
（根因第 3 步先决，B4 只保证"保留 PTRSUB/折叠常量"的二分正确）。全量
`--summary-only` 的 defects/numbering 变化逐条绑 TODO ID。

---

## 6. 结论浓缩

- **共享模型**：Architecture 独占 StringManager（2048 上限；GUI=GhidraStringManager/Java，
  standalone=StringManagerUnicode/image 自读）；键=完整 Address；**正/负都缓存**
  （失败先占坑再读，stringmanage.cc:437/465-471）；截断=isTruncated(numChars>=2048)+
  `/* TRUNCATED STRING LITERAL */`（printc.cc:1548）。Rule(7375) 与 PrintC(1537) 问同一
  对象，负缓存是共享的量化证据（readCount 不增）。
- **六地址判定**（字节实测）：0x7180/0x99a8/0xc1d8 的串在 NUL 前含 0xAD（首个分别在
  +0x5ac/+0x184/+0x18d）→ getCodepoint -1（stringmanage.cc:391）→ 负缓存 → PTRSUB 保留
  → `&DAT_*`；0xea40(+10284B)/0x11270(+10329B)/0x13ad0(+3354B) 纯 ASCII 到 NUL → 正缓存
  → rule 折 COPY typed const → 2048 字符 TRUNCATED 字面量。**注意 native
  StringManagerUnicode 的 2048 终止符搜索界会让六地址全负——golden 证明 oracle 走
  GhidraStringManager 契约（检测无界、返回截断），B4 生产语义必须按此对齐并显式声明。**
- **Rugra 五缺口**：isString 不读缓存外数据（ruleaction.rs:11307 拿到的是空 manager）、
  Architecture 永不构建 manager（arch.rs:662 None）、rule readonly 用 string_table 顶替、
  print ptr-char 是 "<str>" stub、driver 的 string_table 清洗串保留 0xAD 串——联合导致
  hugehelp 全打裸 hex。
- **租约**：`src/ruleaction.rs`（+funcdata.rs）被 `TYPEFACTORY-EXACTPIECE-CALLERS-0001`
  占用须等释放；printc.rs 与 PRINT-SIGNATURE/PRINTC-FORMAT/PRINT-TYPED-CONSTANT-CLOSURE
  串行；本片应挂 `TYPEOP-LOCALTYPE-DISPATCH-0001` D3（其 write-set 已列
  stringmanage/arch/ruleaction/printc/curl_decompile）。机制 B+C 门禁适用
  （printc/ruleaction 双白名单，需 Differential + 独立 Cross-Review）。
- **fbf3266**：不在 HEAD；双侧 fixture 骨架（真实 Ghidra 对象、14 记录、readCount 计数）
  高度可复用，但其 PrintC 私有缓存/自带扫描必须上移为共享 Architecture manager，
  生产 adapter 缺失是它 A/B 零变化的原因，新版必须装上。
