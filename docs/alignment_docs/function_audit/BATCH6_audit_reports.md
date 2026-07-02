# 批6 函数级对齐审计报告（2026-07-02）— 外围/桩（最后一批）

> 纯只读并发审计。9 个 Agent 涵盖 ~22 文件。判档：✅ALIGN / ⚠️DIFF / ❌MISSING / ➕EXTRA。

## 批6 跨文件头号根因（续编 R90+）

| # | 根因 | 文件:行 | 直接症状 | Ghidra 对照 |
|---|---|---|---|---|
| R90 | **database 整 Database/Scope 未接管线 + 无 queryByAddr/queryContainer/queryProperties** | database.rs/arch.rs:541 | ELF 符号进 HashMap 非 DB；符号永不回写（varmap 审计根源）| database.cc:909-1000 |
| R91 | **database findAddr/findContainer 不门 usepoint/inUse** | database.rs:872 | 存储回收跨码区返回陈旧/错符号 | database.cc:2224,2250 |
| R92 | **database makeNameUnique 全缺 + Symbol.id 按 id 键非名** | database.rs | 命名冲突无处去重 | database.cc:2712-2742,2553 |
| R93 | **arch.overrides 字段错置（应在 Funcdata）+ FLOWOPT_ERROR_TOOMANY=1 应 0x20** | arch.rs:252,23 | override 每函数隔离丢 + flowoptions 默认错 | funcdata.hh:98 + flow.hh:65 |
| R94 | **callgraph 无 spanning-tree leaf-walk + complement edge 索引** | callgraph.rs | initLeafWalk/nextLeaf/snipCycles 朴素扫描非 Ghidra | callgraph.cc:293-336 |
| R95 | **marshal 全标准 ATTRIB_*/ELEM_* ID 表未填 + ATTRIB_UNKNOWN=0 应 159** | marshal.rs:21 | 所有 `AttributeId::new(name,0)` 碰撞 id 0=unknown | marshal.cc:1228-1271 |
| R96 | **marshal 无 write_space/read_space + write_bool 发"1"/"0"非"true"/"false"** | marshal.rs | 地址编码全错（确认 override/cpool/context 审计）| marshal.cc:1193-1225,514 |
| R97 | **memstate MemoryImage 持 Vec<u8> 非 LoadImage + 硬小端 + 无 endianness 参数** | memstate.rs:126 | 模拟器够不到二进制字节（jumptable 审计根源）| memstate.cc:365-411 |
| R98 | **memstate MemState 键 String 名非 AddrSpace + 无 IPTR_CONSTANT 短路** | memstate.rs:228 | getValue 对常量空间查不存在的 bank 返 None | memstate.cc:620-736 |
| R99 | **context TrackedContext 丢 space + get_tracked_value 精确匹配非 containment** | context.rs:97,170 | 跨空间跟踪坏 + 部分寄存器读返 0 | globalcontext.cc:224-251 |
| R100 | **context ContextCache::set_context 空桩 + set_variable 不 paint-to-change-point** | context.rs:564,250 | 写回不通；get_variable 在两 split 间返错值 | globalcontext.cc:587-616,424-468 |
| R101 | **float_emulate max_exponent off-by-one（254/2046 应 255/2047）** | float_emulate.rs | inf/NaN 解码错（读成假 normalized）| float.cc:59 |
| R102 | **float_emulate op_int2float 无符号扩展 + op_trunc 不 mask size_out** | float_emulate.rs | 负整转大正 float；截断宽度错 | float.cc:614-615,638 |
| R103 | **emulate execute_load/store 硬"ram" + 忽略 input(0) 空间 + 无 addressToByte** | emulate.rs | 非 ram 空间 LOAD/STORE 全错 | emulate.cc:237-257 |
| R104 | **signature 用捏造 hash 算法 + SignatureDB 非 Ghidra 概念** | signature.rs | hash_opcode/combine_hashes 不匹配 Ghidra CRC | signature.cc:43-59,105-116 |
| R105 | **pcodeparse allocate_temp +1 应 +16 + lexer 词表错 + parse_stream 空桩** | pcodeparse.rs:280,106,311 | temp 碰撞 + token 错 + 不 parse | pcodeparse.cc:3134 + 2795-3104 |
| R106 | **double_precis is_arithmetic_op 集错**（含 ZEXT/NEGATE/XOR/AND/OR/SHIFT/PIECE/SUBPIECE，缺 CARRY/SCARRY/SBORROW/PTRADD/PTRSUB）| double_precis.rs:6924 | 过标逻辑/移位为算术 + 漏 CARRY 等的 SUBPIECE 整体 | typeop.cc addlflags=arithmetic_op |
| R107 | **compression deflate/inflate 返回极性反 + finish 标志忽略 + level clamp 破 0/-1** | compression.rs | 增量压解不可能 + 错默认级 | compression.cc:46-99 |

---

## 报告 1: database.rs — 符号表

**Summary**: **结构在但功能桩，且未接管线**。叶级忠实（flag 枚举、SymbolEntry 字段、Symbol encode/decode header、ID_BASE 常量）。**每结构级不忠实**: per-address-space maptable rangemap 塌成 Vec；findAddr 丢 usepoint/inUse 过滤；whole_count 无条件增量；piece/split-symbol + join-address 处理走；name-dedup 树 + makeNameUnique 走；分层查询栈走。自评 L1→L2 准确可能宽宏。

**关键发现（确认并锐化先前）**:
- addSymbol 部分孤立工作——Scope::add_symbol + add_symbol_mapped 插 Symbol 进 BTreeMap + push SymbolEntry，bare Symbol 编解码往返过
- **find_symbol 不存在为方法**——只有 find_by_name 返 Vec<Arc<Symbol>>。printc.rs:1777 的 find_symbol 解析到 varmap::ScopeLocal::find_symbol 非 database
- **makeNameUnique 全缺**（关键检查#4）。Symbol.name_dedup 字段在但从不读写
- **跨 scope 查询层（queryByAddr/queryContainer/queryProperties + stackAddr/stackContainer 走）全缺**。varmap/printc/coreaction 依赖
- varmap 审计"符号永不回写"成立且扩到整 Database：set_symboltab 从不调；symboltab 永远 None

**Pipeline 接线核查**: **No。Database 管线死码。** ELF 符号进平 HashMap<u64,String>（funcdata.rs:62, bin/rugra.rs:246）绕过符号表。coreaction.rs:6033-6052 自承"Rugra 不移植 Scope::queryProperties/discoverScope"。

**关键修复**（见 R90-R92 +）:
1. P0 接 Database 进管线——填全局 scope 从 ELF 符号图 + printc 回退 Database 查全局地址
2. P0 移植跨 scope 查询层（queryByAddr/queryContainer/queryProperties + stack* 走）
3. P0 修 findAddr/findContainer 门 usepoint/inUse
4. P1 恢复 per-space rangemap 或至少存储-map 序列化（<mapsym>+<addr>/<hash>）—— 现符号存储不往返
5. P1 移植 makeNameUnique + name-dedup 树
6. P1 修 whole_count/type-size 契约（需 Symbol 持真 Datatype）
7. P2 小保真 bug（is_piece/is_dynamic/setIsolated/setAttribute 掩码/map_scope 返/global-scope 名空/ID scope 混合）
8. P2 缺 Symbol 子类 ExternRefSymbol/UnionFacetSymbol + FunctionSymbol 须持 Funcdata

---

## 报告 2: arch.rs + capability.rs + callgraph.rs

**arch.rs Summary**: L1→L2 自评对容器形准，但 **1 确认错置 bug（Override 字段）+ 1 错常量（FLOWOPT_ERROR_TOOMANY）+ 多缺子系统字段 + 桩方法**。

**确认 bug**: Architecture.overrides:Override（arch.rs:252）错——Ghidra 是 Funcdata::localoverride（funcdata.hh:98,206），Architecture 无 Override 字段。doc 自供"Faithful to the Override owned by Funcdata (referenced via Architecture)"——是 Funcdata 拥有句号。**错常量**: FLOWOPT_ERROR_TOOMANY=1<<0(=1) 应 0x20（FlowInfo::error_toomanyinstructions flow.hh:65）→ reset_defaults_internal flowoptions 默认错（1 非 32）。缺子系统字段: translate/pcodeinjectlib/print/printlist/inst/allacts/inferPtrSpaces/defaultReturnAddr/extra_pool_rules。

**capability.rs Summary**: 三文件最干净——capability.{hh,cc} 近忠实 L4 端口。CapabilityPoint trait + CapabilityRegistry 直接映射，initialize_all 匹配 Ghidra initializeAll 精确。唯一适配是结构（静态→实例+OnceLock 全局单例）。

**callgraph.rs Summary**: **三中最弱**。数据结构 + flag 常量忠实翻译，但**核心算法是分歧近似非忠实端口**。spanning-tree leaf-walk 机器（popPossible/pushPossible/insertBlankEdge/LeafIterator——Ghidra initLeafWalk/nextLeaf/snipCycles 算法心脏）**全缺**，Rust 替代是朴素扫描不复制 Ghidra 语义。complement edge-index（双向链入/出边）缺，addEdge 不去重不排序。

**关键修复**（见 R93-R94 +）:
1. [arch] **删 Architecture.overrides 字段**（L252）——改读 Funcdata 每函数 override
2. [arch] **修 FLOWOPT_ERROR_TOOMANY**（L23）1<<0→0x20
3. [callgraph] **实 spanning-tree leaf-walk 机器**（complement + parentedge + LeafIterator + insertBlankEdge + popPossible + pushPossible）+ 重写 add_edge/init_leaf_walk/next_leaf/snip_cycles/cycle_structure 匹配 cc:243/321/336/129/352。至少恢复 add_edge 去重+排序+complement
4. [arch] 补缺子系统字段 + 连 ArchitectureCapability → CapabilityPoint + initialize() hook + 修 encode 元素名 + 子组件编码

---

## 报告 3: marshal.rs + context.rs + loadimage.rs + memstate.rs

**⚠️ 文件配对更正**:
1. context.rs ↔ **globalcontext.hh/.cc 非 context.hh/.cc**（Ghidra context.{hh,cc} 是 Sleigh ParserContext；Rust context.rs 是 globalcontext 端口）。真 context.{hh,cc} Sleigh 解析器类**无 Rust 对应**
2. marshal.rs marshal.hh 行引用不准（xml.hh 内容算 marshal.hh）
3. **三标记上游审计全在 Ghidra 源级确认**（override `<addr>`、cpool marshal ID 0、jumptable 模拟器 LoadImage）

**marshal.rs Headline**: **Ghidra ID 模型**: 全局单例硬编 id 静态注册名→id 表（ATTRIB_CONTENT=1/.../ATTRIB_UNKNOWN=**159** 非 0/ELEM_UNKNOWN=**289** 非 0）。**Rust ID 模型**: ATTRIB_UNKNOWN=**0**, ATTRIB_CONTENT=1，IdRegistry 动态分配 from 2。**无标准 26 属性 + 10 元素表填**。后果: `ElementId::new("…",0)`/`AttributeId::new("…",0)`（每下游调用模式）碰 id 0=ATTRIB_UNKNOWN——"address" 元素/"name"/"space"/"val" 属性全 id 0，id-key 分派不可区分。**Encoder/Decoder trait 缺 write_space/read_space/write_opcode/read_opcode**（为何 override/cpool 编 space 错）。

**context.rs Headline**: 位范围包装数学基本对，但**tracked-variable 模型结构错**（丢地址空间→跨空间跟踪 + 部分寄存器读坏），ContextCache::set_context **空桩**，多区域 set 方法缺，encode/decode 发同畸形"space"属性 + id 0 元素。

**loadimage.rs Headline**: 四中最干净。LoadImage/RawLoadImage/MemoryLoadImage 忠实翻译 loadimage.hh/.cc。**1 真 bug**: adjust_vma 缺 wordsize 缩放（RawLoadImage 无 spaceid）。

**memstate.rs Headline**: **最分歧文件 + jumptable 审计根因**。Ghidra MemoryBank 是**抽象基**全值来自虚 insert/find（字）+ getPage/setPage（页）分解，setValue/getValue/setChunk/getChunk 建其上做字对齐数学 + **端序**处理。Rust MemoryBank 是**具体 BTreeMap<u64,u8> 字节存储**绕过全部，**硬小端**，从不读 LoadImage。MemoryImage 持 Vec<u8> 非 LoadImage*，**代码库无物构它**——模拟器无路径到二进制字节。

**关键修复**（见 R95-R100 +）:
- P0 marshal 填规范 ID 表（全 Ghidra id）+ ATTRIB_UNKNOWN 0→159 + ELEM_UNKNOWN 0→289 + 加 write_space/read_space/write_opcode + write_bool 发"true"/"false" + 修 PackedDecode peek/open/close 走 Ghidra Position 模型
- P0 override `<addr>` 编码 + cpool marshal id + context encode addr（全需 write_space）
- P0 memstate MemoryImage 读 LoadImage 非 Vec<u8>（jumptable 审计根因）—— 给 wordsize/pagesize/space + find/get_page 调 loader.load_fill（catch DataUnavail→零填）+ 接到 jumptable.rs:491,1244 模拟器
- P1 memstate 核心：MemoryBank 抽象基（trait/虚 insert/find/get_page/set_page）+ set_value/get_value 建其上含字对齐+端序 + 加 bigendian 参 + 移植 MemoryHashOverlay + MemState 键 AddrSpace + 持 Translate*-等价 + setValue/getValue(string)/(VarnodeData) 重载 + IPTR_CONSTANT 短路 + 未映射抛非返 0
- P1 context TrackedContext 加 space + get_tracked_value containment+端序 trim 非 exact match + impl ContextCache::set_context（两重载）via setContextChangePoint/setContextRegion + 缓存失效 + 移植 getRegionForSet/getRegionToChangePoint + 修 encode 地址属性（space+offset 非 space=offset）+ id 120-126
- P1 loadimage RawLoadImage 加 AddrSpace spaceid + attach_to_space + adjust_vma 缩 addressToByte
- P2 context.{hh,cc} Sleigh ParserContext 无 Rust 端口——反汇编侧上下文引擎缺

---

## 报告 4: paramid.rs + signature.rs + emulate.rs + float_emulate.rs

**paramid.rs**: ParamRank 评分忠实（无 Score 类型，rank 即评分），walkforward/walkbackward/calculate_rank 大体忠实，但 walkbackward default 案简化 + analyze() 重构 Ghidra justproto/non-justproto 分。

**signature.rs**: **骨架非忠实端口**。核心 hash 原语 hash_opcode/combine_hashes 用**捏造算法**不匹配 Ghidra CRC-based hash_mixin/getOpHash。SignatureDB **Ghidra 无**（Rugra 捏造）。整特征生成管线 localHash/hashIn/removeNoise/noiseDominator/generate + 全 Signature 子类缺。

**emulate.rs**: Rust 塌 Ghidra Emulate+EmulateMemory+EmulatePcodeCache 为一具体 Emulate。execute_current_op 合理移植 executeCurrentOp，但 **execute_load/execute_store 硬"ram" + 忽略 input(0) 空间指针常量 + 无 addressToByte wordsize**，遗留 execute_op 只处理常量地址 LOAD/STORE（文档"对加载坏"路径）。

**float_emulate.rs**: 单/双 FloatFormat 构造匹配，op* 族跟 Ghidra getHostFloat→host-op→getEncoding 模式。**但三真 bug**: (1) max_exponent off-by-one（254/2046 vs Ghidra 255/2047）**破 inf/NaN 解码**；(2) op_int2float 视整为无符号（无符号扩展）；(3) op_trunc 忽略 size_out mask。extract/set helper 用**不同位对齐契约**。

**关键修复**（见 R101-R104 +）:
1. float max_exponent off-by-one（254→255, 2046→2047）—— 破 inf/NaN 解码
2. float op_int2float 符号扩展 a 过 size_in 再 cast；op_trunc mask 到 size_out
3. emulate execute_load/store 从 input(0) 解空间 + 选 bank + 应用 wordsize；删/路由遗留 execute_op
4. 次要: paramid walk_backward default + CALLOTHER getOut 守卫 + MULTIEQUAL isLoopIn；signature 是骨架需移植真算法；emulate 缺断点层/SLEIGH cache/MULTIEQUAL 抛

---

## 报告 5: pcodeinject.rs + pcodeparse.rs + prefersplit.rs

**pcodeinject.rs**: 忠实骨架——PcodeInjectLibrary 名/id 账 + 数据结构 + 4 register*/getPayloadId 方法准。**但非行为端口**: 虚 inject()（整点）缺，抽象基机器 allocateInject/registerInject/decodeInject/decodePayload* 缺，重复名 throw 行为静默丢（HashMap::insert 覆盖）。L1/L2.5 Sleigh 阻一致。

**pcodeparse.rs**: **诚实桩**，自评"L1→L2...Bison 解析器替手写递归下降"。PcodeSnippet 簿记方法忠实。**但 lexer（get_next_token）实质错**: (1) 发不同 token 词表；(2) 误处理多 Ghidra token 形式；(3) parse_stream **不真解析**——只查 Illegal 字符对任何可 tokenize 输入返成功。关键词表（46 项 idents[]）+ 多字符算子状态机（special2/special3/special32）**全无**。allocate_temp **+1 应 +16**（真 bug）。

**prefersplit.rs**: **三中最强**——near-complete 操作忠实翻译整 PreferSplitManager 算法。22/22 C++ 方法在控制流对：二分 findRecord、端序 fillinInstance、每 test*/split* 对、splitVarnode written-vs-free 分派、splitAdditional 两遍 defop 收集、临时分裂逻辑。**2 真语义分歧**（1 正确性 bug，1 健壮性 gap）+ 少量惯用分歧，无缺功能。

**关键修复**（见 R105 +）:
1. 🔴 pcodeparse allocate_temp +1→+16（真 bug，unique 空间对齐）
2. 🔴 pcodeparse get_next_token 词表错——要么重标 toy tokenizer，要么移植 moveState DFA + idents[] 表 + findIdentifier
3. 🟠 pcodeinject register 方法静默覆盖重复——加重复检查 throw
4. 🟠 prefersplit split_load/store 用错端序源（指针空间 ≠ load 目标空间时 hi/lo 反）——从 op.get_in(0) const spaceid 读端序
5. 🟡 pcodeinject get_payload_id 缺 EXECUTABLEPCODE_TYPE 分支；prefersplit split_record 快照 vs 流式迭代

---

## 报告 6: unify.rs — 统一化引擎

**Summary**: **迄今最高保真端口**——结构完整（50/50 Ghidra 类，29/29 约束）+ 忠实回溯引擎。**但全死码**: unify 框架零调用者，所服务消费者（rulecompile.cc/.hh 用户定义 Dolphin 规则编译器）**全未移植**。

- **覆盖**: 每 Ghidra 类有同名 Rust 对应（snake）。全 RHS 常量（Named/Absolute/NZMask/Consumed/Offset/IsConstant/HeritageKnown/VarnodeSize/Expression）✓。全 3 TraverseConstraint 变体 ✓。全 18 谓词/绑定约束 ✓。两 composite（Group, Or）✓。全 6 action 约束 ✓。UnifyState + UnifyCPrinter ✓。
- **引擎正确性**: ConstraintGroup::step（深度优先回溯搜索）+ ConstraintOr::step（析取枚举）忠实仔细翻译。traverse-state 簿记（currentconstraint/state 机 -1/0/1 相）精确复现。
- 模块独立编译；依赖真 opbehavior::evaluate_unary/binary + varnode 访问器 + funcdata 变更——全验在。

**Pipeline 接线**: **未接。全死码。** grep unify:: src/ 仅 unify.rs 内。唯一触点 lib.rs:103 pub mod unify。**rulecompile.cc/.hh 在 Ghidra 树但未移植到 Rust**——这是 unify 引擎唯一消费者（解析用户规则 DSL → ConstraintGroup 树 + UnifyCPrinter C 源）。Rust RuleMatcher 是自撰便利驱动（自承）。

**关键修复**: 
1. **[阻 L2.5/用户规则目标] unify 引擎不可达**——无 rulecompile 端口，无用户定义规则可达 UnifyState/ConstraintGroup。要么移植 rulecompile.{cc,hh}（DSL→ConstraintGroup 前端），要么接 RuleMatcher 进至少一 Rule 证引擎活。否则整 2597 行模块是压舱
2. [正确性-printer] ConstraintVarConst::print 丢 `& calc_mask(sz)`——运行 step 正确 mask 但 UnifyCPrinter 生成重编进 Ghidra C++ 的规则不会 mask
3. [正确性-printer] operator_syntax 返 Ghidra 拒发的有符号 op C 串（s>>/s/s%/s</s<=）——会产不编译 C
4. [健壮] ConstantExpression::get_constant unwrap_or(0) 静默——Ghidra throw LowlevelError
5. 次要: ConstraintBoolean maxnum 0 vs Ghidra -1；buildTraverseState 不填子 traverse 列表（隐不变量）

---

## 报告 7: utils.rs + crc32.rs + compression.rs

**utils.rs**: 独立 Rust 工具库——不对配单 Ghidra 文件。所有函数对其声明目的**正确**。仅挑: bits::sign_extend bits==0 边案（移 64 = UB/panic）。graph::compute_dominators 算法正确（复杂度差）。无错名/错归因。

**crc32.rs**: **完美对齐**。CRC32_TABLE（256 项）vs crc32tab[] **逐字节相同**。crc_update 精确转录。0x7b7c66a9 种子声明对照 stringmanage.cc:98 验证。L3 就绪。无需修。

**compression.rs**: **弱文件**。尽管往返测过，违反 Ghidra Compress/Decompress 契约于忠实移植 + 增量使用关键处: (1) **返回极性反**（deflate/inflate 返 written；Ghidra 返 available）；(2) **finish 标志忽略**（`let _ = finish`）；(3) **level clamp(1,9) 破 Ghidra 文档 0/-1**；(4) **流状态不跨调用保**（每调新 encoder/decoder）；(5) **inflate 吞错**（无 LowlevelError；部分输出静默返）；(6) **过长输出截断 = 静默数据丢**；(7) **CompressBuffer 未移植**。

**关键修复**（见 R107 +）:
1. [高] compression deflate/inflate 返回极性反——选一约定齐代码或 doc
2. [高] Compress::deflate 忽略 finish + 总终止 zlib 流——重实绕持久 ZlibEncoder + write + try_finish/flush，或文档仅单次支持
3. [高] level 处理破 0/-1——map -1→Compression::default(), 0→Compression::none()
4. [中] Decompress::inflate 吞错——返 Result 或报错；只在真 stream end 设 finished（Ghidra 仅 Z_STREAM_END）
5. [中] input() 积累非替换——更 doc 或重构镜像 Ghidra
6. [低] CompressBuffer 未移植——确认无路径需流缓冲压；不需则路线图标
7. [低] crc32 无需改 + utils guard sign_extend bits==0

---

## 报告 8: ffi.rs + error.rs + lib.rs

**ffi.rs Summary**: 717 行 FFI 桥到 Ghidra C++ 对拍。持 CURRENT_PROGRAM: Mutex<Option<Funcdata>>。**两真 bug + 一设计缺陷**:
1. **CPUI_CAST 映射不对称/坏**: map_ghidra_opcode（L129）留 opcode 64 注释掉（"暂无此变体"），然 to_ghidra_opcode（L213）映射 CPUI_CAST→Some(64)，且 OpCode::CPUI_CAST 变体**存在**（opcodes.rs:182）。故 Ghidra→Rugra op 64 静默丢 None，反向工作。注释过时。
2. **rugra_evaluate_constant 重复 opbehavior.rs 且分歧**——不委托。确认 opbehavior 审计"双分歧"。无 in_mask；div0 返 0 非 None；移位用 `&0x3f` 非 `%bits`——**size<8 时不同语义**。_size2/_has_val2 参**未用**。
3. 错处理违 AGENTS.md——6+ .unwrap() on Mutex/RwLock（FFI 可接受但违规）。

**error.rs Summary**: 用 **thiserror 非 anyhow**（AGENTS.md:158 强 anyhow::Result）。19 变体合理覆盖。ErrorContext trait .context() 塌结构错变成 Generic——失类型化显示值。anyhow 风表面，thiserror 敌对语义。

**lib.rs Summary**: ~60 pub mod 声明全映真文件——**无孤立模块**。re-export 干净。**Decompiler struct 全注释**（137-296）——doc 广告的主入口死。doc 引**不存在模块**: pcode/analysis/codegen/translator（只 binary 在）。过时文档。#![allow(dead_code/missing_docs)] 全局压。

**关键修复**（见 ffi.rs R38 +）:
1. 🔴 CPUI_CAST 映射不对称——取消注释 ffi.rs:129 `64 => Some(CPUI_CAST)` + 更过时注释
2. 🔴 删 rugra_evaluate_constant 重复——替内联 24 臂为 opbehavior::evaluate_binary/unary 调用（i32 经 map_ghidra_opcode 转一次再委托）
3. 🟡 CPUI_TRUNC=>Some(56) 别名（两 Rugra 变体撞一 Ghidra int，往返有损）——定 TRUNC 真独立或 FLOAT_TRUNC 别名
4. 🟡 错约定不一致——要么采 anyhow::Result 要么改 AGENTS.md:158 许 thiserror；停 ErrorContext 塌类型错成 Generic
5. 🟡 ffi.rs .unwrap() on locks ×6+——换 .unwrap_or_else(panic) 或返哨兵
6. 🟢 lib.rs 死码 + 过时 doc——删/复活注释 Decompiler；修模块 doc 引不存在 pcode/analysis/codegen/translator

---

## 报告 9: double_precis.rs — **double.cc 端口（非 multiprecision）**

**⚠️ 域错配更正**: double_precis.rs（7426 行，191 fn）**非** 任务"Domain"描述的多精度浮点/JFloat-JDouble 仿真。是 Ghidra **double.cc**——**SplitVarnode 双精度合并子系统**（RuleDoubleLoad/Store/In/Out）忠实 1:1 端口。文件头（1-71）+ lib.rs:66（`// ← double.cc`）+ 函数清单（SplitVarnode, *Form 子类）+ 规则注册全确认。

真多精度算术（multiprecision.cc: udiv128/knuth_algorithm_d/...）+ IEEE FloatFormat（float.cc/float.hh）在**另一文件**: float_emulate.rs（~440 行），设计上用 host f64 替代 Ghidra 多精度引擎（"用 host f64 替代...语义等价"）。**无 knuth_algorithm_d/udiv128 移植**（grep 0）。

**Summary**: double.cc 高保真近逐行端口。4 公共 Rule + SplitVarnode 公共 API 正确且接主管线。*Form 子类（重算法体）**全移植非骨架**——驳 ALIGNMENT_ROADMAP.md:344 过时注。**找 1 真正确性分歧**（opcode 分类门）。文档 hasUnreachableBlocks TODO 是保守过近似非缺陷。

**Pipeline 接线**: ✅ 4 规则注册 oppool1（action.rs:646-649）精确 Ghidra 槽（coreaction.cc:5643-5646）。funcdata.rs:22,174-178 is_double_precis_on/set_double_precis_recovery 镜像 Ghidra。

**关键修复**（见 R106 +）:
1. **P0 is_arithmetic_op opcode 集错**（double_precis.rs:6924-6948）——门 RuleDoubleIn::attemptMarking（double.cc:3239 isArithmeticOp()）。对照 Ghidra typeop.cc addlflags=arithmetic_op 赋值: **错含** INT_ZEXT/SEXT/NEGATE/XOR/AND/OR/LEFT/RIGHT/SRIGHT/PIECE/SUBPIECE（Ghidra 标 logical_op/shift_op/无）；**错漏** INT_CARRY/SCARRY/SBORROW/PTRADD/PTRSUB（Ghidra 标 arithmetic_op）。正确 Ghidra arithmetic_op = {ADD,SUB,CARRY,SCARRY,SBORROW,2COMP,MULT,DIV,SDIV,REM,SREM,PTRADD,PTRSUB}。后果: 过标逻辑/移位为"产逻辑整体"+ 漏 CARRY 等的整体。is_floating_point_op 正确
2. P1 ALIGNMENT_ROADMAP.md:344 过时——Form 子类全移植非骨架；更 L2.5→eff-L3 待 P0 + hasUnreachableBlocks
3. P2 Funcdata::hasUnreachableBlocks 未建模——守卫丢；Rugra 进行非 bail。文档保守过近似 TODO

---

## 批6 总结

- 9/9 报告完成，~22 文件全覆盖
- 头号根因 18 个（R90-R107）入修复清单
- **database（R90）+ memstate（R97-R98）+ marshal（R95-R96）三基础设施缺**是符号表/内存模拟/序列化的系统性塌方
- **float_emulate off-by-one（R101）+ emulate 硬 ram（R103）= 浮点/内存仿真错**
- **double_precis is_arithmetic_op 集错（R106）= 双精度恢复过/欠触发**
- **unify 全死码**——50/50 类完整移植但 rulecompile 缺→引擎空转
- **更正三个前提误判**: double_precis 是 double.cc 非 multiprecision（multiprecision 在 float_emulate.rs 用 host f64）；context.rs 是 globalcontext 非 context（Sleigh ParserContext 无对应）；callgraph 是三文件中最弱非最强
- **零大问题文件**: capability.rs（L4 忠实）、crc32.rs（完美）、prefersplit.rs（近完整）、unify.rs（完整但死码）—— 这些不需修或只需小修
