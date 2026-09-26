# TypeFactory per-Architecture 拆解测绘（TF-SINGLETON-WIRING-0001 第一步）

- 车道：wt/tfsingle（worktree `/dev/shm/rugra-worktrees/tfsingle`，基 = master `d153c868`）
- oracle：Ghidra 12.0.4 `Ghidra_12.0.4_build` = commit `e40ed13014025f82488b1f8f7bca566894ac376b`（worktree `ghidra/` HEAD 亲证）
- 性质：机制 E 亲读记录 + 9 调用点域分类 + 第一步解析机制设计。全部 Ghidra 行号均在锁定 oracle 树亲读。

## §1 oracle TypeFactory 状态面（type.hh:761-869）

`class TypeFactory`（type.hh:762）全部可变成员（type.hh:763-780）：

| oracle 成员 | 行 | 语义 | 是否 per-Architecture |
|---|---|---|---|
| `sizeOfInt/Long/Char/WChar/Pointer/AltPointer` | 763-768 | 核心尺寸配置 | 是（`setupSizes` 从 `glb` 派生，type.cc:3136-3170） |
| `enumsize` / `enumtype` | 769-770 | 枚举默认 | 是 |
| `alignMap` | 771 | 对齐表 | 是 |
| `tree`（DatatypeSet） | 772 | 结构性去重集（全部类型累积） | 是 |
| `nametree`（DatatypeNameSet） | 773 | 名字交叉索引 | 是 |
| `typecache[9][8]`、`typecache10/16` | 774-776 | 常用原子类型缓存 | 是 |
| `type_nochar`、`charcache[5]` | 777-778 | 字符类型侧缓存 | 是 |
| `warnings` | 779 | 类型警告 | 是 |
| `incompleteTypedef` | 780 | 待完成 typedef | 是 |
| `glb`（`Architecture*`） | 802 | **所有者反向指针**（protected） | — |

四类决定性语义核对（构造/生命周期路径）：

1. **引用/输出参数**：构造器 `TypeFactory::TypeFactory(Architecture *g)`（type.cc:3106-3119）仅
   `glb = g;` 保存裸指针——工厂持有 Architecture 引用（非拷贝），每个工厂绑定一个
   Architecture。无其它输出参数。
2. **循环边界/遍历顺序**：`clear()`（type.cc:3250-3263）`for(iter=tree.begin();iter!=tree.end();++iter) delete *iter`
   全量删除；`clearNoncore()`（type.cc:3265-3285）单游标 while，`ct->isCoreType()` 跳过、
   `nametree.erase(ct); tree.erase(iter++);` 删非核心——容器是 per-factory 的 compare-sorted set，
   遍历序=比较序。
3. **计数器/累加器**：**oracle TypeFactory 无任何单调计数器**。类型 id 一律名字哈希：
   decode 侧 `(id==0)&&(name.size()>0) → id = hashName(name)`（type.cc:675-676），
   `hashName`（type.cc:689-701，`res=123` 初值 + 逐字符 rotate-add + `0xC000000000000000` 头位），
   变长类型再 `hashSize`（type.cc:709-716，`id ^= size*0x98251033aecbabaf`）。匿名类型名空、
   id=0，经 `findNoName`（type.cc:3377-3386）结构去重，无编号分配。
4. **排序/比较键**：`tree` 的序=Datatype 比较（`insert` type.cc:3388-3406，id 撞树即
   `throw LowlevelError("Shared type id: ...")`）；`findAdd`（type.cc:3412-3439）先
   `findByIdLocal(name,id)` 再 `compareDependency`，匿名臂 `findNoName`。

## §2 Architecture 所有权/生命周期（arch.cc）

- 成员：`TypeFactory *types`（architecture.hh:197，"List of types for this binary"）——裸指针
  **强所有权**。
- 构造：`Architecture::Architecture()` 置 `types = (TypeFactory *)0;`（architecture.cc:162）。
- 工厂创建：虚 `buildTypeFactory` 落在子类 `buildTypegrp`：
  - `SleighArchitecture::buildTypegrp`：`types = new TypeFactory(this);`（sleigh_arch.cc:198-202）
  - `ArchitectureGhidra::buildTypegrp`：`types = new TypeFactoryGhidra(this);`（ghidra_arch.cc:319-322）
  - 随后 `buildCoreTypes`（sleigh_arch.cc:204-239：有 `<coretypes>` 则 decode，否则
    setCoreType 表 + `cacheCoreTypes()` type.cc:3200-3248）。
- 尾部：`types->setupSizes();`（architecture.cc:1350，decode 收尾——data_organization 未注册时
  给默认值；`setupSizes` 全读 `glb`：栈空间宽度/默认数据空间地址宽/段远指针）。
- 销毁：`Architecture::~Architecture` `if (types != 0) delete types;`（architecture.cc:211-212），
  ~TypeFactory → `clear()`（type.cc:3287-3290）。

**结论：oracle 每个 Architecture 恰好一个工厂，工厂生命周期=Architecture 生命周期，进程内
多 Architecture = 多工厂，类型态零跨 Architecture 通道。Rugra `shared_default()` 的
`OnceLock<Arc<RwLock<TypeFactory>>>`（typefactory.rs:2729-2755）是进程级单例=移植捷径。**

## §3 计数器语义对照（差异面全录）

| 面 | oracle | Rugra 现状 |
|---|---|---|
| 类型 id | 名字哈希 `hashName`（type.cc:689-701） | 同构 `Datatype::hash_name`（typefactory.rs:391/891/…全 id 分配点）——**无差异** |
| 匿名名计数器（struct.%d 类） | 不存在（匿名名空；打印侧 `genericTypeName` 按 id 十六进制拼，无计数器） | 不存在——**无差异** |
| 累积表泄漏 | per-Architecture，随 arch 生灭 | 进程单例累积：`types`/`base_type_tree`/`base_cache`/`typedefs`/`incomplete_typedefs`/`rel_pointers`/`live_local_scopes`（typefactory.rs:29-127）跨 Architecture 永生 |
| spacebase 缓存 | 每工厂独立 | `__spacebase_<space>_<frame>` 合成键入 `types` 表（typefactory.rs:2043-2060）：bin#2 同 frame 偏移直接命中 bin#1 的 TypeSpacebase（携带 bin#1 的 fd 句柄） |
| live_local_scopes | 无此表（oracle 每次 `queryFunction(localframe)->getScopeLocal()` 动态解析，type.cc:2938-2944） | Rugra 所有权缝合表（typefactory.rs:2091-2104）：frame 偏移键控，`.entry(frame).or_insert_with(...)`——bin#2 同 frame 复用 bin#1 的陈旧 ScopeLocal 句柄（重组发布会覆盖内容，但**重组前查询**读到的是 bin#1 残留而非 oracle 的空 ScopeLocal） |
| sizeOf*/alignMap | per-Architecture 从 cspec 派生 | 单例上被**每个 arch 重复 decode**（驱动先 decode+set_types，arch.parse_compiler_config 再 ensure_types 二次 decode）——同 cspec 时幂等无害，多 cspec 时互相污染 |

即：**无计数器泄漏，泄漏面=累积表/缓存/句柄表的身份与内容共享**（bin_sweep 单进程多二进制
场景 oracle 不存在此共享）。canon 单 Architecture 驱动下两种形态恰好重合（canon 恒等掩盖它）。

## §4 39 个 `shared_default` 引用点域分类（grep 亲测，基 d153c868）

| 文件 | 行 | 形态 | 域 | 本车道处置 |
|---|---|---|---|---|
| src/type_system/typefactory.rs | 2789 | `canonical_unknown_base_1` 回退 | 空闲（写域） | 解析机制改造点 |
| src/arch.rs | 2642 | `ensure_types` 借用单例 | 空闲（写域） | fresh per-Architecture 化 |
| src/varnode.rs | 56, 1721 | 注入缺失回退 / 写租约 | 空闲 | 零改动（解析点自动覆盖） |
| src/varmap.rs | 3578, 5852, 5864, 6244, 6266, 6740 | 无句柄回退 | 空闲 | 零改动 |
| src/typeop.rs | 2324, 2335 | 无句柄回退 | 空闲 | 零改动 |
| src/funcdata.rs | 12667 | 无句柄回退 | 空闲 | 零改动 |
| src/fspec.rs | 1614, 1676, 1735, 1892, 1938, 9882, 11330, 11420, 11609, 11623, 13077 | 工厂臂 | 空闲 | 零改动 |
| src/debugproto.rs | 1095, 1500, 1824, 2674, 2725, 2736 | 工厂臂 | 空闲 | 零改动 |
| src/coreaction.rs | 5519, 7810, 11883 | 工厂臂 | **被持（CSPECGLOBAL 在飞）** | **勿碰**——shim 零改动兼容 |
| src/printc.rs | —（无引用） | — | **被持（F4WEBTYPE 在飞）** | 勿碰 |

注释行引用（varnode.rs:2117、typefactory.rs:143 等）不计调用面。核心结论：**39 引用点全部经
`TypeFactory::shared_default()` 单一入口**——把该入口改造成"解析当前 Architecture 工厂"即可
让全部调用点（含被持域 coreaction.rs）零改动获得 per-Architecture 工厂。

## §5 第一步机制设计（本车道实现）

**目标形态**：`Architecture` 持有自己的 TypeFactory 实例（镜像 `buildTypegrp` + dtor delete），
`shared_default()` 变为"解析入口"：线程局部 current-Architecture 工厂优先，无发布时回退
进程规范工厂（保持既有 OnceLock 构造配方逐字节不变）。

1. **线程局部发布**：`CURRENT_ARCH_FACTORY`（factory 句柄 + 发布期预热的 1 字节 unknown 缓存）。
   发布点=`Architecture::set_types`/`ensure_types`（驱动把工厂交给 Architecture 的时刻=
   oracle buildTypegrp 时刻）；`Architecture::Drop` 若线程局部仍指向自己的工厂则清除。
2. **MIRROR2 锁安全**：发布期在**无租约**下预热 unknown1（与 `shared_default` 构造闭包内
   预热同一论证：工厂写租约只可能在发布之后出现）——`canonical_unknown_base_1` 读线程局部
   缓存永远无锁，写租约持有者（down_chain_pointer→get_sub_type）不再进入工厂 RwLock。
3. **单 Architecture 恒等性**：canon 驱动流程 `shared_default()`（此时无发布→进程规范 PC）→
   decode cspec → `set_types(PC)`（发布 PC）→ 引擎解析 current=PC——全链同一句柄，输出必须
   字节恒等。
4. **多 Architecture**（bin_sweep 双二进制探针）：每二进制 fresh 工厂（同一构造配方：
   `TypeFactory::new(8)`+默认对齐表，cspec decode 驱动侧照旧）→ `set_types` 发布 → 引擎
   39 调用点全解析到本二进制工厂——跨二进制累积泄漏关闭。
5. **已知限制（如实记录）**：线程局部=current 指针是**最后发布者胜**语义；同线程交错两个
   Architecture 的处理（无现存驱动形态）不属于本机制覆盖面；跨线程 drop 不清原线程 TLS
   （Arc 保活，解析停留在最后发布的工厂——不会 panic，只是分辨率退化到旧工厂）。

## §6 实证探针（产出见终报）

双二进制单进程 A/B：`--factory shared`（复现修复前形态）vs `--factory fresh`（修复后形态），
对比 bin#2 在"bin#1 先跑"与"fresh 进程独跑"两种前置下的 C 输出。探针载体=
`examples/tf_singleton_probe.rs`（bin_sweep 同构 build/run 路径）。预期：shared 形态下
`__spacebase_*`/`live_local_scopes`/累积表命中产生差异（泄漏实证）；fresh 形态下恒等
（闭合亲证）。若 shared 形态实测无差异→如实报告"单例仅缓存共享、无观察面泄漏"，偏差面
重估为纯性能（争用）面。
