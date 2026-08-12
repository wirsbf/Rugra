# PARAM-BIND-0001：GetStr 参数绑定只读审计

## 结论

**判定：REJECT（当前实现为 `MISMATCH`，DWARF 锁定参数全链路仍为 `UNTESTED/NO_ORACLE`，不得升 L3）。**

首个状态差异不是 PrintC 文本，而是在 `Funcdata` 对象图建立时已经发生：锁定 Ghidra 在
`funcdata.cc:34` 构造函数内创建并挂接 `ScopeLocal`，随后于 `funcdata.cc:69` 用该 Scope 为
`FuncProto` 安装 `ProtoStoreSymbol`；Rugra `src/funcdata.rs:177` 构造的是独立的平面
`FuncProto.parameters`，并在 `src/funcdata.rs:199` 留下 `scope: None`。因此在任何 DWARF 参数
写入之前，Rugra 已经没有 Ghidra 用来贯穿“参数声明 → storage → SymbolEntry → input Varnode
→ HighVariable → PrintC token”的共享对象身份。

在 GetStr 的 DWARF prototype 导入边界，第二个且直接可见的差异是
`src/debugproto.rs:173` 丢弃 SLEIGH 返回的 AddrSpace，并在 `src/debugproto.rs:239` 只构造
offset-only `Address`。Ghidra 的参数 storage 是完整 `Address(space, offset)`；Rugra 只保留
offset。RDI/RSI 的数值偏移 `0x38/0x30` 恰好未丢，但 storage 身份已不完整，而且没有创建
category-0 Parameter `Symbol`/`SymbolEntry`。

随后 `src/coreaction.rs:5046 ActionPrototypeTypes::apply` 没有移植锁定输入物化
（oracle `coreaction.cc:4676-4703`），Heritage 又在 `src/heritage.rs:3511-3512` 和
`3638-3639` 直接调用 `VarnodeBank::set_input_varnode`，绕开
`Funcdata::setInputVarnode` 应执行的 Scope 属性和 ProtoModel effect 查询。结果是：

- 正式 RDI/RSI 参数没有由同一个 Parameter Symbol 锚定到 input Varnode/HighVariable；
- prologue 对 RBP/RBX 的自由读虽成为 SSA input，却没有 `UNAFFECTED`；
- `src/merge.rs:719-737` 把“任意非 RSP 的寄存器 input”错误等同于“正式参数”，从共享
  `base` 计数器生成 `param_35`/`param_33`；
- PrintC header 从 `FuncProto.parameters` 直接取 `string/value`，body 则从 offset-only
  `param_names`、HighVariable 的启发式名字和打印期 fallback 取名，故 header/body 脱节。

不能通过字符串替换、扩大 `param_*` 白名单、或单独把 `plVar*` 加入声明前缀来修复。正确
修复必须先恢复 storage/Scope/Symbol/input-Varnode/High 的对象图与 effect 语义，再让 PrintC
消费同一 Symbol。

## 审计基线与证据边界

- Ghidra 唯一 oracle：tag `Ghidra_12.0.4_build`，commit
  `e40ed13014025f82488b1f8f7bca566894ac376b`；本次确认 `ghidra/` HEAD 精确相等。
- Rugra 工作区基线 HEAD：`fcf1345ff04a6cc11b2dda9fa42b750ba9c4d3a3`。
- 审计快照时间：`2026-08-13T04:36:57+08:00`。工作区当时含其他 agent 的未提交变更；
  本报告按下面列出的内容哈希审计，不把 HEAD 当作完整源码指纹。
- 输入：`examples/curl`，SHA-256
  `4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a`；
  x86-64 SysV gcc，GetStr `0x36d0+0x4a`。
- 观察到的 C artifact：`result/curl_cur.c`，SHA-256
  `018041a8eb273635ed47a19e46ba03946fd619c0ae1256fde4045e860a488ac9`，文件时间早于
  当前 dirty 源码。因此它是症状证据，不是对当前 dirty tree 的新跑门禁。
- 现有 `PIPE-SNAPSHOT-0001` 明确配置为“两端仅 ELF/BFD symbols，无 DWARF”
  （`tests/oracle/getstr_pipeline_1204.metadata.json:12-15,40,106`），整体 `MISMATCH`，且其
  Rust Heritage 层是直接 Action replay。它可以佐证 RBP/RBX effect 差异，不能证明
  DWARF locked-prototype 全链路 `MATCH`。
- 本次没有运行会覆盖 `result/` 的 runner，没有改 `src/`、TODO 或路线图，没有 stage/commit。

审计时关键 Rugra 文件 SHA-256：

| 文件 | SHA-256 |
|---|---|
| `src/address.rs` | `dbb0e1e19b85d101fcf876d2831bdc49258a65586e81d4ed89d11a474ad044a8` |
| `src/debugproto.rs` | `a106db551a29f264efa635a3c0393002391641e78ba774c9f53f6714ba8866ca` |
| `src/fspec.rs` | `874379e57901a1399ed5bdc96ca971023ebc9a3ee279553aaeda3028523ebef8` |
| `src/funcdata.rs` | `53042f2c58fd83967d14fe6b52a5778c5585ee359cdbd2b014d917280175d171` |
| `src/coreaction.rs` | `16227e65dcebd78d2895ed061ae819b0b10b3c78a5160e1a459eee9fc7675be3` |
| `src/heritage.rs` | `0ebda7db0326d6797efad3e709cc5a4c8a30b0784e2320854a5fa63cf4ff6b9c` |
| `src/variable.rs` | `596cea7c86346ee2d80112b39e71f97284e3ed9fea88184a8f1c0fd96ba1d75c` |
| `src/database.rs` | `85c7053fd4f2f64bbf4d449ed757228e4f10b82d09f1022bcc991ccda267e51b` |
| `src/varmap.rs` | `825ad35f6694120b6f196b88cd1bd948e961b77e68963671e6d726e7ddaaf03d` |
| `src/merge.rs` | `433890fcf25f13a72be4665b07349f71d57872d7eba4bcc60dd6bf0bec6cbfe2` |
| `src/printc.rs` | `9c524df948aaab6d77e5fba0bf031b6ea91f504b63ed05daef82d1a5a3f79dbf` |
| `src/action.rs` | `8b31e921421cff842754df073ff5233fcd932dd1d0fc7cd678a546c088671e82` |

## GetStr 输入与 prologue 的可核事实

DWARF 中 GetStr 有两个声明序参数：`string`（`char **`）和 `value`（`char *`）。锁定
`x86-64-gcc.cspec:63-81` 的普通整数/指针资源顺序从 RDI、RSI、RDX、RCX、R8、R9 开始，
之后才进入 stack。因此此输入下期望 storage 为：

| slot | 名字 | 类型 | storage |
|---:|---|---|---|
| 0 | `string` | `char **` | `register:RDI`, Rugra offset `0x38`, size 8 |
| 1 | `value` | `char *` | `register:RSI`, Rugra offset `0x30`, size 8 |

机器码的前八个语义动作是：保存 RBP、`RBP = RSI`、保存 RBX、`RBX = RDI`，再建立 8 字节
栈空间。换言之，RBP/RBX 是承载参数副本的 callee-saved 寄存器，但“函数入口的旧 RBP/RBX”
仍只是 SSA live-in，不是正式参数。锁定 cspec 的 `<unaffected>` 明确包含 RBX、RSP、RBP
（`sleigh_specs/x86-64-gcc.cspec:119-127`）。

现有 raw snapshot 也保留了相同顺序：

1. op 0：`COPY unique <- register:0x28 (RBP)`；
2. op 1/2：`RSP -= 8`，将上述 unique 保存到栈；
3. op 3：`RBP <- register:0x30 (RSI)`；
4. op 4：`COPY unique <- register:0x18 (RBX)`；
5. op 5/6：`RSP -= 8`，将上述 unique 保存到栈；
6. op 7：`RBX <- register:0x38 (RDI)`。

因此 `result/curl_cur.c:143-145` 的：

```c
plVar1 = piVar2 - 8;
*plVar1 = param_35;
*plVar3 = param_33;
```

可作如下受证据约束的归因：

- `param_35` 对应被保存的入口 RBP 值；
- `param_33` 对应被保存的入口 RBX 值；
- 数字 35/33 不是 ABI slot，也不是 DWARF 参数号，而是 Rugra 在遍历 HighVariable 时共享
  `base` 的偶然值；其精确数值依赖前面已经命名的 High 顺序；
- `plVar1` 是 prologue 中 `RSP-8` 的寄存器输出所形成的指针名；token 本身不能证明
  所有 `plVar*` 的 storage，必须由下面要求的 token→High→Varnode snapshot 记录。

现有无-DWARF分层诊断提供了一个额外、直接的 flag 证据：Heritage 后，Ghidra 的 RBP/RBX
input flags 为 `16842792 = COVERDIRTY | UNAFFECTED | INSERT | INPUT`，Rugra 对应位置为
`40 = INSERT | INPUT`。即 Rugra 精确缺失 `UNAFFECTED`（以及该 fixture 已登记的 cover/type
生命周期差异）。因为此 fixture 的 Rust Heritage 边界不是同一 Action pause，它只能作为
根因佐证；新的 PARAM-BIND fixture 必须在相同 Action checkpoint 重跑。

## 锁定 Ghidra 的逐层 oracle

### O0：Funcdata/FuncProto 对象图

- `funcdata.cc:34 Funcdata::Funcdata(...)`：在有名字的函数上创建 `ScopeLocal`，按函数地址
  构造稳定 scope id，attach 到 symbol database，并在 `funcdata.cc:69` 调
  `funcp.setScope(localmap, baseaddr+-1)`。
- `fspec.cc:3879 FuncProto::setScope(Scope *, const Address &)`：安装
  `ProtoStoreSymbol(scope, restricted_usepoint)`；参数随后自动反映到同一 Scope。
- `fspec.cc:3843 FuncProto::setPieces(const PrototypePieces &)`：先按 ProtoModel 分配完整
  storage，再调用 `updateAllTypes`，最后依次锁 input、output、model。

决定性状态：`FuncProto.store`、function `ScopeLocal`、category vectors 和 Symbol map 是同一
对象图，不存在独立的“仅供 header 的参数 Vec”。

### O1：参数写入与锁

- `fspec.cc:3147 ProtoStoreSymbol::setInput(int4, const string &, const ParameterPieces &)`：
  先按 category 0/index 取现有 `ParameterSymbol`；比较**完整 Address 与 size**。不一致时
  删除再建；一致时原位更新 flags/name/type。
- 新建路径 `fspec.cc:3166-3183`：用 `scope->addSymbol(name,type,address,usepoint)` 建
  Symbol+SymbolEntry，设置 category 0/index，并把 indirect/hidden/type/name locks 镜像到
  Symbol/Varnode flags。
- 复用路径 `fspec.cc:3185-3213`：逐 flag 对比、rename/retype，但保持共享 Symbol 身份。
- `fspec.cc:3906 FuncProto::isInputLocked()`：空输入只看 `voidinputlock`；非空以第一参数
  type-lock 为权威。
- `fspec.cc:3921 FuncProto::setInputLock(bool)`：锁 input 同时锁 model；非空按声明顺序遍历
  所有参数并原位设置 type lock。

### O2：ActionPrototypeTypes 强制创建锁定输入

- `coreaction.cc:4590 ActionPrototypeTypes::extendInput(...)`：由 ProtoModel 查询
  `assumedInputExtension`；需要时在 entry block 头插入 COPY/SEXT/ZEXT，符号型整数选 SEXT，
  其他选 ZEXT。
- `coreaction.cc:4609 ActionPrototypeTypes::apply(Funcdata &)`：先处理 model/this、按 op 顺序
  清 RETURN 机制输入并处理输出，再处理 truncated stack。
- 关键循环 `coreaction.cc:4676-4703`：若 input locked，按参数声明顺序 `i=0..numParams-1`
  用参数完整 storage/size 新建 Varnode，经 `Funcdata::setInputVarnode` 去重和绑定，设置
  `locked_input`，再执行 extension 与 pointer-flow。

这保证“未在正文中读取的锁定参数”也存在；小片段读取会从完整参数构造 SUBPIECE，而不是
让 Heritage 另造一个匿名输入。

### O3：Heritage 输入创建仍走 Funcdata 边界

- `funcdata_varnode.cc:25 Funcdata::setVarnodeProperties(Varnode *)`：以完整
  `(Address, size, usepoint)` 向 local Scope 查最小容器；命中则把 SymbolEntry 原位挂到
  Varnode，否则仅加 Scope/property flags。
- `funcdata_varnode.cc:340 Funcdata::setInputVarnode(Varnode *)`：精确重叠去重；部分重叠抛
  `LowlevelError`；成功后依次 `vbank.setInput`、`setVarnodeProperties`、`funcp.hasEffect`。
  `unaffected` 和 `return_address` 在这里设置。源码特别声明 SSA input 不必然是正式参数
  （`funcdata_varnode.cc:330-337`）。
- `heritage.cc:1952 Heritage::guardInput(...)`：补 coverage hole 时也用
  `fd->setInputVarnode`。
- `heritage.cc:2479 Heritage::renameRecurse(...)`：按 block 内执行顺序先读后写；空 address
  stack 时用 `fd->newVarnode` + `fd->setInputVarnode`；处理 INDIRECT 同时语义、phi 输入、
  dominance child，再按写入顺序 pop。
- `heritage.cc:2663 Heritage::heritage()`：按 Architecture space index 顺序、pass/delay 和
  location order 处理。

因此 RBP/RBX 的入口 live-in 会被标为 `UNAFFECTED`，不会因为有 `INPUT` flag 就变成正式
parameter。

### O4：Varnode → HighVariable → Symbol

- `funcdata_varnode.cc:595 Funcdata::setHighLevel()`：只执行一次，按 Varnode loc order 为每个
  Varnode 调 `assignHigh`。
- `variable.cc:220 HighVariable::HighVariable(Varnode *)`：构造时立即共享成员 Varnode；若
  该 Varnode 有 SymbolEntry，立刻 `setSymbol(vn)`。
- `variable.cc:245 HighVariable::setSymbol(Varnode *)`：保存同一 Symbol 指针，并按 exact、
  dynamic、equate、partial 情况确定 symbol offset。
- `variable.cc:418 HighVariable::updateSymbol()`：symbol dirty 时按 instance 顺序取第一个
  有 SymbolEntry 的成员。
- `coreaction.cc:2930 ActionNameVars::linkSymbols(...)`：按 address-space/loc 顺序将现有
  Symbol 与 High 连接；`coreaction.cc:2978 ActionNameVars::apply` 最后只给仍未命名的
  Symbol 分配默认名。

### O5：Scope/MapState 不重造锁定参数

- `database.cc:1263 Scope::queryProperties(...)`：以完整 Address/size/usepoint 找最小容器并
  返回 SymbolEntry+flags。
- `database.cc:1810 ScopeInternal::addSymbolInternal(Symbol *)` 与
  `database.cc:1843 ScopeInternal::addMapInternal(...)`：Symbol 身份、category 与每个
  AddrSpace 的 rangemap 同步建立。
- `database.cc:2224 ScopeInternal::findAddr(...)`：在对应 AddrSpace map 内逆序检查候选及
  usepoint；`database.cc:2250 findContainer(...)` 选最小包含条目，exact size 立即结束。
- `database.cc:2434 ScopeInternal::buildVariableName(...)`：优先级是 unaffected、persist、
  irregular input、regular parameter、addrtied、indirect、local。regular parameter 使用调用者
  提供的 prototype index；只有 local fallback 才递增共享 `index`。
- `varmap.cc:864 MapState::MapState(...)`：从 local range 中移除 parameter ranges。
- `varmap.cc:1063 MapState::initialize()`：用 `stable_sort(...RangeHint::compareRanges)`；不允许
  改变相等 hint 的输入顺序。
- `varmap.cc:1256 ScopeLocal::restructureVarnode(bool)`：只清 unlocked 类别；MapState 不把
  parameter range 当 local；随后仅为未被正式 prototype 覆盖的 input 建 fake input。
- `varmap.cc:1392 ScopeLocal::fakeInputSymbols()`：仅扫描模型允许的 parameter range，并在
  已有 category-0 Symbol 匹配时保留它。

### O6：PrintC header/body 消费同一 Symbol

- `printlanguage.cc:238 PrintLanguage::pushSymbolDetail(...)`：从 Varnode 取 High，再从 High
  取 Symbol；精确命中走 `pushSymbol`，无 Symbol 才走 unnamed location。
- `printc.cc:1905 PrintC::pushSymbol(...)`：category 0 只影响 param color，文本永远来自
  `sym->getDisplayName()`。
- `printc.cc:2222 PrintC::emitPrototypeInputs(...)`：按参数声明顺序取 `param->getSymbol()`；
  有 backing Symbol 就 `emitVarDecl(sym)`。
- `printc.cc:2577 PrintC::emitFunctionDeclaration(...)`：进入同一个 function local Scope 后
  发 header。
- `printc.cc:2641 PrintC::docFunction(...)`：依次发 header、同 Scope 的 local Symbol
  declarations、body graph；body token 仍由 High→Symbol 取得。

因此 header 和 body 不是“两个相同字符串”，而是同一个 Symbol 的两次观察。

## 当前 Rugra 的逐层差异

### R0：storage 表示已丢 AddrSpace

- `src/address.rs:23` 的 `Address(u64)` 只有 offset；`src/address.rs:27` 注释也承认缺
  AddrSpace。
- `src/debugproto.rs:170 X86_64GccStorage::from_sleigh` 在 `:173` 解构 `_space` 后丢弃，map
  只保存 `(offset,size)`。
- `src/debugproto.rs:193 X86_64GccStorage::assign` 对 GetStr 返回 `Address::new(0x38)`、
  `Address::new(0x30)`；它还明确拒绝 aggregate、超过 8 字节和 stack spill，而非完整
  ProtoModel allocation。

### R1：prototype 是值 Vec，不是 Symbol-backed store

- `src/fspec.rs:164 ProtoParameter` 仅含 name/type/offset-only Address/flags，没有 Symbol、
  SymbolEntry、category、usepoint 或 storage size 字段（size 只能从 type 间接取得）。
- `src/fspec.rs:223 FuncProto` 直接持有 `Vec<ProtoParameter>`；没有 `ProtoStoreSymbol` 或
  resolved model pointer。
- `src/debugproto.rs:128 DebugPrototypeDatabase::apply` clone 整个 FuncProto，清 Vec，按 DWARF
  顺序 push 新值，设三个 lock 后整体替换 `fd.funcp`。没有在 function Scope 中创建或更新
  category-0 Symbol。
- `src/database.rs:1272 Scope`、`:1380 add_symbol_mapped`、`:1924 query_properties`、
  `:2013 set_category` 已有部分通用能力，但 `Funcdata.scope` 实际类型是另一套
  `varmap::ScopeLocal`（`src/funcdata.rs:111`），参数路径没有调用 `database::Scope`。这是
  两个断开的 symbol/scope 子系统。

### R2：锁定输入从未物化

- `src/coreaction.rs:5046 ActionPrototypeTypes::apply` 当前只处理 RETURN 的一部分及 active
  output；函数在 `:5094` 结束，没有 oracle `4676-4703` 的 parameter loop。
- 源码 `src/coreaction.rs:5034-5038` 已明确登记：`ProtoParameter` 丢 storage space、FuncProto
  无 resolved ProtoModel/ParamList，不能无猜测实现 `extendInput`。
- `src/coreaction.rs:4900 ActionInputPrototype::apply` 在 `:4909-4910` 看到 input locked 就
  返回；这个 guard 本身符合 oracle，但前置 Action 未创建 locked input，因此“锁住空的
  data-flow input 集合”。
- `src/varnode.rs:90` 虽定义 `LOCKED_INPUT` bit，主管线没有设置它的路径。

### R3：Heritage 绕过属性/effect 边界

- `src/funcdata.rs:275 Funcdata::set_input_varnode` 只是转发给 VarnodeBank；不调用其自身的
  `set_varnode_properties`，也不查 `FuncProto::hasEffect`。
- `src/funcdata.rs:2723 set_varnode_properties` 即使被调用，也只按 offset 查
  `symbol_table: HashMap<u64,String>`；找不到可挂载的 SymbolEntry，无法按 space/usepoint
  比较。
- `src/heritage.rs:3419 visit_rename_direct` 的 empty-stack 两个分支在
  `:3511-3512`、`:3638-3639` 直接使用 VarnodeBank 方法，无法访问 Funcdata Scope/model。
- `src/varnode.rs:2036 VarnodeBank::set_input_varnode` 对部分重叠只打印 warning 后继续，而
  oracle 抛异常；其注释错误地称 effect flags“不影响 SSA correctness”，但本问题正显示
  `UNAFFECTED` 缺失会改变参数分类、High 名称和最终文本。

### R4：HighVariable 没有继承 Symbol

- `src/funcdata.rs:513 set_high_level` 用 `HighVariable::new(dt)` 后手动 add instance 和写
  `vn.high`，没有调用 `set_symbol`。
- `src/variable.rs:122 HighVariable::new` 不接收成员 Varnode，因而无法执行 oracle 构造器的
  “若有 SymbolEntry 立即 setSymbol”。
- `src/variable.rs:146 get_symbol` 直接返回缓存，没有像 `variable.hh:176` 那样先
  `updateSymbol()`；虽然 `src/variable.rs:441 update_symbol` 存在，初始 highflags 又未设置
  `SYMBOLDIRTY`，因此不能补回构造时错过的绑定。

### R5：MapState/命名把 SSA input 当正式参数

- `src/varmap.rs:1444 ScopeLocal::restructure_varnode` 每次先 `symbols.clear()`，使用硬编码
  full stack extent，不从 ProtoModel local/param ranges 建 MapState；会丢既有 local symbols。
- `src/varmap.rs:1653 fake_input_symbols` 只扫描 stack input，且不检查 formal parameter range
  或 category-0 Symbol。
- `src/merge.rs:659 assign_names` 遍历 loc-tree High；`:719` 只要 input + Register + 非 RSP
  就进入“regular parameter”。RDI/RSI 通过硬编码表得到 0/1；RBP/RBX 等未知 input 在
  `:732` 递增共享 local `base`，然后 `:737` 生成 `param_N`。这违反
  `funcdata_varnode.cc:330-337` 的 SSA input/正式参数区分，也违反
  `database.cc:2480-2482` 必须由 prototype index 驱动的语义。
- `src/coreaction.rs:4123 ActionNameVars::apply` 调上述 `Merge::assign_names`，而不是在统一
  local Scope 上 link Symbols 后只给未命名 Symbol 分配默认名。

### R6：PrintC header/body/声明来自三套状态

- header：`src/printc.rs:8764 emit_prototype_inputs` 在 `:8793-8811` 承认没有 backing Symbol，
  直接从 `ProtoParameter.name` 合成 type+name。
- body 参数捷径：`src/printc.rs:371` 保存 `HashMap<u64,String>`；
  `src/printc.rs:5017-5021` 按 offset 填充；`src/printc.rs:6583-6591` 在 Register 空间按 offset
  优先覆盖 High 名字。它没有 size、space identity（map key 本身无 space）、category、
  usepoint 或 Symbol identity。
- body 其他名字：`src/printc.rs:6594-6781` 从 High 启发式名字、def-chain inline、fallback
  取 token；RPN 的 `src/printc.rs:824 make_atom_for_vn` 复用同一打印期 helper，而不是
  Ghidra 的 High→Symbol 路径。
- declarations：`src/printc.rs:5656-5714` 先做 NullEmit discovery，再由
  `src/printc.rs:2925 doc_variable_decls_from_funcdata` 对收集到的字符串做启发式过滤。
  `:2942-2944` 认为任意 `param_*` 都已在 header，故 `param_35/param_33` 不声明；但 header
  实际只有 `string/value`。这就是 header/body 脱节的直接文本原因。
- `plVar*`：Register 声明前缀 `src/printc.rs:2961-2969` 有 `lVar` 和部分 pointer prefixes，
  但没有 `plVar`；RSP/RBP/RBX offset 的 fallback 又只允许 raw register name
  （`:2984-3001`），所以 prologue 的 `plVar1/plVar3/plVar5/...` 被正文发出却被声明过滤。

“未声明 unique”必须按对象身份而非名字认定：raw prologue 确有 RBP/RBX→Unique 的 COPY，
其 High 经 copy merge 后可显示成 `param_*`；但 `param_35` 这个文本本身不携带原始
AddrSpace。现有 snapshot 没有 token→High→Varnode→Symbol 边，不能仅凭 token 宣称每个
未声明量都是 Unique。新 fixture 必须按下节 schema 记录 provenance。

## 首个差异与症状因果链

| 层 | 最早差异 | 后果 |
|---|---|---|
| 构造 | Ghidra `funcdata.cc:66-69` 建 Scope + ProtoStoreSymbol；Rugra `funcdata.rs:199` 为 `None` | 参数从一开始就无共享 Symbol store |
| storage import | Rugra `debugproto.rs:173` 丢 space | RDI/RSI 只剩裸 offset，跨空间 collision 无法区分 |
| prototype apply | Ghidra `fspec.cc:3147` 建 category-0 SymbolEntry；Rugra `debugproto.rs:133-157` 替换 Vec | header name 与 SSA 数据流没有别名关系 |
| locked-input action | Ghidra `coreaction.cc:4676-4703` 强制建 RDI/RSI inputs；Rugra函数缺该块 | 未使用/部分使用参数不受锁定 prototype 约束 |
| heritage | Ghidra始终走 `Funcdata::setInputVarnode`；Rugra直接走 bank | 无 Symbol properties；RBP/RBX 无 UNAFFECTED |
| naming | Ghidra按 Symbol category/prototype index；Rugra按“input register”硬编码 | RBP/RBX 被命名 `param_35/param_33` |
| printing | Ghidra header/body共享 Symbol；Rugra Vec/header、offset map/body、字符串 discovery/decl 三分 | header/body脱节，`param_*` 和 `plVar*` 未声明 |

对当前症状，首个**绝对**状态差异是 Funcdata 构造；首个**参数值**差异是 storage 的
AddrSpace 丢失/未建 category-0 Symbol；首个**`param_35/param_33` 直接决定状态**是 RBP/RBX
input 未置 `UNAFFECTED`，随后被 `Merge::assign_names` 的过宽 guard 分类为正式参数；首个
**未声明文本**差异是 PrintC declaration discovery/filter 不消费与 body 相同的 Symbol 集。

## 必需的逐层 state snapshot schema

新门禁不得只比 C 字符串。两端必须输出同一 schema，opaque 指针可用图同构 ID 规范化，
但不得删除 array 顺序、alias 边、AddrSpace、flags、category、usepoint 或 token provenance。

```json
{
  "schema": "param-bind-v1",
  "provenance": {
    "oracle_commit": "e40ed13014025f82488b1f8f7bca566894ac376b",
    "binary_sha256": "4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a",
    "architecture": "x86:LE:64:default",
    "compiler_spec": "gcc",
    "analysis_options": {},
    "debug_import": "DWARF or identical explicit PrototypePieces",
    "function": {"name": "GetStr", "entry": 14032, "size": 74}
  },
  "stage": "S0_after_locked_prototype",
  "prototype": {
    "store_kind": "symbol",
    "model": "gcc",
    "model_locked": true,
    "input_locked": true,
    "params": [{
      "slot": 0,
      "name": "string",
      "type_fingerprint": {},
      "storage": {"space_id": 4, "space_name": "register", "offset": 56, "size": 8},
      "flags": [],
      "symbol_id": "sym0",
      "category": 0,
      "category_index": 0,
      "entry_id": "entry0",
      "usepoint": {"space": "ram", "offset": 14031}
    }]
  },
  "scope": {
    "scope_id": "scope0",
    "parent_id": "global",
    "category0_order": ["sym0", "sym1"],
    "symbols": [],
    "entries": []
  },
  "varnodes": [{
    "id": "vn0",
    "create_index": 0,
    "storage": {"space_name": "register", "offset": 56, "size": 8},
    "flags": ["input", "locked_input", "mapped", "typelock"],
    "def": null,
    "uses_ordered": [],
    "symbol_entry_id": "entry0",
    "high_id": "high0",
    "type_fingerprint": {}
  }],
  "highs": [{
    "id": "high0",
    "instances_ordered": ["vn0"],
    "name_representative": "vn0",
    "symbol_id": "sym0",
    "symbol_offset": -1,
    "type_fingerprint": {}
  }],
  "ops": [{
    "id": "op0",
    "seq": {"address": 14032, "time": 0, "order": 0},
    "opcode": "COPY",
    "output": "vnX",
    "inputs_ordered": ["vn0"],
    "parent_block": 0
  }],
  "tokens": [{
    "ordinal": 0,
    "text": "string",
    "role": "body_var",
    "symbol_id": "sym0",
    "high_id": "high0",
    "varnode_id": "vn0",
    "op_id": "op0"
  }],
  "declarations": [{
    "kind": "parameter",
    "text": "char ** string",
    "symbol_id": "sym0",
    "category_index": 0
  }],
  "unresolved_identifiers": []
}
```

必须保留以下 checkpoint：

1. `S-1_after_funcdata_ctor`：local Scope、ProtoStore kind、model/effect tables；
2. `S0_after_locked_prototype`：RDI/RSI storage、category-0 Symbols、locks；
3. `S1_after_raw_flow`：原始 prologue ops/Varnodes，仍保留 prototype graph；
4. `S2_after_ActionPrototypeTypes`：强制 input、locked_input、extension/ptrflow；
5. `S3_after_Heritage`：RDI/RSI/RBP/RBX inputs、effects、def/use、phi 与 replacement order；
6. `S4_after_setHigh_ActionNameVars`：High instances、Symbol alias、name representative；
7. `S5_before_PrintC`：Scope categories、真实 local declarations、body graph；
8. `S6_after_PrintC`：header/local/body token 顺序及每个 token 的 provenance。

GetStr 的关键断言至少包括：

- `string` 与 `value` 分别只有一个 category-0 Symbol，storage 分别严格为
  `register:0x38/8`、`register:0x30/8`；
- `ActionPrototypeTypes` 后存在两个 exact locked input Varnode，即使参数未使用也不消失；
- RBP `register:0x28/8` 和 RBX `register:0x18/8` 的入口 inputs 为 `UNAFFECTED`，category 不是
  function_parameter；
- RDI→RBX、RSI→RBP 经 COPY/merge 后，正文参数 token 的 `symbol_id` 与 header declaration
  相同；
- header 正好为 `string,value`，正文不得出现无对应 declaration 的 `param_35/param_33`；
- 所有 Unique/Register/Stack body identifiers 都能解析到 header parameter 或 local Symbol；
  `unresolved_identifiers` 为空。

## 依赖 DAG

```text
Full storage identity (AddrSpace + offset + size)
├── compiler-spec ParamList allocation / effect records
└── function-local database::Scope identity
    └── ProtoStoreSymbol / ParameterSymbol / category-0 SymbolEntry
        ├── FuncProto locked input model
        └── Funcdata::setVarnodeProperties + setInputVarnode
            ├── exact overlap/error behavior
            ├── SymbolEntry flags/type/name locks
            └── ProtoModel effects (RBP/RBX UNAFFECTED)
                └── ActionPrototypeTypes locked-input materialization
                    ├── extendInput / SUBPIECE foundation
                    └── Heritage all input creation through Funcdata
                        └── HighVariable constructor/updateSymbol aliasing
                            └── ScopeLocal/MapState preservation + ActionNameVars
                                └── remove Merge's input-register=parameter heuristic
                                    └── PrintC header/body/declarations from shared Symbol
                                        └── token provenance + GetStr end-to-end gate
```

`ActionPrototypeTypes` 不能先于 storage/ProtoStore/Funcdata input wrapper 修；否则只能再次硬编码
x86 寄存器。PrintC 不能先于 High/Symbol 修；否则只能继续用 offset/string heuristic。

## 可修顺序

1. **先建门禁，不改输出**：实现上述 `param-bind-v1` 两端 checkpoint；Ghidra fixture 应在
   真实 Funcdata local Scope 上通过 `PrototypePieces`/locked `FuncProto` 注入与 Rugra DWARF
   完全相同的 GetStr 参数。metadata 必须记录 debug import 方式，不能复用当前“无 DWARF”
   fixture 宣称 MATCH。
2. **恢复完整 storage**：参数至少改用 `VarnodeData {space,offset,size}` 或等价 full Address；
   `X86_64GccStorage` 保留 SLEIGH AddrSpace，并由 ProtoModel/ParamList 处理 float、aggregate、
   join、hidden return、stack spill，禁止继续按裸 offset 猜。
3. **统一 function local Scope**：使 Funcdata 持有可执行 `database::Scope`/ScopeLocal 语义，
   不再让 `varmap::ScopeLocal` 与 `database::Scope` 两套系统彼此断开。
4. **移植 ProtoStoreSymbol**：参数 set/clear/reuse/category renumber、usepoint、flags/name/type
   原位更新；FuncProto 存 store/model，而非只存 Vec。
5. **补齐 Funcdata input 边界**：`setVarnodeProperties` 查询 full storage/usepoint 并挂
   SymbolEntry；`setInputVarnode` 精确去重、部分 overlap 抛错、查 FuncProto/ProtoModel effect。
6. **补齐 ActionPrototypeTypes**：完整移植 `4590` 与 `4609`，尤其 `4676-4703`；设置
   `LOCKED_INPUT`、input type、extension、ptrflow。
7. **Heritage 改走 Funcdata wrapper**：guard holes、ordinary reads、INDIRECT same-time 和 phi
   empty-stack 都不得直调 bank；保留 oracle 的执行/支配树/pop 顺序。
8. **恢复 High/Symbol alias**：High 构造时接成员 Varnode并立即 setSymbol；`get_symbol` 的
   dirty refresh 与 instance-order first-entry 语义必须一致。
9. **修 ScopeLocal/MapState/ActionNameVars**：保留锁定 category-0 Symbol，排除 param range，
   仅给无 Symbol 的 High 建 local/fake Symbol；删除 `Merge::assign_names` 中“input register 即
   formal parameter”的硬编码分支。
10. **最后收敛 PrintC**：header、local declarations、body 都从 High→Symbol/Scope 发 token；
    去掉 offset-only `param_names` 权威性和打印期字符串声明猜测。`plVar*` 若在上游仍真实存在，
    必须作为真实 local Symbol 声明，而不是靠前缀白名单兜底。
11. **闭包验证**：跑边界矩阵、GetStr 同输入分层 fixture、curl 全语料、gcc syntax audit 和
    Ghidra text/token diff；任何剩余差异保持 `MISMATCH/UNTESTED`。

## 必测边界矩阵

- exact 8-byte RDI/RSI locked parameters；
- locked 参数完全未使用，仍存在 locked input 与 header declaration；
- 只读 1/2/4-byte 子片段，验证 extension/SUBPIECE、signed/unsigned 选择；
- 同 offset 不同 AddrSpace，证明不能 offset-only collision；
- RBP/RBX/R12-R15 callee-saved live-ins，必须 unaffected 且不得成为 formal params；
- general/float 资源交错、单独计数/分组规则；
- 第 7 个以上 stack 参数、正负栈增长、usepoint；
- aggregate/join/hidden return/indirect storage；
- 同 storage+size 重用既有 input，部分 overlap 必须两端同异常；
- name/type lock 的原位更新与 Symbol identity 保持；
- locked unknown type、void locked inputs、varargs；
- COPY 到 callee-saved register 后 header/body 仍共享原 Parameter Symbol；
- Unique COPY、phi、INDIRECT same-time 后 token provenance 仍可回到 Symbol；
- 两个同名候选、category index 移除/重排、default-name counter 与 tie-break。

## 四类决定性语义

### 1. 引用/输出参数与别名

Ghidra 的 `ProtoParameter`/`ParameterSymbol`、Scope category-0 `Symbol`、`SymbolEntry`、Varnode
mapentry、HighVariable symbol 和 PrintC token 共享同一 Symbol 身份。`setInput` 对匹配 storage
原位 rename/retype/改 flags；`setInputVarnode` 返回的可能是既有 Varnode；High 合并后多个
instance 共享一个 High/Symbol。Rugra 当前 clone/replace `FuncProto`、offset-only maps 和
打印期字符串都是值复制，不具有这些 alias/output mutation。

### 2. 循环边界与遍历顺序

参数按声明/category index `0..numParams`；ActionPrototypeTypes 依该顺序强制 inputs；Heritage
按 space index、location、block execution order、dominance child order处理，block 内严格先读
后写、子树后再 pop；Scope 容器查询逆序候选并选最小包含；PrintC header 按 parameter order，
body 按结构/操作顺序。任何 HashMap 随机顺序、打印期 first-touch 或重排都会改变名字和 token。

### 3. 计数器/累加器

Proto category index 是声明 slot，不是 default-name counter。Heritage 的 address stack 是每个
完整 Address 独立，进入 block push、处理完 dominance children 后 pop；pass 每轮递增。
`ActionNameVars::apply` 的 `base=1` 只供仍未命名 local Symbols 共享递增。Ghidra regular
parameter 的 `param_N` 使用调用者传入的 prototype index，不递增 `base`。Rugra 当前在
`merge.rs:732` 为 RBP/RBX 递增 local base，直接制造 35/33 这类伪 slot。

### 4. 排序/比较键

storage/符号匹配键必须含 AddrSpace、offset、size、usepoint；input exact-match 还要求地址和
size 同时相等，部分 overlap 是异常。Scope 查找以 AddrSpace 选择 rangemap，再按 offset、
usepoint 和最小容器 size 比较；MapState 使用 stable RangeHint comparator。不能用
`HashMap<u64,String>`、寄存器 offset 表或 token prefix 代替这些键；不能把 Unique offset
跨实现直接归一为相等，但必须保留 Unique 的对象身份、def-use 与 token provenance。

## 精确函数起始行索引

### Locked Ghidra 12.0.4

| 层 | 起始行与函数 |
|---|---|
| Funcdata | `funcdata.cc:34 Funcdata::Funcdata(...)` |
| Proto store | `fspec.cc:3147 ProtoStoreSymbol::setInput(...)` |
| Proto setup | `fspec.cc:3843 FuncProto::setPieces(...)`; `fspec.cc:3879 FuncProto::setScope(...)` |
| Locks | `fspec.cc:3906 FuncProto::isInputLocked()`; `fspec.cc:3921 FuncProto::setInputLock(bool)` |
| Effects | `fspec.cc:4234 FuncProto::hasEffect(...)` |
| Prototype action | `coreaction.cc:4590 ActionPrototypeTypes::extendInput(...)`; `coreaction.cc:4609 ActionPrototypeTypes::apply(...)`; `coreaction.cc:4707 ActionInputPrototype::apply(...)` |
| Input properties | `funcdata_varnode.cc:25 Funcdata::setVarnodeProperties(...)`; `funcdata_varnode.cc:340 Funcdata::setInputVarnode(...)` |
| High creation | `funcdata_varnode.cc:595 Funcdata::setHighLevel()`; `variable.cc:220 HighVariable::HighVariable(...)`; `variable.cc:245 HighVariable::setSymbol(...)`; `variable.cc:418 HighVariable::updateSymbol()` |
| Heritage | `heritage.cc:1952 Heritage::guardInput(...)`; `heritage.cc:2479 Heritage::renameRecurse(...)`; `heritage.cc:2663 Heritage::heritage()` |
| Scope | `database.cc:1263 Scope::queryProperties(...)`; `database.cc:1810 ScopeInternal::addSymbolInternal(...)`; `database.cc:1843 ScopeInternal::addMapInternal(...)`; `database.cc:2224 ScopeInternal::findAddr(...)`; `database.cc:2250 ScopeInternal::findContainer(...)`; `database.cc:2434 ScopeInternal::buildVariableName(...)`; `database.cc:2850 ScopeInternal::assignDefaultNames(...)` |
| Var map | `varmap.cc:864 MapState::MapState(...)`; `varmap.cc:1044 MapState::gatherSymbols(...)`; `varmap.cc:1063 MapState::initialize()`; `varmap.cc:1124 MapState::gatherVarnodes(...)`; `varmap.cc:1256 ScopeLocal::restructureVarnode(...)`; `varmap.cc:1392 ScopeLocal::fakeInputSymbols()` |
| Naming | `coreaction.cc:2930 ActionNameVars::linkSymbols(...)`; `coreaction.cc:2978 ActionNameVars::apply(...)` |
| Print lookup | `printlanguage.cc:197 PrintLanguage::pushVn(...)`; `printlanguage.cc:218 PrintLanguage::pushVnExplicit(...)`; `printlanguage.cc:238 PrintLanguage::pushSymbolDetail(...)` |
| Print C | `printc.cc:1905 PrintC::pushSymbol(...)`; `printc.cc:1938 PrintC::pushUnnamedLocation(...)`; `printc.cc:2222 PrintC::emitPrototypeInputs(...)`; `printc.cc:2260 PrintC::emitLocalVarDecls(...)`; `printc.cc:2577 PrintC::emitFunctionDeclaration(...)`; `printc.cc:2641 PrintC::docFunction(...)` |

### Rugra 审计快照

| 层 | 起始行与函数/结构 |
|---|---|
| Address/storage | `src/address.rs:23 Address`; `src/debugproto.rs:170 X86_64GccStorage::from_sleigh`; `src/debugproto.rs:193 X86_64GccStorage::assign` |
| Debug apply | `src/debugproto.rs:128 DebugPrototypeDatabase::apply` |
| Prototype | `src/fspec.rs:164 ProtoParameter`; `src/fspec.rs:223 FuncProto`; `src/fspec.rs:344 is_input_locked`; `src/fspec.rs:358 set_input_lock` |
| Funcdata | `src/funcdata.rs:177 Funcdata::new`; `src/funcdata.rs:275 set_input_varnode`; `src/funcdata.rs:513 set_high_level`; `src/funcdata.rs:2723 set_varnode_properties` |
| Prototype action | `src/coreaction.rs:4900 ActionInputPrototype::apply`; `src/coreaction.rs:5046 ActionPrototypeTypes::apply` |
| Heritage | `src/heritage.rs:2631 guard_input`; `src/heritage.rs:2938 heritage`; `src/heritage.rs:3341 rename_direct`; `src/heritage.rs:3419 visit_rename_direct` |
| High | `src/variable.rs:122 HighVariable::new`; `src/variable.rs:146 get_symbol`; `src/variable.rs:180 set_symbol`; `src/variable.rs:441 update_symbol` |
| Scope | `src/database.rs:1272 Scope`; `src/database.rs:1380 add_symbol_mapped`; `src/database.rs:1924 query_properties`; `src/database.rs:2013 set_category` |
| Var map | `src/varmap.rs:1444 ScopeLocal::restructure_varnode`; `src/varmap.rs:1653 fake_input_symbols` |
| Naming | `src/merge.rs:659 Merge::assign_names`; `src/coreaction.rs:4066 ActionNameVars::link_symbols`; `src/coreaction.rs:4123 ActionNameVars::apply` |
| Print | `src/printc.rs:824 make_atom_for_vn`; `src/printc.rs:2925 doc_variable_decls_from_funcdata`; `src/printc.rs:3175 get_varnode_display_name_inner`; `src/printc.rs:4975 doc_function`; `src/printc.rs:6507 push_varnode`; `src/printc.rs:8661 emit_function_declaration`; `src/printc.rs:8764 emit_prototype_inputs` |

## 最终验收条件

只有当 `param-bind-v1` 的全部 checkpoint 在锁定 12.0.4 与 Rugra 间零差异、GetStr header/body
token 共享相同 Symbol graph、RBP/RBX 不再成为 formal params、未解析 identifier 为零，且
受影响调用闭包与 curl/gcc 门禁无新增未解释差异时，`PARAM-BIND-0001` 才能记 `MATCH`。在此
之前，当前的正确状态是 `MISMATCH`；现有无-DWARF GetStr fixture 不能代替这个门禁。
