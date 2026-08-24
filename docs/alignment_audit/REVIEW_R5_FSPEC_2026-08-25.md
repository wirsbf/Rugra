# R5 独立复核报告 — TYPEOP-FSPEC-SPACE-0001 切片1（FspecSpace 身份/编解码/print/查找）

- 复核对象：master 集成提交 `d75f1bb` + `ab84d45` + `2286279`（origin 分支 `agent/fspec-space-s1` 对应 `fb6c21b` + `e8ecd75` + `508e954`，双侧 artifact 字节一致，已 diff 验证）
- 复核 Agent：R5（独立只读复核；未采信实现者 Alignment Evidence 的声明，全部 Ghidra 行号/语义由本 Agent 在锁定 oracle 上亲自打开逐行核对）
- Oracle：`ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b` = tag `Ghidra_12.0.4_build`（本机 `git rev-parse` 验证）
- 复核日期：2026-08-25
- 结论：**APPROVE**（未发现 MISMATCH；6 项非阻断「建议」见文末，其中 S1 行号漂移须在切片2修正）

---

## 0. 本 Agent 亲读的 Ghidra oracle 源码（铁律 1.1 / 机制 C）

| 文件 | 行 | 内容 |
|---|---|---|
| space.hh | 29-38 | spacetype 枚举（IPTR_CONSTANT=0…IPTR_FSPEC=4, IPTR_IOP=5, IPTR_JOIN=6） |
| space.hh | 305-311 | `Address::printRaw`：null base → `"invalid_addr"`，否则 `base->printRaw` |
| space.hh | 356/375-393 | `operator==`（base 指针+offset）/ `operator<`（null<一切、一切<maximal、异空间按 index、同空间按 offset） |
| space.hh | 383-390 | `wrapOffset`（`off<=highest` 直返；否则 `(intb)off % (highest+1)` 带负数修正） |
| space.hh | 469-474/481-487 | `Address::encode` / `encode(size)`（openElement(ELEM_ADDR) → base 非空才 encodeAttributes → close） |
| space.cc | 143-148/156-162 | 基类 `encodeAttributes`：writeSpace(ATTRIB_SPACE,this)+writeUnsignedInteger(ATTRIB_OFFSET,offset)[+ATTRIB_SIZE] |
| space.cc | 169-189 | 基类 `decodeAttributes`：属性游标循环；OFFSET→读无符号、SIZE→读有符号、其余跳过不消费；`foundoffset` 缺失 → `throw LowlevelError("Address is missing offset")` |
| space.cc | 206-221 | 基类 `printRaw`（补零 hex + wordsize `+cut`） |
| space.cc | 339/380/383/646/649 | `AddrSpace::decode` / ConstantSpace::decode throw `"Should never decode the constant space"` / JoinSpace::decode throw `"Should never decode join space"` |
| space.cc | 590+ | JoinSpace::printRaw/encodeAttributes/decodeAttributes（piece 编解码，残差） |
| fspec.cc | 2107-2171 | `FspecSpace::NAME="fspec"`；构造器 `AddrSpace(m,t,IPTR_FSPEC,NAME,false,sizeof(void*),1,ind,0,1,1)` + `clearFlags(heritaged|does_deadcode|big_endian)` + HOST_ENDIAN；encodeAttributes 两形态（invalid entry 只写 `"fspec"`、valid entry 写 **entry 空间+entry offset**[+size]）；printRaw 四形态；decode throw `"Should never decode fspec space from stream"` |
| fspec.hh | 1646-1648 | `FuncCallSpecs` 的 `op/name/entryaddress` 成员（1647 name、1648 entryaddress） |
| op.hh | 49-50 | `IopSpace::encodeAttributes` 覆写：**只** `writeString(ATTRIB_SPACE,"iop")`，丢弃 offset（两形态相同） |
| op.cc | 24/33/41/61-64 | IopSpace::NAME / 构造器 / printRaw / decode throw `"Should never decode iop space from stream"` |
| translate.cc | 352-437 | `insertSpace`（详见 §2；373 `case IPTR_FSPEC`、378 `fspecspace = spc;` 在 throw 之前、417-419 守卫 name2Space 插入、421+ 错误串拼接） |
| translate.cc | 517-573 | `assignShortcut`（fspec → `'f'`） |
| address.cc | 25 | `ElementId ELEM_ADDR = ElementId("addr",11)` |
| address.cc | 110-118/131-142/153-165 | `containedBy` / `justifiedContain` / `overlap`（同 base 指针必须、常量空间排除、wrapOffset 距离） |
| address.cc | 205-212/226-234 | `Address::decode`（→`VarnodeData::decode`→`Address(var.space,var.offset)`）/ decode(size) |
| pcoderaw.cc | 23-31/33-56 | `VarnodeData::decode` / `decodeFromAttributes`：space=0、**size=0 起始**；遇 ATTRIB_SPACE → `space=decoder.readSpace()`（按名解析）→ `decoder.rewindAttributes()`（attributeIndex=-1）→ `offset = space->decodeAttributes(decoder,size)` 重走 → break |
| marshal.cc | 1243/1246/1247 | ATTRIB_OFFSET=16 / ATTRIB_SIZE=19 / ATTRIB_SPACE=20（锁定 id） |
| marshal.cc | 225-239/401-409/425 | `rewindAttributes`（=-1）/ `XmlDecode::readSpace` 按名 `getSpaceByName`，未知名 `throw DecoderError("Unknown address space name: "+nm)` |
| marshal.cc | 569+ | `XmlEncode::writeSpace` = 写空间名字符串 |
| marshal.cc | 1009-1030/1195-1205 | PackedDecode 特殊空间 / PackedEncode TYPECODE_SPECIALSPACE 字节（残差，归 MARSHAL-XML-TEXT-0001） |
| architecture.cc | 631-634 | 生产插入序：fspec@numSpaces() → iop → join |

---

## 1. 清单项 1 — 四类决定性语义核对表（同 offset 判别 + 编解码往返）

### 1.1 五空间同 offset（0x5555aaaa）判别

| 语义点 | Ghidra（亲读行） | Rugra（现行 src） | 判定 |
|---|---|---|---|
| `operator==` | address.hh:356 `(base==op2.base)&&(offset==op2.offset)`（指针同一性） | address.rs:1341-1345 `same_base(other) && self.offset==other.offset`；`same_base`（:995-1002）为 Rc/句柄同一性 | 一致 |
| `operator<` 阶梯 | address.hh:375-393：null→Less、maximal→Greater、对侧对称、否则 `base->getIndex()` 比较、同空间按 offset | address.rs:1352-1383 同阶梯 + index 比较（Equal 时 Rc 指针 tie-break，文档注明为 Rust 全序一致性扩展，注册表内同 index 不可能） | 一致 |
| map/排序序 | std::map 以 operator< 排序 → const(0)<stack(5)<fspec(6)<iop(7)<join(8) | BTreeMap + 上述 `Ord` → 同序；fixture `order=/map_order=` 双侧 oracle 验证一致 | 一致 |
| `overlap` | address.cc:153-165：异 base→-1、IPTR_CONSTANT→-1、`wrapOffset(off+skip-op.off)`，`>=size`→-1 | address.rs:1161-1181 逐条对应（same-handle、Constant 排除、wrap_offset 距离） | 一致 |
| `wrapOffset` | space.hh:383-390（`off<=highest` 直返；有符号余数修正） | space.rs:2084+（highest 上界直返；`rem_euclid` 负修正；8 字节空间 highest=~0 使模路径不可达，与 C++ 一致） | 一致 |
| `+1` 回绕 | `Address(fspec,~0)+1` → uintb 自然回绕 0 → wrapOffset(0)=0 | `add(1)` wrapping_add + wrap_offset → 0（fixture `wrap_max_eq0=1` 双侧一致） | 一致 |
| `containedBy`/`justifiedContain` 跨空间 | address.cc:110-118/131-142：异 base → false/-1 | address.rs:1119-1159 同序同判定 | 一致 |

### 1.2 encode/decode 往返（含"valid entry 解码回 entry 地址"非常规行为）

Ghidra 依据链（本 Agent 亲读）：
1. **encode**（fspec.cc:2124-2136/2138-2151）：`fc=(FuncCallSpecs*)offset`；`fc->getEntryAddress().isInvalid()` → **只** `writeString(ATTRIB_SPACE,"fspec")`（无 offset、无 size）；valid → `writeSpace(ATTRIB_SPACE, entry空间)` + `writeUnsignedInteger(ATTRIB_OFFSET, entry偏移)` [+ATTRIB_SIZE]。即**编码形态从不携带 fspec offset 本身**。
2. **decode**（address.cc:205-212 → pcoderaw.cc:33-56）：`VarnodeData::decodeFromAttributes` 遇 ATTRIB_SPACE → `readSpace()` 按**名字**解析出 entry 空间对象（如 ram）→ `rewindAttributes()`（游标=-1）→ **该 entry 空间的** `decodeAttributes` 重走属性取 offset → `Address(var.space,var.offset)` = **(ram, entry偏移)**，而非原 fspec 地址。
3. **invalid entry 解码**：`<addr space="fspec"/>` 无 offset 属性 → FspecSpace **无 decodeAttributes 覆写**（fspec.hh:349-357 类声明亲读确认仅覆写 encode×2/printRaw/decode）→ 基类 space.cc:169-189 → `throw LowlevelError("Address is missing offset")`。

Rugra 对应：
- `AddrSpace::encode_attributes` / `_with_size`（src/space.rs，d75f1bb 引入）：Iop 臂只写 `"iop"` 丢 offset（=op.hh:49-50）；Fspec 臂 `encode_attributes_fspec`：`None` entry → 只写 `"fspec"`；`Some((spc,off))` → 写 entry 空间名+entry offset[+size]——逐行对齐。基类路径 name+offset（space.cc:146-147）。
- `SpaceAddress::encode/encode_with_size`（src/address.rs:1239/1251）：open addr 元素 → base 存在才 encode_attributes → close（address.hh:469-486）。
- `SpaceAddress::decode_with_size`（src/address.rs:1285）：walk 属性；`"space"` → `read_string` 取名 → registry `get_space_by_name`（未知名 `Err("Unknown address space name: {nm}")`，marshal.cc:407 逐字）→ `rewind_attributes()`（TreeDecoder attr_idx=0，marshal.rs:2516-2520，等价 C++ attributeIndex=-1，marshal.cc:225-229 亲读对照）→ `spc.decode_attributes` 重走。TreeDecoder 游标模型（next 前进、read 读当前，marshal.rs:2497-2513/2626-2635）与 XmlDecode 一致。
- fixture case (b) 双侧断言 `valid_entry_dec_space=ram|valid_entry_dec_off=4660|valid_entry_dec_is_fspec=0|valid_entry_same_as_orig=0`，case (a) 断言 `invalid_entry_attrs=space` + `invalid_entry_decode_err=Address is missing offset` ——非常规往返行为被真实 oracle 逐字节证实。

**四类核对**：引用/输出参数（Encoder& 流式 ↔ &mut dyn Encoder；decode 的 size 出参 ↔ &mut u32）[x]；循环边界/遍历顺序（属性游标序、到 0 止、OFFSET/SIZE 之外跳过不消费）[x]；计数器/累加器（foundoffset 布尔，无累加器）[x]；排序/比较键（属性名 id 分派、==/ < 的指针同一性+index）[x]。

锁定 id：space=20/offset=16/size=19（marshal.cc:1247/1243/1246 ↔ space.rs `attrib_space/attrib_offset/attrib_size`）[x]；elem addr=11（address.cc:25 ↔ address.rs `elem_addr`）[x]。

---

## 2. 清单项 2 — insert_space Fspec 臂 + register_fspec_entry（悬空缓存槽）

Ghidra `insertSpace`（translate.cc:352-437，亲读）关键序：
```
373 case IPTR_FSPEC:
374   if (spc->getName() != "fspec") nameTypeMismatch = true;
376   if (fspecspace != 0) duplicateName = true;
378   fspecspace = spc;            // ← 抛出前替换缓存槽（真实语义）
412   baselist.resize(...)
415   duplicateId = baselist[index] != 0
417   if (!mismatch && !dupName && !dupId)  name2Space.insert(...)   // 失败路径跳过
421   if (mismatch||dupName||dupId) { errMsg 拼 "Space X was initialized with wrong type"/" was initialized more than once"/" was assigned as id duplicating: Y"; if(refcount==0) delete spc; throw; }
     baselist[index]=spc; refcount+=1; assignShortcut(spc);   // 仅成功路径
```
- 抛出后 C++ 的 `fspecspace` 指向已 `delete` 的被拒空间（悬空），name2Space 仍解析原空间。

Rugra `insert_space`（src/space.rs:2594-2724，现行）逐点对照：
- Fspec 臂（:2617-2632）：name≠"fspec"（用 `FSPEC_SPACE_NAME` 常量）→ mismatch；`fspec_space.is_some()` → dup；**然后** `set_fspec_table` + `self.fspec_space = Some(spc.clone())` —— 同样在错误检查（:2700）**之前**替换缓存槽 [x]。
- name_to_space 插入受三条件守卫（:2690-2698）= translate.cc:417-419 [x]。
- base_list[idx] / increment_refcount / assign_shortcut 仅成功路径（:2720-2722）= :421 后段 [x]。
- 错误串逐字（:2700-2718）[x]；C++ `delete spc` ↔ Rust 调用方保留句柄但 refcount 不增（注释声明，注册表级可观察等价）。
- 悬空槽可观察面：双侧 `get_fspec_space()` 均返回**被拒的新空间**而非原空间；名字查找不受影响（name2Space 未动）。C++ 悬空指针在仅做指针比较/判空的使用下与 Rust 活 Rc 同观测；进一步解引用属 C++ UB，无对齐义务。
- `register_fspec_entry` + `FspecEntryTable`（RUGRA-GLUE，space.rs:681-720/2813-2831）：Ghidra fspec offset 即 `FuncCallSpecs*`（fspec.hh:1646-1648 亲读），printRaw/encode 解引用；Rust 以 offset→(name,entry) 侧表承载（字段恰为 Ghidra 两方法所读的 name/entryaddress），未注册 offset 确定性 panic（`"Unresolved fspec address"`）对应 C++ 野指针 UB —— 诚实披露，非静默错码。

fixture case 1 覆盖情况：`dup_msg`（要求槽已占 → " was initialized more than once" 被拼入）、`wrongtype_msg`（fresh manager 只触错型）；case (d) 在被污染的缓存槽状态下继续以名字解析原空间（`crafted_fspec_space=1`）。**注**：双侧均未直接打印 `get_fspec_space()` 与原句柄的恒等性，「替换后再抛」的次序只被间接钉住 —— 见建议 S3。

---

## 3. 清单项 3 — 错误文本与时序

| 错误 | Ghidra（亲读） | Rugra | 文本 | 时序 |
|---|---|---|---|---|
| 缺 offset | 基类 decodeAttributes 完整走完属性游标后 `LowlevelError("Address is missing offset")`（space.cc:186） | `decode_attributes` 循环后 `Err("Address is missing offset")` | 逐字 | 一致（walk 后）[x] |
| 未知名 | `XmlDecode::readSpace` 名字解析即抛 `DecoderError("Unknown address space name: "+nm)`（marshal.cc:407/425），在 rewind/decodeAttributes 之前 | address.rs:1304-1307 解析失败即 `Err(format!("Unknown address space name: {}", nm))`，在 rewind 之前 | 逐字 | 一致（解析点）[x] |
| fspec never-decode | fspec.cc:2169 `"Should never decode fspec space from stream"` | panic 同文本 | 逐字 | 一致 |
| iop never-decode | op.cc:64 `"Should never decode iop space from stream"` | panic 同文本 | 逐字 | 一致 |
| const/join never-decode | space.cc:383/649 | panic 同文本 | 逐字 | 一致 |
| dup/wrongtype 插入 | translate.cc:421-427 拼接串 | space.rs:2700-2718 同拼接序 | 逐字 | 一致 |

异常类型差（C++ LowlevelError vs DecoderError；Rust 统一 `Result<_, String>`/panic）：两侧 fixture 均打印 `err.explain` 字节比对，观测面等价 [x]。

---

## 4. 清单项 4 — 双侧 fixture 5/5 MATCH 证据链

**本 Agent 独立复验的 pin（全部本机执行 sha256sum / git rev-parse 通过）**：
- `tests/oracle/fspec_space_identity_1204.cc` = `2f048267…` ✓、`.rs` = `2fa73dba…` ✓（= metadata `cpp/rust_fixture_sha256`）
- `src/space.rs` = `61496b83…` ✓、`src/address.rs` = `84543b7c…` ✓（现行 HEAD 与 2286279 零漂移，`git diff` 空）
- `docs/api/space.md` = `2ac81026…` ✓、`docs/api/address.md` = `446f4a82…` ✓
- `tools/run_fspec_space_identity_oracle.sh` = `4d7a07de…` ✓（= metadata `runner_sha256`）
- `rugra_base_commit=fb6c21b` / tree `9ca47a39` 在仓库内存在 ✓；fb6c21b 为 agent 分支上的原始切片提交，与 master `d75f1bb` 的 7 个 fspec 相关文件 **diff 为空**（同内容双提交，仅谱系不同）；分支 `agent/fspec-space-s1` 的 metadata/runner 与 master 字节一致 ✓
- oracle 侧：ghidra HEAD/tag/cpp-tree 锁定 ✓（§0 头部）

**Runner 逻辑审计（799 行全文亲读）**：immutable-fd 自重执行 + 空环境；oracle 四重身份锁（HEAD/tag commit/cpp tree/Makefile blob + 树干净）；metadata 全字段交叉 pin（含 host 工具链指纹、input_manifest 规范化 JSON sha、coverage 表前缀强制 MATCH×5+UNTESTED×5）；Rust crate 快照 = 基座 fb6c21b + 仅 space.rs/address.rs overlay 的 crate-tree 哈希；164 包 Cargo.lock 闭包哈希 + 每档案 sha256 校验后展开私有 vendor 树（防路径穿越）；离线 locked `cargo build --lib`；C++ 侧由锁定 archive 全新重建 libdecomp.a 后 -O2 编译 fixture；oracle stdout 强制空 stderr/exit 0/哈希 = `93aaf9de…`；Rust fixture 经 rustc 直连 rlib+librugra_sleigh.a 且零诊断；双侧 stdout `diff -u` 必须为空且各自哈希都等于 pin；6 行 schema + 5 case 定序校验；运行前后 owned 文件哈希漂移检测 + 运行后全套 readback 复核。**自洽，无模板自引用残留**（2286279 所修三处：runner fd 块 :4-20、special_paths :285-304、post-readback :710-797 均已指向 fspec 路径）。

**限制声明**：按本次复核纪律（禁 cargo、只写报告文件），未重跑双侧 runner；`expected_stdout_sha256=93aaf9de…` 与 5/5 MATCH 以 pin 完整性 + runner 逻辑审计 + 双侧 fixture 源码逐行镜像比对（本 Agent 已逐 case 对照两侧投影字段）为证据基础。

---

## 5. 清单项 5 — 残差归属核实

| 残差 | 归属 TODO | metadata coverage | 核实 |
|---|---|---|---|
| PackedEncode::writeSpace 特殊空间字节（marshal.cc:1195-1205，亲读）+ PackedDecode::readSpace 拒绝 | MARSHAL-XML-TEXT-0001（board :571 存在且 own 该域） | `packed_special_space_codec: UNTESTED` | ✓ 如实登记 |
| JoinSpace encodeAttributes/decodeAttributes piece 编解码（space.cc:502-588） | MARSHAL-XML-TEXT-0001 | `join_space_codecs: UNTESTED` | ✓ Rust 三处（encode 2 形态+decode_attributes）**显式 panic 且消息内嵌 TODO ID**（"JoinSpace::… is not ported (MARSHAL-XML-TEXT-0001)"），非静默错码；`AddrSpace::decode` Join panic 是忠实移植（space.cc:649 throw 同文本），非残差 |
| IopSpace::printRaw（op.cc:41-59） | SPACE-IOP-PRINTRAW-0001（board :1183，BLOCKED by ADDRESS-0001） | `iop_print_raw: UNTESTED`；fixture 注释明确声明不练习 | ✓ 现行 Iop 臂回落基类形态=特化引入前可观察行为，带注释+单元测试钉住；残差标注与 TODO 一致 |
| ATTRIB_NAME 寄存器名形态 decode | `SPACE-0001 residual`（board :575 同源残差措辞） | `register_name_decode: UNTESTED`；Rust 显式 Err（非 panic、非错码） | ✓ |
| 消费侧迁移（varnode/funcdata 仍 Iop 地址+typed Weak） | TYPEOP-FSPEC-SPACE-0001 切片2 / TYPEOP-FSPEC-CONSUMER-0002（board :23 已列） | `consumer_migration: UNTESTED` | ✓ |

board 状态（docs/TODO_BOARD.md :23）：PARTIAL、切片1 集成 `d75f1bb..2286279`、5/5 MATCH、R5 复核中、残差归 MARSHAL-XML-TEXT-0001 与 SPACE-IOP-PRINTRAW-0001 —— 与实际仓库状态一致，无虚标 L3/MATCH。

**函数头注解抽查**（铁律 1.3）：新增函数头 `// Ghidra:` 引用逐一亲读验证指向函数定义起始行：space.rs `encode_attributes`(space.cc:143)、`encode_attributes_with_size`(space.cc:156)、`encode_attributes_fspec`(fspec.cc:2124)、`decode_attributes`(space.cc:169)、`print_raw_fspec`(fspec.cc:2153)、`new_fspec_space`(fspec.cc:2116)、`new_iop_space`(op.cc:33)；address.rs `elem_addr`(address.cc:25)、`encode`(address.hh:469)、`encode_with_size`(address.hh:481)、`decode`(address.cc:205)、`decode_with_size`(address.cc:226)。全部命中定义行 [x]。docs/api 同 commit 更新 [x]。

---

## 6. 建议（非阻断，均应记入切片2 TODO）

- **S1（行号漂移，须修）**：`VarnodeData::decodeFromAttributes` 实际位于 **pcoderaw.cc:33**（rewind :44、重走 :45）；被引作 "pcoderaw.cc:107"（该行实为 `PcodeOpRaw::decode` 中的 `(*outvar)->decode(decoder);`）。出现处：`src/address.rs:1291` 行内注释、metadata `stable_function_closure`（`…decodeFromAttributes pcoderaw.cc:107`）、fixture `.cc` 头注释 "pcoderaw.cc:100-130"（该区间属 PcodeOpRaw::decode）、d75f1bb Evidence 块。仓内其余文件（arch.rs/pcodeparse.rs/userop.rs）均正确引 :33。**语义描述本身正确完整，非函数头注解故未被 check_ghidra_refs 拦截**；切片2 修注释 + metadata 重钉。
- **S2**：`SpaceAddress::decode_with_size` 入口未 `*size = 0`；Ghidra 的 `VarnodeData::decodeFromAttributes` 将 size 起始为 0（pcoderaw.cc:37）且 `Address::decode(int4&)` 无条件覆写出参。现有调用方（`decode()` 包装置 0、fixture）无可观察分歧；直接调用者传非零初值 + 无 size 属性时会读到残留值而 Ghidra 得 0。建议入口补 `*size = 0`。
- **S3**：悬空缓存槽仅间接覆盖（dup 消息 + 污染态下名字解析）；建议双侧 fixture 追加直接探针（重复插入失败后 `get_fspec_space() == 被拒空间 && != 原空间`），把「替换后再抛」次序正向钉死。
- **S4**：C++ fixture (b) 硬编码 `valid_entry_same_as_orig=0`（Rust 侧为计算值）；构造上不可能为 1，但双侧都改为计算更严谨。
- **S5**：`src/fspec.rs:2977+` 遗留无调用者的 `fspec_encode_attributes`/`fspec_print_raw` 死孪生（含 `space_name_for_addr` 硬编码 `"ram"` 占位）；切片2 消费侧迁移时删除或改接 registry 实现，防止后人误接占位。
- **S6（流程）**：board/DAG 集成（77bdcd3/941cb40）晚于三个被审提交而非同 commit（铁律 3 字面）；状态现已如实，仅记录。

---

## 7. 结论

四类决定性语义逐点与锁定 oracle 一致；insert_space 抛出前替换缓存槽的真实语义对齐；错误文本与时序逐字一致；证据链 pin 本机复验通过、runner 逻辑自洽无残留自引用；全部残差如实 UNTESTED 并归属在册 TODO，Join 编解码显式 panic 不静默错码。未发现 MISMATCH。

**Cross-Review: APPROVE**
