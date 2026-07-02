# Rugra 反编译质量差距分析（基于逐函数代码对比）

**日期**: 2026-06-29
**方法**: 逐函数 side-by-side 对比 Rugra 与 Ghidra 11.3.2 的实际反编译输出，不看计数指标，看代码可读性和语义恢复效果。

---

## 一、核心差距（按影响排序）

### 差距 1：变量未初始化使用（最严重）

**Ghidra `my_fwrite`**:
```c
FILE *__s;
__s = (FILE *)stream->_IO_read_ptr;     // 清晰的赋值链
if (__s == (FILE *)0x0) {
    __s = fopen(*(char **)stream,"wb");
    stream->_IO_read_ptr = (char *)__s;
    if (__s == (FILE *)0x0) return -1;
}
sVar1 = fwrite(buffer, size, nmemb, __s);
return (int)sVar1;
```

**Rugra `my_fwrite`**:
```c
long lVar4;
long lVar5;
long * piVar1;
long * piVar2;
long lVar1, lVar2, lVar3;

lVar4 = RSP + 0xff0;                    // RSP 泄漏到输出
piVar1 = param_4 + 8;
lVar5 = *(long *)piVar1;
if (lVar5 == 0) {
    fopen(*((long *)piVar2), "wb");     // piVar2 从未赋值！
    *(long *)(lVar1 + 0x8) = lVar2;     // lVar1, lVar2 从未赋值！
    if (lVar3 != 0) return;             // lVar3 从未赋值！
} else {
    fwrite(param_1, param_2, *(long *)((long *)RSP + 0x8), iVar1);
}
return;
```

**根因**: SSA def 链断裂 + copy-propagation 不完整。变量恢复层无法建立正确的 use-def 关系，导致许多变量"声明了但从未赋值"就被读取。

**阻塞模块**:
- `heritage.cc` SSA rename 可能在跨块场景下断裂
- `ActionCopyPropagate` 未完整传播 COPY 链
- `ActionDeadCode` 可能过早删除关键的中间 COPY op

---

### 差距 2：结构体字段访问（`->` 操作符）

**Ghidra**: `stream->_IO_read_ptr` — 识别出结构体字段访问
**Rugra**: `*(long *)(param_4 + 8)` — 只能输出原始指针算术

**根因**: 类型系统未传播到 LOAD/STORE 地址。没有 `TypePointer → TypeStruct` 的关联，所以 printc 无法将 `INT_ADD(ptr, offset)` + `LOAD` 模式识别为结构体字段访问。

**阻塞模块**:
- `ActionInferTypes` 类型传播不完整
- `ActionTypePropagate` 未将 Pointer-to-Struct 传播到 LOAD 的地址输入
- printc 的 `emit_inline_expr` 缺少 `->field_N` 模式检测

---

### 差距 3：CALL 参数恢复不完整

**Ghidra**: `fwrite(buffer, size, nmemb, __s)` — 4 个参数正确
**Rugra**: `fwrite(param_1, param_2, *(long *)((long *)RSP + 0x8), iVar1)` — 第 3/4 参数来自未初始化的栈位置

**根因**: ActionActiveParam + AncestorRealistic 不完整，参数值没有沿 SSA 链正确传播到 CALL op 的输入。ActionCopyPropagate 未将正确的值替换到 CALL 的参数槽位。

**阻塞模块**:
- `ActionActiveParam` 缺 AncestorRealistic 数据流祖先追踪
- `ActionFuncLink::funcLinkInput` 的栈参数 pcode 注入未实现
- `ActionCopyPropagate` 未完整传播到 CALL 输入

---

### 差距 4：函数体缺失（strdup 等调用未恢复）

**Ghidra `GetStr`**:
```c
if ((value != (char *)0x0) && (*value != '\0')) {
    pcVar1 = strdup(value);             // strdup 调用恢复
    *string = pcVar1;
    return;
}
*string = (char *)0x0;
```

**Rugra `GetStr`**:
```c
if (lVar1 != 0) {
    free(param_2);
}
if (lVar2 == 0) {                       // lVar2 从未赋值
    *(int *)piVar1 = 0;
    return;
} else {
    if (bVar1 != 0) return;             // bVar1 从未赋值，strdup 调用完全缺失
}
```

**根因**: copy-propagation + dead-code-elimination 过早删除了中间结果。条件分支的 then/else 体中的 CALL op (strdup) 因其输出未被正确传播而被 dead-code 消除。

**阻塞模块**: 同差距 1（SSA def 链完整性）

---

### 差距 5：语义变量名

**Ghidra**: `buffer`, `size`, `nmemb`, `stream`, `__s` — 有意义的参数名
**Rugra**: `param_1`, `param_2`, `param_3`, `param_4`, `bVar1`, `lVar1` — 匿名名

**根因**: Rugra 没有符号数据库（DWARF 调试信息或内置库函数签名）。Ghidra 通过 ActionNameVars 的 `lookForFuncParamNames` 从被调函数的签名传播参数名。

**阻塞模块**:
- 符号数据库（需 DWARF/ELF 解析或内置库签名）
- `ActionNameVars` 的 `lookForFuncParamNames` 完整实现

---

## 二、已对齐的方面

以下方面 Rugra 与 Ghidra 基本对齐或超越：

| 方面 | 状态 | 证据 |
|---|---|---|
| 控制流结构（if/else/switch/while/do-while） | ⚠️ 待重新验证 | 旧计数显示 curl 36 while > Ghidra 34，但计数已废弃（2026-07-02）；结构骨架 diff 显示 17/24 函数仍有真实缺陷，待修复后重新验证 |
| goto 消除 | ✅ 超越 | Rugra 0 goto vs Ghidra 61 |
| 库函数识别 | ✅ 部分 | fopen/fwrite/free/strlen 等已识别 |
| gcc 语法合法性 | ✅ 对齐 | curl 24/24 + httpd 29/29 |
| 空函数恢复 | ✅ 完全对齐 | main_free 完全匹配 |
| 变量命名方案 | ✅ 对齐 | compact bVar1/lVar1 Ghidra 风格 |
| uVar 碎片 | ✅ 消除 | 149→0 |

---

## 三、优先修复路径

按对输出质量影响的 ROI 排序：

### P0：SSA/copy-prop def 链完整性
- **影响**: 修复差距 1（未初始化变量）+ 差距 4（函数体空），直接影响所有函数的可读性
- **工作**: 深入诊断 heritage SSA rename 在跨块场景的 def 链断裂，修复 ActionCopyPropagate 的 COPY 链传播
- **验证**: my_fwrite 的 piVar2/lVar1/lVar2/lVar3 被正确赋值

### P1：类型传播到 LOAD/STORE
- **影响**: 修复差距 2（结构体字段访问），让 `->` 操作符出现
- **工作**: ActionTypeInfer 将 Pointer-to-Struct 传播到 LOAD 地址输入，printc 检测 `INT_ADD(ptr, offset) + LOAD` 模式
- **验证**: `stream->_IO_read_ptr` 替代 `*(long *)(param_4 + 8)`

### P2：CALL 参数传播
- **影响**: 修复差距 3（CALL 参数错误）
- **工作**: ActionCopyPropagate 传播到 CALL 输入，ActionActiveParam 正确标记活跃参数
- **验证**: `fwrite(buffer, size, nmemb, __s)` 4 参数正确

### P3：语义变量名（符号数据库）
- **影响**: 修复差距 5（匿名参数名）
- **工作**: 构建库函数签名数据库，ActionNameVars 传播参数名
- **验证**: `buffer`/`stream` 替代 `param_1`/`param_4`

---

## 四、会话技术成果总结（43 个提交）

| 类别 | 成果 |
|---|---|
| pipeline 底层 | ActionSpacebase + spacebase() + split_uses() — uVar 149→0 |
| 变量命名 | compact 重编号 (assignDefaultNames) — bVar1/lVar1 |
| 结构化核心 | BlockIf newBlockIfGoto + removeEdge + goto-first + 死锁修复（旧 while 计数 28→36，该计数已废弃） |
| 11 个新 Rule | oppool1 102→112 (skip 12→4) |
| 128 位基础设施 | new_extended_constant + u128 |
| 13 个 Action 改进 | RestrictLocal/DirectWrite/DefaultParams/ExtraPopSetup/ReturnRecovery/InputPrototype/OutputPrototype/UnjustifiedParams/NonzeroMask/PrototypeTypes/PrototypeWarnings + calc_nz_mask |
| 基础设施 | EffectRecord + stackoffset + active_output + mark_not_mapped + find_input |
| 验证 | 17 函数 side-by-side 对比文档 |
