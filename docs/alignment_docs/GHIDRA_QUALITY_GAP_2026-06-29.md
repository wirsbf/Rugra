# Rugra vs Ghidra 反编译质量差距分析（逐函数对比）

**日期**: 2026-06-29
**方法**: 同一个 `examples/curl` 二进制，Rugra（`result/curl_cur.c`）vs Ghidra 参考（`result/ghidra_curl_ref.c`）逐函数对比
**样本**: myprogress / my_get_line / helpf 等共 15+ 个同名函数

---

## 一、量化对比（curl 全局）

| 维度 | Rugra | Ghidra | 差距 |
|---|---|---|---|
| gcc 审计 | 24/24 ✅ | — | 持平（语法合法） |
| goto | 0 ✅ | 0 | 持平 |
| **寄存器名泄漏到 C**（RSP/RBP/RAX 当变量） | **154** | **0** | 🔴 极大 |
| **StackX_ 栈槽命名** | **41** | **0** | 🔴 极大 |
| 空 `do{}while`（结构化残骸） | 21 | 22 | 持平（双方都有，Ghidra 是 unrolled 字符串扫描循环） |
| return 后死代码 | 25 | 0 | 🔴 中 |
| **CALL 参数正确**（my_get_line 的 fgets/strdup） | ❌ 错 | ✅ | 🔴 严重 |
| **CALL 返回值 def**（strdup 结果赋给变量） | ❌ 缺失 | ✅ | 🔴 严重 |

> 注意：Ghidra ref 也用 `lVar1`/`uVar2`/`DAT_` 等占位名，**不是**带符号名。所以"变量命名"双方都在同一水平线——差距在**寄存器泄漏、CALL 语义、返回值 def**，不在符号恢复。

---

## 二、逐函数对比：3 个代表性差距

### 差距 1：寄存器名直接泄漏成 C 变量（myprogress）

Ghidra：
```c
int myprogress(void *clientp, size_t dltotal, ...) {
  long lVar1;
  ulong uVar8;
  long in_FS_OFFSET;          // FS 段（stack canary 基址）
  char format[40];
  bool line[256];
  uVar8 = ulnow + dlnow;
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);   // 读 canary
```

Rugra：
```c
long myprogress(long param_1, ...) {
  long RBP;                   // 🔴 RBP 当变量
  int * RSP;                  // 🔴 RSP 当变量
  long StackX_0;              // 🔴 栈槽命名
  ...
  piVar2 = RSP + 0x257fffffda8;   // 🔴 RSP 算术泄漏到 C
```

**根因**：Rugra 把 RSP/RBP/RAX 等**寄存器当普通 SSA varnode** emit 成 C 变量，而非在分析层解析它们的语义。Ghidra 有专门的机制：
- `in_FS_OFFSET`（FS 段寄存器）→ Ghidra 的 `ActionPrototype` + 寄存器空间映射
- RSP 栈指针 → `ActionStackPtrFlow`（coreaction.cc:481）分析栈指针流，把 RSP 算术折叠成栈帧偏移
- 栈槽 `local_xx` → varmap ScopeLocal 把 `*(RSP+offset)` 映射成具名局部变量

### 差距 2：CALL 参数全错 + 返回值 def 缺失（my_get_line）

Ghidra：
```c
do {
  pcVar3 = fgets(buf, 0x1000, (FILE *)fp);     // ✅ 3 个正确参数
  if (pcVar3 == (char *)0) goto LAB_...;
  if (__dest == (uint *)0x0) {
    __dest = (uint *)strdup(buf);              // ✅ strdup 返回值赋给 __dest
  } else {
    ... __dest = realloc(__dest, len);          // ✅ realloc 返回值
    strcat((char *)__dest, buf);                // ✅ strcat
  }
  pcVar3 = strchr((char *)__dest, 10);          // ✅ strchr 返回值
} while (pcVar3 == (char *)0x0);
```

Rugra：
```c
return;                         // 🔴 无故提前返回（死代码在前）
do { } while (lVar6 == 0);      // 🔴 空循环
while (lVar5 == 0) {
  strdup(piVar2);               // 🔴 strdup 没接返回值，参数错
}
realloc(lVar1, lVar2 + lVar3 + 1);  // 🔴 返回值丢失
strcat(lVar8, piVar2);          // 🔴 参数错
strchr(lVar1, 0xa);             // 🔴 返回值丢失
if (lVar6 != 0) return;
return lVar8;                   // 🔴 lVar8 从哪来？
```

**根因**：三层缺失叠加：
1. **CALL 返回值无 def**：CALL op 在 Rugra 没有 output varnode，`rax = fgets(...)` 的 rax 不建立 SSA def → 返回值"消失" → 下游所有使用它的变量（`__dest`/`pcVar3`）变成"声明却未赋值"
2. **CALL 参数恢复不完整**：`fgets(buf, 0x1000, fp)` 的 3 个参数（RSI/RDX/RCX）没正确关联到 CALL op 的 inrefs
3. **死代码未清理**：`return;` 后的语句没被 ActionDeadCode 删除（因为前面的"死"是语义死，不是 descend 死——返回值 def 缺失让 descend 链断裂）

### 差距 3：栈槽 StackX_ 命名 vs Ghidra local_xx（helpf）

Ghidra：`undefined1 local_b8[8];` `undefined8 local_b0;`（local_ + 负偏移）
Rugra：`long StackX_0;` `long StackX_10;`（StackX_ + 正偏移，且常错位）

**根因**：varmap ScopeLocal 的 RangeHint 收集不完整。Ghidra 把每个 `*(RSP - offset)` 映射成 `local_<offset>`，Rugra 的 spacebase 解析在部分函数里收集到 0 hints（ROADMAP 记录："多数函数 gather_spacebase 收集到 0 hints，根因是栈访问用 RBP/param 指针而非 RSP 直派"）。

---

## 三、差距 → 缺失模块映射（按 ROI 排序）

| 优先级 | 差距 | 缺失模块 | Ghidra 源码位置 | ROADMAP 状态 | 影响 |
|---|---|---|---|---|---|
| **P0** | CALL 返回值无 def（`strdup`/`fgets` 结果丢失） | **FuncCallSpecs 返回值 def** + ActionReturnRecovery active_output | funcdata.cc CALL output 建立；coreaction.cc ActionReturnRecovery | 🔧 L2 | 所有含 CALL 的函数（my_get_line/myprogress/helpf 全中招） |
| **P0** | CALL 参数错（fgets/realloc 参数未关联） | **ActionFuncProto** + FuncCallSpecs 参数槽 + ActiveParam | coreaction.cc:4521 ActionFuncProto；op.hh CALL slot 映射 | 🔧 L2 | 所有 CALL 调用点 |
| **P1** | RSP/RBP 寄存器泄漏成 C 变量（154 处） | **ActionStackPtrFlow**（栈指针流折叠） | coreaction.cc:481 | 🔧 L2（AliasChecker 已移植，Flow 未接入） | myprogress/helpf/my_get_line |
| **P1** | StackX_ 栈槽 vs local_xx（41 处） | **varmap ScopeLocal** RangeHint 收集（RBP/param 基址） | varmap.cc gather_spacebase | 🔧 L2（RSP 基址已通，RBP 未通） | 多数函数 |
| **P2** | return 后死代码（25 处） | **ActionDynamicBranch/Unreachable + remove_unreachable_blocks** | coreaction.cc:3457；block.cc | 🔧 L2（已移植 apply()，**未接入管线**） | my_get_line 等 |
| **P2** | 空循环 `do{}while`（21 处） | **blockaction 循环结构化** + SSA def 修复 | blockaction.cc | 🔧 L2 | my_get_line |

---

## 四、结论：最高 ROI 修复路径

**质量差距的根源不是单一模块，而是一条"CALL 语义链"**：

```
CALL 参数恢复（ActionFuncProto） ──→ CALL 返回值 def（FuncCallSpecs output）
        │                                    │
        ▼                                    ▼
  参数正确传入                       返回值可被后续使用（消除"未赋值"）
        │                                    │
        └──────────► DeadCode 能正确清理 ◄───┘
                        │
                        ▼
                 return 后死代码消失
```

这条链一断，所有含 CALL 的函数都崩（my_get_line 是极端例子）。

### 建议优先级

1. **P0-A：CALL 返回值 def**（最高 ROI）——给 CALL op 建立隐式 output varnode（rax），让返回值进入 SSA def 链。一处修复，连锁解决"返回值丢失 + 下游未赋值 + 死代码"。
2. **P0-B：ActionFuncProto 参数槽**——CALL 的参数（RDI/RSI/RDX/RCX/R8/R9）正确关联到 op.inrefs。
3. **P1：ActionStackPtrFlow**——消除 154 处寄存器泄漏。
4. **P1：varmap RBP 基址**——消除 41 处 StackX_。

---

## 五、复现命令

```bash
cargo run --release --example curl_decompile          # Rugra 输出
# result/curl_cur.c
# 逐函数对比：result/curl_cur.c vs result/ghidra_curl_ref.c
# 关注函数：myprogress / my_get_line / helpf / file2string
```
