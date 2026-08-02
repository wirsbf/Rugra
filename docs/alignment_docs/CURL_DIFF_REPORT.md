# Rugra vs Ghidra 反编译质量差距报告

**生成时间**: 2026-08-02
**测试样本**: curl 二进制，24 个 Rugra 反编译函数 vs Ghidra 黄金输出

## 总体统计

| 维度 | Rugra | Ghidra |
|------|-------|--------|
| 反编译函数数 | 24 | 124（含库导入/stub）|
| 共同函数 | 20 | 20 |
| Skeleton diff 总行数 | 2962 | — |
| Rugra defects (空else/寄存器泄漏/调用丢失) | **0** | — |
| Rugra numbering issues | **0** | — |
| 精确匹配 (0 diff) 函数 | 0/24 | — |
| Trivial diff (1-5 行) 函数 | 2/24 | — |
| Big diff (>20 行) 函数 | **19/24** | — |

**关键结论**: defects=0 + numbering=0 说明没有"非法 C 代码"或"编号 bug"，
但 **几乎所有函数的伪代码与 Ghidra 差距巨大**（skeleton diff 占主导）。

## 差距分类（按严重程度排序）

### 🔴 严重问题 1：函数原型完全错误

每个函数的签名都错了。例：

```c
// Ghidra:
int myprogress(void *clientp, size_t dltotal, size_t dlnow,
               size_t ultotal, size_t ulnow)

// Rugra:
long myprogress(long param_1, long param_2, long param_3, long param_4,
                long param_5, char * param_6, long param_7, long param_8,
                char * param_9, long param_10, long param_11, long param_12)
```

问题：
- **参数数量错误**：Ghidra 推断 5 个参数（正确，符合 curl `progress_callback` 签名），
  Rugra 推断 12 个参数
- **类型丢失**：全是 `long`/`char *`，没有 `size_t`/`void *`/`int`
- **无命名**：用 `param_N` 而非 Ghidra 的语义命名（这部分 Ghidra 也不做，但 Ghidra
  能从 proto model 推出正确参数槽）

**根因**：`ActionDefaultParams` / `ActionActiveParam` / `ActionInputPrototype` 的
参数推断未对齐 Ghidra。Rugra 把所有寄存器都当输入参数。

### 🔴 严重问题 2：局部变量全是 `V` 占位符

```c
// Ghidra:
long lVar1;
ulong uVar2;
bool *pbVar3;
uint uVar4;
float fVar9;
char format [40];
bool line [256];

// Rugra:
bool bVar11;
long lVar10;
int * piVar1;
long * plVar4;
int local_0;
```

Rugra 有类型推断（`bVar`/`lVar`/`piVar` 前缀），但：
- **重复声明**：同一个函数里 `bool V; bool V; bool V;` 反复出现（应该是不同 SSA 版本）
- **local_0** 这种无意义命名（Ghidra 也用 `local_*`，但 Rugra 数量异常多）
- **数组/struct 完全丢失**：Ghidra 推断出 `char format[40]` / `bool line[256]`，
  Rugra 全是标量

**根因**：HighVariable 合并不完整 + 类型推断没有数组/聚合类型支持。

### 🔴 严重问题 3：表达式完全破碎

```c
// Ghidra:
*(ulong *)((long)clientp + 0x10) = uVar8;
uVar2 = *(ulong *)((long)clientp + 8) >> 10;

// Rugra:
*piVar1 = param_8;
*piVar1 = param_119;  // ← param_119 根本不存在！
*plVar4 = lVar3;
```

问题：
- **悬空变量引用**：`param_119`、`param_8` 引用不存在的参数
- **没有 PTRSUB 渲染**：Ghidra 把 `INT_ADD(ptr, 0x10) + STORE` 渲染成 `*(long *)(ptr + 0x10) = ...`，
  Rugra 还在用独立的临时变量 `piVar1`
- **没有 PTRSUB → 字段访问**：本应是 `clientp->field` 的渲染缺失

**根因**：`RulePtrArith` / `RuleStoreVarnode` 转换不完整，PTRSUB op 没有充分生成；
PrintC 没有 Ghidra 的 RPN 表达式重建（plan 文件 `plan-sess_24510194` 描述的那个）。

### 🟠 中等问题 4：调用参数丢失/错位

```c
// Ghidra:
__sprintf_chk(format, 1, 0x28, "%%-%ds %%5.1f%%%%");
__fprintf_chk(stderr, 1, &DAT_001061d9, outline);

// Rugra:
(lVar3 = (*param_9 + 0x28;     // ← 语法错误（缺右括号）
strlen(V);
(V);                            // ← 调用变成表达式语句
puts(V);
```

问题：
- **语法错误**：`(lVar3 = (*param_9 + 0x28;` —— 缺 `)`
- **CALL 渲染错误**：`strlen(V)` 后变成 `(V);` —— 调用目标丢失
- **参数数量错误**：`__sprintf_chk` 应该有 4 个参数，Rugra 一个都没传

**根因**：CALL op 的参数连接（funcLinkInput）+ PrintC op_call 不完整。

### 🟠 中等问题 5：控制流多余 do-while

```c
// Ghidra (无 do-while，纯 if/goto):
if ((int)uVar4 <= (int)uVar2) goto LAB_0010353d;
do {
  uVar6 = (int)uVar7 + 1;
  ...
} while (uVar4 != uVar6);

// Rugra (大量虚假 do-while):
do {
  fputc(param_1, param_2);
  (bVar7);
} while (!(local_0));
```

- Rugra 把 `if-break` 模式强行变成 `do-while(!(local_0))`
- `local_0` 是未初始化变量，循环条件永远假 → 死代码

**根因**：BlockStructure（控制流结构化）算法把 Ghidra 当 goto 处理的模式错误地
结构化成了 do-while。

### 🟢 小问题 6：格式细节

- Rugra 用 2 空格缩进，Ghidra 用 2 空格（OK）
- `{` 单独成行 vs 同行（Ghidra 是单独成行，Rugra 也是，OK）
- LIT 占位符（Ghidra）vs 直接数值（Rugra）—— 反过来更好

## 按函数复杂度的差距分布

| 函数 | LOC Rugra/Ghidra | sk_diff | 主要问题 |
|------|------------------|---------|---------|
| main_free | 3/5 | 4 | 几乎对齐 |
| __libc_csu_fini | 4/4 | 3 | 几乎对齐 |
| SetHTTPrequest.part.0 | 7/10 | 10 | 原型错 |
| my_fwrite | 8/15 | 19 | 原型+调用丢失 |
| hugehelp | 8/17 | 23 | 原型错 |
| glob_url | 25/16 | 35 | **Rugra 更长**，原型错+破碎表达式 |
| progressbarinit | 25/19 | 36 | 原型错 |
| GetStr | 22/14 | 26 | 原型错 |
| __libc_csu_init | 29/12 | 33 | **2.4x 长**，循环结构化错 |
| glob_word | 35/62 | 87 | Rugra 更短（少了字段访问） |
| glob_set | 39/80 | 109 | Rugra 更短 |
| myprogress | 54/58 | 102 | 表达式破碎 |
| match_url | 54/75 | 115 | Rugra 更短 |
| glob_range | 62/71 | 121 | Rugra 更短 |
| my_get_line | 63/70 | 123 | 表达式破碎 |
| next_url | 59/96 | 141 | Rugra 更短 |
| parseconfig.constprop.0 | 62/? | 142 | — |
| helpf | 52/64 | 106 | — |
| file2string.part.0 | 50/? | 186 | — |
| getparameter.constprop.0 | 239/? | 682 | 最大差距 |
| main | 294/471 | 752 | 最大函数，比例 0.62 |

## 与之前计划的关系

- **RPN 表达式重建**（plan-sess_24510194 文件描述的 PrintC RPN 迁移）是
  解决问题 3+4 的核心。
- **参数推断**（ActionDefaultParams 等对齐）解决问题 1。
- **类型推断 + 数组支持**（HighVariable + Array datatype）解决问题 2。
- **控制流结构化**（BlockStructure 对齐）解决问题 5。

## 优先级建议

1. 🔴 **问题 3（表达式破碎 + 悬空变量 param_119）**：这是"非法 C 代码"边缘，
   应该最先修。`param_119` 这种引用不存在的变量说明 SSA rename 后 PrintC 用错了
   varnode 索引。
2. 🔴 **问题 4（CALL 渲染 + 语法错误）**：`(*param_9 + 0x28;` 缺右括号是
   硬语法错误，gcc 审计应该已经抓到。先看 audit_syntax 的结果。
3. 🔴 **问题 1（函数原型）**：影响每个函数。ActionInputPrototype + ProtoModel
   的对齐。
4. 🟠 **问题 2（变量类型/重复声明）**：HighVariable 合并。
5. 🟠 **问题 5（do-while 死循环）**：BlockStructure 对齐。
