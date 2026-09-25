# Lane GH 终报 — 变量类型/编号族归因（NAME residual two-subfamily attribution）

- **Worktree**: wt/nameattr @ /dev/shm/rugra-worktrees/nameattr, 基(亲父) master **892cd755**,交付 commits **9be3d062**(src+docs/api)+**d9a300b8**(TODO 登记)
- **oracle**: Ghidra 12.0.4 e40ed130（canon golden = headless Java 桥契约; direct-runner golden = 纯 C++ 库真值）
- **性质**: 归因优先 + 域内修复（typefactory.rs DataOrg core-type 表; varmap.rs 核对后零改动）
- **CARGO_TARGET_DIR**: /dev/shm/rugra-targets/sb-nameattr

## 0. 两亚族根因（各一句话）

1. **类型差亚族**（`undefined8 uVar3` vs `long lVar2` / `int2` vs `int` 形）:
   **主导根因 = Rugra DataOrg 核心类型表命名与 Java headless `<coretypes>` 流不一致** —
   Rugra 用自造 `int8/uint8/int2/uint1` 拼写, canon 契约是 Java
   `PcodeDataTypeManager.generateCoreTypes` 投影的 `long/ulong/short/byte`
   (同 size 同 metatype, 纯名字差, 且 `printNameBase` 取 name 首字符使前缀
   `i↔l/s`、`u↔b` 跟随漂移)。**本 lane 已修**。
   残余 = 真宽度/metatype 推断差（`int2` vs `int` 2B↔4B、`undefined8` vs `long`
   UNKNOWN↔INT、`size_t` vs `short` 类型源差）→ heritage/typeprop/setcasts/merge
   域（部分已登记 GF 残差①②）。
2. **编号差亚族**（`iVar2` vs `iVar5`）: **命名机器本身核对忠实**（shared base 计数器 /
   persist 臂不递增 / bump 循环 / `$undef` 遍历逐行对照 database.cc:2434-2518 +
   coreaction.cc:2978-2998, RUGRA_NAMETRACE 探针实测序列）; **残差是上游 IR/merge
   分歧的下游读数** — 两机制: ①next_url(投影 MATCH)实证同 10-名多重集纯置换:
   char* high 的 name representative 位置不同（Rugra=Register:0x0:8 RAX vs golden
   靠后寄存器）= **high 分组/name-rep 选取差 = merge 域**（GF 残差②同族）;
   ②myprogress 实证符号集不同: canary 对象 Rugra 物化为栈符号 `lStack_30` 而
   golden 为寄存器 high `lVar1`（heritage/spill 物化域）+ `bool*` vs `undefined1*`
   类型推断差。

## 1. 修复（typefactory.rs, 域内）

`init_data_org_core_types`: `int{N}/uint{N}` 约定式循环 → Java 精确表
（signed: sbyte/short/int3/int/int5/int6/int7/long/int16; unsigned:
byte/ushort/uint3/uint/uint5/6/7/ulong/uint16; float(4)/double(8)/longdouble(16);
wchar_t(4,int,UTF); undefined1..8 不变）。证据链:
- PcodeDataTypeManager.java:1154-1228 generateCoreTypes（12.0.4 发行版 Java 源）
- AbstractIntegerDataType.java:544-566（longSize 覆写 longlong 槽位）
- Undefined.java:31-38; FloatDataType/DoubleDataType/LongDoubleDataType/WideCharDataType 构造名
- canon golden token census: `ulong31/long102/short10/ushort8/byte3`, **零** int8/uint8;
  direct-runner golden **零** ulong → 名字表是 headless 桥层契约（FI 判例口径）
- 消费方核对: get_base(size,metatype) 按身份解析与名字无关; prettyprint
  legacy_never_type_evidence 两拼写集均已覆盖; find_by_name 仅测试使用

## 2. 前后数字（亲父 892cd755 本地复现基线）

| 门禁 | 前(基线) | 后 | 判定 |
|---|---|---|---|
| curl E2E (vs canon golden) | **1910/0/0** (124/124) | **1847/0/0** (−63) | 全改善 |
| httpd E2E (vs canon golden) | **1960/0/0** (32 fn) | **1782/0/0** (−178) | 全改善 |
| 逐函数 | — | curl 11 fn 改善/httpd 16 fn 改善 | **零回退**（positional per-func 校验） |
| 五投影 MATCH (RUGRA_MIRROR=1) | next_url/match_url/parseconfig/getparameter/myprogress MATCH | 同五投影 **MATCH×5 保持** | 类型名不进投影快照 |
| gcc 审计 | 102OK/22FAIL | 同集 | 恒等 |
| 双跑确定性 | — | curl/httpd cmp 恒等 | ✓ |
| cargo test --lib | 18 failed(已知 flaky) | 1688 passed/18 failed 同集 | 零新增 |
| 严格分类器 TYPE 对 | curl 15 / httpd 35 | curl 3 / httpd 12 | 类型拼写族基本消灭 |
| 前缀 census (curl) | iVar350/uVar248/lVar12/sVar24/bVar4 | iVar238/uVar229/lVar110/sVar37/bVar23 | 向 canon (266/104/128/49/31) 收敛 |

五投影函数 NAME 残差行: next_url 92→88, myprogress 57→49, parseconfig 83→81,
getparameter 471→466, match_url 47→47 (−19 合计; match_url 的 47 行残差经样本
核对全为 OTHER 族——吸附分解拼写/DAT 标签, 非本两亚族)。

## 3. 残余移交（NUMBER 亚族 + TYPE 真差）

| 移交项 | 域 | 证据 |
|---|---|---|
| `NAME-NAMEREP-GROUPING-0001`（新登记）: 同名多重集纯置换, name-rep 位置差于共享寄存器位（RAX 族）, = high 分组/merge 差异经命名序暴露 | `src/merge.rs`/high 分组（GF 残差② 同族域） | next_url trace: pos5 char* rep=Register:0x0:8, golden 同 high 名于 pos9; 投影 MATCH 排除 op 层差异 |
| `NAME-CANARY-STACKMATERIAL-0001`（新登记）: canary `*(long*)(FS+0x28)` 载荷 Rugra 物化为栈符号 `lStack_30`, golden 为寄存器 high `lVar1` | heritage/funcdata 物化域 | myprogress decl 对比 + trace（namerec 无该 long, stack 符号尾部命名） |
| TYPE 真差残余（curl 3/httpd 12 对 + 前缀 census 差） | GF 残差①（coreaction setcasts, FV2 后继在飞）+ GF 残差②（varmap/Merge 代表性类型）+ heritage/typeprop 宽度路径 | `int2` vs `int`（next_url pos2 short vs golden int 宽度 2↔4 待逐例）; `size_t sVar6` vs `short sVar2` |

## 4. 产物

- gates/: 5×projection + 5×bisect.txt（MATCH×5）+ final E2E 双语素
- name_resid.py（NAME 两亚族分类器）; curl/httpd {base,fix1,final}.c + .cmp + .pf
- curl_trace.stderr（RUGRA_NAMETRACE 序列探针, 探针代码已从 src 撤除）
