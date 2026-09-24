# LANE REPORT — PRINTC-BOOLLITERAL-0001 (wt/boollit, commit 187d9cd5, base b25bce7a)

## 断点环节（一句话）
不在登记的三环节猜想（lift bool 装配/传播/打印门——打印门 printc.rs TYPE_BOOL 臂与 castInput 常量吸收臂均已在位），
而在 **DWARF 导入边界**：debugproto.rs resolve_type 把 `typedef bool→char`(curl.h:394) 物化为改名 char 克隆
(metatype INT/charPrint)，typedef-bool 的 11 个 Configurable 字段（showerror/use_resume/progressmode/crlf/
configread/nobuffer/passarg/usedarg/extraparam/stillflags）全印 1/0/'\x01'/'\0'。
Ghidra 侧 = DWARF 前端按名字把常规布尔 typedef 映射为布尔原语 → 核心对象 setCoreType("bool",1,TYPE_BOOL)
(sleigh_arch.cc:216) 经 getBase typecache(type.cc:3631-3638) 分发 → coreaction.cc:2687-2691 常量吸收 →
printc.cc:1769-1771 TYPE_BOOL 臂印 true/false。
修复 = TypeFactory::dwarf_conventional_bool(名字 {bool,_Bool}+核心形状门) + resolve_type typedef 分支
1-byte 门控调用（printc/coreaction 零改动）。

## 前提证伪（root 量化勘误，已写入 TODO 行）
236/263 vs 18/1 是全 golden(2010 函数) vs Rugra 32 函数门禁面的错配计数。门禁面内 golden true=17/false=2
vs Rugra 18/1——库级家族已近持平（httpd 剥离无 DWARF，本 lane 对其零影响=输出字节恒等）。
真实可收缺口在 curl 的 DWARF typedef-bool 字段族。"httpd 布尔行 −400" 不可达——该数字不存在。

## 词频前后（curl E2E）
- true: 7 → 13（golden 16）；false: 1 → 11（golden 18）
- 残差=家族 B（Java headless 分析器层,库级无对应物,direct-runner golden 同样印 '\0'/'\x01'）:
  config.remotefile(plain char,≈5 行)、bool[N] 栈数组(myprogress line/outline 等)。

## 三门禁（亲父 b25bce7a 亲测 A/B）
| 门禁 | 基线 | 修复后 |
|---|---|---|
| curl E2E vs ghidra_curl_1204.c | 1995/0/0 | 1927/0/0(−68; main −6, getparameter −62, 其余 122 函数逐个零回退) |
| httpd 门禁面 vs ghidra_httpd_1204.c | 2072/0/0 | 2072/0/0, 输出字节恒等 |
| httpd 全量 MAX_FUNCS=840 | — | panic=0 / TIMEOUT=0 |

## 四投影（RUGRA_MIRROR=1 正典 bundle, curl 驱动）
next_url / match_url / parseconfig.constprop.0 = MATCH×3 保持；myprogress = 继承亲父的
setcasts result/count 5v6 V1 分歧（形态不变，投影文件字节恒等于基线——注意:基线本就非 MATCH，
"四投影 MATCH 保持"的前提对 myprogress 不成立，sb-postadsorb 起同形）。

## 其它验证
- cargo test --lib：失败集全在基线家族（funcdata alignment+heritage，逐名无新增）
- gcc 审计 curl 104/20 == 基线；annotations/refs/机制A/门禁健康 hook 全绿

## 机制 C 声明
typefactory/debugproto 不在核心算法白名单；本 commit 非主管线 Action/Rule 语义
（printc/coreaction 零改动+四投影字节恒等为旁证）→ Cross-Review N/A，建议 root 集成时随对拍复核。
写域扩展已声明：debugproto.rs 在登记写域外，实证断点即在此（TODO 行已记录）。

## 遗留（家族 B，另行登记）
① remotefile/bool 数组 = Java Data Type Propagation 层，无库级对应物；② main 的 bVar3 第三赋值/bVar19
= main 结构族（骨架 diff 域,非打印门）；③ myprogress setcasts 5v6 投影分歧（继承）。

## 回收
产物目录 /dev/shm/rugra-tests/sb-boollit/（base/fix1 E2E 输出+四投影+commit_msg+libtest），
target 目录 /dev/shm/rugra-targets/sb-boollit 已清。
