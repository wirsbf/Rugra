# Lane CAST-PARTIAL: castpartial — partial 免 cast 五臂（DV③）终报
Commit: 79b75978 (wt/castpartial, 基 master 521a99b8)
Oracle: Ghidra 12.0.4 e40ed130; golden: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c

## 分支语义一句话
CastStrategyC::castStandard 对 PartialStruct/PartialUnion 有五个免 cast 点
（req 侧无条件免 cast.cc:341-343 + curmeta 四点 cc:348-349/356-357/366-367/374-375
"partials ride the unknown-metatype whitelist"）；Rugra cast_standard_full
此前一处都没有，partial 片恒落 default 判"需 cast"。

## 交付
src/type_system/cast.rs: cast_standard_full 五臂齐补（1 req + 4 curmeta）；
CastStrategyJava 同形臂（cc:471+）不在 C 策略写域。新增测试
test_cast_standard_full_partial_no_cast（五臂 + 尺寸门/非指针 care 控制组）。
docs/api/type_system/cast.md 同步；TODO_BOARD CAST-PARTIAL-REQ-NOCAST-0001
→ ✅完成（含 SB-FINALCAST 范围修正记录的衔接）。

## main ②③行前后（curl E2E 字节级 A/B，before=pristine 521a99b8）
- ③ :775 `glob._296_8_ = (undefined8)uVar32` → **裸 `uVar32`**（golden 792 同形；
  uVar32/29 编号差属预存 skeleton 家族）——**目标达成**
- ② :729 `glob.pattern[8].content.Set.elements = (undefined8)in_stack_...fd90`
  → 裸 `in_stack_...fd90`（golden 746 为 `(char **)`——**方向收敛**：`(undefined8)`
  前缀已消，`(char **)` 生产方=UNIONRESOLVE-PIPELINE-WIRING-0001，域外）
- 连带 :774 `Set._8_8_` 行同消 `(undefined8)`（golden 791 值侧裸 ✅；
  字段路径 content.Set._8_8_ vs content._8_8_ 属 wiring 域）
- 全输出字节级 diff 仅此 3 行

## 三门禁
- curl: defects=0 numbering=0 skeleton **2563→2561**（唯 main 583→581；
  124 函数逐函数零回退，pristine 二进制 A/B 亲测）
- httpd: 0/0 **2333==2333**，输出字节级 before==after
- next_url **103==103** / match_url **54==54** 投影，函数体字节级 before==after
- cast 模块 9/9；全 lib --test-threads=1 **1656P/18F==预存家族**
  （funcdata×17+heritage×1）零新增；annotations/refs 门禁绿

## 未决
- ② 的 `(char **)` 与字段路径差 → UNIONRESOLVE-PIPELINE-WIRING-0001（P1，域外）
- DZ 报告中 match_url 76 与本 lane 54 的差异源于度量口径（--func 提取方式）；
  本 lane 判据为同命令 before==after，MATCH 保持
- 待 root 集成 + 全量门禁后回收 /dev/shm/rugra-targets/sb-castpartial
