# Lane BD — DETERM-COPYTRIM-0001 + DETERM-DOMINANTCOPY-0001 修复报告

- 日期: 2026-09-22
- 工作目录: /home/ls/Rugra-wt-sb-detcopytrim (wt/sb-detcopytrim, base=5b3391f)
- Commit: **e2c627c** `fix: deterministic iteration for copy-trims and dominantcopy domain`

## 1. 根因(单一调用点,双 ID 同源)

Ghidra `ActionDominantCopy::apply`(coreaction.hh:1008)是单行委托
`data.getMerge().processCopyTrims(); return 0;` ⇒ AZ drill 的
"universal:dominantcopy 工作集漂移"与 AX 的输出 bimodal **同根因**:
`Merge::process_copy_trims` 内 ptr-keyed `HashMap::into_iter()` 驱动
`process_high_dominant_copy` 处理序 → 同一 dom 块内多个 dominant COPY 的
插入序(SeqNum 相对顺序)每 worker 进程随机。

## 2. 修复(只改遍历确定性,零语义变更)

merge.rs `process_copy_trims` 镜像 merge.cc:1418-1435:
- 遍历 `copy_trims` **列表序**;HighVariable 首见即 push 进 `first_seen`
  Vec(= cc:1423 `multiCopy.push_back` + cc:1424 `setCopyIn1`);
- 后续出现仅 `counts[key] += 1`(= cc:1427 `setCopyIn2`);
- `copy_trims.clear()` 移至两循环之间(= cc:1429 原位,原先在末尾);
- `first_seen` 序中计数 ≥2 的 high 依次 `process_high_dominant_copy`
  (= cc:1430-1435 `hasCopyIn2()`);
- HashMap 仅 keyed 计数查找,绝不迭代(纪律同 merge.rs:2197-2209)。

coreaction.rs `ActionDominantCopy`:无容器行为变更(oracle apply 本身无
自身容器);更正过期 "faithful no-op/copyTrims never populated" 注释
(snip 链路 2026-07-04 已接 merge_addr_tied)。

附带卫生:examples/curl_decompile.rs 驱动 payload(symbol/string/prototype
entries)collect 后按地址 sort(消除 driver 级随机请求序通道)。

## 3. 实证证据(AX 验收标准)

### 3.1 修复前(受控 baseline,base=5b3391f 干净树,/dev/shm/rugra-baseline-wt)
6 连跑: **3× 2ff151b6 + 3× d46404c2**(硬币分布,AX 双值复现);
两 variant 差异 = getparameter_constprop_0 单条语句位移:
```
2347d2346 <     uVar27 = uVar25;
2348a2348 >     uVar27 = uVar25;
```

### 3.2 修复后(fast-release,同机连跑)
**12/12 全部 `d46404c22ec9292ccdc22125eaf26a0aa8c70a321d9fd213ac81f2848a4af0b0`**
(12 run 产物: run1..12.out 本目录;locus 2347-2348 行 12 run md5 单值)

### 3.3 零附带输出变化
修复后 run1.out 与修复前 d464 variant(pre1.out)**字节相同**(cmp 通过)
⇒ 修复 = 纯序钉死;examples payload sort 输出零变化(worker 侧 keyed 消费)。

## 4. 差分门禁(机制 B,curl 124 函数全量)

| 指标 | 值 |
|---|---|
| defects | **0** ✅ |
| numbering | **0** ✅ |
| skeleton | 3693(修复前两 variant 同为 3693 → **修复零 skeleton 移动**)|
| gp 函数级(--func getparameter.constprop.0) | 855/0/0(gp=855 与 TODO_BOARD 记录一致)|

## 5. oracle 序可比性(如实)

- gp locus A/B 对:golden 同源区域语句/变量状态结构性不同
  (oracle: local_5b8/statbuf/time/curl_getdate;Rugra: uVar27/uVar32/__xstat)
  → 该对文本级 oracle 对照**不可比**(属既有分歧域,另行 TODO)。
- next_url 标准路径:golden 含 `Type propagation not settling` 告警 +
  不同变量集(TOP3_PAIRING 的 next_url 字节相等是 mirror 态 env
  (FLOW_MIRROR/BARE_LOAD/ORACLE_FIXTURE_DATA)下另一 lane 的口径)→ 不可比。
- 结论:oracle 序等价性由 merge.cc:1418-1435 逐行语义镜像保证
  (commit message `## Alignment Evidence` 四类核对),运行态 gp/next_url
  投影对照留待 mirror 态环境(root 决定)。

## 6. 未决问题(移交 root)

1. **TODO_BOARD "skeleton 3685→3694" 对账**:本树(5b3391f=集成后+docs)
   修复前后两 variant 全为 3693;root 记录的 3694/sha ad0e4170 既非 2ff1
   也非 d464,且 ad0e4170 归档已被并发 lane 于 03:52 覆盖
   (result/curl_cur.c 现为 bd3705ac,skeleton=3371,系 master 新代码)。
   需 root 在集成时重钉正式 baseline。
2. merge.rs = 机制 C 白名单 → **Cross-Review: PENDING**(root 集成前)。
3. DETERM-COPYTRIM-0001 / DETERM-DOMINANTCOPY-0001 的 TODO_BOARD 登记
   (含本报告证据 commit e2c627c)由 root 执行。

## 7. 文件清单

- run1..12.out/.err(修复后 12 连跑)/ baseline/pre1..6.out(修复前 6 连跑)
- next_url.{rugra,oracle}.c + next_url.diff(157 行,既有分歧证据)
- FIX_REPORT.md(本文件)
