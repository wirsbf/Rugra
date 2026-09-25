# Lane SB-JOINSTOP 终报 — PARSECONFIG-JOINBLOCK-STOPADDR-0001(P1)

- worktree: /dev/shm/rugra-worktrees/joinstop, branch wt/joinstop
- commit: **b1bbe151**(parent 6b4ca15a = master),tree clean,hooks 全绿(annotations/refs/机制 A 4/4)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b(亲核 HEAD ✓)
- 写域遵守:src/funcdata.rs + docs/api/funcdata.md + docs/TODO_BOARD.md(行 613 收尾)

## 修复形态(= DS 已证明补丁原样,无变体)

`Funcdata::node_join_create_block`(src/funcdata.rs:3253)在
`set_flags(JOINED_BLOCK)`(对应 cc:785)之后、任何 edge 手术之前补:

```rust
newblock.write().unwrap().as_any_mut()
    .downcast_mut::<crate::block::BlockBasic>()
    .expect("nodeJoinCreateBlock: newblock must be a BlockBasic")
    .set_initial_range(addr, addr);   // oracle funcdata_block.cc:786
```

载体=已有 BlockBasic::set_initial_range(block.rs:2347,对应 block.cc:2625)。
附带卫生:函数头 `// Ghidra:` 790→779(定义起始行);边删除段注释误引
merge.cc:807-818→funcdata_block.cc:789-805。Ghidra 全库 f_joined_block 唯一
设置点=cc:785(Rugra 唯一 set_flags 点同修,无第二处遗漏)。

## 验收(全过)

| 项 | 结果 | 基线 | 判定 |
|---|---|---|---|
| parseconfig.constprop.0 投影 bisect | **MATCH**(335 stages/130099 ops,oracle pin b2ace56a) | 首分歧 320 | PASS(A/B 后二次复跑仍 MATCH) |
| next_url 投影 bisect | **MATCH**(335/96457) | MATCH | PASS 保持 |
| match_url 投影 bisect | **MATCH**(340/80385) | MATCH | PASS 保持 |
| curl E2E compare | **2585/0/0**,C 文本字节级==基线 | 亲父 6b4ca15a 亲测 2585/0/0 | PASS 零回退 |
| httpd E2E compare | **2333/0/0**,C 文本字节级==基线 | 亲父 6b4ca15a 亲测 2333/0/0 | PASS 零回退 |
| gcc 语法审计 | 82 OK/25 FAIL == 基线(同 C 文本) | 82/25 | PASS |
| cargo test --lib funcdata | 单线程 17 failed==master 逐字 | 17(DS 记录) | PASS(并行批跑 17↔23 波动=既有噪声,3 个 *_alignment* 波动用例单跑全过) |

A/B 方法:git checkout funcdata.rs→重建→基线 run→git apply 补丁→sha256
逐字节复原(ae247f7d…)→重建→终态复验(parseconfig MATCH 重证)。
注:主仓 result/curl_cur.c 归档(12:14)产自 56f88fb2(DX 车道并入后),
其 glob_url 变量形态差异属 DX 变量映射,与本修复无关。

## 机制 B2 状态

parseconfig.constprop.0:真实 oracle 行为门禁 **MATCH**(本 commit 起);
next_url/match_url:双 MATCH 保持。正式 tests/oracle fixture 挑拣留 root。

## 未决(移交 root)

1. 本 commit 待并入 master(wt/joinstop → master,root 串行集成)。
2. DS 遗留#2(condconst MULTIEQUAL 臂 out.is_addr_tied() 附加条件)不受本
   修复影响,维持原登记。
3. 批跑 funcdata 测试 17↔23 并行噪声为既有现象(master 同在),建议另行
   登记测试基建 TODO(非本车道写域)。

## 归档清单(/dev/shm/rugra-reports/sb-joinstop/)

bisect_{parseconfig,next_url,match_url}.log(全 MATCH)、
parseconfig.rugra.recheck.proj(修复态投影)、commitmsg.txt、joinstop.patch、
curl_fixed.c、funcdata_failures_{base,fixed}.txt、LANE_REPORT.md(本文件)。
/dev/shm/rugra-targets/sb-joinstop 已自清。
