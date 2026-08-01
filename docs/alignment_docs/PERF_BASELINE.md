# 性能瓶颈定位报告 (Phase 1 — 基线测量)

**生成时间**: 2026-07-27
**结论修正**: 之前推测的 RwLock 性能瓶颈**不是**真正的根因。真正的根因是
`Heritage::rename_direct` 的算法性死循环/爆炸。

## 测量方法

在 `ActionGroup::apply` / `ActionPool::apply` / `ActionHeritage::apply` /
`ActionRestartGroup::apply` 加入 `eprintln!("[PERF]/[CHILD]/[HA-...]")` 时间戳
(env `RUGRA_PERF=1` 触发)。在 `examples/curl_decompile.rs` 加 `RUGRA_PERF_FUNC`
单函数过滤。运行 `cargo run --release --example curl_decompile`。

## 基线数据 (release build)

```
=== Summary: 17 functions decompiled, 7 skipped/failed ===

TIMEOUT 函数:
  0x34d0: myprogress
  0x3f00: getparameter.constprop.0
  0x4a60: glob_word
  0x4bc0: glob_set
  0x4d60: glob_range
  0x4f70: glob_url
  0x4ff0: next_url
```

## 关键发现 — 卡点定位

### 错误推测 (已排除)

- ❌ RwLock kernel overhead (~10μs/op × 300K ops = 3s+)：main (2987 ops) 在 353ms 完成；若 RwLock 是瓶颈，main 应最慢
- ❌ Rule 乒乓：ActionPool apply() 从未超 22ms
- ❌ mainloop 非收敛：ActionGroup perform() 有 lcount>=count 守卫

### 真正卡点 (已证实)

**`ActionHeritage::apply` → `Heritage::rename_direct` 卡死**。

证据 (myprogress, RUGRA_PERF=1 RUGRA_PERF_FUNC=myprogress)：
```
[CHILD] 36/61 myprogress decompile.fullloop ...
[CHILD] 1/10  myprogress fullloop.mainloop ...
[CHILD] 1/25  myprogress mainloop.varnodeprops ...
[CHILD] 2/25  myprogress mainloop.starttypes ...
[CHILD] 3/25  myprogress mainloop.heritage ...
[HA-ENTER]    myprogress pass=0           ← 进入 ActionHeritage
[HA-PHASE]    myprogress pass1 place_multiequals → 0ms   ← phi 放置完成
                                                       ← rename_direct 永不返回
```

place_multiequals_direct 在 0ms 完成（phi 节点已建好），但 `rename_direct`
进入后**永不返回**——这是算法性死循环或指数爆炸，**不是锁开销**。

## 推断的可能原因

1. **dom-tree 循环**：rename_direct 沿 dom-tree 递归，若 dom-tree 有循环（已知
   `build_dom_subtree` 可能因 idom 自引用产生环），递归永不终止。已有 visited
   HashSet 保护（commit 24221cd），但可能未覆盖所有路径。

2. **VariableStack 爆炸**：rename 用 dominator-tree 顺序维护 VariableStack，
   若某个变量被反复 push 不 pop，栈无限增长。

3. **opSetInput 反复触发 erase_descend**：rename 修改 op 输入，可能触发连锁
   重写（已知 erase_descend 警告大量出现）。

## 修复方向

读 Ghidra heritage.cc 的 `rename` / `renameInBlock` / `renameBaseDown` 算法，
对比 Rugra `rename_direct` / `visit_rename_direct`，找出口条件缺失或栈管理
错误。
