# Heritage rename_direct 死锁诊断 (Phase 1 完成)

## 根因（已证实）

**`Heritage::rename_direct` 在 `destroy_varnode` 调用中死锁，不是性能问题。**

### 死锁链

1. **持有写锁**：`visit_rename_direct` 的 op 处理循环里
   `let mut op = op_ref.0.write().unwrap();` 持有 op#60 (BOOL_NEGATE) 的
   `RwLockWriteGuard`。

2. **触发 BTreeSet::remove**：循环内替换 inref 后，若 `vnin_arc.has_no_descend()`
   为真，调用 `vbank.destroy_varnode(&vnin_arc)`，其中
   `self.def_tree.remove(&VarnodeDefRef(vn.clone()))`。

3. **比较回调再读 op**：`VarnodeDefRef::Ord::cmp` (varnode.rs:1778-1781) 对
   WRITTEN varnode 取 `a.def.upgrade().read().unwrap().start.clone()`
   读取其 defining op。BTreeSet remove 遍历比较时，遇到 op#60 的 output varnode
   （其 `def` Weak 指向 op#60），尝试 `op#60.read()` → 同一线程在已持写锁时
   再读 → **死锁**（std::sync::RwLock 非重入）。

### 证据（myprogress, RUGRA_PERF=1）

```
[HA-OP] enter#1 op#60/61 opc=37 nin=1          ← BOOL_NEGATE
[HA-OP-IN] op#60 in#0
...
[HA-OP-IN-HND] op#60 in#0 no_desc=true         ← 决定销毁
[HA-DV-ENTER] loc_tree=1141
[HA-DV-LOC] done                               ← loc_tree.remove 完成
                                                ← def_tree.remove 永不返回
```

loc_tree.remove 能完成是因为 VarnodeLocRef::Ord 的 WRITTEN 分支也读 op
(varnode.rs:1727-1728)，但 BOOL_NEGATE 的 output 在 loc_tree 排序中可能不
参与比较路径（地址更小，先被剪枝）；而 def_tree 按 def SeqNum 排，必然要
比较到 op#60 的 output。

### 修复方向

**方案 A（推荐）**：在 op 写锁释放后再 destroy。每个 op 收集 to-destroy
varnodes，op 循环结束后统一 destroy。

**方案 B**：VarnodeDefRef::Ord / VarnodeLocRef::Ord 改用 Arc::as_ptr 比较 op
（不读锁）。但 SeqNum 字面值排序对 SSA 重要，指针排序会破坏 BTreeSet 顺序
不变量。

**方案 C**：换 parking_lot::RwLock（不支持重入但 upgrade/downgrade 更灵活）。
不解决根因——只是把死锁变成 panic。

选 A。

## 影响范围

7 个超时函数（myprogress, getparameter, glob_word, glob_set, glob_range,
glob_url, next_url）都有此模式：BOOL_NEGATE/比较 op + 其 input 被 SSA rename
promote 后无后代 → 触发 destroy_varnode → 死锁。
