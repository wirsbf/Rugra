# `action.rs` API Reference (分析行动框架与调度中心)

**源代码路径**: `src/action.rs`

## 模块说明 (Module Doc)

对应 Ghidra `action.hh`。定义了反编译分析管道的**插件式行动框架**。所有的分析步骤（SSA 构造、死代码清理、结构化恢复等）都实现同一个 `Action` Trait，由 `ActionDatabase` 统一注册调度。
此外还定义了 `Rule` Trait 用于小粒度的单操作码优化规则。

---

## 导出的公共 API (Public API)

### `pub trait Action` (分析行动基元)

所有反编译分析动作的**统一接口契约**：
*   `fn apply(&self, fd: &mut Funcdata) -> Result<i32>`: 执行分析。返回 `action_status::CHANGE` 表示做了修改，`NO_CHANGE` 表示无事发生，`RESTART` 表示需要重头再来。
*   `fn get_name(&self) -> &str`: 行动的标识名称（用于日志和调度查找）。

### `pub trait Rule` (微观优化规则基元)

针对特定操作码的小粒度代数化简规则：
*   `fn apply_op(&self, op: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32>`: 针对**单条**微操的局部化简尝试。
*   `fn get_opcodes(&self) -> Vec<OpCode>`: 声明该规则关注哪些操作码（调度器据此仅在匹配的操作上触发此规则）。

---

### `pub struct ActionGroup` (行动组/批处理容器)

将多个 `Action` 打包为一个可被嵌套调度的组合执行体。执行时按注册顺序依次调用每个子行动并累计变更计数。

### `pub struct ActionDatabase` (全局行动注册库)

管理并查询所有可用的分析行动。
*   `pub fn set_default_actions(&mut self)`: 一键注册标准反编译管道的默认行动序列：`ActionStart` → `ActionHeritage` → `ActionConstantPtr` → `ActionCse` → `ActionDeadCode` → `ActionBlockStructure` → `ActionNormalizeBranches` → `ActionFinalStructure`。

### `pub mod action_status` (执行状态码)

*   `NO_CHANGE = 0`: 管道无扰动通过。
*   `CHANGE = 1`: 有修改发生，应当重新迭代前序检查。
*   `RESTART = 2`: 请求完全回滚重启管道。
