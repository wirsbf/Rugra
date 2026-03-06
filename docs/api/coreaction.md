# `coreaction.rs` API Reference (核心行为反应流驱动器)

**源代码路径**: `src/coreaction.rs`

## 模块说明 (Module Doc)

本模组是对等于 Ghidra 内 `coreaction.hh` 与内建行为反应体系集的实现。
所谓 `Action` 是反编译管道分析流水线上的一枚枚离散独立的操作钩子或优化 Pass 任务。所有的诸如“构造控制图”、“剔除死去不再使用的微操”、“执行常量折叠”等动作，都会被包装成一个个**可以自由调遣与控制执行频次的策略对象**。

---

## 导出的公共 API (Public API)

所有列出的公开结构体全员无例外地都实现了 `crate::action::Action` Trait 这一唯一标准门面方法 `fn apply(&self, fd: &mut Funcdata) -> Result<i32>`，代表针对该函数的全局数据施展该变换大动作。

### 1. 静态单赋值图层转换系
*   **`pub struct ActionHeritage`**  
    名称: `heritage`  
    **作用**: 该行动组接管那些尚未完全梳理由原始物理机器码译过来的读写乱麻，负责在函数域的全局插入支配边界所需的 `MULTIEQUAL` (Phi) 控制结点并完成 `Varnode` 大规模多版本升阶构建！它是后续所有高级代数演算与类型分析的前提。

### 2. 代码剪枝裁剪系
*   **`pub struct ActionDeadCode`**  
    名称: `deadcode`  
    **作用**: 分析整座函数的 `obank` (操作树池)，扫清所有结果没有任何下游 `descend` 接盘消费且不具备副作用保护（如函数执行打印、越界、抛出等）的指令群，并将废弃点置入亡者树 (`deadlist`) 清扫。它每改变/删除过代码就会反馈状态 `CHANGE`，要求流水线再次迭代检查死血。

### 3. 常量折叠沉淀系 (WIP)
*   **`pub struct ActionConstantPtr`**  
    名称: `constantptr`  
    **作用**: 对那些本意是获取常量池数据或直接操作全量硬编码大地址进行提前固化和解构的提取特判行动。
*   **`pub struct ActionCse` (Common Subexpression Elimination)**  
    名称: `cse`  
    **作用**: **公共子表达式消除行动**。极高阶的代数树分析规则，用来防止多次发生同样的庞杂运算堆叠重复。

*(提示: 每个具体执行组件被执行反馈的信号包括 `action_status::CHANGE` 用于昭告函数本身在刚刚的一趟里发生过改变，以此提醒需要继续回滚套用上游的判定流组来确保稳定性。这也是 Ghidra Action Rule 流转的核心理念模型！)*
