# Agent Session Log Template (会话工程日志模板)

此文件用于定义 AI 助手在项目中进行迭代开发时的会话日志记录规范。每次开发会话结束时，必须在此目录中产生一份报告。

## 约定文件命名
`engineering_progress_YYYY-MM-DD_<topic>.md` （例如 `engineering_progress_2024-03-07_ssa_alignment.md`）

---

## 报告模板结构要求

### 会话元信息 (Session Meta)
- **日期时间**: YYYY-MM-DD HH:MM
- **核心意图**: （一句话总结本次会话旨在解决什么问题）
- **触及模块**: `src/...`

### 1. 代码变更与迭代 (Progress & Code Changes)
- 实现了哪些具体的算法、特性或函数。
- 修补了哪些缺陷。
- 是否对之前的代码进行了妥协或重构。

### 2. 架构推进与一致性审计 (Architecture & Alignment Audit)
- **文档同步确认**: 是否已按规矩更新了 `CURRENT_STATUS.md` 与 `ALIGNMENT_PROGRESS.md`。
- 本次代码实现，与原版 Ghidra 对拍的阶段成果（有没有跑通哪个验证点）。

### 3. 下一步干涉计划 (Next Steps / Blockers)
- 由于会话中断或技术阻塞，遗留给下一次会话、下一次 AI 的直接切入点与痛点描述。
    
