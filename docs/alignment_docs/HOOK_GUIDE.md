# Edit-Before-Read Alignment Hook (铁律 5.5/6 强制机制)

> **目的**: 强制执行 AGENTS.md 铁律 5.5/6 —— "修改一个函数的代码前, 必须重新先看
> 对应的 Ghidra 函数代码"。防止 agent "声称对齐但实际没读对应行" 的自欺
> (2026-07-02 `181538f` 事故的根因模式)。

## 机制概览

三层强制, 互为冗余:

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1 (运行时, 主): PreToolUse hook on Edit|Write|MultiEdit  │
│   .zcode/align_gate.py                                          │
│   编辑 src/*.rs 前拦截: 该 fn 的 // Ghidra: file:line 引用必须   │
│   有"本 session 读过"的回执, 否则 deny (exit 2).                │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2 (自动回执): PostToolUse hook on Read                    │
│   .zcode/record_receipt.py                                      │
│   agent 每读一个 Ghidra cpp 源文件, 自动写入回执到               │
│   .alignment_receipts.json (key=ghidra相对文件名, val=ts+ranges) │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3 (commit 兜底): pre-commit hook                          │
│   rugra/.githooks/pre-commit → tools/check_ghidra_refs.py       │
│   commit 时校验所有 // Ghidra: 引用的 file:line 真实存在          │
│   (抓"行号漂移/伪造引用"; advisory 模式, --strict 升级硬门禁)    │
└─────────────────────────────────────────────────────────────────┘
```

## 配置位置 (逆向 ZCode 二进制确认)

ZCode CLI 的项目级 hook 配置在 **`<project>/.zcode/config.json`** (不是
`settings.json`!)。schema (来自 `app.asar` `out/host/index.js`):

```jsonc
{
  "hooks": {
    "enabled": true,                    // 顶层总开关, 必须为 true
    "events": {
      "PreToolUse": [                   // 支持的事件: SessionStart,
        {                               //   UserPromptSubmit, PreToolUse,
          "matcher": "Edit|Write|MultiEdit",  //  PermissionRequest,
          "hooks": [                    //   PostToolUse, PostToolUseFailure,
            {                           //   Stop
              "type": "process",        // ← 注意: "process", 非 "command"
              "command": "python <abs path>"
            }
          ]
        }
      ]
    }
  }
}
```

**关键差异 (与 Claude Code 原版)**:
- 文件名是 `config.json` (zcode source) 或 `settings.json` (legacy/claude source)
- ZCode 格式 hook 条目用 `type: "process"`, Claude 格式用 `type: "command"`
- 事件放在 `hooks.events.<EventName>` (zcode) 或 `hooks.<EventName>` (legacy)

## Hook 输入/输出契约 (逆向 zcode.cjs 确认)

### stdin payload (PreToolUse on Edit)
```json
{
  "hook_event_name": "PreToolUse",
  "session_id": "sess_...",
  "tool_name": "Edit",
  "tool_input": { "file_path": "...", "old_string": "...", "new_string": "..." },
  "tool_use_id": "...",
  "cwd": "...",
  "timestamp": "..."
}
```

### 阻断编辑 (deny) —— 两种等价方式
1. **stdout JSON** (结构化, 推荐):
   ```json
   {"hookSpecificOutput":{"hookEventName":"PreToolUse",
     "permissionDecision":"deny",
     "permissionDecisionReason":"...原因..."}}
   ```
2. **exit code 2 + stderr 文本** (兜底, `Gcn()` in zcode.cjs 会把 stderr
   文本当作 deny 原因): 最可靠, 即使 JSON 路径不被 honoring 也能阻断。

`align_gate.py` 两种都发 (belt-and-suspenders)。

## 回执新鲜度语义

- **session 级**: 一次 read 覆盖该 fn 在**同一 session** 内的所有后续编辑。
  这是对 "每次修改前必须重新看" 的实用化 —— 强制每个新 session 重读
  (防止跨 session 的 Ghidra 记忆陈旧), 同时不折磨 agent 在一次 read 后做
  多次相关编辑。
- `.alignment_session_start` 文件由 SessionStart hook (`align_gate.py --session-start`)
  打时间戳。回执 ts 必须 >= 该时间戳才算 fresh。
- 若 PostToolUse hook 未生效 (旧 session), agent 可手动
  `python .zcode/record_receipt.py coreaction.cc 4886 4960` 补回执。

## 哪些 fn 会被 gate

`align_gate.py` 对**受编辑影响的 src/*.rs fn**, 找其 Ghidra 对应位置:
1. fn 上方注释块的规范 `// Ghidra: <file>:<line> <fn>` 标注; 或
2. fn body 内首个 `// ... <file>.<cc|hh>:<digits> ...` 内联引用
   (覆盖本代码库的 `(coreaction.cc:4886)` 风格, 302 处)。

无任何 Ghidra 引用的 fn → 不 gate (由 `check_ghidra_annotations.py`
在 commit 时强制要求加注释)。`// RUGRA-GLUE:` 标注的 fn → 豁免。

## 紧急逃生

`ZCODE_ALIGN_GATE=0` 环境变量禁用 gate (临时, 应记录理由)。
git commit 仍可用 `--no-verify` 跳过 (但会失去所有对齐门禁保护)。

## ⚠ 重要: 配置仅在新 session 加载

ZCode 在 **session 创建时** 加载 `.zcode/config.json` (一次)。若在 session
中途添加/修改 hook 配置, **当前 session 不会生效**, 必须重启 session
(或 clear/compact 触发 SessionStart) 后才生效。

验证 hook 已加载: 重启后做一次 src/*.rs 编辑, 若被 deny (且你没读对应
Ghidra), 即生效; 也可查 `.zcode/align_gate.log` 是否有新条目。

## 文件清单

| 文件 | 作用 |
|---|---|
| `.zcode/config.json` | hook 配置 (PreToolUse + PostToolUse + SessionStart) |
| `.zcode/align_gate.py` | PreToolUse gate + SessionStart 打戳 |
| `.zcode/record_receipt.py` | PostToolUse 自动回执 + 手动补回执 |
| `.alignment_receipts.json` | 回执存储 (gitignore, 不入库) |
| `.alignment_session_start` | session 起始时间戳 |
| `tools/check_ghidra_refs.py` | commit 时引用有效性校验 |
| `rugra/.githooks/pre-commit` | pre-commit hook (接入 check_ghidra_refs) |
