# Lane sb-f2string (DN 第四函数归因) — LANE REPORT 2026-09-23
branch wt/sb-f2string @ master 8fd23706 | commits: 4c53bfeb (fix) + 8573e087 (TODO)
oracle: Ghidra 12.0.4 e40ed130 | 投影 sha: curl.file2string.part.0.oracle.projection
  83a679cc8055852483f639a51e6a7a7ff30f5855648769f821666536441fa75d (340 stages/87957 ops)

## 首分歧与根因
- 首分歧: ord 76 universal:fullloop:mainloop:blockstructure count 1v4(round 0 第二次结构化)
- 根因(一句话): RuleLoadVarnode 自创 `create_with_space+set_varnode_properties` 组合绕过
  newVarnode 符号尾的 ScopeLocal 腿(database.cc:1268 先走本函数 scope), 栈 varnode 永不获
  addrtied → BlockBasic::isComplex(block.cc:2419) 少计语句 → ruleBlockOr 的
  orblock->isComplex() 守卫放行 oracle 拒绝的 OR 折叠 → negate 4v1 → 结构化分叉。
- 修复: ruleaction.rs RuleLoadVarnode→new_varnode_in_space;RuleStoreVarnode 补
  newVarnodeOut 三步(assignHigh+laned+ScopeLocal 腿 fold)。
- 修后: 首分歧 **76→178**(SB-F2STRING-ORD178-0001), negate census 10/10 逐 site 全等,
  feb8:1 flags 逐 stage 逐字同 oracle(0x1208000)。

## 三门禁(诚实)
1. curl E2E: defects=0/numbering=0 ✅;skeleton 2689→4072 ❌(+1383, 13 函数签名塌缩 raw 型,
   unaff_ 2→72)=下游暴露层 SB-F2STRING-ADDRTIED-PARAMRECOVERY-0001(P0, 先修或同批集成)
2. httpd E2E: defects=0 ✅;numbering 0→4 ❌(main 4 重复声明);skeleton 2331→4250
3. 双函数投影: next_url MATCH + match_url MATCH ✅ 保持
4. cargo test --lib: 串行 1650/18(总数=基线);config 域: 全面回退(见 lane 行)

## 结论
集成顺序建议: P0 SB-F2STRING-ADDRTIED-PARAMRECOVERY-0001 先修(或同批), 再并入 4c53bfeb;
否则 curl/httpd 文本质量回退不可接受。投影层证据(双侧探针)完整保留于
/dev/shm/rugra-tests/sb-f2string/(bisect1/2.json, rugra1/2.projection, oracle_run.stderr,
e2e_*.log, 探针脚本 patch_*.py + run_probe_oracle.sh)。
