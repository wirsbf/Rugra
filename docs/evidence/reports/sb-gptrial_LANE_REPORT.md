# Lane DK 终报归档 — GETPARAM-ACTIVEPARAM-TRIAL-0001

- worktree: /home/ls/Rugra-wt-sb-gptrial, branch wt/sb-gptrial
- commit: **1b968722** (parent 8fd23706 = master), tree clean
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- getparameter oracle projection pin: sha256 4464f2ff… (tests/oracle/stage_projection_1204.metadata.json functions[curl/getparameter.constprop.0])
- 复跑时间: 2026-09-23 (revival 收尾轮)

## 根因(一句话)

rugra `Funcdata::check_call_double_use` 对未 checked 的对端 trial 无条件
`return true`(旧 RUGRA-GAP),而 Ghidra
funcdata_varnode.cc:1789-1790 在 `TraverseNode::isAlternatePathValid(vn,fl)==true`
时 `return false` → onlyOpUse res=false → RSI trial markInactive;
缺此拒绝使 getparameter CALL@4151:20a(strequal@plt) 的 RSI register:38 trial
误 active → fillinMap markUsed → buildInputFromTrials 保留 u:23e00
(投影 ord 55 activeparam op-idx 953 分歧)。

## 双探针证据(修复前)

- oracle probe: /dev/shm/rugra-tests/sb-gptrial/probe/(archive 树 stderr 插桩,
  仅 stderr,projection 体与 pin 4464f2ff 逐字节同——run.stderr / run2.stderr)
  - RSI trial 判定: `call=4151:20a slot=5 vn=register:38 B(ck=0,ac=0,kb=1)
    A(ck=1,ac=0,ar=1,so=1)` = markInactive(ar/so 与 rugra 相同,ao 分叉)
  - 关键行: `[DOUBLEUSE-DBG] op=46db:2e4 match=4151:20a j=5 ck=0 ac=0 alt=1`
    → cc:1789-1790 isAlternatePathValid=true → return false
- rugra probe(修复前): RSI trial `ar=Some(true) ao=Some(true)` → mark_active;
  stack:fa40 trial 被交叉翻转 ao=Some(false)

## 门禁复跑数字(revival 轮,commit 1b968722)

| 门禁 | 数字 | 基线(亲父 8fd23706) | 判定 |
|---|---|---|---|
| cargo build --release 两 example | 5m02s 完成,0 error | — | PASS |
| curl E2E compare | skeleton 2689 / defects 0 / numbering 0 | 2689/0/0 | PASS(恒等) |
| httpd E2E compare | 2331 / 0 / 0 | 2331/0/0 | PASS(恒等) |
| getparameter Phase 2 | 首分歧 ord 55→**65**,ord 1-64 identical | (修前 55) | PASS(后移) |
| next_url Phase 2 | MATCH(335 stages, snapshot identical) | MATCH | PASS(保持) |
| match_url Phase 2 | MATCH(340 stages, snapshot identical) | MATCH | PASS(保持) |
| config 域 | getparameter 逐字节同基线;main 621/match_url 76/helpf 81 不变 | 同 | PASS(零回退) |

- getparameter 新首分歧: **ordinal 65**
  `universal:fullloop:mainloop:stackstall:oppool1`
  `V1_RESULT_COUNT_DIVERGENCE` result/count oracle 740 vs rugra 734
  (ruleaction/oppool 计数域;已登记 docs/TODO_BOARD.md `GETPARAM-OPPOOL-COUNT-0001`)

## 产物清单(本目录)

- curl_full.log / httpd_full.log(+ .stderr)— 全量 E2E
- getparam_final.projection + getparam_final_bisect.txt
- next_url_final.projection / match_url_final.projection + *_final_bisect.txt
- probe/ — oracle 插桩探针(build_probe.sh/build_probe2.sh/trialuse_probe_1204/
  locked-cpp archive/run.stderr/run2.stderr/projection*.txt)
- trialuse*.stderr — rugra 侧 trial 判定 trace(修复前)
- funcdata_fix_backup.rs — 修复版源备份

## 未决(移交 root)

1. `GETPARAM-OPPOOL-COUNT-0001`(新排队): ord 65 oppool1 计数 740 vs 734。
2. fspec 域 root 快速复核 + Differential 基线亲父实测(funcdata.rs 非白名单,
   本 lane 三门禁全零;commit 已带 ## Alignment Evidence 4/4)。
3. 只读发现未动(不在 write-set): check_input_trial_use 栈路径缺
   fspec.cc:5618-5625 的 getLocalRange().inRange 与 callee_pop 守卫
   (本函数 ord 1-64 identical 证明未触发;建议 root 登记)。
4. funcdata:: 批量测试 17 个 order-dependent 失败在 master 既有(单跑通过)。
5. 机制 B2 正式 tests/oracle fixture 按 RAM 盘约定留 root 集成挑拣。
