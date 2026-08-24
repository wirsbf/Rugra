# hugehelp / progressbarinit / my_fwrite 对齐交接（2026-08-24）

## 0. 停止点

用户要求停止当前实现并交给下一位开发者。本文件记录停止时的可复算状态；这里没有把“骨架改善”写成完成。

- 主线：`1cda523d7aba2aa7bd393e2e1492bcad85b86eed`
- 主线 tree：`08c7ebd3034900c2084561e10529516350eaed57`
- 锁定 oracle：Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`
- 三个目标函数严格字节一致：**0/3**
- 已停止所有本轮子 Agent；当前无 Cargo/rustc 进程，`/tmp/rugra-cargo-build.lock` 空闲。
- 主工作区原有 6 个中央文件仍为未提交状态，属于此前连续性/registry 工作：
  `ALIGNMENT_ROADMAP.md`、`docs/TODO_BOARD.md`、
  `docs/alignment_audit/{DEPENDENCY_DAG.json,FUNCTION_LEDGER.json,FUNCTION_MAP.generated.md}`、
  `tests/oracle/fixture_registry.json`。**不要 restore/reset/stash 或整批 add。**

## 1. fresh 主线反编译基线

不要使用仓库中的 `result/curl_cur.c`；它是陈旧快照。停止前从不可变提交 `f7b3c31`
（与当前 HEAD 仅相差一条 TODO 文档提交，production 字节相同）做了 release 构建并单次运行：

- artifact 根：`/home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/`
- C 输出：`curl.stdout.c`
- C 输出 SHA-256：`fc9a33baaab1310929b78b508b27f6810fd5e2eca7da80bf17d2a584e91d60e7`
- stderr SHA-256：`9ed73fe7d9416728dc1feb6c277e4f9d5b0d366cb5ee6ae05962f14550158527`
- build 和 run 均 exit 0；stdout/stderr 分离。

按 `tools/compare_ghidra.py` 的函数匹配与 skeleton 口径：

| 函数 | 当前 body | Ghidra body | skeleton diff | 严格字节 |
|---|---:|---:|---:|---|
| `hugehelp` | 281 B，SHA `b19410b4…0830` | 6725 B，SHA `67c311f8…386c` | 18 | MISMATCH |
| `progressbarinit` | 522 B，SHA `cd718a4b…4870` | 402 B，SHA `f97c77bf…3dcb` | 20 | MISMATCH |
| `my_fwrite` | 236 B，SHA `35fa298b…3726` | 370 B，SHA `2c3f0e59…0c18` | 16 | MISMATCH |

当前关键输出形态：

```c
/* hugehelp */
puts(0x7180); puts(0x99a8); puts(0xc1d8);
puts(0xea40); puts(0x11270); puts(0x13ad0);

/* progressbarinit */
*bar = 0;
bar->prev = 0;
curl_getenv(0x626a);
/* width store still becomes seven nested ->total dereferences */

/* my_fwrite */
undefined8 uVar1;
long uVar_8f00;
if (*((FILE *)uVar_8f00) != (FILE *)0x0 || pFVar_0 != (FILE *)0x0) {}
fwrite(buffer, size, nmemb, stream);
return;
```

全局严格统计的最近已复核口径记录在 `CURRENT_STATUS.md`/`e0b20e1`：123 个可比块中
52 个严格相同，但其中 48 个是 synthetic import stub；75 个真实内部函数仅
`GetStr`、`main_free`、`__libc_csu_fini`、`_fini` 四个相同。不要把 compare 工具的 skeleton `✓`
当作逐字节 MATCH。

## 2. 已经安全合入的地基

这些提交已进主线，不能回退：

| 机制 | 主线提交 | 已证效果 / 状态 |
|---|---|---|
| shared-return flow override | `33793c1` | `hugehelp` 恢复第 6 个 puts/return；`progressbarinit` 恢复 free/return |
| mergeAddrTied gates | `e9a0b7a` | `progressbarinit` 把 getenv/strtol/free 合并错误分离为 `extraout_RAX`；`my_fwrite` 仅小幅改善 |
| LOAD/STORE pointee width gate | `92daed3` | `progressbarinit` 去掉 `0.total` 污染；`my_fwrite` 临时变量爆炸显著减少；窄 B2 MATCH、overall MISMATCH |
| TypeFactory canonical foundation | `594ed4f` → `874e81f` → `23ef9c9` → `651045a` | layout、array/partial/pointer tree、`getExactPiece` traversal；overall MISMATCH |
| TypeFactory bilateral fixture | `cf3b10b` | 32 records：30 byte-identical，46 个显式 allowlist 差异；独立 APPROVE，仍非 L3 |
| stable callspec identity D0 | `cad41c2` | stable Arc owner、typed Weak annotation、sort/delete/clone identity；7-record covered projection MATCH，overall MISMATCH |
| D0 commit pin | `f7b3c31` | TODO 记录真实集成 hash |
| exact-piece caller claim | `1cda523` | 新稳定 ID `TYPEFACTORY-EXACTPIECE-CALLERS-0001` 与精确租约 |

重要历史候选：

- `fbf326600ed31fcbfbf593020bbab6accb096124`：PrintC pointer-to-char constant 窄 fixture
  14 条 MATCH，但 production 无 adapter，curl A/B 为零变化；可作为后续地基，不可宣称修好 `hugehelp`。
- `c4e5ecf033995484b18859240b6db11b79d9d255`：旧 SplitDatatype gate 实验，**禁止集成**。
  它有非 Ghidra apply guard、本地复制 exact-piece、没有合格 B2；只保留其 A/B 根因证据。

## 3. 每个函数剩余根因与正确顺序

### 3.1 `hugehelp`

当前 Flow 已恢复 6 个 puts；剩余不是单纯 printer 格式问题。

1. `TYPEOP-LOCALTYPE-DISPATCH-0001` D1：
   `TypeOpCall::getInputLocal` 必须从 input0 的 typed callspec Weak 读取同一 prototype，按 `slot-1`，
   type-lock 分支优先，`nonvoid && param.size <= input.size`，this 仅 PTR→STRUCT，否则返回同一
   Architecture TypeFactory 的 canonical UNKNOWN。Ghidra `typeop.cc:687-718`；Rust当前入口
   `src/typeop.rs` 的 TypeOpCall。
2. D2 Action caller：当前 `ActionInferTypes::build_localtypes` 只特殊播种 CALL output，未让 CALL
   inputs 经过 TypeOpCall local dispatch。必须在 D1 后单独做真实 Action fixture；不要用名称或地址表旁路。
3. Program Database / SymbolEntry / readonly loader：`ActionConstantPtr` 必须在 Action 阶段经
   `queryContainer`/`spacebaseConstant` 建 PTRSUB；晚期 printer 不能补造这个 IR。
4. `RulePtrsubCharConstant` 与 PrintC 必须共用 Architecture-owned、Address-keyed、正/负都缓存的
   StringManager。非法字节 0x7180/0x99a8/0xc1d8 保留 PTRSUB 并打印 `&DAT_*`；合法
   0xea40/0x11270 折回 typed constant 并打印字符串；0x13ad0 同样走真实数据判定。

### 3.2 `progressbarinit`

最早剩余分叉已由只读审计重新确认：

1. PTRSUB：Ghidra `TypeOpPtrsub::propagateType` (`typeop.cc:2366-2378`) 只做 input→output，
   经 `propagateAddIn2Out` (`1215-1253`) 和 `TypePointer::downChain` (`type.cc:1084-1121`)
   得到字段 pointer/PointerRel。Rust生产 `src/coreaction.rs` 仍把整个 `ProgressData *` 原样传播，
   已有 `TypeFactory::down_chain` 目前没有 production caller。
2. STOP：`RuleStructOffset0` 已设置 op 的 STOP flag，但 Rust `stops_type_propagation()` 没有消费者。
   Ghidra `Varnode::getLocalType` (`varnode.cc:900-936`) 在 def 上消费 STOP，返回 local type并置
   `blockup`；`ActionInferTypes::buildLocaltypes` (`coreaction.cc:5008-5037`) 再设 varnode
   stop-up flag。Rust `Varnode::get_local_type` 仍是未接线 stub，也没有 0x800 stop-up flag。
3. 当前最终 C 两个 width store 都恰有 7 层 `->total`，与 ActionInferTypes 7-pass cap 相符；
   但没有逐轮 IR，因此不要声称已直接观察到“每轮新增一层”。
4. STOP 完成后再闭合 SplitDatatype、SetCasts、PrintC half-open field lookup；不要先在 PrintC 抹平坏 IR。

### 3.3 `my_fwrite`

TypeFactory canonical `getExactPiece` 已存在，但 production 尚未全部使用。全仓四处本地替代路径：

1. `HighVariable::finalize_datatype`（`variable.cc:551-566` / `src/variable.rs`）；
2. `SymbolEntry::get_sized_type`（`database.cc:151-162` / `src/database.rs`）；
3. `Funcdata::sync_varnodes_with_symbols` 经 sized type（`funcdata_varnode.cc:938-989` / `src/funcdata.rs`）；
4. `RulePieceStructure::get_exact_piece`（`ruleaction.cc:7625-7718` / `src/ruleaction.rs`）。

先完成 `TYPEFACTORY-EXACTPIECE-CALLERS-0001`，再做
`SPLITDATATYPE-EXACTPIECE-0001`：RuleSplitLoad/Store 必须调用 canonical factory，覆盖
`FILE * + 8` scalar 不误拆、ProgressData 的 16-byte stores 形成正确 PartialStruct/字段 pieces、
并观察原 op/varnode identity、次序、flags、异常前状态和第二轮稳定。禁止复制旧 local helper。

## 4. 停止时留下的未提交隔离 worktree

这两处只是在途 WIP，**均未通过 Cargo、双侧 runner、独立 review，也没有 commit；不得直接合入。**

### D1 TypeOpCall

- worktree：`/home/wirs/.cache/rugra-wt-typeop-localtype-d1`
- branch：`agent/typeop-localtype-d1`
- base：`cad41c27104b0b5314fb3bcc78d54f6f5b55a1db`
- dirty：`src/typeop.rs`、`tests/oracle/typeop_local_type_1204.rs`
- diff stat：140 insertions / 37 deletions
- binary diff SHA-256：`f23536abbe4888cd6cd476360bd902f4edd5bbecd176c3af4edfb75ca4bb76d0`
- 尚缺：docs、C++/metadata/runner重钉、真实双侧执行、independent review、commit。

### exact-piece production callers

- worktree：`/home/wirs/.cache/rugra-wt-myfwrite-splitdatatype`
- branch：`agent/myfwrite-splitdatatype`
- base：`cad41c27104b0b5314fb3bcc78d54f6f5b55a1db`
- dirty：`src/{coreaction,database,funcdata,ruleaction,variable}.rs`
- diff stat：88 insertions / 141 deletions
- binary diff SHA-256：`a5a47eaee2ac2c5aa4c587ca09ccd5c45e6b253e09d984e2d99ed20965a924ab`
- `coreaction.rs` 租约仅允许 `ActionNameVars` 把 Architecture-owned TypeFactory 传给
  `HighVariable::finalize_datatype`；不得混入 ActionInferTypes/PTRSUB/STOP。
- 尚缺：4份 paired docs、双侧 fixture/metadata/runner、Cargo、independent review、commit。

下一位开发者应先审 diff，不要从这两个 worktree继续“默认相信”；任何修改都会使旧审计失效。

## 5. 串行租约与推荐接手顺序

1. 完成 D1（只占 `typeop.rs`），双侧 oracle + review + 原子 commit。
2. 完成 exact-piece callers WIP；它当前占一个极窄 `coreaction.rs` 调用点。提交后释放 coreaction。
3. D2 才占 `coreaction.rs` 做 CALL input local dispatch；与步骤 2 串行。
4. 完成 canonical callers 后，单独占 `subflow.rs` 做 RuleSplitLoad/Store。
5. PTRSUB downChain 需要 `typeop.rs` + TypeFactory caller plumbing，必须等 D1释放；STOP 需要
   `varnode.rs/coreaction.rs`，必须等 D2与caller释放。
6. hugehelp 的 Database/StringManager/Rule/PrintC 波可与 subflow 并行，但 `coreaction.rs` 的
   ActionConstantPtr 必须在 D2之后串行。
7. 每个原子片都跑 immutable three-function A/B；任一函数未严格 byte-equal 就继续定位最早 IR 分叉。

## 6. 复算命令和环境约束

```bash
# 门禁健康
python3 tools/check_gate_health.py
python3 tools/check_ghidra_annotations.py --all
python3 tools/check_ghidra_refs.py --all --strict

# Cargo 只允许这样串行；target/TMPDIR 必须换成任务专属 home 路径
/usr/bin/flock /tmp/rugra-cargo-build.lock \
  env CARGO_INCREMENTAL=0 \
      CARGO_TARGET_DIR=/home/wirs/.cache/<task>-target \
      TMPDIR=/home/wirs/.cache/<task>-tmp \
      cargo build --locked --release --example curl_decompile

# 三函数差分（stdout 只能放 C，stderr 分离）
python3 tools/compare_ghidra.py <fresh.c> tests/golden/ghidra_curl_1204.c --func hugehelp -v
python3 tools/compare_ghidra.py <fresh.c> tests/golden/ghidra_curl_1204.c --func progressbarinit -v
python3 tools/compare_ghidra.py <fresh.c> tests/golden/ghidra_curl_1204.c --func my_fwrite -v
```

`compare_ghidra.py` 的 skeleton 是诊断指标，不是完成定义。最终必须按函数签名首字节到匹配
closing brace 的原始 bytes 比较；空行、空格、warning 和字符串内容都不能被归一化掉。
