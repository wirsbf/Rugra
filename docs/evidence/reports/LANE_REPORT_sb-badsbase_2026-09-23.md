# LANE REPORT — sb-badsbase（PRINTC-BADSPACEBASE-RENDER-0001）

- Branch: wt/badsbase @ **95b42101**（基=亲父 master 983e0fc9 亲测）
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-badsbase
- Oracle: Ghidra 12.0.4 e40ed130（gate health OK）
- **写域偏离声明**：车道假设写域=printc.rs/varmap.rs；归因证伪后实际写域=
  `examples/httpd_decompile.rs` + `src/funcdata.rs`（+docs/api/funcdata.md+TODO_BOARD），
  printc.rs/varmap.rs 零改动。两文件当时均无占线（HTTPD-DRIVER-ARCH-INIT-0001 待派、
  funcdata.rs 前租约 w-scopefix 已 DONE 并入）。

## 0. TL;DR（抑制机制缺口一句话）

Ghidra 打印侧对 TypeSpacebase **没有第二道抑制门**——`PrintC::emitScopeVarDecls`
(printc.cc:2518) 声明一切已存在符号，`BADSPACEBASE` 字串只是 genericTypeName 的
TYPE_SPACEBASE 兜底名（printc.cc:3387）；抑制完全在上游"符号不创建"：
`Funcdata::setInputVarnode` 效应尾（funcdata_varnode.cc:365-370）从 cspec
`<unaffected>` RSP 记录给 sp 输入置 `Varnode::unaffected` →
`HighVariable::hasName` spacebase 臂（variable.cc:737-744）返 false →
`ActionNameVars::linkSymbols`（coreaction.cc:2961-2962）不建符号。
Rugra 两缺口：①httpd 驱动未挂 parseCompilerConfig（funcp 零效应记录；curl 有）；
②iced prelude Phase 3 直连 `vbank.set_input_prevalidated` 绕过效应尾（Ghidra
`vbank.setInput` 唯一调用点=setInputVarnode cc:363；SLEIGH 侧输入经 heritage
guardInput/renameRecurse 的 `fd->setInputVarnode` 重建，heritage.cc:1975/2501）。

## 1. 复现与定位（工件 /dev/shm/rugra-tests/badsbase/）

- 基线亲测：httpd 门禁面（29 fns）**2225/0/0**，BADSPACEBASE×3 @ main:19 /
  ap_fini_vhost_config:272 / ap_ht_time:735（声明死变量，函数体零引用；类型名
  来自 TypePointer→TypeSpacebase 的 genericTypeName 兜底）。
- 运行时探针（已撤，git diff 干净）：curl main 的 sp 输入 `unaff_vn=true`
  （has_name 抑制生效、零泄漏），httpd main `unaff_vn=false`（has_name 放行）→
  分歧=unaffected 位缺失。curl 与 httpd 驱动都只解 data_organization，但 curl 的
  SLEIGH 路径输入经 heritage set_input_varnode（funcp 有模型→效应尾跑），
  httpd 的 iced prelude 直连 bank 层（效应尾从未跑）。
- 全模型挂载实验：parse_compiler_config 全量挂上后 sp unaff=true、泄漏归零，但
  `funcp.has_model()` 翻 CALLSPEC-DRIVER-0002 门 → httpd **2225→2634**（+409
  守卫重载拷贝，main 668→839；ActionCopyPropagation coreaction.cc:5510 缺失族）
  → 不可接受，弃。

## 2. 修复（commit 95b42101，4 文件 +124/−7）

1. `examples/httpd_decompile.rs`：tracked_context_architecture 照 curl worker 形状
   挂 parse_compiler_config（TrackedSpecHost 补 `unique_inject_base` +
   `SleighSymbolLookup`；pcodeinjectlib+userops 挂载），**defaultfp 捕获后清空**，
   仅把 default 模型的 EffectRecord 表注入每函数 `fd.funcp.effects`
   （FuncProto::hasEffect/effectBegin 先读该表，fspec.cc:4234-4240/4243-4257——
   效应面答案与 oracle 模型同源），模型门姿态（CALLSPEC-DRIVER-0002）保持。
2. `src/funcdata.rs`：iced prelude Phase 3 输入晋升后补 setInputVarnode 效应尾
   （unaffected/return_address 置位；try_has_effect=None 时惰性=零行为差）。
   已知非镜像：setVarnodeProperties(cc:363) 未并跑——prelude 时点 fd.scope 未建，
   符号尾查询天然空载（TODO 行记录）。

## 3. 验收（全部亲测，fast-release，commit 后二进制复跑 httpd 字节恒等）

| 门禁 | 修后 | 基线（亲父 983e0fc9 亲测） |
|---|---|---|
| BADSPACEBASE 泄漏 | **0**（门禁面+全量语料） | 3 |
| httpd 门禁面 29 fns | **2221/0/0**（main −1 / ap_fini −1 / ap_ht_time −2，其余 26 函数字节不变；ap_ht_time 另消解 golden 无对应的 `[32] aStack_20;`） | 2225/0/0 |
| httpd 全量 | **470/470 零 TIMEOUT**，警告 5==EO2 验收态，L2 **37655/2/0**（defects 恒 2=HTTPD-FULLEMPTY-ELSE-0001 既有） | 470/470，37677/2/0 |
| curl E2E | **2512/0/0**（亲测=任务书基线；iced 函数仅 __libc_csu_init/fini，字节级不变——效应尾惰性） | 2512/0/0 |
| 三投影 | next_url / match_url / parseconfig.constprop.0 **MATCH×3**（RUGRA_MIRROR=1 全家 env，stage_bisect v1.2 stage+snapshot identical） | 保持 |
| lib 测试 | funcdata 批 17 failed ⊆ 预存基线 18 集（cr-alivelist/fails_base.txt）零新增 | 17-18 预存 |
| commit 门禁 | docs-sync/annotations/refs/机制 A Evidence 4/4 全过 | — |

## 4. 未决移交

1. **全模型绑定**（defaultfp 清空的解除条件）：需 ActionCopyPropagation
   （coreaction.cc:5510-5511，universal 树缺失）+ queryCall/checkForFlowModification
   尾部移植——归属 CALLSPEC-DRIVER-0002 既有修复路径，HTTPD-DRIVER-ARCH-INIT-0001
   家族（该 TODO 剩余件：set_register_xref/set_commentdb/archid）。
2. ap_ht_time 等仍有 golden 无对应的 `int in_register_00000008;` /
   `char *in_register_00000010;` 不规则输入声明（非 spacebase 家族，预存）——
   全模型绑定+寄存器名表族（HTTPD-DRIVER-ARCH-INIT-0001）。
3. Phase 3 效应尾未并跑 setVarnodeProperties（见 §2；prelude 时点空载，保持最小差）。

## 5. 产物

/dev/shm/rugra-tests/badsbase/：httpd_gate_{before,fix1,final}.c、
httpd_full_fix1.{c,stderr}、curl_{after,final}.c、p_{next_url,match_url,parseconfig}.projection、
before/after_perfunc.txt、funcdata_fails_mine.txt、commit_msg.txt。
（/dev/shm/rugra-targets/sb-badsbase 待 root 集成后按回收纪律清除。）
