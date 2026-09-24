# LANE_EY2 终报 — COREACTION-FSPARAM-SYMINSTALL-0001（wt/chainfix，2026-09-23）

- owner: sb-chainfix@wt/chainfix（fixer，续 EY 配额墙中断；基 wt/chainmerge@736982f2 合并态）
- commit: **f8ee7548**（src 三件 + docs/api 三件 + TODO_BOARD 三行）
- oracle pin: e40ed130（gate health OK；机制 A 4/4；annotations/refs 绿）

## 交互根因（一句话）

EH 恢复的参数经 `updateInput(No)Types` 的 `store->setInput`（fspec.cc:4079/4121）装
ProtoStoreSymbol→ScopeLocal `function_parameter` 符号（寄存器参数 uselimit={baseaddr-1}，
栈参数 addrtied），而 Rugra 平铺 FuncProto store 丢掉该安装——`ActionNameVars::link_symbols`
→ `Funcdata::link_symbol` 的 `queryProperties(usepoint=baseaddr-1)`（`Varnode::getUsePoint`
varnode.cc:696-703 未写 varnode 分支）查空 → 输入 high 无符号 → 打印层落 `in_RDI` 族；
**EK 的 usepoint 匹配已就位，只缺符号在表**（= EU 终报残差 ③、EV delta ① 族）。

## 修复面（f8ee7548）

- coreaction.rs `ActionInputPrototype`：cc:4715 `clearUnlockedInput` store 尾折
  `clear_category(FUNCTION_PARAMETER)`（fspec.cc:3233-3236→database.cc:2020-2029）；
  `store_install` 闭包镜像 `ProtoStoreSymbol::setInput`（fspec.cc:3147-3183：slot 漂移
  removeSymbol；`discoverScope`（database.cc:1353-1365）语义决定 usepoint——`in_scope`
  命中=None（空 uselimit→addrtied），未命中=Some(baseaddr-1)；`add_symbol`+
  `set_category(FUNCTION_PARAMETER, count)`，命名折叠 `param_<count+1>`）。
- fspec.rs：`update_input_types`/`update_input_no_types` 新增 `store_set_input` 回调，
  两 setInput 调用点逐字锚定；体内走查不变。
- prettyprint.rs `legacy_never_type_evidence`：符号驱动证据集扩宽（uint*/int1/int2/int8/
  ushort/ulong/longlong/__int*_t），消除符号退休 in_ 证据后的 legacy `int uVarN;`
  K&R 注入（CHAINFIX-LEGACY-BYPASS-0001）。

## in_ 前后（httpd）

| | pre（基线 2539 态） | post |
|---|---|---|
| in_ 总计 | 182 | **40** |
| 参数寄存器族（RDI 48/RSI 45/RCX 17/RDX 15/R8 8/32 位变体 7） | 142 | **0** |
| in_RIP | 21 | 21（CHAINMERGE-INRIP-PRINTFAMILY-0001 已登记域） |
| in_RAX / in_RSP | 12 / 7 | 12 / 7（CHAINFIX-INRAXRSP-RESIDUAL-0001 新登记） |
| param_ 记号 | 243 | 329 |

## 三门禁 + 投影（基线=亲父 736982f2/EQ2 亲测，oracle e40ed130，fast-release）

| 门禁 | pre | post | 判定 |
|---|---|---|---|
| httpd E2E | 2539/0/0 | **2433/0/0**（−106） | ✅ defects/numbering 0 |
| curl E2E | 2512/0/0 | **2507/0/0**（−5 全为 legacy 死声明删除：_start/__libc_csu_init 的 in_RDX/in_RSI/in_EDI 无引用声明+glob_word `int uVar2;` K&R dupe；零新增行） | ✅ 改善非恒等 |
| gcc 审计 | curl 82/25；httpd 6/23 | **逐字==基线** | ✅ |
| 三投影 stage_bisect --v1 | MATCH×3（EQ2） | **MATCH×3**（match_url/next_url/parseconfig.constprop.0 vs sb-oracle 投影；与 EQ2 基线 md5 三同=结构性继承；ey2 重生成 next_url cmp 恒等佐证） | ✅ |
| cargo test --lib 串行 | 18F（EH 记录基线） | 1658P/**18F 逐名同集**（funcdata/heritage 预存；并行 20=已知 flaky 子集） | ✅ |
| annotations/refs/机制 A | — | 全绿（提交时 hook 实测） | ✅ |

## E2E 可复现性

httpd_ey2.c == httpd_final2.c、curl_ey2.c == curl_final2.c（字节恒等；None-scope
guard 加固后输出零漂移）；注释重构后 curl 输出 cmp 恒等。

## 残差/新登记

1. `CHAINFIX-INRAXRSP-RESIDUAL-0001`（P2，新登记）：in_RAX 12+in_RSP 7——非参数
   寄存器输入（返回值寄存器/栈指针，模型不收），双基线 main 位置不发射该形态；
   归因域待查（printing/输入挂接链）。
2. in_RIP 21 维持 CHAINMERGE-INRIP-PRINTFAMILY-0001（已登记域，非本修复引入）。
3. EV ① 族残余 = 上述两项共 40 记号（179→40）；②③④⑤⑥ 族未动（本 lane 域外）。

## 机制 C 复核请求（阻塞并 master）

coreaction.rs 主管线 Action 白名单改动。请复核者**自读**（勿采信本报告 Evidence 声明）：
- coreaction.cc:4707-4763（ActionInputPrototype::apply 全函数）
- fspec.cc:3147-3214（ProtoStoreSymbol::setInput）/ 3233-3236（clearAllInputs）
- fspec.cc:4052-4128（updateInputTypes/updateInputNoTypes）
- database.cc:1353-1365（discoverScope）/ 2020-2029（clearCategory）
对照 src/coreaction.rs:10096 起 apply 与 src/fspec.rs:1340/1432 的四类决定性语义
（引用/遍历/计数器/比较键——重点：usepoint 三态 None/Some(baseaddr-1) 与 discoverScope
在 register/stack/join 可达域的逐 case 等价、count 即 setInput 的 i、漂移键
addr+size）。

## 产物

/dev/shm/rugra-tests/sb-chainfix/：httpd_ey2.c、curl_ey2.c、ey2.next_url.projection、
final2.*.projection×3、commit_msg.txt、test_ey2_failures.txt（其余 dbg/中间产物已清）。
/dev/shm/rugra-targets/sb-chainfix：留 root 集成后统一回收。
