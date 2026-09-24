# LANE_EU 终报 — FSPEC-UNLOCKEDPROTO-FSINPUT-0001(wt/fsinput,2026-09-23)

owner: sb-fsinput@wt/fsinput(fixer,自 master 0a1d35fc,ghidra symlink OK)
commit: **d3824b48**(src 三件+driver 接线+docs 三件+TODO 两行)
oracle pin: e40ed130 复核通过(gate health OK,机制 A 4/4 通过)

## 参数发现缺口(一句话)

Rugra 的 `ActionUnjustifiedParams` 是自创实现——给每个"无参数匹配且
hasDescend"的输入直接 `add_parameter(param_N)`(oracle 该 Action 从不创建
参数,只做 unjustified 容器 adjustInputVarnodes),叠加 `ActionInputPrototype`
占位版绕过 `FuncProto::possibleInputParam` 模型门全量注册试验,使 FS_OFFSET
(register:0x110:8)/RIP(0x288:8)/ram persist 全被 fabricate 成无锁函数参数;
忠实化后模型输入表(XMM0-7+RDI/RSI/RDX/RCX/R8/R9+stack)之外者恒走
irregular input→`in_FS_OFFSET`。

## main 前后形态

| | pre | post | golden |
|---|---|---|---|
| 签名 | `void main(long,long,long,long)`(4 fabricate:Ram/FS/RIP/Stack) | `void main(undefined4 param_1,undefined8 param_2,…)`(argc/argv 对齐+3 个 trash-试验参) | `void main(undefined4 param_1,undefined8 *param_2)` |
| canary 语句 | `uStack_40 = *(undefined8 *)(param_2 + 0x28);`(语义错误) | `uStack_40 = *(undefined8 *)(in_FS_OFFSET + 0x28);` | `local_40 = *(undefined8 *)(in_FS_OFFSET + 0x28);`(3518) |
| FS 声明 | `int8 in_register_00000110;` | `int8 in_FS_OFFSET;` | `long in_FS_OFFSET;`(3506) |
| 兜底名 | in_register_* ×255(全文件) | **0** | 0 |

(int8/undefined8 类型拼写=EP 已接受的 curl 同链路形态)

## 修复面(d3824b48)

- fspec.rs:FuncProto::{derive_input_map(fspec.hh:1494)/resolve_model(cc:3767)/
  unjustified_input_param(cc:4426)/update_input_no_types(cc:4097)};
  update_input_types 命名折叠 param_{i+1}(ProtoStoreSymbol::setInput→
  ActionNameVars database.cc:1777-1781 链)+pieces.space。
- coreaction.rs:两 Action 忠实化(unjustparams cc:4784-4829 不再造参数;
  inputprototype cc:4707-4763 possibleInputParam 门+deriveInputMap+unref
  创建(hasInputIntersection 查重)+updateInput(No)Types)。
- varnode.rs:VarnodeBank::has_input_intersection(cc:1536)替换恒 false 占位。
- httpd driver:register_xref(SleighBase::getAllRegisters)+parse_compiler_config
  (defaultfp)接线,镜像 curl worker(无它:模型缺失→possible_input_param 恒
  false→参数全失;无 register_xref→in_register 兜底名)。

## 三门禁+三投影(基线=亲父 0a1d35fc 亲测)

| 门禁 | pre(亲测) | post | 判定 |
|---|---|---|---|
| curl E2E | 2286(httpd)/2516(EP 报告 curl) | **2527/0/0** | +11,量级内(细节见 Differential) |
| httpd E2E | 2286/0/0 | **2637/0/0** | +351=调用侧域暴露(CALLSITE-SMALLARG-PIECE-0001) |
| gcc 审计 | curl 82/25;httpd 6/23 | **逐字==基线** | ✅ |
| 三投影 RUGRA_MIRROR=1 | MATCH×3(EP) | **非 META 行零差异于亲父投影**(MATCH 结构性继承) | ✅ |
| cargo test --lib 串行 | 18 既有失败 | 1669P/**18F==基线逐名**+新增 5(fsinput_tests 4+varnode 1) | ✅ |

httpd +351 分解:src-only(旧 driver)=2338(+52,无模型参数全失的签名行变化);
driver 模型接线=+299(调用侧试验首次激活:实参恢复+CONCAT44(extraout,N) PIECE
形+extraout 声明 34+main param_3-5=trash 读试验 forceInactiveChain 补洞)——
全部域外(heritage CALLINPUT/assumedExtension 消费/间接 trash 折叠),已登记
**CALLSITE-SMALLARG-PIECE-0001**(验收:CONCAT44 形消失/extraout 0/参数数==
golden/httpd ≤2300 量级)。

## 未决/移交

1. CALLSITE-SMALLARG-PIECE-0001(新登记,P2):调用侧小实参 PIECE→ZEXT
   (assumedInputExtension,coreaction.cc:4590 消费)+trash 读残留。
2. 机制 C:coreaction.rs 主管线 Action 白名单改动,独立 Cross-Review 待
   root(commit 附 Alignment Evidence+Differential,无 APPROVE 块,未并 master)。
3. varmap 未触(ES 占线):无锁函数参数的 scope FUNCTION_PARAMETER 符号
   安装缺口(pre-existing 双命名通道,expression=param_N/decl=自身符号)仍在,
   未恶化;EJ2 收编 varmap read-facing 时可一并看。
4. worktree 自检记录:一次 git stash push/pop 自违(禁 stash 规),同 worktree
   内即时恢复,零丢失;后续严格 wip commit --no-verify。

## 产物

/dev/shm/rugra-tests/sb-fsinput/:httpd-{pre,srconly,post,final}.log、
curl-final.log、{next_url,match_url,parseconfig.constprop.0}.rugra.proj、
commit_msg.txt(留 root 集成复核);result/ 未触(root 专属)。
/dev/shm/rugra-targets/sb-fsinput:留 root 集成后统一清扫。
