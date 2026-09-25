# Lane EN2: unwire — UNIONRESOLVE-PIPELINE-WIRING-0001 终报
Commit: dbd06779 (wt/unwire, 基 dd22aba5;前会话 EN 配额墙中断续跑)
Oracle: Ghidra 12.0.4 e40ed130; golden: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c

## 接线图(一句话)
`ActionInferTypes::propagateTypeEdge`(cc:5081-5084,backtrack 前)与
`ActionSetCasts::resolveUnion`(cc:2490,apply slot 前置)/`castOutput`(cc:2556)/
`castInput` PTRSUB0+tryResolutionAdjustment+CAST 记账(cc:2424/2692-2717)以及
`RulePieceStructure` 叶 COPY(cc:7675/7678)全部经 `unionresolve.rs` 的
fd-threaded `resolve_in_flow/find_resolve/find_compatible_resolve/
union_resolve_truncation` + read-facing 四孪生(type.cc:574-2540 + varnode.cc:626-672
virtual 镜像)生产/消费 `fd.union_map`;map 生命周期=funcdata.cc:100 clear 镜像,
action restart 轮保持(oracle 语义)。

## main ②行前后(after==golden 746)
- parent: `glob.pattern[8].content.Set.elements = in_stack_fffffffffffffd90;`
- after:  `glob.pattern[8].content.Set.elements = (char **)in_stack_fffffffffffffd90;` ✅
- **124 curl 函数 A/B(pristine dd22aba5 worktree 亲测)唯一文本变化就是这一行**;
  httpd 29 函数字节级恒等。

## 三门禁(baseline=亲父 dd22aba5 pristine 重跑)
- curl **2589/0/0**(parent 2593/0/0,−4=main 588→584;gcc 审计 82OK/25FAIL==基线)
- httpd **2335/0/0** 字节级恒等
- 三投影(RUGRA_MIRROR=1):next_url **MATCH**(335/96457)+match_url **MATCH**
  (340/80385)+parseconfig **MATCH**(335/130099);curl/httpd main 投影
  ordinal-5 extrapopsetup round-0 分歧(DELAY_SLOT/uniq-id 家族)=
  HTTPD_FLOW_MIRROR §4.2 预存(capture-mode 语料,从未 MATCH),与 union 接线无关。
- unionresolve 21/21;lib 串行 1657P/18F==预存家族零新增。

## 残留/移交
- **varnode.rs 移交件 ×2**(EJ2 写域):①四 read-facing fn(get_type_read_facing/
  get_type_def_facing/get_high_type_read_facing/get_high_type_def_facing)收编到
  unionresolve.rs fd-aware 孪生调用(现退化实现保留,coreaction 全 input_cast 族
  已改走孪生);②`setImpliedField`(varnode.cc addlflag,唯一消费方
  printlanguage.cc:527 pushImpliedField,Rugra print 路径现无读者,非阻塞)。
- `RESOLVEINFLOW-DRIVER-0001` 已闭合(propagateTypeEdge 接线,TODO 行已注)。
- **机制 C 待 root**:coreaction/ruleaction=主管线 Action/Rule 白名单,commit
  dbd06779 已附 Evidence+Differential,需独立 Cross-Review APPROVE 后并入。

## 证据
/dev/shm/rugra-tests/unwire/(curl_true_parent|curl_after|httpd_*|perfunc 账+三投影
proj/+commit_msg.txt);baseline 测量脚手架已回收(unwire-baseline worktree+
sb-unwire-parent target)。
