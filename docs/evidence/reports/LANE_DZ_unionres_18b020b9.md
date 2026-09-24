# Lane DZ: unionres — 钻取 cast 目标选择(DV②③)终报
Commit: 18b020b9 (wt/unionres,基 master 6b4ca15a)
Oracle: Ghidra 12.0.4 e40ed130; golden: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c

## 钻取机制偏差(一句话)
DV②③ 的可观测差异**不在 unionresolve.rs 本身**:Rugra 的 ScoreUnionFields 是死代码
(无任何管线生产方调用,fd.union_map 无写者,varnode read-facing 四个 fn 退化为
恒返回原类型),且 cast.rs `cast_standard_full` 缺 cast.cc:341-349 的
PartialStruct/PartialUnion **req 侧免 cast 臂**;oracle 的 `(char **)` 经
read-facing→resolveInFlow→ScoreUnionFields(derefPointer 钻 Set→elements@0 尺寸门)
→setUnionField→PTRSUB downChain→`char ***`→TypeOpStore::getInputCast slot2,③的
裸化只需 cast.rs partial 臂(unionresolve.cc 侧链路不参与)。

## 交付
1. **域内保真修复 ×9**(src/unionresolve.rs,全部键到 oracle 行):
   ResolveEdge PartialUnion 键臂(cc:73-74)/with_field unwrap+指针臂(cc:40-59)/
   type_pointer_strip_array 真镜像(type.cc:3849-3859,返回 intern 指针非裸 pointee)/
   INT_ADD 族常量臂 downChain 钻取+成功才 +5(cc:429-438)/LOAD 上行指针包装+slot1
   递归(cc:664-666)/CALL 族锁参数 consult(fd: Option<&Funcdata> 透传,cc:184/204)/
   数组算术门用剥指针后 union 尺寸(cc:94)/score_locked_type 去自造循环内检查
   (cc:149-150)/scoreTruncation +5 改 Arc 身份(cc:856-857)。
   typegrp 改 Arc<RwLock<TypeFactory>>(Ghidra TypeFactory& 的可变孪生,intern 臂需要)。
2. **登记两枚 TODO**(可观测修复的精确地图):
   - `CAST-PARTIAL-REQ-NOCAST-0001`(P1,cast.rs)= ③裸化+②现形 `(undefined8)` 前缀消除;
   - `UNIONRESOLVE-PIPELINE-WIRING-0001`(P1,跨域须 root 协调)= ②的 `(char **)` 生产方
     (read-facing findResolve/resolveInFlow 移植+coreaction.cc:2499/2556/5083+
     ruleaction.cc:7678 接线;RESOLVEINFLOW-DRIVER-0001 只覆盖其中 typeprop 一点)。

## main 前后(②③行,预期不变——修复在域外)
- ② `glob.pattern[8].content.Set.elements = (undefined8)in_stack_...fd90`(curl_after.c:729)
  vs golden 746 `(char **)` — 不变(等 UNIONRESOLVE-PIPELINE-WIRING-0001)
- ③ `glob._296_8_ = (undefined8)uVar32`(:775) vs golden 792 裸 `uVar29` — 不变
  (等 CAST-PARTIAL-REQ-NOCAST-0001)

## 三门禁(自测基线=亲父 6b4ca15a,pristine HEAD 二进制重跑 before)
- curl: defects=0 numbering=0 skeleton **2585==2585**(全输出字节级 before==after)
- httpd: 0/0 **2333==2333**(字节级 before==after)
- next_url **103**/match_url **76** skeleton,0/0,函数体字节级 before==after
- main 583 0/0;cargo test --lib:unionresolve 21/21;全 lib 1655P/18F==预存家族
  (funcdata SSA/alignment×17 + heritage_creation×1),零新增
- check_ghidra_annotations/refs(src/unionresolve.rs)绿

## 未决
- DV②③可观测修复=两枚新 TODO(见上);本 lane 写域(unionresolve.rs)内已无已知偏差。
- with_field 指针臂为结构化构造(签名收 &TypeFactory,funcdata.rs 持读锁),canonical
  interning 随 wiring 落地(已注释+TODO 内记录)。
- SUBPIECE 常量臂 offset 未走 computeByteOffsetForComposite(LE 下等价,BE 未建模,
  沿既有注释)。
