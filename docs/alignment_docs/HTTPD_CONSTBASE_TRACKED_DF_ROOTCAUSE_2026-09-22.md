# httpd 首跨侧分歧根因档案(universal:constbase 期 tracked-DF COPY 缺失)

任务:Lane BQ `SB-CONSTBASE`(writer wt/sb-constbase, 2026-09-22)
worktree:`/home/ls/Rugra-wt-sb-constbase`(master=31bc1e0)
oracle:Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`(decompile cpp)
SLEIGH spec:`sleigh_specs/x86-64.sla` + `sleigh_specs/x86-64.pspec`(同 oracle 语言树锁定生成)
复现材料:BP(wt/sb-httpdff)镜像态对拍 `/dev/shm/rugra-tests/sb-httpdff/cross_side_report2.txt`
+ oracle 投影 `/dev/shm/rugra-tests/sb-oracle/httpd.main.oracle.projection`(sha256 3815f999…)

## 0. 结论(一句话)

**httpd main(0x2b820) 镜像对拍在 `universal:constbase` 的首分歧不是 constbase 算法差异,
也不存在"多余的 ZEXT 存活":oracle 侧 `ActionConstbase::apply`(coreaction.cc:678)因
pspec `<tracked_set>` 里登记的 `DF=0`(register:20a:1)在函数入口块头插入了第 2041 个 op
`2b824:7f8 COPY out=n:register:20a:1 in=c:0:1`;Rugra 的 `ActionConstbase`
(coreaction.rs:8544)本身是忠实移植,但 httpd 驱动挂的是裸 `Architecture::new()`
(httpd_decompile.rs:401),pspec `<context_data>` 从未被 `decode_context_data` 摄入,
tracked set 为空 → 一个 COPY 都不插。对拍报告里的 "rugra-only INT_ZEXT" 是 bisect
窗口伪影:oracle 的 SNAP 3 里 `2b826:6 INT_ZEXT` 仍在(投影原文行),双侧都保留 ZEXT,
真实差异 = 恰好一个 op。**

## 1. 分歧现场(stage_bisect v1.2, 2026-09-22 BP run 2)

```
kind: V1_OP_LINE_DIVERGENCE
stage ordinal: 3  tree-path: universal:constbase  round 0  op-line index 3
@@ -1,7 +1,7 @@
 2b824:0 COPY     d=0 out=u:4f900:8      in=n:register:b8:8      ; push r15
 2b824:1 INT_SUB  d=0 out=n:register:20:8 in=n:register:20:8,c:8:8 ; RSP(0x20) -= 8
 2b824:2 STORE    d=0 out=- in=s:ram,n:register:20:8,u:4f900:8
-2b824:7f8 COPY   d=0 out=n:register:20a:1 in=c:0:1               ; ← oracle-only
 2b826:3 COPY     d=0 out=n:register:200:1 in=c:0:1               ; CF=0 (xor edx,edx)
 2b826:4 COPY     d=0 out=n:register:20b:1 in=c:0:1               ; OF=0
 2b826:5 INT_XOR  d=0 out=n:register:10:4 in=n:register:10:4,n:register:10:4 ; EDX^EDX
+2b826:6 INT_ZEXT d=0 out=n:register:10:8 in=n:register:10:4      ; ← 窗口伪影,见 §0
```

oracle 投影原文(SNAP 2 → SNAP 3):

```
@END 2 universal:start result=0 count=0  → @SNAP 2 ops 2040   ; 不含 COPY(20a)
@BEGIN 3 universal:constbase
@END 3 universal:constbase result=0 count=0                  ; apply 无条件 return 0
@SNAP 3 ops 2041                                              ; +1 = DF COPY
2b824:7f8 COPY d=0 out=n:register:20a:1 in=c:0:1             ; uniq 0x7f8=2040=初始树后新分配
2b826:6 INT_ZEXT d=0 out=n:register:10:8 in=n:register:10:4  ; ← oracle 同样保留
```

寄存器布局(由投影内 flag 写入自证):RSP=0x20、R15=0xb8、RDX/EDX=0x10、
CF=0x200、PF=0x202、ZF=0x206、SF=0x207、**DF=0x20a**、OF=0x20b(INT_SLESS→207、
INT_EQUAL→206、POPCOUNT 链→202、INT_LESS→200、INT_SBORROW→20b)。
0x2b820 `endbr64` 无 pcode,入口块锚在首 op 地址 0x2b824
(splitBasic,flow.cc:996-998;Rugra flow.rs:2369-2381 同锚),故 COPY 印为 `2b824:7f8`。

## 2. oracle 侧完整链(本 session 逐行核读)

1. **资产**:`sleigh_specs/x86-64.pspec`(与 oracle x86-64 语言树同指纹):

   ```xml
   <context_data>
     <context_set space="ram"> … addrsize/opsize/rexprefix/longMode … </context_set>
     <tracked_set space="ram"><set name="DF" val="0"/></tracked_set>
   </context_data>
   ```

2. **架构初始化**(BfdArchitecture::init → restoreFromSpec):
   `Architecture::parseProcessorConfig`(architecture.cc:1173)循环体
   `ELEM_CONTEXT_DATA` 臂(:1190)`context->decodeFromSpec(decoder)`。
3. **摄入**:`ContextInternal::decodeFromSpec`(globalcontext.cc:531-549):逐子元素
   `Range::decodeFromAttributes`(必须有 range)→ `ELEM_TRACKED_SET` 臂
   `decodeTracked(decoder, createSet(addr1,addr2))`(whole-ram 分区)。
   `ContextDatabase::decodeTracked`(globalcontext.cc:85-93):vector 先 clear,
   每个剩余 `<set>` 依文档序 emplace_back;
   `TrackedContext::decode`(globalcontext.cc:56-63)→
   `VarnodeData::decodeFromAttributes`(pcoderaw.cc:33-53):`name="DF"` 经
   `SleighBase::getRegister`(sleighbase.cc:133-142)解析 → register 空间 0x20a:1,
   `val=0`。
4. **消费**(universal 组,coreaction.cc:5478 挂载 "base"):
   `ActionConstbase::apply`(coreaction.cc:678-705):
   - 块 0 为空即返回(:679-680);
   - injectUponEntry 生产为 -1(跳过 live inject);
   - `const TrackedSet trackset(context->getTrackedSet(data.getAddress()))`
     (globalcontext.hh:220 → partmap `trackbase` getValue 前驱分区,whole-ram 命中);
   - 逐 ctx:`newOp(1,bb->getStart())` → `newVarnodeOut(ctx.loc.size,addr,op)`
     → `newConstant(ctx.loc.size,ctx.val)` → COPY → `opInsertBegin(op,bb)`;
   - 无条件 `return 0`(无 change 计数 → `@END … count=0` 而 ops 2040→2041)。

## 3. Rugra 侧对照与四类语义核对(coreaction.rs:8544-8615)

| 决定性语义 | oracle(coreaction.cc:678-705) | Rugra(coreaction.rs:8544-8615) | 判定 |
|---|---|---|---|
| 引用/输出参数 | `const TrackedSet&` 指入全局 context 库,循环不 mutate;out 为按 loc 新建 varnode,in 为新 constant | `.to_vec()` 浅拷贝(注释已证循环内无 mutate,观察等价);`new_varnode_out`/`new_constant` 同建 | 一致 |
| 循环边界/遍历顺序 | `for i=0; i<trackset.size(); ++i`,pspec `<set>` 文档序(仅 DF) | `for ctx in &trackset`,同序 | 一致 |
| 计数器/累加器 | 无计数器;无条件 return 0 | 无计数器;`NO_CHANGE` | 一致 |
| 排序/比较键 | partmap<Address> 前驱查找(upper_bound+--),键=(space 顺序,offset);whole-ram 分区必命中 | `TrackedSetMap::get_value` partition_point(<=) 前驱,键=(space_id,offset);ram 内查询等价(arch.rs:133-139 已登记 caveat) | 一致 |

库层机制已由单测钉死:`test_action_constbase_inserts_tracked_copy_at_entry_head`
(coreaction.rs:17927)摄入生产 pspec 形状后,恰在入口块头插一条
`COPY out=register:0x20a:1 in=const 0`。**算法层 MATCH;缺的是输入数据**:
httpd 驱动没有任何 `decode_context_data` 调用点。curl 驱动已接
(curl_decompile.rs:1925-1972,ARCH-CONTEXT-TRACKED-0001:pspec 字节 → DocumentStorage
→ 每个 `<context_data>` 子元素 → `Architecture::decode_context_data`),httpd 漏接。

## 4. 修复面(本 lane 落地)

- 驱动侧最小面:examples/httpd_decompile.rs 在 main 里一次性构建带 tracked set 的
  `Architecture` 模板(SLEIGH 寄存器目录 host + pspec 解码),每函数线程克隆挂载
  (Architecture: Clone;逐线程克隆保持既有 mutation 隔离);pspec 缺失/解码失败按
  curl 同标准 fatal。
- 不改 `src/*`(constbase 本体无需动)。
- 判定依据:修复后镜像对拍 `universal:constbase` 应逐行一致(含 `2b824:7f8 COPY
  out=n:register:20a:1 in=c:0:1`,入口块锚同为首 op 地址),首分歧后移;
  env-off 默认路径每个函数同样获得 DF COPY(向 oracle 行为靠拢,DF 无读者时被
  死代码消除,最终 C 不变),curl/httpd E2E defects=numbering=0 门禁复核。

## 5. 遗留与边界

- `<context_set>`(addrsize/opsize/rexprefix/longMode)是 SLEIGH 上下文变量通道,
  Rugra 侧为 SLEIGH-0002C 残留(计数跳过,arch.rs:1294-1305),与本分歧无关
  (constbase 只消费 tracked 通道)。
- TrackedSetMap 跨 space 交错排序 caveat 已在 arch.rs 登记(SLEIGH-0002C/ADDRESS-0001),
  x86-64 单 ram 分区不受影响。
- injectUponEntry 生产 -1(INJECT-0001),双侧同跳过。

## 6. 修复验证(commit ea0f7a7,2026-09-22)

1. **镜像对拍复跑**(观测构建 = BP 分支 3e34488 + 本修复,/dev/shm/rugra-tests/
   sb-constbase/):修复前首分歧 `universal:constbase` stage 3 / op-line 3;
   修复后 stage 3 SNAP 3 头部与 oracle 逐字节一致,含
   `2b824:7f8 COPY d=0 out=n:register:20a:1 in=c:0:1`(ops 2040→2041,
   register:20a 全投影出现次数 1456 = oracle 1456)。
   **首分歧后移至 stage ordinal 5 `universal:extrapopsetup` op-line 68**:
   oracle `2b864:7f9 INT_ADD out=n:register:20:8 in=n:register:20:8,c:8:8`
   vs rugra `2b864:7f9 DELAY_SLOT out=n:register:20:8 in=n:register:20:8,
   o:2b864:42`(callee extrapop 应用形态:INT_ADD vs DELAY_SLOT 伪 op,新的
   待派发 lane 材料,cross_side_report_fixed.txt)。
2. **httpd E2E**(release,29 函数):skeleton 2326 / defects 0 / numbering 0。
   修复前后对照:以 31bc1e0 干净构建(master-before,无本修复)重跑,
   **输出逐字节相同**(`cmp` clean)——DF COPY 如预期被死代码消除,无
   register:20a 泄漏,skeleton 增减 = 0。
3. **curl E2E**(release,124 函数):defects 0(0/124)/ numbering 0,
   skeleton 3304(修复前后逐字节相同);`--func next_url` 0/0 且函数体
   逐字节相同(Phase 2 spot check,无回退)。
4. 库层回归:`cargo test --lib -- constbase` 通过
   (test_action_constbase_inserts_tracked_copy_at_entry_head)。

