# x86_lift.rs API Reference

2026-06-27: opcode 改名对齐 Ghidra 规范名 (INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE / BOOL_NOT->BOOL_NEGATE)，纯重命名，行为不变。

2026-06-29: CALL op 建立 RAX 返回值 output（Register@0x0 size 8）。对齐 Ghidra `ActionFuncLink::funcLinkOutput`（coreaction.cc:1551 `newVarnodeOut`）：为未锁定 prototype 的 CALL 分配返回值寄存器作为 output，使返回值进入 SSA def 链。此前 CALL output 永远为 None，导致返回值"丢失"——下游使用（如 `__dest = strdup(buf)`）变成"声明却未赋值"。多寄存器/XMM 返回与 assumedOutputExtension 是后续工作。

2026-06-29（完整移植）：lifter 精简——CALL op 现在只挂目标地址 inrefs[0]（对齐 Ghidra x86 lifter ia.sinc）。移除了此前 lifter 硬塞的 6 个 SysV 参数寄存器 input + RAX output。参数和返回值现由 `ActionFuncLink::funcLinkInput/funcLinkOutput`（coreaction.cc:1474/1521）在分析层建立：funcLinkInput 对已知函数用 `opInsertInput(create_with_space(8, Register, reg_off))` 建参数 varnode，funcLinkOutput 用 `newVarnodeOut` 建 RAX 返回值。这是 Ghidra 四步链（lifter CALL → setupCallSpecs → funcLink → trial 恢复）的完整对齐。

### 2026-07-04：BRANCHIND 发射
- `jmp` 指令的非 Immediate 操作数（Register/Memory）现在正确发射 CPUI_BRANCHIND。
- Register 操作数：直接用寄存器 varnode 作为 BRANCHIND 目标。
- Memory 操作数：先 LOAD 再 BRANCHIND。
- 新增 `reg_offset` helper（复用 get_register 的映射表）。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-30：RIP/EIP 偏移修正(0x200 → 0x288)
- `get_register` 表中 `"rip" | "eip"` 的寄存器空间偏移由 0x200 改为 **0x288**。
- 依据:锁定 oracle `sleigh_specs/x86-64.sla` getAllRegisters 全量 dump
  (RIP=0x288:8 / EIP=0x288:4 / rflags=0x280 / CF=0x200..ID=0x214 各 1 字节;
  证据见 `examples/x86carry_probe.rs` 与
  `docs/alignment_docs/CARRY-PRINT-ROOTCAUSE-2026-08-30.md` §2.1)。
- 旧值 0x200 与 1-bit flags 区(CF..F5)别名:所有 rip 相对内存操作数的地址计算
  曾落在 flags 区 varnode 上。curl E2E 实测输出字节不变(3104/0/0)。

### 2026-08-30：X86LIFT-FLAG-PCODE-0001 — add/sub/neg/not 全量 flag pcode(w-iced)
- `add`/`sub`/`neg`/`not` 离开旧的 "temp+COPY 无 flags" 形态,按锁定 oracle
  `sleigh_specs/x86-64.sla`(12.0.4 语言)逐 op 提升:
  - `add` = ia.sinc `addflags`(CF=INT_CARRY, OF=INT_SCARRY)+ INT_ADD 直写
    dst(寄存器形式无 temp/COPY 链)+ 32-bit dst 的 INT_ZEXT 进 64-bit 父寄存器
    (check_Reg32_dest)+ `resultflags`(SF=INT_SLESS(r,0), ZF=INT_EQUAL(r,0),
    PF=INT_AND(r,0xff)→POPCOUNT→INT_AND(1)→INT_EQUAL(0))。
  - `sub` = `subflags`(CF=INT_LESS, OF=INT_SBORROW)+ INT_SUB + zext + resultflags。
  - `neg` = `negflags`(CF=INT_NOTEQUAL(a,0), OF=INT_SBORROW(0,a))+ INT_2COMP +
    resultflags + zext(NEG 的 zext 在 resultflags 之后,ia.sinc:4134)。
  - `not` = INT_NEGATE 直写,无 flags,32-bit dst zext。
- flag 寄存器偏移修正为 sla 布局:CF=0x200 PF=0x202 AF=0x204 ZF=0x206 SF=0x207
  OF=0x20b(各 1 字节;全量 dump 见 examples/x86flag_probe.rs)。
- 内存 dst 按 SLEIGH rm-操作数逐用重求值:每次宏使用重新 LOAD(add/sub 每
  flag 对、值 op、STORE 后每个 flag 组各一次),共用同一地址 varnode。
- 立即数尺寸规范化到操作数尺寸(`sub rsp,0x98` 的 imm8 → const 0x98:8)。
- 新增高字节寄存器 ah=0x1/ch=0x9/dh=0x11/bh=0x19。
- 新 helper:flag_cf/pf/zf/sf/of、const_vn、ram_space_const、parent64_name、
  compute_mem_addr、emit_load/emit_store_v、emit_resultflags(sf/zf/pf 三段)、
  emit_addflags/subflags/negflags/logicalflags、AluDst/Op1Ref + materialize、
  resolve_alu、emit_alu_tail、lift_add/sub/neg/not。
- 双侧证据:SLEIGH 直通 dump vs iced 提升投影,add/sub/neg/not 的 reg+mem 形态
  op-for-op 一致(唯一差异为可规范化的 uniq 临时 id)——
  /tmp/w-iced-flagprobe3.out(oracle 段)与 examples/x86flag_probe.rs。

### 2026-08-30:X86LIFT-FLAG-PCODE-0001 — logic/cmp/test + jcc cc 表(w-iced c2)
- `and`/`or`/`xor` = ia.sinc `logicalflags()`(COPY CF=0, COPY OF=0,在操作数
  LOAD 之前)+ 值 op 直写 dst + 32-bit zext + resultflags;mem dst STORE 后逐
  flag 组重新 LOAD(mem src 逐用重 LOAD,同 add/sub)。
- `cmp` 重写:旧实现 ZF=INT_EQUAL(dst,src)/CF=INT_LESS/SF=INT_SLESS 全部错位
  (偏移 0x201/0x203/0x202 非 sla 布局,且 ZF/SF 语义错误)。新实现 =
  `local temp = rm; subflags(temp,src); local diff = temp - src;
  resultflags(diff)`:INT_LESS(CF=0x200) + INT_SBORROW(OF=0x20b) +
  INT_SUB→uniq + SF/ZF/PF 链;双操作数 reg 直用 / mem 单次 LOAD+COPY 局部缓存。
- `test` 重写:logicalflags + 单次操作数读取 + INT_AND→uniq + resultflags
  (mem dst 地址计算在 COPY CF/OF 之前,LOAD 在其后)。
- `jCC` 全族重写为 ia.sinc cc 条件表(ia.sinc:1523-1539):je=ZF、jne=
  BOOL_NEGATE(ZF)、jl=INT_NOTEQUAL(OF,SF)、jge=INT_EQUAL(OF,SF)、jle=
  BOOL_OR(ZF,NOTEQUAL(OF,SF))、jg=BOOL_AND(!ZF,EQUAL(OF,SF))、ja=!BOOL_OR
  (CF,ZF)、jb=CF 等;修正旧错位偏移(ZF 0x201→0x206 等)与旧简化条件
  (jl 只用 SF、jge 只用 !SF 等);新增 js/jns/jo/jno/jp/jnp(此前完全未
  处理,js/jns 在 httpd 语料 47 处,直接丢控制流)。
- cmp 与 jcc 的偏移修正必须原子落地:cmp 写 0x206 而 je 读 0x201 会断链。
- 双侧投影:17 个 jcc/cmp/test/logic 形态 op-for-op MATCH(探针
  /tmp/w-iced-flagprobe8.out vs flagprobe6 oracle 段)。

### 2026-08-30:X86LIFT-FLAG-PCODE-0001 — sbb/adc(w-iced c3)
- `adc` = ia.sinc `addCarryFlags(op1,op2)` 全加器进位链 + zext + resultflags:
  CFcopy=zext(CF)(size==1 时 COPY)→ CF=INT_CARRY(op1,op2) → OF=INT_SCARRY
  → result=INT_ADD(op1,op2) → CF=BOOL_OR(CF,INT_CARRY(result,CFcopy)) →
  OF=BOOL_XOR(OF,INT_SCARRY(result,CFcopy)) → dst=INT_ADD(result,CFcopy)。
- `sbb` = `subCarryFlags(op1,op2)` 同构(INT_LESS/INT_SBORROW/INT_LESS/
  BOOL_OR/INT_SBORROW/BOOL_XOR/INT_SUB)。
- 此前两族完全未实现(0 op,直接丢指令)。双侧投影:adc(16 op)/
  sbb(15 op)op-for-op MATCH(flagprobe9)。

### 2026-08-30:X86LIFT-FLAG-PCODE-0001 — cmovcc/setcc(w-iced c4)
- `cmovCC` = ia.sinc `:CMOV^cc Reg,rm`(ia.sinc:3043-3046)`{ local tmp = rm;
  if (!cc) goto inst_next; Reg = tmp; }`:cc 条件 op 序 → tmp(COPY 源寄存器
  /LOAD 源内存)→ 32-bit dst 旧值 INT_ZEXT 进父寄存器 → BOOL_NEGATE(cond) →
  CBRANCH(inst_next,!cc) → COPY dst←tmp。此前完全未实现(0 op;httpd 语料
  90 处)。
- `setCC` = ia.sinc `:SET^cc rm8`(ia.sinc:4595)`{ rm8 = cc; }`:cc 条件 op
  序 → COPY dst:1←cond(reg dst)/STORE(addr,cond)(mem dst)。此前完全未
  实现(0 op;httpd 语料 90 处)。
- 复用 emit_cc_cond(与 jcc 同一 cc 表);双侧投影 11 个采样变体 op-for-op
  MATCH(flagprobe10),其余变体走同一代码路径。

### 2026-08-30:X86LIFT-ZEROOP-ARMS — pop/movzx/movsx/movsxd/cbw-cwde-cdqe/cdq-cqo(w-iced c5,coordinator 扩展)
- 背景(w-zombie 根因链):CBRANCH 目标指令提升为 0 个 p-code op → 边丢弃 →
  僵尸决策块(funcdata 侧合成块修复已入 master);这些目标(0x2e010/0x2e022/
  0x2e06a/0x2e0b9/0x2e0c8)是 movzbl/movslq/pop —— 本提交补齐其提升臂,使
  Ghidra 侧 LAB_0012e022 形态的标签区域获得真实语句而非空投影。
- `pop` = ia.sinc:4215 `local val=0; pop88(val); Rmr=val;`(pop88:`x=*:8 RSP;
  RSP=RSP+8`):COPY val=0(局部死初始化,保 op 序)→ LOAD val=(ram,RSP)→
  INT_ADD RSP+=size → COPY reg=val / STORE addr=val(mem dst)。此前 0 op
  (httpd 语料 1903 处)。
- `movzx`/`movsx`/`movsxd` = ia.sinc:4092-4115 `Reg=zext/sext(rm)`(+32-bit
  dst 的 check_Reg32_dest zext;同尺寸形式(Reg16,rm16 / Reg32,rm32)为
  纯 COPY)。此前 0 op(movzx 462 处 + movsx 13 处)。
- `cbw`/`cwde`/`cdqe` = 累加器 INT_SEXT(cwde 另有 check_EAX_dest zext);
  `cdq`/`cqo` = INT_SEXT 双宽 temp + SUBPIECE 低半 → EDX/RDX(cdq 另有
  check_EDX_dest zext)。此前 0 op(cdqe 18 处、cqo 2 处)。
- 新增 iced REX 低字节寄存器别名 r8l..r15l(iced 在 REX 前缀下用 "r8l"
  而非 "r8b" 命名,此前 movsx eax,r8b 整条丢弃)。
- 双侧投影:pop(4 op)/movsx(2 op)/cdqe(1 op)op-for-op MATCH;movzx 唯一
  差异为地址临时操作数序 (disp,base) vs (base,disp)(INT_ADD 交换律,与
  compute_memaddr 既有形态一致,值等价)。
- 残余:push(push88:mysave=x;RSP-=8;STORE)仍在零-op 状态 — 影响
  httpd 全部函数序言(1385 处),单独 commit 评估爆炸半径后再落。

### 2026-08-30:X86LIFT-PUSH88-0001 — push 全形态(w-push88)
- `push` = ia.sinc :PUSH 构造器族 + `push88` 宏(`RSP = RSP - sizeof(v);
  *:sizeof(v) RSP = v`):所有形态先物化源到局部 val,再 INT_SUB
  `out=RSP:8 in=(RSP:8, const size:8)`,再 `STORE in=(ramconst, RSP:8, val)`。
  按形态(oracle dump,examples/x86push_probe.rs):
  - imm8(6a)/imm32(68):`COPY val:8 ← const sext(imm):8`(0x9c→
    0xffffffffffffff9c);imm16(66 68):`COPY val:2 ← const imm:2` 无扩展,
    INT_SUB/STORE 尺寸为 2。
  - reg(50+rd/41 50+rd/FF /6):`COPY val:s ← reg:s`;push rsp 读的是
    INT_SUB **之前**的 RSP(COPY 在前,序言语义正确)。
  - fs/gs(0f a0/a8):`INT_ZEXT val:8 ← seg:2`(FS=register:0x108:2、
    GS=0x10a:2,get_register 新增两段寄存器)。
  - rm 内存(FF /6):地址 op + `LOAD tl:s` + `COPY val:s ← tl:s`。地址
    op 序按 oracle modrm/SIB 两张表**不同序**:modrm-direct [base+d] =
    `INT_ADD(base,d)`(base 在前);SIB([rsp/r12+..] 或带 index)=
    `INT_ADD(d,base)`(disp 在前)、`INT_MULT(idx,scale)`(**scale=1 也
    发射**)、`INT_ADD(t1,t2)`;SIB 无 disp = MULT 先,再 `INT_ADD(base,prod)`;
    SIB 无 base = MULT 先,再 `INT_ADD(d,prod)`;d=0 全部折叠为裸 base/
    product。SIB 判定从 Operand 形状可恢复:index 存在,或 base∈{rsp,r12}
    (rm=100 无 modrm-direct 编码)。新 helper `compute_push_src_addr`
    (独立于 ALU 路径的 compute_mem_addr,后者已有自己的双侧证据)。
  - 常量地址(rip-relative / 绝对 disp-only):**无 LOAD、无地址 op** —
    sla 把常量地址折叠为 ram 空间 varnode 直接作为 COPY 输入
    (`COPY val:s ← ram:abs:s`)。注意 Rugra 反汇编器对 rip 操作数报告的
    displacement 已是解析后的**绝对目标**(探针实证 `ff 35 ..`@0x1036 报
    0x2270=addr+len+delta),直接取用,不可再加 addr+len。
- 双侧证据:examples/x86push_probe.rs 对 33 个合成形态(push imm/reg/mem、
  rsp/rbp 特例、REX、64/32/16-bit、SIB 各形、fs/gs)做 sla 直通 dump vs
  iced 提升的**规范化逐 op 对比**(uniq 临时 id 按首现序规范化),33/33
  PASS,非零退出码作为 fixture 门禁;httpd 语料 1385 处 push 的形态普查
  (imm 23/mem 65/reg 1297)与真实字节 oracle 样本同附。
- E2E 爆炸半径(评估结论):curl(SLEIGH 路径)**字节不变**(3119/0/0,
  cmp 同零);cargo test 失败集与 master 完全一致(17 个既有失败);
  httpd(iced 路径)2325/7/0 → 2574/7/0:defects/numbering 不变,skeleton
  +249 全部来自 push STORE/INT_SUB 首次进入 iced 下游管线暴露的**既有**
  缺口(此前 push 0-op 被掩盖):
  1. SP 相对 STORE 未折叠为 stack 槽位(Ghidra 由 spacebase/heritage 将
     `*RSP-k` 重索引进 stack 空间并经 push/pop 数据流死码消除序言),
     Rugra iced 路径以 `*(undefined8*)(in_RSP-8)=..` 指针表达式打印
     (in_RSP 行 52→150);
  2. "analysis" 组内某子步在有 STORE 压力时把 CALL in(0) coderef 替换为
     const:0(FUN_0 症状 63→65,examples/x86push_dbg.rs 前缀二分定位:
     prefix 18→19 即 analysis 组引入);
  3. CAST 插入后 STORE 地址停在 unique(见 dbg 探针 surviving ops)。
  以上均为 coreaction/heritage/varmap 侧缺口,不在本 write-set,待主
  agent 派工;lifter 侧 33/33 op-for-op MATCH 无差异。

### 2026-08-30:X86LIFT-SHIFTS-FLAGS-0001 c1 — shl/sal 全形态 flag pcode(w-shifts)
- `shl`/`sal` 离开旧的 "INT_LEFT→temp→COPY 无 flags" 形态,按锁定 oracle
  `sleigh_specs/x86-64.sla`(12.0.4 语言)逐 op 提升,三种计数编码形态分派
  (`shift_count_form`):
  - **imm 形(C0/C1)**(38 op):`t0:4=INT_AND(imm:4, mask:4)`(mask=
    0x1f,S==8 时 0x3f;imm 原始值,非执行值——eax,33 → 0x21:4 参与运算)
    → `save=COPY(rm)` → 值 op `rm=INT_LEFT(rm,t0)`(reg 直写,无 temp
    链)→ 32-bit GPR 的 INT_ZEXT(zext 在 flag 组**之前**)→ shlflags():
    `CF = count==0 ? CF : SLESS(save<<(count-1),0)` mux、
    `OF = count==1 ? CF^SLESS(rm,0) : OF` mux(rm 为 post-value 读)→
    shiftresultflags():SF/ZF/PF 三组各自 `count!=0` gate mux(count==0
    保留旧 flag),PF=popcount(rm&0xff) 偶校验链。
  - **cl 形(D2/D3)**(同构):`t0:1=INT_AND(CL:1, mask:1)`,count 相关
    const 全 1 字节(imm 形为 4 字节)。
  - **by-one 形(D0/D1)**(短形态,无 count temp):`CF=SLESS(rm,0)` 在值
    op **之前** → `rm=INT_LEFT(rm, const:0x1:4)` → `OF=XOR(CF,SLESS(rm,0))`
    直接写 flag → zext(32-bit,在 OF **之后**)→ SF/ZF/PF 直写无 gate。
  - **mem dst**:地址 op 先于 count-AND 绑定;一个共享 unique slot 被
    每次 rm 重读复用(`t=LOAD; save=COPY(t); t=LOAD; t=shift(t,count);
    STORE`;之后每个 flag 组前重 LOAD 同一 slot)。
  - **形态判别**:CL 操作数 → D2/D3;imm≠1 → C0/C1;imm==1 用 by-one
    规范编码长度精确算术判别(by-one 编码恒比 imm8 编码短 1 字节:
    `shl eax,1` D1=2 字节,C1=3 字节)。**已知限制**(已披露):反汇编器
    从不填充 `Instruction.bytes`(x86_64.rs:51),非规范 disp32 冗余编码
    的 by-one 形态会回退 imm 形;根修 = 在 x86_64.rs 填充 bytes/iced
    `code()`(不在本任务 write-set)。
- 新 helper:`lift_shift`/`shift_count_form`/`shift_byone_len`/`gpr_id`/
  `emit_load_slot`(slot 复用 LOAD)/`push_raw`、类型 `ShiftDir`/`ShiftCount`。
- 双侧证据:examples/x86shift_probe 56 形态矩阵,SLEIGH 直通 dump vs iced
  投影规范化逐 op 对比(uniq 临时 id 按首现序规范化)——29/29 shl 形态
  MATCH(/tmp/w-shifts-dump-sleigh.out / w-shifts-compare-c1.out);
  shr/sar 暂留旧臂至 c2/c3。

### 2026-08-30:X86LIFT-SHIFTS-FLAGS-0001 c2 — shr 全形态(w-shifts)
- `shr` 路由到 lift_shift(ShiftDir::Right),同 shl 三计数形态分派:
  - imm/cl 形:CF 位 = `INT_NOTEQUAL(INT_AND(save >> (count-1), 1), 0)`
    (shl 是 INT_SLESS);**OF = count==1 ? SLESS(save,0) : OF 读保存的原始
    值**(shl 读 post-value 新值);值 op INT_RIGHT。
  - by-one 形:`t0=INT_AND(rm,1:S); CF=INT_NOTEQUAL(t0,0:S)` 直写;**8-bit
    时 CF 由 INT_AND 直接输出**(dump `-- shr al,1` [0]、`-- shr byte
    [rbx],1` [1]);`OF=COPY(0)` 在值 op **之前**;SF/ZF/PF 直写无 gate。
- 双侧证据:14/14 shr 形态 MATCH(累计 43/58;14 个 sar 留旧臂;1 个
  index-address 形态带 w-iced F5 地址 op 序残差——44 个 shift 语义 op
  全 MATCH,仅 3-op 地址前缀异序,compute_mem_addr SIB 序,另行任务)。

### 2026-08-30:X86LIFT-SHIFTS-FLAGS-0001 c3 — sar 全形态 + 旧 shift 臂移除(w-shifts)
- `sar` 路由到 lift_shift(ShiftDir::Arith),旧的内联 value-only shift
  臂(临时 temp+COPY 无 flags,mem 操作数二次地址计算)整体删除。
  - imm/cl 形:CF 位与 shr 同构(`INT_AND(save >>>(count-1),1)` + 
    NOTEQUAL);**OF = OF & (count != 1)**——直接 `INT_AND` 输出到 OF
    flag 寄存器(dump `-- sar al,3` [14]),无 mux 无 temp;值 op
    INT_SRIGHT。
  - by-one 形:与 shr 同构(CF=AND(rm,1)/NOTEQUAL 直写,OF=COPY(0) 在值
    op 前,SF/ZF/PF 直写)。
- 双侧证据:14/14 sar 形态 MATCH;最终 57/58(唯一 MISMATCH =
  `shr dword [rbx+rcx*4+8],cl` 的 3-op 地址前缀序,w-iced F5 既有残差
  的 SIB 分支,44 个 shift 语义 op 全同;修复路径已在 w-push88 的
  compute_push_src_addr 双表序证实,建议另立 compute_mem_addr 任务)。

### 2026-09-01:X86LIFT-FLAG-PCODE-0001 ext-c1 — rol/ror 全形态 rotate flag pcode(w-x86flags)
- `rol`/`ror` 此前走 `_ => {}` 零 op 臂(httpd 语料 77 处,全部丢弃);按锁定
  oracle `sleigh_specs/x86-64.sla`(12.0.4 语言,sleigh_shim 直通 dump
  /tmp/w-ext-rol.out + /tmp/w-ext-ror.out,26 形态)逐 op 补齐
  (`lift_rotate`/`RotDir`):
  - **imm 形(C0/C1)**:`t0:4=INT_AND(imm:4,(bits-1):4)`(mask=
    7/15/0x1f/0x3f 按位宽;操作数序 (imm,mask))→ 值 `rm=INT_OR(rm<<c,
  rm>>(bits-c))`(rol)或 `INT_OR(rm>>c, rm<<(bits-c))`(ror),`tsub=
    INT_SUB(const bits:4, t0)` → **8/16-bit 形态在值段之后**再算
    `cf1:1=INT_AND(imm:1,0x1f:1)` 作 flag count;32/64-bit 直接复用 t0:4。
  - **cl 形(D2/D3)**:`t0:1=INT_AND(CL:1,(bits-1):1)`;8/16-bit **先**算
    `cf1:1=INT_AND(CL:1,0x1f:1)`(在值段之前,与 imm 形态的时序相反);
    32/64-bit 单 AND 复用。tsub 为 1 字节宽。
  - **flag 组**:CF mux `count!=0 ? (rol: rm&1 / ror: rm s<0) : CF`;
    OF mux `count==1 ? (rol: CF^SLESS(rm,0) / ror: SLESS(rm,0)^
    SLESS(rm<<1,0)) : OF`(rm<<1 的 shift const 恒 1:4);AND/OR mux 结构
    与 shift 组相同。
  - **by-one 形(D0/D1)**:rol = `CF=SLESS(rm,0)`(值 op 前)→
    `rm=(rm<<1)|CF`(8-bit CF 直连,更宽 zext(CF):W)→ `OF=XOR(CF,
    SLESS(rm,0))`;ror = `CF=rm&1`(8-bit AND 直写 CF,更宽 AND:W+
    NOTEQUAL)→ `rm=(rm>>1)|(CF<<(bits-1):4)`(8-bit CF 直连)→
    `OF=XOR((rm&second-top)!=0, SLESS(rm,0))`(second-top mask =
    0x40/0x4000/0x40000000/0x4000000000000000,按操作数宽度)。
  - **mem dst**:一个共享 unique slot,每次 rm 读前重 LOAD(与 shift 组
    同构);值 op OR 进 slot 后 STORE。
  - 32-bit GPR dst 的 zext 在**所有 flag op 之后**(与 shift imm 形态
    zext-before-flags 相反)。
- 双侧证据:examples/x86ext_probe(EXTPROBE_FAMILY=rol|ror,
  EXTPROBE_MODE=compare)22/22 rol + 15/15 ror 形态 MATCH
  (reg/mem × 8/16/32/64 × imm/cl/by-one,ax/ah 高位形,ax,17 mask 边界,
  rol eax,0 count==0 边界,REX.R r9w,SIB mem+cl)。
- E2E:httpd 骨架 2274/0/0 与 master 基线(a31db12c)**字节级一致**
  (77 处 rol 所在函数不在当前 29 函数对比窗口,零回归);curl sha256
  ff6bef47 字节不变。

### 2026-09-01:X86LIFT-FLAG-PCODE-0001 ext-c2 — imul 全形态 CF/OF(w-x86flags)
- `imul` 此前零 op(httpd 69 处:3-op imm 形为主,含 dst≠src;1-op;2-op);
  按锁定 oracle dump(/tmp/w-ext-imul.out,20 形态)逐 op 补齐
  (`lift_imul`/`lift_imul_two_op`/`lift_imul_three_op`/
  `lift_imul_one_op`/`imul_bind_rm`/`imul_read_rm`):
  - 统一 flag 链:双宽乘积 `p:D=INT_MULT(sext(op1):D, sext(op2):D)`
    (D=2W)→ `CF=INT_NOTEQUAL(sext(result):D, p)` → `OF=COPY(CF)`;
    SF/ZF/PF 不动。
  - **2-op(0F AF)**:s0=sext(dst) 先,rm 后读;W==8 值 op =
    `INT_MULT(dst, rm 重读)` 直写,W<8 值 op = `SUBPIECE(p,0)`;每形态
    带一个 dead `SUBPIECE(p,W):W`;W==4 末尾 parent zext。
  - **3-op(69/6B)**:iced 把 dst==src 折叠成 2 操作数 → 以 (dst,imm)
    识别;src 先读;**6B 编码(iced imm size 1)的 imm 常量在操作数宽度
    W(64-bit 即 const:8),69 编码在编码宽度(:4/:2)**;W==8 值 op =
    `INT_MULT(src 重读, ext)`,ext = 6B ? const:8 : sext(const):8;
    W<8 = SUBPIECE(p,0)。
  - **1-op(F6/F7 /5)**:AX 族累加器;W==1 特例 `INT_MULT(s0,s1)` 直写
    AX:2 且 `CF=sext(AL):2 != AX`(无 SUBPIECE);W==8 =
    `acc=INT_MULT(acc,rm)` + `RDX=SUBPIECE(p,8)`;W==4 高半先
    (`EDX=SUBPIECE(p,4);RDX=zext;EAX=SUBPIECE(p,0);RAX=zext`);
    W==2 = `DX=SUBPIECE(p,2);AX=SUBPIECE(p,0)`。
  - mem rm:一个共享 unique slot,每次读重 LOAD(dump `imul rbx,[rax]`
    [1][4] 全落 unique#1)。
- 双侧证据:examples/x86ext_probe imul 20/20 MATCH(1/2/3-op ×
  8/16/32/64 × reg/mem × imm8/imm32/imm16,REX.R r8)。
- E2E:httpd 2274/0/0 与 master 基线字节级一致(imul 站点在对比窗口
  外,零回归);curl sha256 ff6bef47 不变。

### 2026-09-01:X86LIFT-FLAG-PCODE-0001 ext-c3 — bt/bts/btr/btc 位测试 CF(w-x86flags)
- `bt` 家族此前零 op(httpd 20 处:15 reg,reg bt + 2 btc imm64 + 3 其他);
  按锁定 oracle dump(/tmp/w-ext-{bt,bts,btr,btc}.out,26 形态)逐 op 补齐
  (`lift_bt`/`BtKind`):
  - **reg dst, reg/imm idx**:`c = idx & (bits-1)`(reg 形态在操作数宽度,
    imm 形态双 const 恒 :4,mask=bits-1)→ `sh=rm>>c; b=sh&1` →
    **CF 位置按宽度**:W==8 modify(OR/AND~XOR 1<<c)之后,W<8 之前;
    32-bit GPR modify 形态末尾 parent zext;plain bt 仅 CF 无写回。
  - **mem dst, imm idx**:`c:4 = imm & (bits-1)`;共享 slot 全宽 LOAD;
    W<8 CF 在 modify 前(t=1:W<<c;btr 先 NEGATE 再重 LOAD 再 AND),
    W==8 在 modify 后。
  - **mem dst, reg idx**(位串字节寻址):`s:8=sext(idx)` →
    `sar=s>>3(const:4)` → `addr=base+sar` → `c=idx&7` → 字节 LOAD →
    `(byte>>c)&1`;modify 重 LOAD 新字节 temp 与 `1:1<<c` 组合后 STORE,
    CF 在 STORE 后。**plain bt 的 LOAD/AND(idx,7) 次序与 modify 形态相反**
    (bt [rax],edx [3]=LOAD[4]=AND vs bts [3]=AND[4]=LOAD)。
- 双侧证据:examples/x86ext_probe 8 bt + 7 bts + 5 btr + 6 btc 形态全
  MATCH(reg/mem × imm/reg × 32/64,mask 边界 3Fh,btr 的 NEGATE-重LOAD 序)。
- E2E:httpd 2274/0/0 输出与 master 基线 a31db12c 字节级一致(bt 站点在
  对比窗口外,零回归);curl sha256 ff6bef47 不变。

### 2026-09-01:X86LIFT-FLAG-PCODE-0001 ext-c4 — comiss/ucomiss/comisd/ucomisd(w-x86flags)
- FP 比较家族此前零 op(httpd 37 处,含 25 处 rip-relative);按锁定
  oracle dump(/tmp/w-ext-comis.out,8 形态)逐 op 补齐(`lift_comis` +
  `flag_af` + get_register 的 xmm0-15 表):
  - COMISS 与 UCOMIS 的 pcode **完全相同**(两侧都做 FLOAT_NAN):
    `PF=BOOL_OR(NAN(lhs),NAN(rhs))`(0x202)、
    `ZF=INT_OR(PF,FLOAT_EQUAL(lhs,rhs))`(0x206,INT_OR 非 BOOL_OR)、
    `CF=INT_OR(PF,FLOAT_LESS(lhs,rhs))`(0x200)、
    `OF/AF/SF=COPY(0)`(0x20b/0x204/0x207)。
  - 操作数宽度来自助记符后缀(*ss=4,*sd=8)——iced 报 16 字节向量宽,
    oracle 按操作宽度读 XMM 寄存器(register:0x1200+0x40*N,
    xmm8=0x1400 已 dump 验证)。
  - mem rhs:位移形态地址 op 先绑定,共享 slot 每个 float op 前重
    LOAD;**常量地址(rip-relative/纯 displacement)折叠为直接
    ram 空间 varnode 输入,无 LOAD 无地址 op**(dump `comiss
    xmm0,[rip+0]`:FLOAT_NAN in=(ram:0x1c:4))。
- 双侧证据:examples/x86ext_probe comis 8/8 MATCH(reg/mem/xmm8/
  rip-fold/disp-mem/d 形态)。
- E2E:httpd 2274/0/0 输出与 master 基线 a31db12c 字节级一致(comis
  站点在对比窗口外,零回归);curl sha256 ff6bef47 不变。
