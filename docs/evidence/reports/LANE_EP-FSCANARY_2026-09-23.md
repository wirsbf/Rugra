# LANE_EP 终报 — LIFT-FS-CANARY-FORM-0001(wt/fscanary,2026-09-23)

owner: sb-fscanary@wt/fscanary(fixer,自 master 6b0c1b89,ghidra symlink OK)
commits: **f377acda**(lift 修复+docs+probe+单测)/ **d8462dbf**(TODO DONE+移交行)
oracle pin: ghidra HEAD = e40ed130… 复核通过(hook gate health OK)

## 形态差根因(一句话)

iced 提升路径在 `Operand::Memory` 上**没有 segment 字段**——`mov %fs:0x28,%rax`
的段前缀在 disasm 层即被丢弃,lift 成 `LOAD(ram, const 0x28)`,下游 directify
成 persist 全局输入 `uStack_40 = uRam0000000000000028;`;而 oracle(.sla 段寻址
构造器,examples/x86fs_probe.rs 逐 op dump)形为
`INT_ADD tmp = FS_OFFSET(reg:0x110:8), 0x28 → LOAD(3, tmp) → COPY rax`
(段基为第一输入;纯绝对位移也**不**折叠成直接 ram varnode)。

## 修复面(f377acda)

- `.sla` register 目录(examples/x86fs_probe.rs dump):FS_OFFSET=0x110:8、
  GS_OFFSET=0x118:8(区别 2 字节选择器 FS=0x108/GS=0x10a);get_register 补
  fs_offset/gs_offset。
- `segment_base`/`apply_segment` helper;`compute_mem_addr` 加 segment 首参
  (12 调用点):尾部 `Some(EA)+seg → INT_ADD(SEG_OFFSET, EA)`、`None+seg →
  裸 SEG_OFFSET`(d==0 折叠约定)。
- `parse_operand`/`parse_dest_operand` Memory 臂同包装;
  `push_source_val` 的 rip/绝对位移直连 ram COPY 捷径与 `lift_comis` 常量地址
  折叠加 `segment.is_none()` 门(oracle `push [fs:0x28]` = INT_ADD+LOAD+COPY
  +RSP-8+STORE)。
- `Operand::Memory.segment: Option<String>`;x86_64 提取自 iced
  `segment_prefix()`(仅 fs/gs;CS/DS/ES/SS 长模式无效)。
- 逐 op 双侧 MATCH(tmp 序号归一):mov-load/store/[fs:rbx]/full-EA/gs/cmp/push
  全一致;FS 前非本项引入的已知形差如实记录(32 位 eax 载入缺尾 INT_ZEXT、
  无段绝对位移 iced 为 LOAD(3,const) 而 oracle 直连 ram COPY)。

## 前后数字(验收)

| 门禁 | pre(EK 6b0c1b89) | post(f377acda) | 判定 |
|---|---|---|---|
| httpd E2E | 2335/0/0 | **2310/0/0** | ✅ 超目标(≤2333)25 |
| curl E2E | 2516/0/0 | **2516/0/0** | ✅ 持平不回退 |
| gcc 审计 | curl 82OK/25FAIL;httpd 6OK/23FAIL | 逐函数 A/B 恒等 | ✅ |
| 三投影(RUGRA_MIRROR=1) | MATCH×3 | **MATCH×3**(335/96457,340/80385,335/130099) | ✅ |
| cargo test --lib | 18 failed(既有集) | 同集逐字+新增 6 过(1664/18/5) | ✅ |

curl 侧说明:curl 主解码走 **SleighLifter**(.sla 直通),本就有 `in_FS_OFFSET`
oracle 形——EK 报告"golden 620 vs Rugra 0"实为 iced/httpd 侧横切;本修复后
curl 唯一字节差 = 2 处 `} while ( true)`→`} while( true)` 空白异形(_start/
glob_set 的尾循环 Block 重分类副作用),骨架归一化与 gcc 审计均不可见(已记
入 x86_lift.md 残余观察)。

## 残余移交(域外,已登记 TODO `FSPEC-UNLOCKEDPROTO-FSINPUT-0001`)

httpd 剥离符号→无原型锁函数把 FS_OFFSET(register:0x110:8)输入**并入默认参数
发现**:main 签名 `void main(long,long,long)`→`(long,long,long,long)`,canary
语句渲染成 `uStack_40 = *(param_2 + 0x28);`(语义错误)+ `int8
in_register_00000110;` 声明(printc 兜底名,表达式解析未用)+ 同义反复形
`if (*(param_3 + 0x28) == *(param_3 + 0x28))`。curl 有 DWARF 原型锁的函数同
下游链路渲染**正确**(`int8 in_FS_OFFSET; iStack_40 = *(int8 *)(in_FS_OFFSET
+ 0x28);`——varmap INPUT 分支+register_xref 0x110:8→FS_OFFSET 已在位)。
Ghidra 参照:x86-64-gcc.cspec 默认模型参数寄存器表不含 FS_OFFSET→oracle 恒走
irregular input→`in_FS_OFFSET`(database.cc:2478);Rugra 疑似按任意输入寄存器
枚举而非模型 possibleinputs 过滤。修域=fspec 原型输入表/varmap 输入符号安装
(被占,本 lane 不写)。验收点:httpd main/ap_fini 出现
`long in_FS_OFFSET;` + `*(long *)(in_FS_OFFSET + 0x28)` 对照 golden 3518/4225。

## 产物与回收

- /dev/shm/rugra-tests/sb-fscanary/:fs_probe{,_fixed}.out(oracle/iced 逐 op
  对照)、curl_fs.c/httpd_fs.c(E2E)、三 .rugra.proj(投影)、test_out.txt、
  commit_msg.txt;**保留**(root 集成复核用)。
- result/:curl_cur.c、httpd_cur.c 已回流(新建 result/ 目录,gitignored)。
- /dev/shm/rugra-targets/sb-fscanary:留 root 集成后统一清扫(车道未集成不回收)。
