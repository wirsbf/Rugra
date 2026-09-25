# Lane A M1 审计报告(stage projection oracle 生产端)

日期: 2026-09-22 | worktree: wt/sb-oracle @ 59f7507(+本审计修复)
被审对象: tests/oracle/stage_projection_1204.cc(wip 59f7507 版,331 行)
走线产物: /dev/shm/rugra-tests/sb-oracle/m1-events.txt(710 行 = 355 @BEGIN + 355 @END)
          /dev/shm/rugra-tests/sb-oracle/m1-output.txt(6.2MB,含 @SNAP)
规范: stage-bisect-e2e.md「投影格式规范 v1.1」(Gate 1 attempt2 锁定版)

## ① 嵌套交错(规范 iii)— PASS(观测流),restart 路径 latent 缺陷已修

机检(python,严格 LIFO 栈校验):
- 355 个 @BEGIN/@END 事件对全部满足:关闭的 seq 恒为当前打开栈顶(零违例)。
- 根 `@END 1 universal` 是文件最后一行(组未完成时先出子级事件,组 @END 恢复后补发)。
- 组级迟关实例: `@BEGIN 9 …:mainloop` 的 @END 在流位置 ~163(mainloop 多轮遍历后);
  `@BEGIN 8 …:fullloop` 的 @END 在位置 ~326;兄弟组事件按嵌套交错排列,非扁平序。
- 步进逻辑无需为扁平序重构。

**Latent 缺陷(本审计修复,next_url 未触发:0 restart)**:
旧代码 restart 边界 `closeAll` 会把 root(universal)事件提前关掉并在 restart 后以新
seq 重开 — 违反 (iii)(restart 组 apply 仍在栈上,未完成)。修复:restart 分支只关
round-N 尾部事件(root 事件跨 @RESTART 保持打开,最终完成时以累计 count 结束);
closeInactive 对 root 豁免 status 测试(restart 把 root status 置回 status_start,
action.cc:583,但 apply 未返回)。尾部事件 @END 计数器仍有效:
`Action::reset` 只重置 status,不清零 count/count_tests/count_apply
(action.cc:100-105;resetStats 是独立 API,restart 路径不调用)。

## ② seq 全局 1 基连续 — PASS

机检: @BEGIN seq = 1..355 连续无缺口;@END seq 集合与 @BEGIN 完全相等;
每对 seq 的 path 一致(零 mismatch)。42/76 个路径多次出现(repeatapply 组内重遍历,
每次 apply 独立编号,规范 (i))。

## ③ result=完成时刻 Action::count — PASS(实现读法确认)

- 代码路径: endEvent 读 `action->count`(`#define protected public` hack,action.hh
  protected 标签 79/144 行;curstart 经 instrumented accessor,先例
  action_break_pool_1204.cc:561 + run_action_break_pool_oracle.sh:248-252)。
- 根节点 override 为 performResult:等价冗余 — Action::perform 自然完成返回 count
  (action.cc:368),组只 override apply 不 override perform,故组/叶同构。
  实证: `@END 1 universal result=1269 count=1269`。
- tests/apply = getNumTests/getNumApply 差值(action.hh 公开接口)✓。
- 步进系统性 tests=0 已被规范声明(action.cc:306-311 breakstarthit 恢复跳过自增)✓。

## 附带修复

- `d=` 位补 unattached 语义: op.cc:380-381 为 `isDead()||(parent==0)`,
  旧代码只测 isDead;现按引用行语义 `isDead()||getParent()==0`。

## 事件流头部抽查(META 已在 m1-output.txt 就位)

META side=oracle oracle_commit=e40ed130… arch=x86:LE:64:default cspec=gcc
META analysis_options=default build_flags=v1-no-OPACTION_DEBUG
META binary_sha256=8af50bca2f81… func_entry=0x4ff0 func_name=next_url load_mode=single_function_bfd
META producer=m1-test maxrestarts=1 unique_base=0x364200

(producer 旧占位 "m1-test",M2 定稿改为 fixture git blob sha。)
