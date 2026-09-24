# LANE REPORT — SETCASTS-COPYINPUT-0001 (wt/sb-copyinput)

- commit: **1cd11409** (base master 49c303c4), branch wt/sb-copyinput
- files: src/coreaction.rs (+copy_input_cast & CPUI_COPY dispatch arm),
  src/type_system/cast.rs (cast_standard_full enum metatype norm),
  docs/api/{coreaction,type_system/cast}.md, docs/TODO_BOARD.md
- 语义: TypeOpCopy::getInputCast (typeop.cc:397-403) — reqtype=OUT
  getHighTypeDefFacing, curtype=in0 getHighTypeReadFacing(op),
  castStandard(false,true)。配套 oracle 证据: TypeEnum 全构造路径存
  TYPE_INT/UINT (type.hh:491-494, type.cc:1475) → Enum→Int/PartialEnum→Uint 规范化。
- 三门禁 (亲父 49c303c4 新跑基线, 非陈旧引用):
  - curl 124 fn: 0 defects/0 numbering, skeleton 2689→2665 (-24);
    perfunc 仅 main 621→605 / getparameter 754→748 / file2string.part.0
    125→123 全改善零回退; gcc audit 81OK/26FAIL==基线
  - httpd 29 fn: 0/0, 2331==2331 零漂移 (1 行 puVar10 cast, golden 无对应行)
  - next_url 103 / match_url 76 字节不变 0/0; config 域 6 fn 全 0/0
- lib tests: 18 fail ∈ 基线 19-20 (严格子集; heritage_creation 预存@master)
- 残差: (union_5a7) 名=DWARF-ANON-TYPENAME-0001 (既有);
  (_IO_FILE*)stdout/(undefined8) 符号字段类型态=DWARF-SYMFIELD-TYPESTATE-0001 (新登记)
- 工件: /dev/shm/rugra-tests/sb-copyinput/ (curl_after2.log=httpd_after.log
  为 mine 产物; curl_parent.log/httpd_parent.log 为亲父基线; before_after2.diff;
  perfunc_delta.txt; curl_dump.err=RUGRA_DUMP_FUNC=main IR 证据)
- root 集成后可回收本目录与 target/
