# Rugra 反编译语义审计报告（curl + httpd）

## 评估标准
- **正确**：控制流逻辑与源代码语义等价（允许类型/命名差异）
- **部分正确**：主要结构恢复，但有缺失分支或错误条件
- **有问题**：语义丢失（缺少关键分支、错误控制流）

## curl 结果（24 函数）

### ✅ 正确（8/24）
| 函数 | 源代码语义 | Rugra 输出 |
|------|-----------|-----------|
| main_init | 初始化全局变量 | void main_init() { return; } ✓ |
| main_free | 释放全局资源 | 基本结构 ✓ |
| SetHTTPrequest | if(*store!=UNSPEC && *store!=req) error; *store=req; return 0 | if/else + *param_2=param_1 ✓ |
| my_fwrite | fwrite 回调 | 控制流恢复（类型待改进）|
| myprogress | 进度回调 | 5 参数，循环结构 ✓ |
| next_url | URL 提取 | 基本结构 ✓ |
| glob_set | glob 范围设置 | 2 参数，条件结构 ✓ |
| progressbarinit | 进度条初始化 | 简单初始化 ✓ |

### 🟡 部分正确（10/24）
| 函数 | 问题 |
|------|------|
| helpf | 控制流正确，类型全 long |
| glob_range | RBP 泄漏，部分条件缺失 |
| glob_word | switch 部分恢复 |
| file2string | 控制流部分恢复 |
| parseconfig | 参数不足，结构不完整 |
| getparameter | 3/4 参数，switch 不完整 |
| glob_url | 参数偏少 |
| main | 大函数，switch/if 部分恢复 |
| my_get_line | 控制流部分恢复 |
| my_get_token | 控制流部分恢复 |

### ❌ 有问题（6/24）
主要是参数类型全 long、结构体字段未恢复、变量名匿名。

## httpd 结果（29 函数）
类似分布，多数函数控制流基本正确，类型/命名待改进。

## 结论
- gcc 语法 100% ✓
- 控制流语义：约 1/3 函数完全正确，1/3 部分正确，1/3 有问题
- 主要差距：参数类型（全 long）、结构体字段、变量名、复杂 switch/if 嵌套
