import ctypes
import os
import sys

# 自动定位 DLL 路径 (假设在 Windows 下运行，路径为 target/debug/rugra.dll)
script_dir = os.path.dirname(os.path.abspath(__file__))
dll_path = os.path.join(script_dir, "target", "debug", "rugra.dll")

if not os.path.exists(dll_path):
    print(f"错误: 找不到 {dll_path}")
    print("请先在 rugra 目录下运行 'cargo build' 生成动态库。")
    sys.exit(1)

# 加载动态链接库
try:
    lib = ctypes.CDLL(dll_path)
except Exception as e:
    print(f"无法加载 DLL: {e}")
    sys.exit(1)

# 配置函数签名
# pub extern "C" fn rugra_evaluate_constant(...) -> u64
lib.rugra_evaluate_constant.argtypes = [
    ctypes.c_int32,  # opcode
    ctypes.c_size_t, # size_out
    ctypes.c_uint64, # val1
    ctypes.c_size_t, # size1
    ctypes.c_uint64, # val2
    ctypes.c_size_t, # size2
    ctypes.c_bool    # has_val2
]
lib.rugra_evaluate_constant.restype = ctypes.c_uint64

# pub extern "C" fn rugra_version() -> *const c_char
lib.rugra_version.restype = ctypes.c_char_p

def run_tests():
    print(f"Rugra 版本: {lib.rugra_version().decode()}")
    print("=" * 50)
    print(f"{'测试项':<20} | {'结果':<15} | {'状态'}")
    print("-" * 50)

    # Ghidra OpCode 常量 (参考 opcodes.hh)
    CPUI_INT_EQUAL = 11
    CPUI_INT_ADD = 19
    CPUI_INT_SUB = 20
    CPUI_INT_2COMP = 24  # 负号 (-)
    CPUI_INT_NEGATE = 25 # 取反 (~)
    CPUI_INT_MULT = 32

    # 测试用例: (名称, opcode, size_out, v1, s1, v2, s2, has_v2, 预期值)
    test_cases = [
        ("1 + 2 (32-bit)", CPUI_INT_ADD, 4, 1, 4, 2, 4, True, 3),
        ("10 - 3 (32-bit)", CPUI_INT_SUB, 4, 10, 4, 3, 4, True, 7),
        ("5 * 6 (32-bit)", CPUI_INT_MULT, 4, 5, 4, 6, 4, True, 30),
        ("42 == 42", CPUI_INT_EQUAL, 1, 42, 4, 42, 4, True, 1),
        ("42 == 43", CPUI_INT_EQUAL, 1, 42, 4, 43, 4, True, 0),
        ("~0 (32-bit)", CPUI_INT_NEGATE, 4, 0, 4, 0, 0, False, 0xFFFFFFFF),
        ("-1 (32-bit)", CPUI_INT_2COMP, 4, 1, 4, 0, 0, False, 0xFFFFFFFF),
        ("-1 (64-bit)", CPUI_INT_2COMP, 8, 1, 8, 0, 0, False, 0xFFFFFFFFFFFFFFFF),
    ]

    for name, op, sout, v1, s1, v2, s2, has_v2, expected in test_cases:
        result = lib.rugra_evaluate_constant(op, sout, v1, s1, v2, s2, has_v2)
        status = "✅ PASS" if result == expected else f"❌ FAIL (预期 {expected:x}, 实际 {result:x})"
        print(f"{name:<20} | {result:<15x} | {status}")

if __name__ == "__main__":
    run_tests()
