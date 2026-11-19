# cmake/embed_text.cmake
#
# 把任意文本/二进制文件转成一个 C++17 的 inline constexpr char 数组头文件。
# 通过 cmake -DSRC=... -DDST=... -DVAR=... -P embed_text.cmake 调用，
# 通常被 add_custom_command 包起来，由 ui_core_embed_text() 高层函数生成。
#
# 输出形如：
#   #pragma once
#   inline constexpr char k_app_uix[] = {
#       (char)0x3c, (char)0x21, ...,
#       (char)0x00      // C 字符串结束符，方便直接传给吃 const char* 的 API
#   };
#   inline constexpr unsigned k_app_uix_size = sizeof(k_app_uix) - 1;

if(NOT SRC OR NOT DST OR NOT VAR)
    message(FATAL_ERROR
        "Required: -DSRC=<input> -DDST=<output> -DVAR=<symbol_name>")
endif()
if(NOT EXISTS "${SRC}")
    message(FATAL_ERROR "embed_text: source not found: ${SRC}")
endif()

file(READ "${SRC}" hex HEX)
string(LENGTH "${hex}" hexLen)
math(EXPR byteCount "${hexLen} / 2")

# 每 12 字节换一行，批量转换避免逐字节复制已经生成的内容。
string(REPEAT "[0-9a-f][0-9a-f]" 12 line)
string(REGEX REPLACE "(${line})" "\\1\n    " lines "${hex}")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "(char)0x\\1, " body "${lines}")
string(REPLACE ", \n" ",\n" body "${body}")

file(WRITE "${DST}"
    "#pragma once\n"
    "// AUTO-GENERATED — do not edit\n"
    "// source: ${SRC}\n"
    "// bytes:  ${byteCount} (excluding terminator)\n\n"
    "inline constexpr char ${VAR}[] = {\n    "
    "${body}(char)0x00\n};\n"
    "inline constexpr unsigned ${VAR}_size = sizeof(${VAR}) - 1;\n")
