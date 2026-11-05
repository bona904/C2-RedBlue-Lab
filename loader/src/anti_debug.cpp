#include "anti_debug.h"
#include <windows.h>

// 手动定义 PEB 结构体（因为官方头文件里没包含）
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
} PEB, *PPEB;

bool IsDebuggerAttached() {
    // 方法1：Windows API 基础检测
    if (IsDebuggerPresent()) {
        return true;
    }

    // 方法2：读取 PEB 的 BeingDebugged 标志
    BOOL isDebugged = FALSE;
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (pPeb && pPeb->BeingDebugged) {
        return true;
    }

    return false;
}