#pragma once
#ifndef FILEENCRYPTORDLL_H
#define FILEENCRYPTORDLL_H

#ifdef FILEENCRYPTORDLL_EXPORTS
#define FILEENCRYPTORDLL_API __declspec(dllexport)
#else
#define FILEENCRYPTORDLL_API __declspec(dllimport)
#endif

#include <windows.h>

// C linkage for export functions
#ifdef __cplusplus
extern "C" {
#endif

    // Core encryption/decryption functions with original names (for internal use)
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorEncryptFileA(LPCSTR filePath);
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorEncryptFileW(LPCWSTR filePath);
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorDecryptFileA(LPCSTR filePath, const BYTE* key, const BYTE* iv);
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorDecryptFileW(LPCWSTR filePath, const BYTE* key, const BYTE* iv);
    FILEENCRYPTORDLL_API VOID WINAPI StartEncryption(void);
    // Helper functions
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorInitialize(void);
    FILEENCRYPTORDLL_API VOID WINAPI FileEncryptorCleanup(void);
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorGetLastError(LPWSTR buffer, DWORD bufferSize);

#ifdef __cplusplus
}
#endif

// Convenience macros for easier usage (only in C++ and for the prefixed functions)
#ifdef __cplusplus
#ifdef UNICODE
#define FileEncryptorEncryptFile FileEncryptorEncryptFileW
#define FileEncryptorDecryptFile FileEncryptorDecryptFileW
#else
#define FileEncryptorEncryptFile FileEncryptorEncryptFileA
#define FileEncryptorDecryptFile FileEncryptorDecryptFileA
#endif
#endif // __cplusplus

#endif // FILEENCRYPTORDLL_H