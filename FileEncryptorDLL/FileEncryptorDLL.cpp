#include "pch.h"
#define WIN32_LEAN_AND_MEAN
// Remove this line - FILEENCRYPTORDLL_EXPORTS should be defined in project settings only
// #define FILEENCRYPTORDLL_EXPORTS
#include "FileEncryptorDLL.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <time.h>
#include <sys/timeb.h>
#include <shlobj.h> 

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "shell32.lib")

// Global paths
TCHAR g_desktopPath[MAX_PATH] = { 0 };
TCHAR g_appFolderPath[MAX_PATH] = { 0 };
TCHAR g_logsFolderPath[MAX_PATH] = { 0 };
TCHAR g_encryptFolderPath[MAX_PATH] = { 0 };

// Forward declarations for internal functions
BOOL InternalEncryptFile(LPCTSTR filePath, BYTE* key, BYTE* iv);
BOOL InternalDecryptFile(LPCTSTR filePath, BYTE* key, BYTE* iv);
void ScanAndEncryptFiles(LPCTSTR directory, BYTE* key, BYTE* iv);

// Initialize desktop paths
BOOL InitializeDesktopPaths() {
    // 1. Get Desktop path
    if (SHGetFolderPath(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, g_desktopPath) != S_OK) {
        _tprintf(_T("Failed to get Desktop path\n"));
        return FALSE;
    }

    // 2. Create app folder on Desktop
    _tcscpy_s(g_appFolderPath, MAX_PATH, g_desktopPath);
    _tcscat_s(g_appFolderPath, MAX_PATH, _T("\\FileEncryptor"));

    if (GetFileAttributes(g_appFolderPath) == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectory(g_appFolderPath, NULL)) {
            _tprintf(_T("Failed to create app folder (Error %d)\n"), GetLastError());
            return FALSE;
        }
    }

    // 3. Create logs subfolder
    _tcscpy_s(g_logsFolderPath, MAX_PATH, g_appFolderPath);
    _tcscat_s(g_logsFolderPath, MAX_PATH, _T("\\logs"));

    if (GetFileAttributes(g_logsFolderPath) == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectory(g_logsFolderPath, NULL)) {
            _tprintf(_T("Failed to create logs folder (Error %d)\n"), GetLastError());
            return FALSE;
        }
    }

    // 4. Create encryption source folder
    _tcscpy_s(g_encryptFolderPath, MAX_PATH, g_appFolderPath);
    _tcscat_s(g_encryptFolderPath, MAX_PATH, _T("\\FilesToEncrypt"));

    if (GetFileAttributes(g_encryptFolderPath) == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectory(g_encryptFolderPath, NULL)) {
            _tprintf(_T("Failed to create encryption folder (Error %d)\n"), GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}

// Get log file path with timestamp
void GetLogFilePath(LPTSTR path, size_t size) {
    _tcscpy_s(path, size, g_logsFolderPath);
    _tcscat_s(path, size, _T("\\EncryptLog_"));

    // Add timestamp - corrected version
    struct __timeb64 timebuffer;
    _ftime64_s(&timebuffer);

    TCHAR timeStr[20];
    {
        struct tm tm_time;
        errno_t err = _localtime64_s(&tm_time, &timebuffer.time);
        if (err != 0) {
            _tcscpy_s(timeStr, 20, _T("00000000_000000"));
        }
        else {
            _tcsftime(timeStr, 20, _T("%Y%m%d_%H%M%S"), &tm_time);
        }
    }

    _tcscat_s(path, size, timeStr);
    _tcscat_s(path, size, _T(".txt"));
}

// Internal AES-256 Encryption with CBC mode (modified for Desktop)
BOOL InternalEncryptFile(LPCTSTR filePath, BYTE* key, BYTE* iv) {
    DWORD bytesRead = 0, bytesWritten = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbData = 0;
    PUCHAR pbKeyObject = NULL;
    const DWORD bufferSize = 4096;
    BYTE buffer[bufferSize];
    BYTE encryptedBuffer[bufferSize + 16];
    DWORD encryptedSize = 0;
    BYTE localIv[16];
    BOOL success = FALSE;

    CopyMemory(localIv, iv, 16);

    HANDLE hInFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInFile == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Failed to open input file: %s\n"), filePath);
        return FALSE;
    }

    // Create encrypted file in same directory with .enc extension
    TCHAR outPath[MAX_PATH];
    _stprintf_s(outPath, MAX_PATH, _T("%s.enc"), filePath);

    HANDLE hOutFile = CreateFile(outPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Failed to create output file: %s\n"), outPath);
        CloseHandle(hInFile);
        return FALSE;
    }

    // Rest of encryption logic...
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        _tprintf(_T("Failed to open algorithm provider\n"));
        goto CLEANUP;
    }

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
        _tprintf(_T("Failed to set chaining mode\n"));
        goto CLEANUP;
    }

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject,
        sizeof(DWORD), &cbData, 0) != 0) {
        _tprintf(_T("Failed to get object length\n"));
        goto CLEANUP;
    }

    pbKeyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        _tprintf(_T("Failed to allocate key object\n"));
        goto CLEANUP;
    }

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, 32, 0) != 0) {
        _tprintf(_T("Failed to generate symmetric key\n"));
        goto CLEANUP;
    }

    while (ReadFile(hInFile, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
        if (BCryptEncrypt(hKey, buffer, bytesRead, NULL, localIv, 16, encryptedBuffer,
            sizeof(encryptedBuffer), &encryptedSize, BCRYPT_BLOCK_PADDING) != 0) {
            _tprintf(_T("Encryption failed\n"));
            goto CLEANUP;
        }

        if (!WriteFile(hOutFile, encryptedBuffer, encryptedSize, &bytesWritten, NULL)) {
            _tprintf(_T("Failed to write encrypted data\n"));
            goto CLEANUP;
        }
    }

    success = TRUE;
    if (success) {
        // Verify encrypted file exists before deleting original
        if (GetFileAttributes(outPath) != INVALID_FILE_ATTRIBUTES) {
            // Double-check encrypted file is not empty
            DWORD encryptedSize = GetFileSize(hOutFile, NULL);
            if (encryptedSize != INVALID_FILE_SIZE && encryptedSize > 0) {
                CloseHandle(hInFile); // Must close handle before deletion
                hInFile = INVALID_HANDLE_VALUE;

                if (!DeleteFile(filePath)) {
                    _tprintf(_T("Warning: Failed to delete original file %s (Error %d)\n"),
                        filePath, GetLastError());
                    // Note: Encrypted file still exists
                }
            }
            else {
                _tprintf(_T("Error: Encrypted file is empty, preserving original\n"));
                success = FALSE; // Cancel success status
            }
        }
        else {
            _tprintf(_T("Error: Encrypted file missing, preserving original\n"));
            success = FALSE;
        }
    }

CLEANUP:
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hInFile != INVALID_HANDLE_VALUE) CloseHandle(hInFile);
    if (hOutFile != INVALID_HANDLE_VALUE) CloseHandle(hOutFile);
    return success;
}

// Internal Decrypt function implementation
BOOL InternalDecryptFile(LPCTSTR filePath, BYTE* key, BYTE* iv) {
    // Check if file has .enc extension
    size_t pathLen = _tcslen(filePath);
    if (pathLen < 4 || _tcscmp(filePath + pathLen - 4, _T(".enc")) != 0) {
        _tprintf(_T("File must have .enc extension\n"));
        return FALSE;
    }

    DWORD bytesRead = 0, bytesWritten = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbData = 0;
    PUCHAR pbKeyObject = NULL;
    const DWORD bufferSize = 4096;
    BYTE buffer[bufferSize];
    BYTE decryptedBuffer[bufferSize];
    DWORD decryptedSize = 0;
    BYTE localIv[16];
    BOOL success = FALSE;

    CopyMemory(localIv, iv, 16);

    HANDLE hInFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInFile == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Failed to open encrypted file: %s\n"), filePath);
        return FALSE;
    }

    // Create output file without .enc extension
    TCHAR outPath[MAX_PATH];
    _tcscpy_s(outPath, MAX_PATH, filePath);
    outPath[pathLen - 4] = _T('\0'); // Remove .enc extension

    HANDLE hOutFile = CreateFile(outPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Failed to create output file: %s\n"), outPath);
        CloseHandle(hInFile);
        return FALSE;
    }

    // Initialize BCrypt for decryption
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        _tprintf(_T("Failed to open algorithm provider\n"));
        goto CLEANUP;
    }

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
        _tprintf(_T("Failed to set chaining mode\n"));
        goto CLEANUP;
    }

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject,
        sizeof(DWORD), &cbData, 0) != 0) {
        _tprintf(_T("Failed to get object length\n"));
        goto CLEANUP;
    }

    pbKeyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        _tprintf(_T("Failed to allocate key object\n"));
        goto CLEANUP;
    }

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, 32, 0) != 0) {
        _tprintf(_T("Failed to generate symmetric key\n"));
        goto CLEANUP;
    }

    // Decrypt file
    while (ReadFile(hInFile, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
        if (BCryptDecrypt(hKey, buffer, bytesRead, NULL, localIv, 16, decryptedBuffer,
            sizeof(decryptedBuffer), &decryptedSize, BCRYPT_BLOCK_PADDING) != 0) {
            _tprintf(_T("Decryption failed\n"));
            goto CLEANUP;
        }

        if (!WriteFile(hOutFile, decryptedBuffer, decryptedSize, &bytesWritten, NULL)) {
            _tprintf(_T("Failed to write decrypted data\n"));
            goto CLEANUP;
        }
    }

    success = TRUE;

CLEANUP:
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hInFile != INVALID_HANDLE_VALUE) CloseHandle(hInFile);
    if (hOutFile != INVALID_HANDLE_VALUE) CloseHandle(hOutFile);
    return success;
}

// Modified ScanAndEncryptFiles for Desktop
void ScanAndEncryptFiles(LPCTSTR directory, BYTE* key, BYTE* iv) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind;
    TCHAR searchPath[MAX_PATH];
    FILE* logFile = NULL;
    TCHAR logPath[MAX_PATH];

    // Get log file path
    GetLogFilePath(logPath, MAX_PATH);

    // Open log file
    errno_t fileErr = _tfopen_s(&logFile, logPath, _T("w, ccs=UTF-8"));
    if (fileErr != 0 || logFile == NULL) {
        _tprintf(_T("FATAL: Could not create log file at %s (Error %d)\n"), logPath, fileErr);
        return;
    }

    _tprintf(_T("Log file created at: %s\n"), logPath);

    // Write log header
    struct __timeb64 timebuffer;
    _ftime64_s(&timebuffer);
    TCHAR timeStr[26];
    _tctime_s(timeStr, sizeof(timeStr) / sizeof(TCHAR), &timebuffer.time);

    _ftprintf(logFile, _T("=== File Encryption Log ===\n"));
    _ftprintf(logFile, _T("Started at: %s"), timeStr);
    _ftprintf(logFile, _T("Target directory: %s\n"), directory);
    _ftprintf(logFile, _T("Log file: %s\n\n"), logPath);
    fflush(logFile);

    // Begin directory scan
    _stprintf_s(searchPath, MAX_PATH, _T("%s\\*"), directory);
    hFind = FindFirstFile(searchPath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        _ftprintf(logFile, _T("ERROR: Could not open directory %s (Error %d)\n"), directory, err);
        _tprintf(_T("Could not open directory %s (Error %d)\n"), directory, err);
        fclose(logFile);
        return;
    }

    do {
        if (_tcscmp(findFileData.cFileName, _T(".")) == 0 ||
            _tcscmp(findFileData.cFileName, _T("..")) == 0) {
            continue;
        }

        TCHAR fullPath[MAX_PATH];
        _stprintf_s(fullPath, MAX_PATH, _T("%s\\%s"), directory, findFileData.cFileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            _ftprintf(logFile, _T("Entering directory: %s\n"), fullPath);
            ScanAndEncryptFiles(fullPath, key, iv);
        }
        else {
            _ftprintf(logFile, _T("Encrypting: %s\n"), fullPath);
            _tprintf(_T("Encrypting: %s\n"), fullPath);

            BOOL encryptResult = InternalEncryptFile(fullPath, key, iv);
            _ftprintf(logFile, _T("%s: %s\n"),
                encryptResult ? _T("SUCCESS") : _T("FAILED"),
                fullPath);
            _tprintf(_T("%s: %s\n"),
                encryptResult ? _T("SUCCESS") : _T("FAILED"),
                fullPath);

            fflush(logFile);
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
    _ftprintf(logFile, _T("\n=== Encryption completed ===\n"));
    _ftprintf(logFile, _T("Finished at: %s"), _tctime(&timebuffer.time));
    fclose(logFile);
    FileEncryptorCleanup();
}

// C-style export functions - Only the original function names
extern "C" {

    // Core encryption/decryption functions with original names
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorEncryptFileA(LPCSTR filePath) {
        if (!filePath) return FALSE;

        if (g_desktopPath[0] == 0) {
            InitializeDesktopPaths();
        }

        HCRYPTPROV hProv = 0;
        BYTE key[32] = { 0 };
        BYTE iv[16] = { 0 };

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return FALSE;
        }

        if (!CryptGenRandom(hProv, sizeof(key), key) ||
            !CryptGenRandom(hProv, sizeof(iv), iv)) {
            CryptReleaseContext(hProv, 0);
            return FALSE;
        }
        CryptReleaseContext(hProv, 0);

        WCHAR wFilePath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, filePath, -1, wFilePath, MAX_PATH);

        return InternalEncryptFile(wFilePath, key, iv);
    }

    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorEncryptFileW(LPCWSTR filePath) {
        if (!filePath) return FALSE;

        if (g_desktopPath[0] == 0) {
            InitializeDesktopPaths();
        }

        HCRYPTPROV hProv = 0;
        BYTE key[32] = { 0 };
        BYTE iv[16] = { 0 };

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return FALSE;
        }

        if (!CryptGenRandom(hProv, sizeof(key), key) ||
            !CryptGenRandom(hProv, sizeof(iv), iv)) {
            CryptReleaseContext(hProv, 0);
            return FALSE;
        }
        CryptReleaseContext(hProv, 0);

        return InternalEncryptFile(filePath, key, iv);
    }

    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorDecryptFileA(LPCSTR filePath, const BYTE* key, const BYTE* iv) {
        if (!filePath || !key || !iv) return FALSE;

        if (g_desktopPath[0] == 0) {
            InitializeDesktopPaths();
        }

        WCHAR wFilePath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, filePath, -1, wFilePath, MAX_PATH);

        return InternalDecryptFile(wFilePath, (BYTE*)key, (BYTE*)iv);
    }

    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorDecryptFileW(LPCWSTR filePath, const BYTE* key, const BYTE* iv) {
        if (!filePath || !key || !iv) return FALSE;

        if (g_desktopPath[0] == 0) {
            InitializeDesktopPaths();
        }

        return InternalDecryptFile(filePath, (BYTE*)key, (BYTE*)iv);
    }

    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorInitialize(void) {
        return InitializeDesktopPaths();
    }

    FILEENCRYPTORDLL_API VOID WINAPI FileEncryptorCleanup(void) {
        // Clean up any global resources if needed
        // For now, just clear the paths
        memset(g_desktopPath, 0, sizeof(g_desktopPath));
        memset(g_appFolderPath, 0, sizeof(g_appFolderPath));
        memset(g_logsFolderPath, 0, sizeof(g_logsFolderPath));
        memset(g_encryptFolderPath, 0, sizeof(g_encryptFolderPath));
    }
    FILEENCRYPTORDLL_API VOID WINAPI StartEncryption() {
        // Generate a random key and IV
        HCRYPTPROV hProv = 0;
        BYTE key[32] = { 0 };
        BYTE iv[16] = { 0 };

        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return;
        }

        if (!CryptGenRandom(hProv, sizeof(key), key) || !CryptGenRandom(hProv, sizeof(iv), iv)) {
            CryptReleaseContext(hProv, 0);
            return;
        }

        CryptReleaseContext(hProv, 0);

        // Initialize desktop paths
        if (!InitializeDesktopPaths()) {
            return;
        }

        // Encrypt all files in FilesToEncrypt folder
        ScanAndEncryptFiles(g_encryptFolderPath, key, iv);
    }
    FILEENCRYPTORDLL_API BOOL WINAPI FileEncryptorGetLastError(LPWSTR buffer, DWORD bufferSize) {
        if (!buffer || bufferSize == 0) return FALSE;

        DWORD error = ::GetLastError();
        LPWSTR messageBuffer = NULL;

        DWORD size = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&messageBuffer, 0, NULL);

        if (size && messageBuffer) {
            wcsncpy_s(buffer, bufferSize, messageBuffer, _TRUNCATE);
            LocalFree(messageBuffer);
            return TRUE;
        }
        else {
            swprintf_s(buffer, bufferSize, L"Unknown error code: %d", error);
            return FALSE;
        }
    }

} // extern "C"

// Entry point (console app) - Optional, remove if you only want DLL
#ifdef _CONSOLE
int wmain() {
    // Initialize desktop paths
    if (!InitializeDesktopPaths()) {
        MessageBox(NULL,
            _T("Failed to initialize working directories on Desktop"),
            _T("Error"),
            MB_ICONERROR);
        return 1;
    }

    _tprintf(_T("Place files to encrypt in: %s\n"), g_encryptFolderPath);

    HCRYPTPROV hProv = 0;
    BYTE key[32] = { 0 };
    BYTE iv[16] = { 0 };

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        _tprintf(_T("Error acquiring cryptographic context: %d\n"), GetLastError());
        return 1;
    }

    // Generate random key and IV
    if (!CryptGenRandom(hProv, sizeof(key), key)) {
        _tprintf(_T("Error generating key: %d\n"), GetLastError());
        CryptReleaseContext(hProv, 0);
        return 1;
    }
    if (!CryptGenRandom(hProv, sizeof(iv), iv)) {
        _tprintf(_T("Error generating IV: %d\n"), GetLastError());
        CryptReleaseContext(hProv, 0);
        return 1;
    }

    CryptReleaseContext(hProv, 0);

    // Target the FilesToEncrypt folder on Desktop
    ScanAndEncryptFiles(g_encryptFolderPath, key, iv);

    TCHAR logPath[MAX_PATH];
    GetLogFilePath(logPath, MAX_PATH);

    TCHAR msg[512];
    _stprintf_s(msg, 512, _T("File encryption complete.\nLog file: %s"), logPath);
    MessageBox(NULL, msg, _T("Done"), MB_OK);

    return 0;
}
#endif