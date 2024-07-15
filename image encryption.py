import os
from tkinter import Tk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from tkinter.filedialog import askopenfilename
def generate_key(password, salt):
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    return key
def decrypt_image(encrypted_path, password):
    with open(encrypted_path, 'rb') as file:
        encrypted_data = file.read()
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    tag = encrypted_data[32:48]
    ciphertext = encrypted_data[48:]
    key = generate_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    decrypted_path = encrypted_path.replace(".enc","")
    with open(decrypted_path, 'wb') as file:
        file.write(plaintext)
    return decrypted_path
def browse_file():
    Tk().withdraw()  
    file_path = askopenfilename(title="Select encrypted File", filetypes=[("Encrypted Files", "*.enc")])
    return file_path
password = "securepassword"
print("Select the encrypted file to decrypt:")
encrypted_file_path = browse_file() 
if encrypted_file_path:
    decrypted_path = decrypt_image(encrypted_file_path, password)
    print(f"Decrypted image saved to: {decrypted_path}")
else:
    print("No file selected.")
