import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
def generate_key(password, salt):
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    return key
def encrypt_image(image_path, password):
    with open(image_path, 'rb') as file:
        plaintext = file.read()
    salt = get_random_bytes(16)
    key = generate_key(password.encode(), salt)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encrypted_path = image_path + '.enc'
    with open(encrypted_path, 'wb') as file:
        file.write(salt + iv + tag + ciphertext) 
    return encrypted_path
def browse_file():
    Tk().withdraw()  
    file_path = askopenfilename(title="Select Image File", filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp *.gif")])
    return file_path
password = "securepassword"
print("Select the image file to encrypt:")
image_path = browse_file()
if image_path:
    encrypted_path = encrypt_image(image_path, password)
    print(f"Encrypted image saved to: {encrypted_path}")
else:
    print("No file selected.")
