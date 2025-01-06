import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from tkinter import Tk, filedialog, simpledialog, messagebox
import base64
import secrets

# Function to derive a key from a password
def derive_key(password, salt, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a file
def encrypt_file(file_path, password):
    try:
        # Generate a random salt and IV
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)

        # Derive the encryption key
        key = derive_key(password, salt)

        # Read the file data
        with open(file_path, 'rb') as file:
            data = file.read()

        # Pad the data
        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted file
        encrypted_file = file_path + ".enc"
        with open(encrypted_file, 'wb') as file:
            file.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", f"File encrypted successfully: {encrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

# Function to decrypt a file
def decrypt_file(file_path, password):
    try:
        # Read the encrypted file
        with open(file_path, 'rb') as file:
            data = file.read()

        # Extract the salt, IV, and encrypted data
        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        # Derive the decryption key
        key = derive_key(password, salt)

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # Save the decrypted file
        decrypted_file = file_path.rstrip(".enc")
        with open(decrypted_file, 'wb') as file:
            file.write(data)

        messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Function to open a file for encryption
def open_file_encrypt():
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if file_path:
        password = simpledialog.askstring("Password", "Enter a password for encryption:", show="*")
        if password:
            encrypt_file(file_path, password)

# Function to open a file for decryption
def open_file_decrypt():
    file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    if file_path:
        password = simpledialog.askstring("Password", "Enter the password for decryption:", show="*")
        if password:
            decrypt_file(file_path, password)

# GUI setup
def create_gui():
    root = Tk()
    root.title("Advanced Encryption Tool")
    root.geometry("300x150")

    encrypt_button = filedialog.Button(root, text="Encrypt File", command=open_file_encrypt)
    encrypt_button.pack(pady=10)

    decrypt_button = filedialog.Button(root, text="Decrypt File", command=open_file_decrypt)
    decrypt_button.pack(pady=10)

    exit_button = filedialog.Button(root, text="Exit", command=root.quit)
    exit_button.pack(pady=10)

    root.mainloop()

# Entry point
if __name__ == "__main__":
    create_gui()
