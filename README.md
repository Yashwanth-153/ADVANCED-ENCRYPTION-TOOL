# ADVANCED-ENCRYPTION-TOOL

**COMPANY**     : CODTECH IT SOLUTIONS

**NAME**        : SRIPADHI YASHWANTH

**INTERN ID**   : CT08HZS

**DOMAIN**      : CYBER SECURITY & ETHICAL HACKING

**BATCH DURATION**   : DECEMBER 30th, 2024 to JANUARY 30th, 2025

**MENTOR NAME**      : NEELA SANTHOSH KUMAR

#   DESCRIPTION TOOLS AND LIBRARIES

This Python program is an Advanced Encryption Tool with a graphical user interface (GUI) built using the Tkinter library. Its purpose is to provide file encryption and decryption functionalities using AES encryption. Below is a detailed description of its components and functionality:

*  Key Features

1)  File Encryption:
-->  Encrypts a selected file using a password-based key derivation technique.
-->  The output is a secure file with .enc appended to the filename.

2)  File Decryption:
-->  Decrypts an encrypted file with a .enc extension using the correct password.

3)  Graphical Interface:
-->  Provides a user-friendly GUI for selecting files and entering passwords.
-->  Includes buttons for encryption, decryption, and exiting the application.

*  How It Works
  
1. Key Derivation
-->  A key is derived from a user-provided password using the PBKDF2 (Password-Based Key Derivation Function 2) algorithm with:
-->  SHA256 hash as the base hashing algorithm.
-->  A randomly generated 16-byte salt to ensure uniqueness.
-->  100,000 iterations for computational security.

2. File Encryption
-->  A random IV (Initialization Vector) and salt are generated for secure AES encryption.
-->  The AES encryption is performed in CBC (Cipher Block Chaining) mode.
-->  The file's content is padded using PKCS7 padding to ensure block alignment for AES.
-->  The resulting encrypted file contains the concatenated salt, IV, and encrypted data.

3. File Decryption
-->  Reads the salt and IV from the encrypted file.
-->  Derives the decryption key using the same password and salt.
-->  Decrypts the file using AES-CBC mode and removes the padding.

4. GUI Operations
-->  Encrypt File: Opens a dialog to select a file for encryption and prompts the user for a password.
-->  Decrypt File: Opens a dialog to select an encrypted file and prompts for the decryption password.
-->  Exit: Closes the application.

*  Libraries Used

1)  os: Interacts with the operating system (file paths, etc.).
2)  cryptography.hazmat: Provides secure cryptographic operations for key derivation, encryption, and padding.
3)  tkinter: Implements the graphical user interface for file selection and password input.
4)  secrets: Generates secure random values for salt and IV.

*  Intended Use

-->  This tool is designed for individuals who want to securely encrypt and decrypt files on their system, ensuring data privacy and security through strong cryptographic practices.






