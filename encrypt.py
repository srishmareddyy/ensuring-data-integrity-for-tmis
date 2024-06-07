from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os

def generate_key():
    return os.urandom(32)  # 256-bit key

def encrypt_message(key, plaintext):
    nonce = os.urandom(12)  # 96-bit nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return (nonce, ciphertext, tag)

def decrypt_message(key, nonce, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

# Example usage
if __name__ == "__main__":
    plaintext = input("Enter the plaintext message: ").encode()

    key = generate_key()

    nonce, ciphertext, tag = encrypt_message(key, plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())

    decrypted_data = decrypt_message(key, nonce, ciphertext, tag)
    print("Decrypted Message:", decrypted_data.decode())
