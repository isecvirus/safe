from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

default_salt = b'\x00' * 18
default_iv = b'\x00' * 16

class AES:
    def __init__(self, password: str, salt: bytes = default_salt, iv: bytes = default_iv):
        self.password = password.encode()
        self.salt = salt
        self.iv = iv
        self.backend = default_backend()

    def encrypt(self, plaintext:bytes) -> bytes:
        cbc = modes.CBC(initialization_vector=self.iv)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=65536,
            backend=default_backend()
        )
        key = kdf.derive(self.password)

        padder = padding.PKCS7(256).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), cbc, backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def decrypt(self, ciphertext:bytes) -> bytes:
        cbc = modes.CBC(initialization_vector=self.iv)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=65536,
            backend=default_backend()
        )
        key = kdf.derive(self.password)

        cipher = Cipher(algorithms.AES(key), cbc, backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(256).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext
