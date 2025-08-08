from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import base64

class SimpleCrypto:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    # RSA encryption
    def rsa_encrypt(self, public_key, aes_key: bytes):
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # RSA decryption
    def rsa_decrypt(self, encrypted_aes_key: bytes):
        return self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # AES (Fernet)
    def generate_aes_key(self):
        return Fernet.generate_key()

    def aes_encrypt(self, key, message: str):
        cipher = Fernet(key)
        return cipher.encrypt(message.encode())

    def aes_decrypt(self, key, token: bytes):
        cipher = Fernet(key)
        return cipher.decrypt(token).decode()

    # HMAC
    def compute_hmac(self, key: str, message: str):
        h = hmac.HMAC(key.encode(), hashes.SHA256(), backend=default_backend())
        h.update(message.encode())
        return base64.urlsafe_b64encode(h.finalize())

    def verify_hmac(self, key: str, message: str, signature: bytes):
        h = hmac.HMAC(key.encode(), hashes.SHA256(), backend=default_backend())
        h.update(message.encode())
        try:
            h.verify(base64.urlsafe_b64decode(signature))
            return True
        except:
            return False
