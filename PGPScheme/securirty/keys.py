import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from datetime import datetime
import base64
import os


class PrivateKeyPair:
    def __init__(self, name, email, passphrase, key_size):
        self.timestamp = time.time()
        self.user_id = email + "|" + name
        self.public_key = 0
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = private_key.public_key()
        self.key_id = self._get_key_id()
        self.encrypted_private_key = self._encrypt_private_key(passphrase, private_key)

        # writeInFile
        self.__str__()

    def __delete__(self, instance):
        return

    def __str__(self) -> str:
        return self.timestamp.__str__() + "|" + self.user_id + "|" + self.public_key.__str__() \
            + "|" + self.encrypted_private_key.__str__() + "|" + self.key_id.__str__()

    def _get_key_id(self):
        public_numbers = self.public_key.public_numbers()
        key_id = public_numbers.n & ((1 << 64) - 1)
        return hex(key_id)


    def _get_cast_key_from_passphrase(self, passphrase):
        # Create a 160-bit hash of the passphrase using SHA-1
        passphrase_bytes = passphrase.encode()
        hash_obj = SHA1.new(passphrase_bytes)
        hash_bytes = hash_obj.digest()
        # Use the first 128 bits (16 bytes)
        cast_key = hash_bytes[:16]
        return cast_key

    def _encrypt_private_key(self, passphrase, private_key):
        # Generate CAST-128 key from passphrase
        cast_key = self._get_cast_key_from_passphrase(passphrase)

        # Serialize the private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Encrypt the private key using CAST-128
        #TODO Which mode do we have to use? CFB?
        cipher = CAST.new(cast_key, CAST.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(private_pem)

        # Concatenate the nonce, tag, and ciphertext for storage
        encrypted_private_key = base64.urlsafe_b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
        return encrypted_private_key

    def _decrypt_private_key(self, passphrase):
        # Decode the stored encrypted private key
        decoded = base64.urlsafe_b64decode(self.encrypted_private_key)

        # Extract the nonce, tag, and ciphertext
        nonce = decoded[:CAST.block_size]
        tag = decoded[CAST.block_size:CAST.block_size + 16]
        ciphertext = decoded[CAST.block_size + 16:]

        # Generate CAST-128 key from passphrase
        cast_key = self._get_cast_key_from_passphrase(passphrase)

        # Decrypt the private key using CAST-128
        cipher = CAST.new(cast_key, CAST.MODE_EAX, nonce=nonce)
        private_pem = cipher.decrypt_and_verify(ciphertext, tag)

        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
        return private_key


class PrivateKeyRingCollection:
    def __init__(self):
        self.key_rings = {}

    def add_key_pair(self, name, email, passphrase, key_size):
        key_pair = PrivateKeyPair(name, email, passphrase, key_size)
        self.key_rings[key_pair.key_id] = key_pair
        return key_pair

    def get_key_pair_by_key_id(self, key_id):
        return self.key_rings.get(key_id)

    def delete_key_pair_by_key_id(self, key_id):
        if key_id in self.key_rings:
            del self.key_rings[key_id]
