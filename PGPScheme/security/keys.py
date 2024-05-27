import time
from Cryptodome.Cipher import CAST
from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64


class PrivateKeyPair:
    __timestamp = None
    __user_id = None
    __public_key = None
    __key_id = None
    __encrypted_private_key = None

    def __init__(self, name, email, passphrase, key_size):
        self.__timestamp = time.time()
        self.__user_id = email + "|" + name
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.__public_key = private_key.public_key()
        self.__key_id = self.__calc_key_id()
        self.__encrypted_private_key = self.encrypt_private_key(passphrase, private_key)

        # writeInFile
        self.__str__()

    def __delete__(self, instance):
        return

    def __str__(self) -> str:
        return self.__timestamp.__str__() + "|" + self.__user_id + "|" + self.__public_key.__str__() \
            + "|" + self.__encrypted_private_key.__str__() + "|" + self.__key_id.__str__()

    def __calc_key_id(self):
        public_numbers = self.__public_key.public_numbers()
        key_id = public_numbers.n & ((1 << 64) - 1)
        return hex(key_id)

    def get_key_id(self):
        return self.__key_id

    def get_user_id(self):
        return self.__user_id

    @staticmethod
    def __get_cast_key_from_passphrase(passphrase):
        # Create a 160-bit hash of the passphrase using SHA-1
        passphrase_bytes = passphrase.encode()
        hash_obj = SHA1.new(passphrase_bytes)
        hash_bytes = hash_obj.digest()
        # Use the first 128 bits (16 bytes)
        cast_key = hash_bytes[:16]
        return cast_key

    def encrypt_private_key(self, passphrase, private_key):
        # Generate CAST-128 key from passphrase
        cast_key = self.__get_cast_key_from_passphrase(passphrase)

        # Serialize the private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        iv = get_random_bytes(CAST.block_size)
        cipher = CAST.new(cast_key, CAST.MODE_CFB, iv)
        ciphertext = cipher.encrypt(private_pem)

        # Concatenate the nonce, tag, and ciphertext for storage
        encrypted_private_key = base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')
        return encrypted_private_key

    def decrypt_private_key(self, passphrase):
        # Decode the stored encrypted private key
        decoded = base64.urlsafe_b64decode(self.__encrypted_private_key)

        # Extract the IV and ciphertext
        iv = decoded[:CAST.block_size]
        ciphertext = decoded[CAST.block_size:]

        # Generate CAST-128 key from passphrase
        cast_key = self.__get_cast_key_from_passphrase(passphrase)

        # Decrypt the private key using CAST-128
        cipher = CAST.new(cast_key, CAST.MODE_CFB, iv)
        private_pem = cipher.decrypt(ciphertext)

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
        self.key_rings[key_pair.get_user_id()] = key_pair
        return key_pair

    def get_key_pair_by_user_id(self, user_id) -> PrivateKeyPair:
        return self.key_rings.get(user_id)

    def delete_key_pair_by_user_id(self, user_id):
        if user_id in self.key_rings:
            del self.key_rings[user_id]


