import time
from Cryptodome.Cipher import CAST
from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from datetime import datetime


class PrivateKeyPair:

    def __init__(self, name, email, passphrase, key_size, import_key=""):
        if import_key == "":
            self.__timestamp = time.time()
            self.__user_id = email + "|" + name
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )

            self.__public_key = private_key.public_key()
            self.__key_id = self.__calc_key_id()
            self.__encrypted_private_key = self.encrypt_private_key(passphrase, private_key)
        else:
            timestamp, user_id, name, public_key, encr_priv_key, key_id = import_key.split("|")
            self.__timestamp = datetime.fromtimestamp(float(timestamp)).timestamp()
            self.__user_id = user_id + "|" + name
            self.__encrypted_private_key = encr_priv_key
            self.__public_key = serialization.load_pem_public_key(
                public_key.encode(),
                backend=default_backend()
            )
            self.__key_id = self.__calc_key_id()

    def __delete__(self, instance):
        return

    def __str__(self) -> str:
        return self.__timestamp.__str__() + "|" + self.__user_id + "|" + self.__public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        ).decode() \
            + "|" + self.__encrypted_private_key.__str__() + "|" + self.__key_id.__str__()

    def __calc_key_id(self):
        public_numbers = self.__public_key.public_numbers()
        key_id = public_numbers.n & ((1 << 64) - 1)
        return hex(key_id)

    def get_key_id(self):
        return self.__key_id

    def get_user_id(self):
        return self.__user_id

    def get_public_key(self):
        return self.__public_key

    @staticmethod
    def __get_cast_key_from_passphrase(passphrase):
        passphrase_bytes = passphrase.encode()
        hash_obj = SHA1.new(passphrase_bytes)
        hash_bytes = hash_obj.digest()
        cast_key = hash_bytes[:16]
        return cast_key

    def encrypt_private_key(self, passphrase, private_key):
        cast_key = self.__get_cast_key_from_passphrase(passphrase)

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        iv = get_random_bytes(CAST.block_size)
        cipher = CAST.new(cast_key, CAST.MODE_CFB, iv)
        ciphertext = cipher.encrypt(private_pem)

        encrypted_private_key = base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')
        return encrypted_private_key

    def decrypt_private_key(self, passphrase):
        decoded = base64.urlsafe_b64decode(self.__encrypted_private_key.encode("utf-8"))

        iv = decoded[:CAST.block_size]
        ciphertext = decoded[CAST.block_size:]

        cast_key = self.__get_cast_key_from_passphrase(passphrase)

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
        self.key_rings_user_id = {}
        self.key_rings_key_id = {}

    def add_key_pair(self, name, email, passphrase, key_size):
        key_pair = PrivateKeyPair(name, email, passphrase, key_size)
        self.key_rings_user_id[key_pair.get_user_id()] = key_pair
        self.key_rings_key_id[key_pair.get_key_id()] = key_pair

        return key_pair

    def delete_key_pair(self, name, email):
        if self.key_rings_user_id.keys().__contains__(email + "|" + name):
            del self.key_rings_key_id[self.key_rings_user_id[email + "|" + name].get_key_id()]
            del self.key_rings_user_id[email + "|" + name]
            return
        raise KeyError

    def get_key_pair_by_user_id(self, user_id) -> PrivateKeyPair:
        return self.key_rings_user_id.get(user_id)

    def get_key_pair_by_key_id(self, key_id) -> PrivateKeyPair:
        return self.key_rings_key_id.get(key_id)

    def delete_key_pair_by_user_id(self, user_id):
        if user_id in self.key_rings_user_id:
            del self.key_rings_user_id[user_id]

    def __calc_key_id(self, pub_key):
        public_numbers = pub_key.public_numbers()
        key_id = public_numbers.n & ((1 << 64) - 1)
        return hex(key_id)

    def export_key_ring_to_pem(self, pem_file_path):
        if not self.key_rings_user_id:
            raise ValueError("Key ring is empty, nothing to export.")

        with open(pem_file_path, "wb") as pem_file:
            for user_id, key_pair in self.key_rings_user_id.items():
                try:
                    pem_file.write(
                        f"---BEGIN---{user_id};{key_pair.__str__()}---END---\n".encode("utf-8")
                    )
                except Exception as e:
                    print(f"Failed to export key for user_id {user_id}: {e}")

    def import_key_ring_from_pem(self, pem_file_path):
        with open(pem_file_path, "rb") as pem_file:
            pem_data = pem_file.read()

        pem_blocks = pem_data.split(b"---END---\n")
        for pem_block in pem_blocks:
            try:
                user_id, str_key_pair = pem_block[11:-9].split(b";")
                self.key_rings_user_id[user_id.decode()] = PrivateKeyPair("", "", "", 2048,
                                                                          str_key_pair.decode("utf-8"))

                key_id = self.__calc_key_id(serialization.load_pem_public_key(
                    str_key_pair.decode("utf-8").split("|")[3].encode(),
                    backend=default_backend()
                ))
                self.key_rings_key_id[key_id] = PrivateKeyPair("", "", "", 2048, str_key_pair.decode("utf-8"))
            except Exception as e:
                if len(pem_block) > 1:
                    print(e)

    def get_ring_data(self):
        data = []

        for p, q in self.key_rings_user_id.items():
            val2 = f"{q._PrivateKeyPair__key_id[0:2]}0{q._PrivateKeyPair__key_id[2:].upper()}"
            val1 = f"{q._PrivateKeyPair__key_id[0:2]}{q._PrivateKeyPair__key_id[2:].upper()}"

            line = {
                "user_id": f"{p}",
                "timestamp": f"{datetime.fromtimestamp(q._PrivateKeyPair__timestamp)}",
                "key_id": f"{val1 if len(q._PrivateKeyPair__key_id) == 18 else val2.upper()}",
                "public_key": f"public_key{q._PrivateKeyPair__public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1, ).decode()}",
                "encrypted_private_key": f"{q._PrivateKeyPair__encrypted_private_key}"}
            data.append(line)
        return data
