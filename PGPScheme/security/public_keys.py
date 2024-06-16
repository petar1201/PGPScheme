import csv
import time
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class PublicKeyPair:
    __timestamp = None
    __user_id = None
    __public_key = None
    __key_id = None

    def __init__(self, user_id, public_key: RSAPublicKey):
        self.__timestamp = time.time()
        self.__user_id = user_id
        self.__public_key: RSAPublicKey = public_key
        self.__key_id = self.__calc_key_id()

    def __str__(self) -> str:
        return self.__timestamp.__str__() + "|" + self.__user_id + "|" + self.__public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        ).decode() \
             + "|" + self.__key_id.__str__()


    def __calc_key_id(self):
        public_numbers = self.__public_key.public_numbers()
        key_id = public_numbers.n & ((1 << 64) - 1)
        return hex(key_id)

    def get_user_id(self):
        return self.__user_id

    def get_key_id(self):
        return self.__key_id

    def get_public_key(self):
        return self.__public_key


class PublicKeyRingCollection:
    def __init__(self):
        self.key_rings_user_id = {}
        self.key_rings_key_id = {}

    def add_key_pair(self, user_id, public_key):
        key_pair = PublicKeyPair(user_id, public_key)
        self.key_rings_user_id[key_pair.get_user_id()] = key_pair
        self.key_rings_key_id[key_pair.get_key_id()] = key_pair
        return key_pair

    def get_key_pair_by_user_id(self, user_id) -> PublicKeyPair:
        return self.key_rings_user_id.get(user_id)

    def get_key_pair_by_key_id(self, key_id) -> PublicKeyPair:
        return self.key_rings_key_id.get(key_id)

    def delete_key_pair_by_user_id(self, user_id):
        if user_id in self.key_rings_user_id:
            del self.key_rings_user_id[user_id]
            del self.key_rings_key_id[self.key_rings_user_id[user_id].get_key_id()]

    def import_public_key_pairs_from_file(self, filepath):
        with open(filepath, mode='r', newline='') as file:
            reader = csv.reader(file)
            next(reader)
            for row in reader:
                if len(row) == 2:
                    user_id, public_key = row
                    self.add_key_pair(user_id, public_key)


    def get_ring_data(self):
        data = []

        for p, q in self.key_rings_user_id.items():
            val2 = f"{q._PublicKeyPair__key_id[0:2]}0{q._PublicKeyPair__key_id[2:].upper()}"
            val1 = f"{q._PublicKeyPair__key_id[0:2]}{q._PublicKeyPair__key_id[2:].upper()}"

            line = {
                "user_id": f"{p}",
                "timestamp": f"{datetime.fromtimestamp(q._PublicKeyPair__timestamp)}",
                "key_id": f"{val1 if len(q._PublicKeyPair__key_id) == 18 else val2.upper()}",
                "public_key": f"public_key{q._PublicKeyPair__public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1, ).decode()}",
            }
            data.append(line)
        return data

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
                pub_key = serialization.load_pem_public_key(
                    str_key_pair.decode("utf-8").split("|")[3].encode(),
                    backend=default_backend()
                )
                public_key_pair = PublicKeyPair(user_id, pub_key)
                self.key_rings_user_id[user_id.decode()] = public_key_pair
                self.key_rings_key_id[public_key_pair.get_key_id()] = public_key_pair
            except Exception as e:
                if len(pem_block)>1:
                    print(e)
