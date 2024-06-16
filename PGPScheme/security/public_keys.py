import csv
import time


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

    def import_public_key_pairs_from_file(self, filepath):
        with open(filepath, mode='r', newline='') as file:
            reader = csv.reader(file)
            next(reader)
            for row in reader:
                if len(row) == 2:
                    user_id, public_key = row
                    self.add_key_pair(user_id, public_key)