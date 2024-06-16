from random import getrandbits, choice

from Cryptodome.Cipher import DES3

from PGPScheme.algorithms.algorithm import Algorithm
from Cryptodome.Random import get_random_bytes

class TripleDes(Algorithm):

    @staticmethod
    def encrypt(key, data):
        iv = get_random_bytes(DES3.block_size)

        cipher = DES3.new(key, DES3.MODE_CFB, iv)

        ciphertext = cipher.encrypt(data)

        return iv + ciphertext

    @staticmethod
    def decrypt(key, encrypted_data):
        iv = encrypted_data[:DES3.block_size]
        ciphertext = encrypted_data[DES3.block_size:]

        cipher = DES3.new(key, DES3.MODE_CFB, iv)

        encrypted_data = cipher.decrypt(ciphertext)

        return encrypted_data




