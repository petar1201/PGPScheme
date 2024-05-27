from Cryptodome.Signature import pkcs1_15
from cryptography.hazmat.primitives import serialization

from PGPScheme.security.configuration import *
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
import time


class Message:
    __message: str = None
    __data: str = None
    __file_name: str = None
    __creation_time = None

    __signature_time = None
    __message_digest = None
    __leading_two_octets = None
    __sender_key_id = None

    def __init__(self, data: str, filename: str):
        self.__data = data
        self.__file_name = filename
        self.__creation_time = time.time()
        self.__message = self.__data + str(self.__creation_time) + self.__file_name

    def authentication(self, user_id, passphrase):
        key_pair = private_key_ring_collection.get_key_pair_by_user_id(user_id)
        private_key = key_pair.decrypt_private_key(passphrase)

        self.__signature_time = time.time()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key = RSA.import_key(private_pem)
        hash = SHA1.new(self.__message.encode() + str(self.__signature_time).encode())
        self.__message_digest = pkcs1_15.new(private_key).sign(hash)
        self.__leading_two_octets = self.__message_digest[:2]
        self.__sender_key_id = key_pair.get_key_id()

        self.__message += str(self.__message_digest) + str(self.__leading_two_octets) + str(self.__sender_key_id) \
            + str(self.__signature_time)

    def security(self, algorithm):
        message_block = get_message_block()
        session_key = key_generator.generate_session_key(message_block)

        #pozvati enkripciju odgovarajucim algoritmom aes ili 3des
        #dohvatiti javni kljuc iz prstena javnih kljuceva za enkripciju kljuca sesije i konkatenirati na poruku

    def compression(self):
        pass

    def radix(self):
        pass