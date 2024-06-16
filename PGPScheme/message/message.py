import base64
import hashlib
import re
import zlib

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.algorithms import AES

from PGPScheme.algorithms.aes import Aes
from PGPScheme.algorithms.algorithm import Algorithm
from PGPScheme.algorithms.triple_des import TripleDes
from PGPScheme.security.configuration import *
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
import time


class Header:
    def __init__(self, authentication, security, compression, radix, algorithm = ""):
        self.authentication = authentication
        self.security = security
        self.compression = compression
        self.radix = radix
        self.algorithm = algorithm

    def __str__(self):
        return (f"Header(authentication={self.authentication}, security={self.security}, "
                f"compression={self.compression}, radix={self.radix}, "
                f"algorithm={self.algorithm})")

    @classmethod
    def from_string(cls, header_str):
        pattern = rb'Header\(authentication=(.*?), security=(.*?), compression=(.*?), radix=(.*?), algorithm=(.*?)\)'
        match = re.match(pattern, header_str)

        if match:
            authentication = int(match.group(1))
            security = int(match.group(2))
            compression = int(match.group(3))
            radix = int(match.group(4))
            algorithm = match.group(5).decode()
            return cls(authentication, security, compression, radix, algorithm), match.end()
        else:
            raise ValueError(f"String does not match Header format: {header_str}")


class AuthenticationData:
    def __init__(self, passphrase, user_id=None):
        self.user_id = user_id
        self.passphrase = passphrase


class SecurityData:
    def __init__(self, user_id):
        self.user_id = user_id


class Message:
    __header: Header = None
    __message: bytes = None

    __data: str = None
    __file_name: str = None
    __creation_time = None

    __signature_time = None
    __message_digest = None
    __leading_two_octets = None
    __sender_key_id = None

    __session_key = None
    __receiver_key_id = None

    def send(self, data: str, filename: str, header: Header,
             authentication_data: AuthenticationData = None, security_data: SecurityData = None):
        self.__header = header
        self.__data = data
        self.__file_name = filename
        self.__creation_time = time.time()
        self.__message = b"Filename: " + self.__file_name.encode() + b"\n" +\
                         b"Timestamp: " + str(self.__creation_time).encode() + b"\n" +\
                         b"Data: " + self.__data.encode() + b"\n"

        if self.__header.authentication:
            self.authentication(authentication_data.user_id, authentication_data.passphrase)
        if self.__header.compression:
            self.compression()
        if self.__header.security:
            algorithm = object
            if self.__header.algorithm == "3des":
                algorithm = TripleDes()
            else:
                algorithm = Aes()
            self.security(security_data.user_id, algorithm)
        if self.__header.radix:
            self.radix()

        self.__message = self.__header.__str__().encode() + self.__message

        with open(filename, "wb") as file:
            file.write(self.__message)

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
        hash = SHA1.new(self.__message + str(self.__signature_time).encode())
        self.__message_digest = pkcs1_15.new(private_key).sign(hash)
        self.__leading_two_octets = hash.hexdigest()[:2].encode()
        self.__sender_key_id = key_pair.get_key_id()
        self.__message = b"---SignatureSTART---" +\
                         b"Timestamp: " + str(self.__signature_time).encode() + \
                         b"SenderKeyID: " + str(self.__sender_key_id).encode() + \
                         b"LeadingTwoOctets: " + self.__leading_two_octets +\
                         b"MessageDigest: " + self.__message_digest + \
                         b"---SignatureEND---" + \
                         self.__message

    def security(self, user_id, algorithm: Algorithm):
        session_key = key_generator.generate_session_key()

        self.__message = algorithm.encrypt(session_key, self.__message)

        key_pair = public_key_ring_collection.get_key_pair_by_user_id(user_id)
        public_key = key_pair.get_public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        public_key = RSA.import_key(public_pem)

        self.__session_key = PKCS1_OAEP.new(public_key).encrypt(session_key)
        self.__receiver_key_id = key_pair.get_key_id()
        self.__message = b"---START---" +\
                         b"ReceiverKeyID: " + self.__receiver_key_id.encode() +\
                         b"SessionKey: " + self.__session_key + b"---END---" + \
                         self.__message

    def compression(self):
        self.__message = zlib.compress(self.__message)

    def radix(self):
        self.__message = base64.b64encode(self.__message)

    def receive_radix(self):
        self.__message = base64.b64decode(self.__message)

    def receive_secured(self):
        pattern = b'---START---ReceiverKeyID: (.*)SessionKey: (.*)---END---'
        match = re.match(pattern, self.__message, re.S)

        if match:
            end_index = match.end()
            self.__receiver_key_id = match.group(1).decode()
            self.__session_key = match.group(2)
            self.__message = self.__message[end_index:]
        else:
            raise ValueError(f"Can't find ReceiverKeyID and SessionKey")

    def read_secured(self, passphrase):
        key_pair = private_key_ring_collection.get_key_pair_by_key_id(self.__receiver_key_id)
        private_key = key_pair.decrypt_private_key(passphrase)

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        private_key = RSA.import_key(private_pem)
        self.__session_key = PKCS1_OAEP.new(private_key).decrypt(self.__session_key)
        algorithm = None
        if self.__header.algorithm == "3des":
            algorithm = TripleDes()
        else:
            algorithm = Aes()
        self.__message = algorithm.decrypt(self.__session_key, self.__message)

    def read_compressed(self):
        self.__message = zlib.decompress(self.__message)

    def read_authenticated(self):
        pattern = b'---SignatureSTART---' \
                  b'Timestamp: (.*)' \
                  b'SenderKeyID: (.*)' \
                  b'LeadingTwoOctets: (.*)' \
                  b'MessageDigest: (.*)' \
                  b'---SignatureEND---'
        match = re.match(pattern, self.__message, re.S)

        if match:
            end_index = match.end()
            self.__signature_time = match.group(1)
            self.__sender_key_id = match.group(2).decode()
            self.__leading_two_octets = match.group(3)
            self.__message_digest = match.group(4)
            self.__message = self.__message[end_index:]
        else:
            raise ValueError(f"Can't find Signature")

        key_pair = public_key_ring_collection.get_key_pair_by_key_id(self.__sender_key_id)

        public_key = key_pair.get_public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        public_key = RSA.import_key(public_pem)

        hash = SHA1.new(self.__message + self.__signature_time)

        try:
            pkcs1_15.new(public_key).verify(hash, self.__message_digest)
        except (ValueError, TypeError):
            raise ValueError(f"Signature is not valid")

    def receive(self, filename):
        with open(filename, "rb") as file:
            self.__message = file.read()
            self.__header, end_index = Header.from_string(self.__message)
            self.__message = self.__message[end_index:]
            if self.__header.radix:
                self.receive_radix()
            if self.__header.security:
                self.receive_secured()
                return True, self.__receiver_key_id

            return False, None

    def read(self, passphrase=None):
        if self.__header.security:
            self.read_secured(passphrase)
        if self.__header.compression:
            self.read_compressed()
        if self.__header.authentication:
            self.read_authenticated()

        pattern = b'Filename: (.*)' \
                  b'Timestamp: (.*)' \
                  b'Data: (.*)'

        match = re.match(pattern, self.__message, re.S)
        if match:
            self.__file_name = match.group(1).decode()
            self.__creation_time = match.group(2)
            self.__data = match.group(3).decode()
            print(self.__data)
        else:
            raise ValueError(f"Can't find Message")


