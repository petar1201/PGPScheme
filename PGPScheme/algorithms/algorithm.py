from abc import ABC, abstractmethod


class Algorithm(ABC):

    @staticmethod
    def encrypt(key_session, message):
        pass

    @staticmethod
    def decrypt(key, encrypted_data):
        pass