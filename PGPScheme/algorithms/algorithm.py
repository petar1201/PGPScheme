from abc import ABC, abstractmethod


class Algorithm(ABC):
    key_session = None
    message = None

    def set_parameters(self, key_session, message):
        self.key_session = key_session
        self.message = message

    @abstractmethod
    def encrypt(self, key, data):
        pass

    @abstractmethod
    def decrypt(self, key, encrypted_data):
        pass