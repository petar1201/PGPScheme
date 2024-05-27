from abc import ABC, abstractmethod


class Algorithm(ABC):
    def __init__(self, key_session, message):
        self.key_session = key_session
        self.message = message

    @abstractmethod
    def encrypt(self):
        pass

    @abstractmethod
    def decrypt(self):
        pass