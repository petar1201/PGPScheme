from Cryptodome.Cipher import CAST
from Cryptodome.Random import get_random_bytes


class CAST128SessionKeyGenerator:
    def __init__(self, initial_key):
        self.initial_key = initial_key
        self.session_key = initial_key

    def generate_session_key(self, message_block):
        cipher = CAST.new(self.session_key, CAST.MODE_CFB, iv=get_random_bytes(CAST.block_size))
        encrypted_block = cipher.encrypt(message_block)
        self.session_key = encrypted_block
        return self.session_key


def generate_initial_key():
    return get_random_bytes(16)


def get_message_block():
    return get_random_bytes(8) + get_random_bytes(8)
