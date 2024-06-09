from random import getrandbits, choice

from PGPScheme.algorithms.algorithm import Algorithm
from Cryptodome.Random import get_random_bytes


class TripleDes(Algorithm):
    INITIAL_PERMUTATION = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    EXPANSION_TABLE = [
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1
    ]

    S_BOX = [
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    PERMUTATION = [
       16,  7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2,  8, 24, 14,
       32, 27,  3,  9,
       19, 13, 30,  6,
       22, 11,  4, 25
    ]

    FINAL_PERMUTATION = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

    SHIFT_TABLE = [
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1]

    PC_2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    __key1 = None
    __key2 = None
    __key3 = None
    plain_text = None
    plain_text_blocks = []

    def __init__(self, session_key, message):
        super(TripleDes, self).__init__(session_key, message)
        self.plain_text = self.message
        self.plain_text = self.string_to_bits(self.plain_text)
        self.key_session = self.bytes_to_bits(self.key_session)
        self.__initial_key_generation()
        self.__pad_plain_text()
        self.__plain_text_2_blocks()

    def __pad_plain_text(self):
        self.padding_length = 64 - len(self.plain_text) % 64 if len(self.plain_text) % 64 != 0 else 0
        self.plain_text += ''.join(choice('01') for _ in range(self.padding_length))

    def __plain_text_2_blocks(self):
        for i in range(len(self.plain_text) // 64):
            self.plain_text_blocks.append(self.plain_text[i * 64: i * 64 + 64])

    def encrypt(self):
        print(self.bin2hex(self.plain_text_blocks[0]))
        self.des_encrypt(self.generate_keys(self.__key1))
        self.des_decrypt(self.generate_keys(self.__key2))
        self.des_encrypt(self.generate_keys(self.__key3))
        print(self.bin2hex(self.plain_text_blocks[0]))

    def decrypt(self):
        self.des_decrypt(self.generate_keys(self.__key3))
        self.des_encrypt(self.generate_keys(self.__key2))
        self.des_decrypt(self.generate_keys(self.__key1))
        print(self.bin2hex(self.plain_text_blocks[0]))

    @staticmethod
    def permute(block, table):
        return ''.join([block[x - 1] for x in table])

    @staticmethod
    def xor(bits1, bits2):
        result = ''.join('1' if bit1 != bit2 else '0' for bit1, bit2 in zip(bits1, bits2))
        return result

    @staticmethod
    def bytes_to_bits(byte_string):
        return ''.join(format(byte, '08b') for byte in byte_string)

    @staticmethod
    def bits_to_bytes(bits):
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = int(''.join(str(bit) for bit in bits[i:i + 8]), 2)
            bytes_data.append(byte)
        return bytes(bytes_data)

    def string_to_bits(self, text):
        bits = ''.join(format(ord(char), '08b') for char in text)
        return bits

    @staticmethod
    def left_shift(bits, shift):
        return bits[shift:] + bits[:shift]

    def s_box_substitution(self, bits):
        substituted = []
        for i in range(8):
            row = int(f"{bits[i * 6]}{bits[i * 6 + 5]}", 2)
            column = int(f"{bits[i * 6 + 1]}{bits[i * 6 + 2]}{bits[i * 6 + 3]}{bits[i * 6 + 4]}", 2)
            substituted += format(self.S_BOX[i][row][column], '04b')

        return substituted

    def __initial_key_generation(self):
        self.__key1 = self.key_session[:56]
        self.__key2 = self.key_session[56:112]
        self.__key3 = self.key_session[112:] + self.key_session[:(56 - len(self.key_session[112:]))]

    def generate_keys(self, key):
        #key = permute(key, PC1)
        left, right = key[:28], key[28:]
        round_keys = []
        for shift in self.SHIFT_TABLE:
            left = self.left_shift(left, shift)
            right = self.left_shift(right, shift)
            combined = left + right
            round_key = self.permute(combined, self.PC_2)
            round_keys.append(round_key)

        return round_keys

    def f(self, right, subkey):
        expanded = self.permute(right, self.EXPANSION_TABLE)
        xored = self.xor(expanded, subkey)
        substituted = self.s_box_substitution(xored)
        return self.permute(substituted, self.PERMUTATION)

    def round(self, subkey, block):
        left, right = block[:32], block[32:]
        feistel_result = self.xor(self.f(right, subkey), left)
        left, right = right, feistel_result
        return left + right

    def swap(self, block):
        left, right = block[:32], block[32:]
        return right + left

    def des_encrypt(self, keys):
        for index, block in enumerate(self.plain_text_blocks):
            block = self.permute(block, self.INITIAL_PERMUTATION)
            for i in range(16):
                block = self.round(keys[i], block)
            block = self.swap(block)
            self.plain_text_blocks[index] = self.permute(block, self.FINAL_PERMUTATION)


    def bin2hex(self, s):
        mp = {"0000": '0',
              "0001": '1',
              "0010": '2',
              "0011": '3',
              "0100": '4',
              "0101": '5',
              "0110": '6',
              "0111": '7',
              "1000": '8',
              "1001": '9',
              "1010": 'A',
              "1011": 'B',
              "1100": 'C',
              "1101": 'D',
              "1110": 'E',
              "1111": 'F'}
        hex = ""
        for i in range(0, len(s), 4):
            ch = ""
            ch = ch + s[i]
            ch = ch + s[i + 1]
            ch = ch + s[i + 2]
            ch = ch + s[i + 3]
            hex = hex + mp[ch]

        return hex

    def des_decrypt(self, keys):
        return self.des_encrypt(keys[::-1])




