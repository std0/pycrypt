import random
from typing import TextIO, Generator

from cipher.base import Cipher
from utils import HEX_LENGTH, int_to_hex, hex_to_int
from validators import char_int_allowed


def _random_int_generator() -> Generator[int, None, None]:
    """Generator function which returns random integers."""
    while True:
        yield random.randint(0, 255)


class Vernam(Cipher):
    """Class that encapsulates the Vernam cipher's logic."""

    def __init__(self) -> None:
        self.__key_int_gen = _random_int_generator()

    def encrypt(self, text: TextIO, key_filename: str, cipher: TextIO) -> None:
        """Encrypt the text and save generated key to the file."""
        with open(key_filename, 'w') as key_file:
            while True:
                text_char = text.read(1)
                if text_char == '':
                    break

                text_int = ord(text_char)
                char_int_allowed(text_int)

                key_int = next(self.__key_int_gen)

                cipher_int = text_int ^ key_int

                key_file.write(int_to_hex(key_int))
                cipher.write(int_to_hex(cipher_int))

    def decrypt(self, cipher: TextIO, key_filename: str, text: TextIO) -> None:
        """Decrypt the cipher using the key from the file."""
        with open(key_filename, 'r') as key_file:
            while True:
                cipher_hex = cipher.read(HEX_LENGTH)
                key_hex = key_file.read(HEX_LENGTH)
                if cipher_hex == '' or key_hex == '':
                    break

                cipher_int = hex_to_int(cipher_hex)
                char_int_allowed(cipher_int)

                key_int = hex_to_int(key_hex)
                char_int_allowed(key_int)

                text_int = cipher_int ^ key_int

                text.write(chr(text_int))
