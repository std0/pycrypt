from abc import ABC, abstractmethod
from typing import List, TextIO

from errors import EmptyKeyError, InputLengthError
from utils import (
    ints_to_chars, chars_to_ints,
    HEX_LENGTH, int_to_hex, hex_to_int,
    ints_to_hexes, hex_str_to_ints,
    add_padding, remove_padding
)
from validators import char_int_allowed


class Cipher:
    """Class that encapsulates general cipher's logic."""

    @staticmethod
    def _validate_input(input_ints: List[int]) -> None:
        """Validate the input."""
        for num in input_ints:
            char_int_allowed(num)


class KeyCipher(ABC, Cipher):
    """Class that encapsulates general key cipher's logic."""

    def __init__(self, key_bytes: int) -> None:
        self.key_bytes = key_bytes

    @staticmethod
    def _validate_key(key_ints: List[int]) -> None:
        """Validate the key."""
        if len(key_ints) == 0:
            raise EmptyKeyError()

        for num in key_ints:
            char_int_allowed(num)

    def _preprocess_key(self, key: str) -> List[int]:
        """Preprocess and validate the key."""
        key = key[:self.key_bytes]
        key_ints = chars_to_ints(key)
        self._validate_key(key_ints)
        return key_ints

    @abstractmethod
    def _set_key(self, key: str, is_encrypt: bool) -> None:
        """Validate and set the key."""
        pass

    @abstractmethod
    def encrypt(self, text: TextIO, key: str, cipher: TextIO) -> None:
        """Encrypt the text using the key."""
        self._set_key(key, True)

    @abstractmethod
    def decrypt(self, cipher: TextIO, key: str, text: TextIO) -> None:
        """Decrypt the cipher using the key."""
        self._set_key(key, False)


class StreamCipher(KeyCipher):
    """Class that encapsulates general stream cipher's logic."""

    def __init__(self, key_bytes: int) -> None:
        super().__init__(key_bytes)

    @abstractmethod
    def _process(self, input_int: int) -> int:
        """Process the input's integer."""
        pass

    def encrypt(self, text: TextIO, key: str, cipher: TextIO) -> None:
        """Encrypt the text using the key."""
        super().encrypt(text, key, cipher)

        while True:
            text_char = text.read(1)
            if text_char == '':
                break

            text_int = ord(text_char)
            char_int_allowed(text_int)

            cipher_int = self._process(text_int)

            cipher.write(int_to_hex(cipher_int))

    def decrypt(self, cipher: TextIO, key: str, text: TextIO) -> None:
        """Decrypt the cipher using the key."""
        super().decrypt(cipher, key, text)

        while True:
            cipher_hex = cipher.read(HEX_LENGTH)
            if cipher_hex == '':
                break

            cipher_int = hex_to_int(cipher_hex)
            char_int_allowed(cipher_int)

            text_int = self._process(cipher_int)

            text.write(chr(text_int))


class BlockCipher(KeyCipher):
    """Class that encapsulates general block cipher's logic."""

    def __init__(self, block_bytes: int, key_bytes: int) -> None:
        super().__init__(key_bytes)
        self.block_bytes = block_bytes

    @abstractmethod
    def _encrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Encrypt the text block's integers."""
        pass

    def __encrypt_block(self, block: str) -> str:
        """Encrypt the text block."""
        block_ints = chars_to_ints(block)
        self._validate_input(block_ints)
        block_ints = add_padding(block_ints, self.block_bytes)

        cipher_ints = self._encrypt_block_ints(block_ints)
        cipher = ''.join(ints_to_hexes(cipher_ints))

        return cipher

    def encrypt(self, text: TextIO, key: str, cipher: TextIO) -> None:
        """Encrypt the text using the key."""
        super().encrypt(text, key, cipher)

        while True:
            text_block = text.read(self.block_bytes)
            if text_block == '':
                break

            cipher_block = self.__encrypt_block(text_block)
            cipher.write(cipher_block)

    @abstractmethod
    def _decrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Decrypt the cipher block's integers."""
        pass

    def __decrypt_block(self, block: str) -> str:
        """Decrypt the cipher block."""
        block_ints = hex_str_to_ints(block, HEX_LENGTH)
        self._validate_input(block_ints)

        if len(block_ints) < self.block_bytes:
            raise InputLengthError(self.block_bytes)

        text_ints = self._decrypt_block_ints(block_ints)
        text = ''.join(ints_to_chars(text_ints))

        return remove_padding(text)

    def decrypt(self, cipher: TextIO, key: str, text: TextIO) -> None:
        """Decrypt the cipher using the key."""
        super().decrypt(cipher, key, text)

        while True:
            cipher_block = cipher.read(self.block_bytes * HEX_LENGTH)
            if cipher_block == '':
                break

            text_block = self.__decrypt_block(cipher_block)
            text.write(text_block)
