from typing import Generator, TextIO

import numpy as np

from cipher.base import Cipher
from errors import MaskNotValidError, InputLengthError

# Number of grille's flips.
FLIPS_N = 4

# Sign with which mask's empty cells are marked.
EMPTY_CELL = 'x'


def _char_generator(string: str) -> Generator[str, None, None]:
    """Generator function which returns single chars of the string."""
    for char in string:
        yield char


def load_mask(filename: str) -> np.ndarray:
    """Load mask from the file."""
    with open(filename, 'r') as file:
        mask = [list(line.rstrip()) for line in file]

    return np.array(mask)


class Cardan(Cipher):
    """Class that encapsulates the Cardan grille's logic."""

    def __init__(self) -> None:
        self.__mask = None

    @staticmethod
    def __validate_mask(mask: np.ndarray) -> None:
        """Validate the mask."""
        if len(mask.shape) != 2 or mask.shape[0] != mask.shape[1]:
            raise MaskNotValidError("Mask's shape must be square")

    def __set_mask(self, mask: np.ndarray) -> None:
        """Validate and set the mask."""
        self.__validate_mask(mask)
        self.__mask = mask

    def __encrypt_chunk(self, text: str) -> str:
        """Encrypt the text chunk."""
        if len(text) < self.__mask.size:
            text += '\x01' * (self.__mask.size - len(text))

        text_gen = _char_generator(text)
        grille = np.zeros(self.__mask.shape, 'U1')

        try:
            for flip_i in range(0, FLIPS_N):
                empty_i = np.argwhere(self.__mask == EMPTY_CELL)
                for i, j in empty_i:
                    grille[i][j] = next(text_gen)
                self.__mask = np.rot90(self.__mask, -1)
        except StopIteration:
            raise MaskNotValidError("Too much empty cells in the mask")

        if np.any(grille == ''):
            raise MaskNotValidError("Not enough empty cells in the mask")

        return ''.join(np.concatenate(grille))

    def encrypt(self, text: TextIO, mask: np.ndarray, cipher: TextIO) -> None:
        """"Encrypt the text using the mask."""
        self.__set_mask(mask)

        while True:
            text_chunk = text.read(self.__mask.size)
            if text_chunk == '':
                break

            cipher_chunk = self.__encrypt_chunk(text_chunk)

            cipher.write(cipher_chunk)

    def __decrypt_chunk(self, cipher: str) -> str:
        """Decrypt the cipher chunk."""
        if len(cipher) < self.__mask.size:
            raise InputLengthError(self.__mask.size)

        grille = np.array(list(cipher)).reshape(self.__mask.shape)

        text = ''
        for flip_i in range(0, FLIPS_N):
            text_chars = np.extract(self.__mask == EMPTY_CELL, grille)
            text += ''.join(text_chars)
            self.__mask = np.rot90(self.__mask, -1)

        return text.rstrip('\x01')

    def decrypt(self, cipher: TextIO, mask: np.ndarray, text: TextIO) -> None:
        """"Decrypt the cipher using the mask."""
        self.__set_mask(mask)

        while True:
            cipher_chunk = cipher.read(self.__mask.size)
            if cipher_chunk == '':
                break

            text_chunk = self.__decrypt_chunk(cipher_chunk)

            text.write(text_chunk)
