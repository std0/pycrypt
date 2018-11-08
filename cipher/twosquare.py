import random
import string
from typing import Tuple, TextIO

import numpy as np

from cipher.base import Cipher
from errors import SquareNotValidError, CharNotAllowedError, InputLengthError
from utils import nearest_sqrt

# List of allowed marks in the chars square.
ALLOWED_MARKS = ['!', '"', '#', '$', '%', '&', "'", '(', ')', '*',
                 '+', ',', '-', '.', '/', ':', ';', '<', '=', '>',
                 '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|',
                 '}', '~', ' ', '\x01', '\x18', '\x19', '\x1a', '\x1b']

# Full list of allowed chars in the chars square.
ALLOWED_CHARS = list(string.ascii_letters + string.digits) + ALLOWED_MARKS

# Length of chunk to process in bytes.
CHUNK_BYTES = 2

# Type alias for a tuple of char's coordinates in a chars square.
Coords = Tuple[int, int]


def _get_random_chars_square() -> np.ndarray:
    """Generate random square with ASCII chars."""
    full_random_list = random.sample(ALLOWED_CHARS, len(ALLOWED_CHARS))
    sqrt = nearest_sqrt(len(full_random_list))

    return np.resize(full_random_list, (sqrt, sqrt))


class Square:
    """Class that encapsulates chars square's logic."""

    def __init__(self, data: np.ndarray = None) -> None:
        if data is None:
            data = _get_random_chars_square()
        self.data = data

    def find_char(self, char: str) -> Coords:
        """Find char's coordinates."""
        coords = np.concatenate(np.where(self.data == char))
        if len(coords) == 0:
            raise CharNotAllowedError(char)

        return tuple(coords.tolist())

    def shift_vertical(self, coords: Coords, is_increasing: bool) -> Coords:
        """Get vertically shifted coordinates of the char."""
        max_coord = self.data.shape[0]

        if is_increasing:
            return (coords[0] + 1) % max_coord, coords[1]

        if coords[0] == 0:
            coords = (max_coord, coords[1])

        return coords[0] - 1, coords[1]

    def shift_horizontal(self, coords: Coords, is_increasing: bool) -> Coords:
        """Get horizontally shifted coordinates of the char."""
        max_coord = self.data.shape[1]

        if is_increasing:
            return coords[0], (coords[1] + 1) % max_coord

        if coords[1] == 0:
            coords = (coords[0], max_coord)

        return coords[0], coords[1] - 1


# Type alias for a tuple of two chars squares.
SquaresTuple = Tuple[Square, Square]


def load_squares(filename: str) -> SquaresTuple:
    """Load chars squares from the file."""
    with open(filename, 'r') as square_file:
        squares = [list(line.rstrip('\n')) for line in square_file]

    if len(squares) == 0:
        raise SquareNotValidError("Squares must be not empty")

    side_length = len(squares[0])

    return (
        Square(np.array(squares[:side_length])),
        Square(np.array(squares[side_length:]))
    )


def save_squares(filename: str, squares: SquaresTuple) -> None:
    """Save chars squares to the file."""
    with open(filename, 'w') as square_file:
        for square in squares:
            for line in square.data:
                square_file.write(''.join(line) + '\n')


class TwoSquare(Cipher):
    """Class that encapsulates the two-square cipher's logic."""

    def __init__(self) -> None:
        self.__squares = None

    @staticmethod
    def __validate_squares(squares: SquaresTuple) -> None:
        """Validate squares."""
        for square in squares:
            shape = square.data.shape
            if len(shape) != 2 or shape[0] != shape[1]:
                raise SquareNotValidError("Square's shape must be square")

    def __set_squares(self, squares: SquaresTuple) -> None:
        """Validate and set squares."""
        self.__validate_squares(squares)
        self.__squares = squares

    def __process_chunk(self, chunk: str, is_encrypt: bool) -> str:
        """Get opposite chars in chars squares (works in both ways)."""
        squares = self.__squares

        coords = (
            squares[0].find_char(chunk[0]),
            squares[1].find_char(chunk[1]),
        )

        if coords[0][0] == coords[1][0]:
            # Same row.
            new_coords = (
                squares[0].shift_horizontal(coords[0], is_encrypt),
                squares[1].shift_horizontal(coords[1], is_encrypt)
            )
        elif coords[0][1] == coords[1][1]:
            # Same column.
            new_coords = (
                squares[0].shift_vertical(coords[0], is_encrypt),
                squares[1].shift_vertical(coords[1], is_encrypt)
            )
        else:
            new_coords = (
                (coords[1][0], coords[0][1]),
                (coords[0][0], coords[1][1])
            )

        return squares[0].data[new_coords[0]] + squares[1].data[new_coords[1]]

    def __encrypt_chunk(self, text_chunk: str) -> str:
        """Encrypt the text chunk."""
        if len(text_chunk) < CHUNK_BYTES:
            text_chunk += '\x01' * (CHUNK_BYTES - len(text_chunk))
        return self.__process_chunk(text_chunk, True)

    def encrypt(self, text: TextIO, squares: SquaresTuple,
                cipher: TextIO) -> None:
        """Encrypt the text using chars squares."""
        self.__set_squares(squares)

        while True:
            text_chunk = text.read(CHUNK_BYTES)
            if text_chunk == '':
                break

            cipher_chunk = self.__encrypt_chunk(text_chunk)

            cipher.write(cipher_chunk)

    def __decrypt_chunk(self, cipher_chunk: str) -> str:
        """Decrypt the cipher chunk."""
        if len(cipher_chunk) < CHUNK_BYTES:
            raise InputLengthError(CHUNK_BYTES)

        text_chunk = self.__process_chunk(cipher_chunk, False)
        return text_chunk.rstrip('\x01')

    def decrypt(self, cipher: TextIO, squares: SquaresTuple,
                text: TextIO) -> None:
        """Decrypt the cipher using chars squares."""
        self.__set_squares(squares)

        while True:
            cipher_chunk = cipher.read(CHUNK_BYTES)
            if cipher_chunk == '':
                break

            text_chunk = self.__decrypt_chunk(cipher_chunk)

            text.write(text_chunk)
