from typing import List, Generator

from cipher.base import StreamCipher
from utils import BYTE_BITS
from validators import value_in_range

# Length of word in bits.
WORD_BITS = 16

# Size of the S array.
S_SIZE = 2 ** WORD_BITS

# Maximum length of key in bytes.
MIN_KEY_BYTES = 5

# Maximum length of key in bytes.
MAX_KEY_BYTES = 256


def _ksa(key_ints: List[int]) -> List[int]:
    """Initialize the key permutation using key-scheduling
    algorithm (KSA)."""

    s = list(range(S_SIZE))

    j = 0
    for i in range(S_SIZE):
        j = (j + s[i] + key_ints[i % len(key_ints)]) % S_SIZE
        s[i], s[j] = s[j], s[i]

    return s


def _prga_generator(s: List[int]) -> Generator[int, None, None]:
    """Generator function implementing pseudo-random generation
    algorithm (PRGA)."""
    i = 0
    j = 0
    while True:
        i = (i + 1) % S_SIZE
        j = (j + s[i]) % S_SIZE
        s[i], s[j] = s[j], s[i]
        k_elem = s[(s[i] + s[j]) % S_SIZE]
        yield k_elem


class ARC4(StreamCipher):
    """Class that encapsulates the ARC4 cipher's logic."""

    def __init__(self, key_bytes: int = MAX_KEY_BYTES) -> None:
        self.__validate_init_params(key_bytes)
        super().__init__(key_bytes)
        self.__prga = None

    @staticmethod
    def __validate_init_params(key_bytes: int) -> None:
        """Validate initialization parameters."""
        value_in_range("Key bytes", key_bytes, MIN_KEY_BYTES, MAX_KEY_BYTES)

    def _set_key(self, key: str, is_encrypt: bool) -> None:
        """Validate and set the key."""
        key_ints = self._preprocess_key(key)
        s = _ksa(key_ints)
        self.__prga = _prga_generator(s)

    def _process(self, input_int: int) -> int:
        """Process the input's integer (works in both ways)."""
        key_int = next(self.__prga)
        output_int = input_int ^ key_int
        return output_int % 2 ** BYTE_BITS
