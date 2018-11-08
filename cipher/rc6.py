import math
from typing import List

from cipher.base import BlockCipher
from utils import BYTE_BITS, bin_join, bin_split, rotl, rotr, odd
from validators import value_in_range

# Length of word in bits.
W = 32

# Length of word in bytes.
U = W // BYTE_BITS

# Decimal logarithm of W.
LG_W = round(math.log(W, 10))

# Modulo, in a group of which all arithmetics are held.
MOD = 2 ** W

# Number of rounds.
R = 20

# Length of block in bits.
BLOCK_BITS = 128

# Length of block in bytes.
BLOCK_BYTES = BLOCK_BITS // BYTE_BITS

# Minimum length of key in bytes.
MIN_KEY_BYTES = 0

# Maximum length of key in bytes.
MAX_KEY_BYTES = 255

# Golden ratio.
F = (1 + 5 ** 0.5) / 2

# Euler's number.
E = math.e

# The first magic constant.
Q_W = odd((F - 1) * MOD)

# The second magic constant.
P_W = odd((E - 2) * MOD)


def _key_expansion(key_ints: List[int]) -> List[int]:
    """Generate round subkey words (key expansion algorithm)."""
    b = len(key_ints)

    # Length of words array L.
    c = math.ceil(b / U)
    l = [0] * c

    # Break K into words.
    k = key_ints
    for i in range(b - 1, -1, -1):
        l[i // U] = (l[i // U] << 8) + k[i]

    # Initialize key-independent pseudo-random S array.
    t = 2 * R + 4
    s = [P_W]
    for i in range(1, t):
        s.append((s[i - 1] + Q_W) % MOD)

    # The main key scheduling loop.
    a = b = i = j = 0

    v = 3 * max(c, t)
    for k in range(1, v):
        a = s[i] = rotl((s[i] + a + b) % MOD, 3, W)
        b = l[j] = rotl((l[j] + a + b) % MOD, a + b, W)
        i = (i + 1) % t
        j = (j + 1) % c

    return s


class RC6(BlockCipher):
    """Class that encapsulates the RC6 cipher's logic."""

    def __init__(self, key_bytes: int = MAX_KEY_BYTES) -> None:
        self.__validate_init_params(key_bytes)
        super().__init__(BLOCK_BYTES, key_bytes)
        self.__s = None

    @staticmethod
    def __validate_init_params(key_bytes: int) -> None:
        """Validate initialization parameters."""
        value_in_range("Key bytes", key_bytes, MIN_KEY_BYTES, MAX_KEY_BYTES)

    def _set_key(self, key: str, is_encrypt: bool) -> None:
        """Validate and set the key."""
        key_ints = self._preprocess_key(key)
        self.__s = _key_expansion(key_ints)

    def _encrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Encrypt the text block's integers."""
        s = self.__s

        # Join individual block bytes into 4 registers.
        regs = []
        for i in range(0, len(block_ints), 4):
            reg = bin_join(block_ints[i:i + 4], BYTE_BITS)
            regs.append(reg)

        [a, b, c, d] = regs

        b = (b + s[0]) % MOD
        d = (d + s[1]) % MOD
        for i in range(1, R + 1):
            t = rotl((b * (2 * b + 1)) % MOD, LG_W, W)
            u = rotl((d * (2 * d + 1)) % MOD, LG_W, W)
            a = (rotl(a ^ t, u, W) + s[2 * i]) % MOD
            c = (rotl(c ^ u, t, W) + s[2 * i + 1]) % MOD
            (a, b, c, d) = (b, c, d, a)
        a = (a + s[2 * R + 2]) % MOD
        c = (c + s[2 * R + 3]) % MOD

        cipher_int = bin_join([a, b, c, d], W)
        cipher_ints = bin_split(cipher_int, BLOCK_BITS, BYTE_BITS)

        return cipher_ints

    def _decrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Decrypt the cipher block's integers."""
        s = self.__s

        # Join individual block bytes into 4 registers.
        regs = []
        for i in range(0, len(block_ints), 4):
            reg = bin_join(block_ints[i:i + 4], BYTE_BITS)
            regs.append(reg)

        [a, b, c, d] = regs

        c = (c - s[2 * R + 3]) % MOD
        a = (a - s[2 * R + 2]) % MOD
        for j in range(R, 0, -1):
            (a, b, c, d) = (d, a, b, c)
            u = rotl((d * (2 * d + 1)) % MOD, LG_W, W)
            t = rotl((b * (2 * b + 1)) % MOD, LG_W, W)
            c = (rotr((c - s[2 * j + 1]) % MOD, t, W) ^ u)
            a = (rotr((a - s[2 * j]) % MOD, u, W) ^ t)
        d = (d - s[1]) % MOD
        b = (b - s[0]) % MOD

        text_int = bin_join([a, b, c, d], W)
        text_ints = bin_split(text_int, BLOCK_BITS, BYTE_BITS)

        return text_ints
