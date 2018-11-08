from typing import List, Tuple

from cipher.base import BlockCipher
from utils import BYTE_BITS, bin_join, bin_split, rotl, mod_inv

# Length of block in bits.
BLOCK_BITS = 64

# Length of block in bytes.
BLOCK_BYTES = BLOCK_BITS // BYTE_BITS

# Length of subblock in bits.
SUBBLOCK_BITS = 16

# Length of key in bits.
KEY_BITS = 128

# Length of key in bytes.
KEY_BYTES = KEY_BITS // BYTE_BITS

# Length of subkey in bits.
SUBKEY_BITS = 16

# Number of subkeys.
SUBKEYS_N = 52

# Number of rounds.
ROUNDS_N = 8

# Modulo, in a group of which all arithmetics are held.
MOD = 2 ** 16

# Type alias for a tuple of subblocks.
LayerOut = Tuple[int, int, int, int]

# Type alias for a list of round's subkeys.
RoundSubkeys = List[int]

# Type alias for a list of all rounds' subkeys.
BlockSubkeys = List[RoundSubkeys]


def _add(x1, x2):
    """Addition in the additive group (mod 2**16)."""
    return (x1 + x2) % MOD


def _add_inv(x):
    """Additive inverse in the additive group (mod 2**16)."""
    return (MOD - x) % MOD


def _mul(x1, x2):
    """Multiplication in the multiplicative group (mod 2**16 + 1)."""
    if x1 == 0:
        x1 = MOD
    if x2 == 0:
        x2 = MOD

    return (x1 * x2) % (MOD + 1)


def _mul_inv(x):
    """Multiplicative inverse in the multiplicative group (mod 2**16 + 1)"""
    return mod_inv(x, MOD + 1)


def _ka_layer(x1: int, x2: int, x3: int, x4: int,
              subkeys: RoundSubkeys) -> LayerOut:
    """Key addition layer. One of components of a round transformation."""
    k1, k2, k3, k4 = subkeys

    y1 = _mul(x1, k1)
    y2 = _add(x2, k2)
    y3 = _add(x3, k3)
    y4 = _mul(x4, k4)

    return y1, y2, y3, y4


def _ma_layer(y1: int, y2: int, y3: int, y4: int,
              subkeys: RoundSubkeys) -> LayerOut:
    """Multiplication-addition layer. One of components of a round
    transformation."""
    k5, k6 = subkeys

    a = _mul(y1 ^ y3, k5)
    b = _mul(k6, _add(y2 ^ y4, a))
    c = _add(b, a)

    x1 = y1 ^ b
    x2 = y3 ^ b
    x3 = y2 ^ c
    x4 = y4 ^ c

    return x1, x2, x3, x4


def _generate_subkeys(key_ints: List[int]) -> BlockSubkeys:
    """Generate the subkeys from the given key."""
    key_bin = bin_join(key_ints, BYTE_BITS)

    subkeys = []
    while len(subkeys) < SUBKEYS_N:
        subkeys += bin_split(key_bin, KEY_BITS, SUBKEY_BITS)
        key_bin = rotl(key_bin, 25, KEY_BITS)

    subkeys = subkeys[:SUBKEYS_N]

    step = SUBKEYS_N // ROUNDS_N
    subkeys = [subkeys[i:i + step] for i in range(0, len(subkeys), step)]

    return subkeys


def _invert_subkeys(subkeys: BlockSubkeys) -> BlockSubkeys:
    """Invert the subkeys for decryption."""
    inv_subkeys = []
    for i in range(len(subkeys)):
        j = (len(subkeys) - 1) - i
        [k1, k2, k3, k4] = subkeys[j][:4]
        if i != 0 and i != len(subkeys) - 1:
            k2, k3 = k3, k2

        k1 = _mul_inv(k1)
        k2 = _add_inv(k2)
        k3 = _add_inv(k3)
        k4 = _mul_inv(k4)

        curr_subkeys = [k1, k2, k3, k4]
        if j != 0:
            curr_subkeys += subkeys[j - 1][4:]

        inv_subkeys.append(curr_subkeys)

    return inv_subkeys


class IDEA(BlockCipher):
    """Class that encapsulates the IDEA cipher's logic."""

    def __init__(self) -> None:
        super().__init__(BLOCK_BYTES, KEY_BYTES)
        self.__subkeys = None

    def _set_key(self, key: str, is_encrypt: bool) -> None:
        """Validate and set the key."""
        key_ints = self._preprocess_key(key)
        subkeys = _generate_subkeys(key_ints)
        if is_encrypt is False:
            subkeys = _invert_subkeys(subkeys)
        self.__subkeys = subkeys

    def __process_block(self, block_ints: List[int]) -> List[int]:
        """Process the input block's integers (works in both ways)."""
        block_bin = bin_join(block_ints, BYTE_BITS)
        [x1, x2, x3, x4] = bin_split(block_bin, BLOCK_BITS, SUBBLOCK_BITS)

        for i in range(ROUNDS_N):
            y1, y2, y3, y4 = _ka_layer(x1, x2, x3, x4, self.__subkeys[i][:4])
            x1, x2, x3, x4 = _ma_layer(y1, y2, y3, y4, self.__subkeys[i][4:])

        y1, y2, y3, y4 = _ka_layer(x1, x3, x2, x4, self.__subkeys[ROUNDS_N])
        output_bin = bin_join([y1, y2, y3, y4], SUBBLOCK_BITS)
        output_ints = bin_split(output_bin, BLOCK_BITS, BYTE_BITS)

        return output_ints

    def _encrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Encrypt the text block's integers."""
        return self.__process_block(block_ints)

    def _decrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Decrypt the cipher block's integers."""
        return self.__process_block(block_ints)
