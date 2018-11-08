from typing import List

import numpy as np

from cipher.base import BlockCipher
from utils import BYTE_BITS, bin_join, bin_split, bin_slice

# Length of key in bits.
KEY_BITS = 32

# Length of key in bytes.
KEY_BYTES = KEY_BITS // BYTE_BITS

# Length of block in bits.
BLOCK_BITS = 64

# Length of block in bytes.
BLOCK_BYTES = BLOCK_BITS // BYTE_BITS

# Number of rounds.
ROUNDS_N = 20


def _round_function(left: np.ndarray, subkey: List[int]) -> np.ndarray:
    """Xor function used for each round of processing."""
    return np.bitwise_xor(left, subkey)


class Feistel(BlockCipher):
    """Class that encapsulates the Feistel network's logic."""

    def __init__(self) -> None:
        super().__init__(BLOCK_BYTES, KEY_BYTES)
        self.__key_ints = None

    def _set_key(self, key: str, is_encrypt: bool) -> None:
        """Validate and set the key."""
        self.__key_ints = self._preprocess_key(key)

    def __get_subkey(self, round_n: int) -> List[int]:
        """Function used for subkey generation by shifted cyclic reading of
        32-bit key."""
        key_ints = self.__key_ints

        bytes_cut = round_n // BYTE_BITS
        bits_cut = round_n % BYTE_BITS

        # +1 because in order to slice we need to have some extra bits.
        req_key_length = bytes_cut + self.key_bytes + 1
        while len(key_ints) < req_key_length:
            key_ints += key_ints

        key_ints = key_ints[bytes_cut:req_key_length]
        subkey = bin_join(key_ints, BYTE_BITS)
        subkey_width = len(key_ints) * BYTE_BITS

        key_bits = self.key_bytes * BYTE_BITS
        subkey = bin_slice(subkey, bits_cut, key_bits + bits_cut, subkey_width)

        subkey_ints = bin_split(subkey, key_bits, BYTE_BITS)

        return subkey_ints

    def __process_block(self, block_ints: List[int],
                        is_encrypt: bool) -> List[int]:
        """Process the input block's integers (works in both ways)."""
        block_ints = np.array(block_ints)

        chunk_middle = len(block_ints) // 2
        left = block_ints[:chunk_middle]
        right = block_ints[chunk_middle:]

        round_nums = list(range(1, ROUNDS_N + 1))
        if not is_encrypt:
            round_nums.reverse()

        for round_n in round_nums:
            subkey = self.__get_subkey(round_n)
            left = np.bitwise_xor(left, _round_function(right, subkey))
            if round_n != round_nums[len(round_nums) - 1]:
                left, right = right, left

        return left.tolist() + right.tolist()

    def _encrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Encrypt the text block's integers."""
        return self.__process_block(block_ints, True)

    def _decrypt_block_ints(self, block_ints: List[int]) -> List[int]:
        """Decrypt the cipher block's integers."""
        return self.__process_block(block_ints, False)
