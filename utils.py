import math
from typing import List

import numpy as np

from errors import HexNotValidError

# Number of bits in ASCII char.
BYTE_BITS = 8

# Length of hex which represents an ASCII char.
HEX_LENGTH = 2


def add_padding(text_ints: List[int], req_length: int) -> List[int]:
    """Add padding using the padding method 2."""
    if len(text_ints) < req_length:
        padding = [1] + [0] * (req_length - len(text_ints) - 1)
        return text_ints + padding
    return text_ints


def remove_padding(text: str) -> str:
    """Remove the padding added with padding method 2."""
    return text.rstrip('\x00\x01')


def ints_to_chars(nums: List[int]) -> List[str]:
    """Convert a list of integers into a list of chars."""
    return list(map(chr, nums))


def chars_to_ints(chars: str) -> List[int]:
    """Convert a list of chars into a list of integers."""
    return list(map(ord, chars))


def int_to_hex(num: int) -> str:
    """Convert an integer to a hexadecimal."""
    return "{:02X}".format(num)


def hex_to_int(hex: str) -> int:
    """Convert a hexadecimal to an integer."""
    try:
        return int(hex, 16)
    except ValueError:
        raise HexNotValidError(hex)


def ints_to_hexes(nums: List[int]) -> List[str]:
    """Convert a list of integers into a list of hexadecimals."""
    return list(map(int_to_hex, nums))


def hexes_to_ints(hexes: List[str]) -> List[int]:
    """Convert a list of hexadecimals into a list of integers."""
    return list(map(hex_to_int, hexes))


def hex_str_to_ints(hex_str: str, width: int) -> List[int]:
    """Convert a hex string into a list of integers."""
    hexes = [hex_str[i:i + width] for i in range(0, len(hex_str), width)]
    return hexes_to_ints(hexes)


def rotl_arr(array: np.ndarray, num: int) -> np.ndarray:
    """Perform left circular shift of an array by num."""
    num = num % len(array)
    array = array.tolist()
    return np.array(array[num:] + array[:num])


def rotr_arr(array: np.ndarray, num: int) -> np.ndarray:
    """Perform right circular shift of an array by num."""
    num = num % len(array)
    array = array.tolist()
    return np.array(array[-num:] + array[:-num])


def bin_slice(value: int, start: int, end: int, width: int) -> int:
    """Slice integer's bits."""
    max_value = 2 ** (width - start) - 1
    value = value & max_value
    return value >> (width - end)


def bin_join(values: List[int], width: int) -> int:
    """Join bits of all integers."""
    num = 0
    for value in values:
        num = (num << width) | value
    return num


def bin_split(value: int, old_width: int, new_width: int) -> List[int]:
    """Split bits of an integer into a list of integers."""
    nums = []
    for i in range(old_width // new_width):
        num = bin_slice(value, i * new_width, (i + 1) * new_width, old_width)
        nums.append(num)

    return nums


def rotl(value: int, num: int, width: int) -> int:
    """Perform left circular shift of an integer."""
    num = num % width
    l_slice = bin_slice(value, 0, num, width)
    r_slice = bin_slice(value, num, width, width)
    return r_slice << num | l_slice


def rotr(value: int, num: int, width: int) -> int:
    """Perform right circular shift of an integer."""
    num = num % width
    l_slice = bin_slice(value, 0, width - num, width)
    r_slice = bin_slice(value, width - num, width, width)
    return r_slice << width - num | l_slice


def odd(num: int) -> int:
    """Find nearest odd number."""
    num = math.floor(num)
    return num + 1 if num % 2 == 0 else num


def nearest_sqrt(num: int) -> int:
    """Find nearest square root of the number."""
    answer = 0
    while answer ** 2 < num:
        answer += 1

    return answer


def egcd(a, b):
    """Extended Euclidean algorithm. Used to calculate the coefficients of
    Bézout's identity (x, y)."""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def mod_inv(a, m):
    """Modular multiplicative inverse in the multiplicative group (mod m)."""
    g, x, y = egcd(a, m)
    return x % m if g == 1 else 0
