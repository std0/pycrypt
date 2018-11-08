from typing import Any, List

from errors import (
    CharNotAllowedError, ValueNotInRangeError,
    ValueNotInListError
)


def char_int_allowed(char_int: int) -> None:
    """Validate whether the char is allowed for input."""
    if char_int > 255:
        raise CharNotAllowedError(chr(char_int))


def value_in_range(value_name: str, value: int, min_value: int,
                   max_value: int) -> None:
    """Validate whether the value is in the given range."""
    if value < min_value or value > max_value:
        raise ValueNotInRangeError(value_name, value, min_value, max_value)


def value_in_list(value_name: str, value: Any, allowed: List[Any]) -> None:
    """Validate whether the value is in the list of allowed values."""
    if value not in allowed:
        raise ValueNotInListError(value_name, value, allowed)
