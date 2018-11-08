from typing import Any, List


class MaskNotValidError(Exception):
    """Exception raised for errors in the mask structure."""

    def __init__(self, message: str) -> None:
        self.message = message


class SquareNotValidError(Exception):
    """Raised for errors in the square structure."""

    def __init__(self, message: str) -> None:
        self.message = message


class InputLengthError(Exception):
    """Raised for errors in the input's length."""

    def __init__(self, length: int) -> None:
        self.length = length

    def __str__(self):
        return "Input's length must be a multiple of {0}".format(self.length)


class EmptyKeyError(Exception):
    """Raised if the key is empty."""

    def __str__(self):
        return "Key must be not empty"


class CharNotAllowedError(Exception):
    """Raised when the char is not allowed for input."""

    def __init__(self, char: str) -> None:
        self.char = char

    def __str__(self):
        return "Char '{0}' is not allowed".format(self.char)


class HexNotValidError(Exception):
    """Raised if read hex is not valid."""

    def __init__(self, hex: str) -> None:
        self.hex = hex

    def __str__(self):
        return "Hex '{0}' is not valid".format(self.hex)


class ValueNotInListError(Exception):
    """Raised if the value is not in the list of allowed values."""

    def __init__(self, name: str, value: Any, allowed: List[Any]) -> None:
        self.name = name
        self.value = value
        self.allowed = allowed

    def __str__(self):
        return "{0} value ({1}) is not allowed. Allowed values: {2}".format(
            self.name, self.value, self.allowed)


class ValueNotInRangeError(Exception):
    """Raised if the value is not in the given range."""

    def __init__(self, value_name: str, value: int, min_value: int,
                 max_value: int) -> None:
        self.name = value_name
        self.value = value
        self.min = min_value
        self.max = max_value

    def __str__(self):
        return "{0} value ({1}) is not in range ({2} - {3}).".format(
            self.name, self.value, self.min, self.max)
