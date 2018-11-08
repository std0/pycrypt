from io import StringIO
from typing import TextIO

import click

from cipher.arc4 import ARC4
from cipher.base import KeyCipher
from cipher.blowfish import Blowfish
from cipher.cardan import Cardan, load_mask
from cipher.feistel import Feistel
from cipher.idea import IDEA
from cipher.rc6 import RC6
from cipher.rijndael import Rijndael
from cipher.twosquare import Square, save_squares, load_squares, TwoSquare
from cipher.vernam import Vernam
from errors import (
    CharNotAllowedError, HexNotValidError,
    MaskNotValidError, SquareNotValidError,
    InputLengthError, EmptyKeyError,
    ValueNotInListError, ValueNotInRangeError
)


@click.group()
@click.option(
    "--encrypt/--decrypt",
    "-e/-d",
    default=True,
    show_default="encrypt",
    help="Whether you want to encrypt text or decrypt it."
)
@click.option(
    "-i",
    "--input_file",
    type=click.File('r', encoding='utf-8'),
    help="File, from which the input will be read. "
         "If not provided, a prompt will appear.",
)
@click.option(
    "-o",
    "--output_file",
    type=click.File('w', encoding='utf-8'),
    help="File, in which the output will be written. "
         "If not provided, the output will be printed.",
)
@click.pass_context
def cli(ctx: click.core.Context, encrypt: bool, input_file: TextIO,
        output_file: TextIO) -> None:
    """Allows to encrypt or decrypt plain text or text files with
    various ciphers."""
    ctx.ensure_object(dict)

    ctx.obj['is_encrypt'] = encrypt

    if input_file is None:
        input_text = click.prompt("Enter input")
        ctx.obj['input_stream'] = StringIO(input_text)
    else:
        ctx.obj['input_stream'] = input_file
        print("Input loaded from {0}".format(input_file.name))

    if output_file is None:
        ctx.obj['output_stream'] = StringIO()
    else:
        ctx.obj['output_stream'] = output_file

    ctx.obj['to_stdout'] = output_file is None


@cli.command(short_help="Cardan grille")
@click.argument(
    "mask_filename",
    type=click.Path(exists=True)
)
@click.pass_obj
def cardan(obj: dict, mask_filename: str) -> None:
    """Encrypt/decrypt text with Cardan grille using the mask from
    MASK_FILENAME."""
    cipher = Cardan()
    mask = load_mask(mask_filename)
    print("Mask loaded from {0}".format(mask_filename))

    action = cipher.encrypt if obj['is_encrypt'] is True else cipher.decrypt

    action(obj['input_stream'], mask, obj['output_stream'])


@cli.command(short_help="Two-square cipher")
@click.argument(
    "squares_filename",
    type=click.Path(exists=True)
)
@click.pass_obj
def two_square(obj: dict, squares_filename: str) -> None:
    """Encrypt/decrypt text with two-square cipher using the squares from
    SQUARES_FILENAME."""
    cipher = TwoSquare()

    if obj['is_encrypt'] is True:
        squares = Square(), Square()
        save_squares(squares_filename, squares)
        print("Squares saved to {0}".format(squares_filename))
        action = cipher.encrypt
    else:
        squares = load_squares(squares_filename)
        print("Squares loaded from {0}".format(squares_filename))
        action = cipher.decrypt

    action(obj['input_stream'], squares, obj['output_stream'])


@cli.command(short_help="Vernam cipher")
@click.argument(
    "key_filename",
    type=click.Path(exists=True)
)
@click.pass_obj
def vernam(obj: dict, key_filename: str) -> None:
    """Encrypt/decrypt text with Vernam cipher using the key from
    KEY_FILENAME."""
    cipher = Vernam()

    if obj['is_encrypt'] is True:
        action = cipher.encrypt
        key_message = "Key saved to {0}".format(key_filename)

    else:
        action = cipher.decrypt
        key_message = "Key loaded from {0}".format(key_filename)

    action(obj['input_stream'], key_filename, obj['output_stream'])
    print(key_message)


def key_cipher_command(obj: dict, key_file: TextIO,
                       cipher: KeyCipher) -> None:
    """Encrypt/decrypt text with given cipher using the key from
    KEY_FILE. If KEY_FILE is not provided, a prompt will appear."""
    if obj['is_encrypt'] is True:
        action = cipher.encrypt
    else:
        action = cipher.decrypt

    if key_file is None:
        key = click.prompt("Enter key")
    else:
        key = key_file.read(cipher.key_bytes)
        print("Key loaded from {0}".format(key_file.name))

    action(obj['input_stream'], key, obj['output_stream'])


@cli.command(short_help="Feistel network")
@click.argument(
    "key_file",
    type=click.File('r'),
    required=False
)
@click.pass_obj
def feistel(obj: dict, key_file: TextIO) -> None:
    """Encrypt/decrypt text with Feistel network using the key from
    KEY_FILE. If KEY_FILE is not provided, a prompt will appear."""
    cipher = Feistel()
    key_cipher_command(obj, key_file, cipher)


@cli.command(short_help="Rijndael cipher")
@click.argument(
    "key_file",
    type=click.File('r'),
    required=False
)
@click.pass_obj
def rijndael(obj: dict, key_file: TextIO) -> None:
    """Encrypt/decrypt text with Rijndael cipher using the key from
    KEY_FILE. If KEY_FILE is not provided, a prompt will appear."""
    cipher = Rijndael()
    key_cipher_command(obj, key_file, cipher)


@cli.command(short_help="ARC4 cipher")
@click.argument(
    "key_file",
    type=click.File('r'),
    required=False
)
@click.pass_obj
def arc4(obj: dict, key_file: TextIO) -> None:
    """Encrypt/decrypt text with ARC4 cipher using the key from
    KEY_FILE. If KEY_FILE is not provided, a prompt will appear."""
    cipher = ARC4()
    key_cipher_command(obj, key_file, cipher)


@cli.command(short_help="RC6 cipher")
@click.argument(
    "key_file",
    type=click.File('r'),
    required=False
)
@click.pass_obj
def rc6(obj: dict, key_file: TextIO) -> None:
    """Encrypt/decrypt text with RC6 cipher using the key from
    KEY_FILE. If KEY_FILE is not provided, a prompt will appear."""
    cipher = RC6()
    key_cipher_command(obj, key_file, cipher)


@cli.command(short_help="Blowfish cipher")
@click.argument(
    "key_file",
    type=click.File('r'),
    required=False
)
@click.pass_obj
def blowfish(obj: dict, key_file: TextIO) -> None:
    """Encrypt/decrypt text with Blowfish cipher using the key from
    KEY_FILE. If KEY_FILE is not provided, a prompt will appear."""
    cipher = Blowfish()
    key_cipher_command(obj, key_file, cipher)


@cli.command(short_help="IDEA cipher")
@click.argument(
    "key_file",
    type=click.File('r'),
    required=False
)
@click.pass_obj
def idea(obj: dict, key_file: TextIO) -> None:
    """Encrypt/decrypt text with IDEA cipher using the key from
    KEY_FILE. If KEY_FILE is not provided, a prompt will appear."""
    cipher = IDEA()
    key_cipher_command(obj, key_file, cipher)


@cli.resultcallback()
@click.pass_obj
def print_output(obj, *args, **kwargs):
    """Print output after the end of command execution"""
    if obj['to_stdout'] is True:
        print("Output:", obj['output_stream'].getvalue())
    else:
        print("Output saved to {0}".format(obj['output_stream'].name))


@cli.resultcallback()
def print_success_message(result, encrypt, *args, **kwargs):
    """Print success message after the end of command execution"""
    action = "encrypted" if encrypt is True else "decrypted"
    print("Successfully {0}".format(action))


def main():
    try:
        cli(obj={})
    except (MaskNotValidError, SquareNotValidError, InputLengthError,
            EmptyKeyError, CharNotAllowedError, HexNotValidError,
            ValueNotInListError, ValueNotInRangeError) as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
