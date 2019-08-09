# PyCrypt

PyCrypt is a command-line program which allows to encrypt or decrypt plain text or text files using various ciphers. Written for a university project.

## Installation

```sh
$ pip install -r requirements.txt
```

## Usage

```sh
$ python cli.py [OPTIONS] COMMAND [ARGS]...
```

## Options

```
-e, --encrypt / -d, --decrypt  Whether you want to encrypt text or decrypt
                               it.  [default: (encrypt)]
-i, --input_file FILENAME      File, from which the input will be read. If
                               not provided, a prompt will appear.
-o, --output_file FILENAME     File, in which the output will be written. If
                               not provided, the output will be printed.
--help                         Show help message.
```

## Commands

```
arc4        ARC4 cipher
blowfish    Blowfish cipher
cardan      Cardan grille
feistel     Feistel network
idea        IDEA cipher
rc6         RC6 cipher
rijndael    Rijndael cipher
two-square  Two-square cipher
vernam      Vernam cipher
```
