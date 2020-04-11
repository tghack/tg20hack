# -*- coding: utf-8 -*-

import ast
from argparse import ArgumentTypeError
from pathlib import Path
from .constants import MAX_CHUNK_LENGTH


def valid_header_id(argument: str) -> int:
    '''Validate a command line argument as a header id integer'''

    if len(argument) > 6:
        raise ArgumentTypeError('expected an integer with at most six digits')

    try:
        hi = int(ast.literal_eval(argument))
    except (SyntaxError, ValueError):
        raise ArgumentTypeError('expected a string that evaluates to an integer')

    if hi <= 0:
        raise ArgumentTypeError('expected a positive integer')

    if hi > 0xffff:
        raise ArgumentTypeError('expected a 16-bit (2-byte) positive integer')

    return hi


def valid_chunk_length(argument: str) -> int:
    '''Validate a command line argument as a chunk length integer'''

    try:
        cl = int(argument)
    except ValueError:
        raise ArgumentTypeError('expected an integer')

    if cl <= 0:
        raise ArgumentTypeError('expected a positive integer')

    if cl > MAX_CHUNK_LENGTH:
        raise ArgumentTypeError(f'expected a positive integer equal or smaller than {MAX_CHUNK_LENGTH}')

    return cl


def valid_file_path(argument: str) -> Path:
    '''Validate a command line argument as a path to a file'''

    datapath = Path(argument)

    if not datapath.is_file():
        raise ArgumentTypeError('expected a path to a file')

    return datapath


def valid_directory_path(argument: str) -> Path:
    '''Validate a command line argument as a path to a directory'''

    datapath = Path(argument)

    if not datapath.is_dir():
        raise ArgumentTypeError('expected a path to a directory')

    return datapath

