#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Stores and retrieves arbitrary data inside the Extra field of an APK/ZIP
archive without invalidating the APK signature. Know that this embedding does
not yet work for APKv2 signed APKs, because that signature modifies the ZIP
headers and I have not yet figured out how to account for that.

# Example Usage

On a new Android project:
- Call `./poc.py prepare /path/to/android/project` to generate the appropriate files with hints,
- Build the project,
- Sign the APK with V1 signature (not V2 or V3),
- Call `./poc.py write /path/to/signed.apk /path/to/modified.apk` to write the payload,
- Call `./poc.py read /path/to/modified.apk` to extract the payload.
"""

import base64
import binascii
import struct
import re
import tempfile
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from itertools import zip_longest
from typing import Optional, Iterable, TypeVar, Tuple, List
from pathlib import Path
from zipfile import ZipFile, ZipInfo


TGHACK_HEADER_ID = 0x1337
TGHACK_NUM_FILES = 512
TGHACK_FILE_PREFIX = 'supersecret'
TGHACK_FILE_SUFFIX = '.dat'
TGHACK_FILE_CONTENT = 'I am hiding something'
ENCODING = 'UTF-8'
EXTRA_MAX_LENGTH = 32
MAX_CHUNK_LENGTH = EXTRA_MAX_LENGTH - 4
ASSETS_DIR = 'app/src/main/assets'
T = TypeVar('T')


def valid_header_id(argument: str) -> int:
    """Validate a command line argument as a header id integer"""

    try:
        hi = int(argument)
    except ValueError:
        raise ArgumentTypeError("expected an integer")

    if hi <= 0:
        raise ArgumentTypeError("expected a positive integer")

    if hi > 0xffff:
        raise ArgumentTypeError("expected a 16-bit (2-byte) positive integer")

    return hi


def valid_chunk_length(argument: str) -> int:
    """Validate a command line argument as a chunk length integer"""

    try:
        cl = int(argument)
    except ValueError:
        raise ArgumentTypeError("expected an integer")

    if cl <= 0:
        raise ArgumentTypeError("expected a positive integer")

    if cl > MAX_CHUNK_LENGTH:
        raise ArgumentTypeError(f"expected a positive integer equal or smaller than {MAX_CHUNK_LENGTH}")

    return cl


def valid_file_path(argument: str) -> Path:
    """Validate a command line argument as a path to a file"""

    datapath = Path(argument)

    if not datapath.is_file():
        raise ArgumentTypeError("expected a path to a file")

    return datapath


def valid_directory_path(argument: str) -> Path:
    """Validate a command line argument as a path to a directory"""

    datapath = Path(argument)

    if not datapath.is_dir():
        raise ArgumentTypeError("expected a path to a directory")

    return datapath


def grouper(iterable: Iterable[T], n: int,  fillvalue: Optional[T] = None) -> Iterable[Iterable[T]]:
    """Collect data into fixed-length chunks or blocks"""

    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def prepare_project(matches: Namespace) -> None:
    dry_run = matches.dry_run
    force = matches.force
    verbose = matches.verbose
    assets_dir_rel = matches.assets_dir
    num_files = matches.num_files
    prefix = matches.prefix
    suffix = matches.suffix
    content = matches.data
    project_path = matches.project

    if dry_run and verbose > 0:
        print("Dry-run mode. I will not do anything irreversible, promise")

    __prepare_project(project_path, assets_dir_rel, num_files, prefix, suffix, content, dry_run, force, verbose)

def write_payload(matches: Namespace) -> None:
    dry_run = matches.dry_run
    force = matches.force
    verbose = matches.verbose
    chunk_length = matches.chunk_length
    target_pattern = re.compile(matches.target_pattern)
    header_id = matches.header_id
    comment = matches.comment.encode(ENCODING)
    payload = matches.payload.encode(ENCODING)
    source_path = matches.source
    destination_path = matches.destination

    if dry_run and verbose > 0:
        print("Dry-run mode. I will not do anything irreversible, promise")

    if not force and destination_path.exists():
        raise ValueError(f"The path {destination_path} exists already")

    __write_payload(source_path, destination_path, target_pattern, header_id, comment, payload, chunk_length, dry_run, force, verbose)


def read_payload(matches: Namespace) -> None:
    verbose = matches.verbose
    header_id = matches.header_id
    source_path = matches.source

    (rpayload, rcomment) = __read_payload(source_path, header_id, verbose)

    if verbose == 0:
        if len(rcomment) > 0:
            print(rcomment.decode(ENCODING))
        if len(rpayload) > 0:
            print(rpayload.decode(ENCODING))


def __prepare_project(project_path: Path, assets_dir_rel: Path, num_files: int, prefix: str, suffix: str, content: str, dry_run: bool, force: bool, verbose: int) -> None:
    """Prepare an Android project for payload embedding by creating a set of nonsense asset files"""

    # Create the assets directory
    assets_path = project_path.joinpath(assets_dir_rel)
    if verbose > 0:
        print(f"Creating the asset directory at {assets_path}")
    if not dry_run:
        assets_path.mkdir(parents=True, exist_ok=force)

    # Create a number of files
    if verbose > 0:
        print(f"Creating {num_files} files")
    write_mode = 'x' if not force else 'w'
    for i in range(0, num_files):
        filename = f'{prefix}_{i:04}{suffix}'
        file_path = assets_path.joinpath(filename)
        if verbose > 1:
            print(f"Creating the file at {file_path}")
        if not dry_run:
            with file_path.open(mode=write_mode, encoding=ENCODING) as f:
                f.write(content)


def __write_payload(source_path: Path, destination_path: Path, target_pattern: re.Pattern, header_id: int, comment: bytes, payload: bytes, chunk_length: int, dry_run: bool, force: bool, verbose: int) -> None:
    """Write the specified payload to the APK ZIP archive"""

    with ZipFile(source_path, mode='r') as s:
        # Verify the CRCs of all files in the archive
        result = s.testzip()
        if result is not None:
            raise Exception(f'CRC mismatch at least for the file {result}')

        # Grab the ZipInfo objects only for those files we are interested in,
        # then sort the list
        source_infos = list(sorted(s.infolist(), key=lambda i: i.filename))

        # Prepare the payload
        if verbose > 0:
            print(f"The payload is {len(payload)} bytes long")

        # Base64-encode the payload
        b64_payload = base64.b64encode(payload)
        b64_payload_len = len(b64_payload)
        if verbose > 0:
            print(f"The base64-encoded payload is {b64_payload_len} bytes long")

        # Split the payload up into chunks
        chunk_length = min(MAX_CHUNK_LENGTH, max(1, chunk_length))
        b64_chunks = list()
        for i in range(0, b64_payload_len, chunk_length):
            b64_chunks.append(b64_payload[i:min(b64_payload_len, i+chunk_length)])
        if verbose > 1:
            print(f"The chunked payload is {len(b64_chunks)} chunks long")

        # Create the extra field data
        extra_fields = [struct.pack(f'<2H{len(c)}s', header_id, len(c), c) for c in b64_chunks]
        if verbose > 1:
            print(f"The extra fields are: {extra_fields}")

        # Write the payload
        if not dry_run:
            with tempfile.TemporaryDirectory() as tmp:
                write_mode = 'x' if not force else 'w'
                with ZipFile(destination_path, mode=write_mode) as d:
                    # Create a comment
                    d.comment = comment

                    # Clone the archive
                    i = 0
                    for zipinfo in source_infos:
                        # Write the extra field only to the selected files
                        if target_pattern.search(zipinfo.filename) is not None:
                            if i >= 0 and i < len(extra_fields):
                                zipinfo.extra = extra_fields[i]
                            i += 1

                        # Extract and recompress the file
                        tmp_output_path = s.extract(zipinfo, tmp)
                        with open(tmp_output_path, 'rb') as f:
                            d.writestr(zipinfo, f.read())


                    # Verify the CRCs of all files in the archive
                    result = d.testzip()
                    if result is not None:
                        raise Exception(f'CRC mismatch at least for the file {result}')


def __read_payload(source_path: Path, header_id: int, verbose: int) -> Tuple[bytes, bytes]:
    """Decode the payload stored in the Extra field of the APK ZIP archive"""

    with ZipFile(source_path, mode='r') as s:
        # Retrieve the archive comment
        comment = s.comment
        if verbose > 0:
            print(f'Retrieved the archive comment: {comment}')

        # Grab the ZipInfo objects only for those files we are interested in,
        # then sort the list
        source_infos = list(sorted(s.infolist(), key=lambda i: i.filename))

        if verbose > 1:
            print('Retrieved the extra fields (partially filtered):')
            for zipinfo in source_infos:
                ex = binascii.b2a_hex(zipinfo.extra)
                print(f'{zipinfo.filename}: {ex}')

        # Grab all relevant extra fields
        header_id_packed = struct.pack('<H', header_id)
        extra_fields = (z.extra for z in source_infos if len(z.extra) > 0 and z.extra.startswith(header_id_packed))

        # Parse the extra fields and extract the b64 payload
        raw_b64_payload = list()
        for field in extra_fields:
            (_, length) = struct.unpack('<2H', field[:4])
            (data, ) = struct.unpack(f'<{length}s', field[4:4+length])
            raw_b64_payload.append(data)
        if verbose > 1:
            print('Retrieved the raw payload:')
            for rpl in raw_b64_payload:
                print(rpl)

        # Decode the b64 data
        joined_raw_b64_payload = b''.join(raw_b64_payload)
        if verbose > 1:
            print(f'Retrieved the joined raw payload: {joined_raw_b64_payload}')
        payload = base64.b64decode(joined_raw_b64_payload)
        if verbose > 0:
            print(f'Retrieved the payload {payload}')

        return payload, comment


def main() -> None:
    parser = ArgumentParser(
        description="""
        Stores and retrieves arbitrary data inside the Extra field of the ZIP
        archive without invalidating the APK signature.  Read the source file
        for more information.
        """,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help='Control the level of output',
    )
    actions = parser.add_subparsers(title="subcommands", required=True)

    # Define the prepare subcommand
    prepare_parser = actions.add_parser(
        "prepare",
        help="Prepare an android project for payload embedding",
    )
    prepare_parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Nothing will be written if this flag is set",
    )
    prepare_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Causes any previously existing changes at the destination to be overwritten",
    )
    prepare_parser.add_argument(
        "-a",
        "--assets-dir",
        type=Path,
        default=ASSETS_DIR,
        help="The asset directory path, relative to the Android project",
    )
    prepare_parser.add_argument(
        "-c",
        "--num-files",
        type=int,
        default=TGHACK_NUM_FILES,
        help="The number of asset files to create",
    )
    prepare_parser.add_argument(
        "-p",
        "--prefix",
        default=TGHACK_FILE_PREFIX,
        help="The file prefix",
    )
    prepare_parser.add_argument(
        "-s",
        "--suffix",
        default=TGHACK_FILE_SUFFIX,
        help="The file suffix",
    )
    prepare_parser.add_argument(
        "-d",
        "--data",
        default=TGHACK_FILE_CONTENT,
        help="The file content",
    )
    prepare_parser.add_argument(
        "project",
        type=valid_directory_path,
        help="Specify the Android project path",
    )
    prepare_parser.set_defaults(func=prepare_project)

    # Define the write subcommand
    write_parser = actions.add_parser(
        "write",
        help='Write a payload to an APK',
    )
    write_parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Nothing will be written if this flag is set",
    )
    write_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Causes any previously existing archives at the destination to be overwritten",
    )
    write_parser.add_argument(
        "-t",
        "--target-pattern",
        default=f"{TGHACK_FILE_PREFIX}_[0-9]+{TGHACK_FILE_SUFFIX}",
        help="Filenames in the archive that match this regular expression have their ZIP extra fields overwritten",
    )
    write_parser.add_argument(
        "-i",
        "--header-id",
        type=valid_header_id,
        default=TGHACK_HEADER_ID,
        help="The magic number with which to identify our payloads",
    )
    write_parser.add_argument(
        "-l",
        "--chunk-length",
        type=valid_chunk_length,
        default=MAX_CHUNK_LENGTH,
        help='Specify the length of each payload chunk',
    )
    write_parser.add_argument(
        "-c",
        "--comment",
        default='The imp finally consents to give up his claim to the child if she can guess his name',
        help='Specify the APK ZIP comment',
    )
    write_parser.add_argument(
        "-p",
        "--payload",
        default='TG20{Mein_Name_ist_Rumpelstilzchen}',
        help='Specify the payload',
    )
    write_parser.add_argument(
        "source",
        type=valid_file_path,
        help="Specify the source APK path",
    )
    write_parser.add_argument(
        "destination",
        type=Path,
        help="Specify the destination APK path",
    )
    write_parser.set_defaults(func=write_payload)

    # Define the read subcommand
    read_parser = actions.add_parser(
        "read",
        help="Read a payload from an APK",
    )
    read_parser.add_argument(
        "-i",
        "--header-id",
        type=valid_header_id,
        default=TGHACK_HEADER_ID,
        help="The magic number with which to identify our payloads",
    )
    read_parser.add_argument(
        "source",
        type=valid_file_path,
        help="Specify the source APK path",
    )
    read_parser.set_defaults(func=read_payload)

    # Parse the command line arguments
    matches = parser.parse_args()

    # Run the appropriate subcommand
    matches.func(matches)


if __name__ == '__main__':
    main()

