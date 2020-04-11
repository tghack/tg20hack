#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from .validators import valid_header_id, valid_chunk_length, valid_file_path, valid_directory_path
from .actions import prepare_project, write_payload, read_payload
from .constants import TGHACK_HEADER_ID, TGHACK_EXTRA_DATA, TGHACK_APK_COMMENT, TGHACK_FILE_NAME, TGHACK_FILE_CONTENT, TGHACK_FILE_COMMENT, TGHACK_TARGET_PATTERN, TGHACK_NUM_FILES, EXTRA_MAX_LENGTH, MAX_CHUNK_LENGTH, ASSETS_DIR
from .encoders import primary_payload, file_name, secondary_payload, apk_comment, file_comment, primary_payload_decoder, secondary_payload_decoder, apk_comment_decoder, file_comment_decoder


def _subcommand_prepare_project(matches: Namespace) -> None:
    verbose: int = matches.verbose
    dry_run: bool = matches.dry_run
    force: bool = matches.force
    assets_dir_rel: Path = matches.assets_dir
    num_files: int = matches.num_files
    chunk_length: int = matches.chunk_length
    project_path: Path = matches.project

    prepare_project(project_path, assets_dir_rel, num_files, chunk_length, primary_payload, file_name, dry_run, force, verbose)

def _subcommand_write_payload(matches: Namespace) -> None:
    verbose: int = matches.verbose
    dry_run: bool = matches.dry_run
    force: bool = matches.force
    target_pattern: re.Pattern = re.compile(matches.target_pattern)
    header_id: int = matches.header_id
    chunk_length: int = matches.chunk_length
    source_path: Path = matches.source
    destination_path: Path = matches.destination

    write_payload(source_path, destination_path, target_pattern, header_id, chunk_length, secondary_payload, apk_comment, file_comment, dry_run, force, verbose)


def _subcommand_read_payload(matches: Namespace) -> None:
    verbose: int = matches.verbose
    header_id: int = matches.header_id
    source_path: Path = matches.source

    read_payload(source_path, header_id, primary_payload_decoder, secondary_payload_decoder, apk_comment_decoder, file_comment_decoder, verbose)


def main() -> None:
    parser = ArgumentParser(
        prog='apk_metadata',
        description='''
        Stores and retrieves arbitrary data inside the Extra field of the ZIP
        archive without invalidating the APK signature. Read the source file
        for more information.
        ''',
        add_help=True,
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help='Control the level of output (default: quiet)',
    )
    actions = parser.add_subparsers(
        title='subcommands',
        description='Known subcommands',
        help='Specify the action to take',
    )

    # Define the prepare subcommand
    prepare_parser = actions.add_parser(
        'prepare',
        help='''
        Within the asset directory of an Android project, create a set of files
        with a secondary payload split over them. This payload is probably seen
        first and should be used to hint at the primary payload.
        ''',
    )
    prepare_parser.add_argument(
        '-n',
        '--dry-run',
        action='store_true',
        help='Nothing will be written if this flag is set',
    )
    prepare_parser.add_argument(
        '-f',
        '--force',
        action='store_true',
        help='Causes any previously existing changes at the destination to be overwritten',
    )
    prepare_parser.add_argument(
        '-a',
        '--assets-dir',
        type=Path,
        default=ASSETS_DIR,
        help=f'The asset directory path, relative to the Android project (default: {ASSETS_DIR})',
    )
    prepare_parser.add_argument(
        '-c',
        '--num-files',
        type=int,
        default=TGHACK_NUM_FILES,
        help=f'The number of asset files to create (default: {TGHACK_NUM_FILES})',
    )
    prepare_parser.add_argument(
        '-l',
        '--chunk-length',
        type=valid_chunk_length,
        default=MAX_CHUNK_LENGTH,
        help=f'Specify the length of each payload chunk in bytes (default: {MAX_CHUNK_LENGTH})',
    )
    prepare_parser.add_argument(
        'project',
        type=valid_directory_path,
        help='Specify the Android project path',
    )
    prepare_parser.set_defaults(func=_subcommand_prepare_project)

    # Define the write subcommand
    write_parser = actions.add_parser(
        'write',
        help='''
        Within the ZIP metadata of the signed APK, write the primary payload.
        This should contain the flag.
        ''',
    )
    write_parser.add_argument(
        '-n',
        '--dry-run',
        action='store_true',
        help='Nothing will be written if this flag is set',
    )
    write_parser.add_argument(
        '-f',
        '--force',
        action='store_true',
        help='Causes any previously existing archives at the destination to be overwritten',
    )
    write_parser.add_argument(
        '-t',
        '--target-pattern',
        default=TGHACK_TARGET_PATTERN,
        help=f'Filenames in the archive that match this regular expression have their ZIP extra fields overwritten (default: {TGHACK_TARGET_PATTERN})',
    )
    write_parser.add_argument(
        '-i',
        '--header-id',
        type=valid_header_id,
        default=TGHACK_HEADER_ID,
        help=f'The magic number with which to identify our payloads (default: 0x{TGHACK_HEADER_ID:x})',
    )
    write_parser.add_argument(
        '-l',
        '--chunk-length',
        type=valid_chunk_length,
        default=MAX_CHUNK_LENGTH,
        help=f'Specify the length of each payload chunk in bytes (default: {MAX_CHUNK_LENGTH})',
    )
    write_parser.add_argument(
        'source',
        type=valid_file_path,
        help='Specify the source APK path',
    )
    write_parser.add_argument(
        'destination',
        type=Path,
        help='Specify the destination APK path',
    )
    write_parser.set_defaults(func=_subcommand_write_payload)

    # Define the read subcommand
    read_parser = actions.add_parser(
        'read',
        help='''
        Read both the primary and secondary payload from the APK
        ''',
    )
    read_parser.add_argument(
        '-i',
        '--header-id',
        type=valid_header_id,
        default=TGHACK_HEADER_ID,
        help=f'The magic number with which to identify our payloads (default: {TGHACK_HEADER_ID})',
    )
    read_parser.add_argument(
        'source',
        type=valid_file_path,
        help='Specify the source APK path',
    )
    read_parser.set_defaults(func=_subcommand_read_payload)

    # Parse the command line arguments
    matches = parser.parse_args()

    # Run the appropriate subcommand
    if hasattr(matches, 'func'):
        matches.func(matches)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

