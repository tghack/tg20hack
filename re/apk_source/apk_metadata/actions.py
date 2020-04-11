# -*- coding: utf-8 -*-

import base64
import math
import hashlib
import secrets
import struct
import re
import tempfile
from typing import Optional, Iterable, TypeVar, Tuple, List, Callable
from pathlib import Path
from zipfile import ZipFile, ZipInfo
from .validators import valid_header_id, valid_chunk_length, valid_file_path, valid_directory_path
from .utilities import chunker
from .constants import MAX_CHUNK_LENGTH


def prepare_project(
        project_path: Path,
        assets_dir_rel: Path,
        num_files: int,
        chunk_length: int,
        primary_payload: Callable[[], bytes],
        file_name: Callable[[int, bytes], str],
        dry_run: bool,
        force: bool,
        verbose: int
) -> None:
    '''Prepare an Android project for payload embedding by creating a set of nonsense asset files'''

    if dry_run and verbose > 0:
        print('Dry-run mode. I will not do anything irreversible, promise')

    # Create the assets directory
    assets_path = project_path.joinpath(assets_dir_rel)
    if verbose > 0:
        print(f'Creating the asset directory at {assets_path}')
    if not dry_run:
        assets_path.mkdir(parents=True, exist_ok=force)

    # Get the file content
    fc = primary_payload()
    if verbose > 1:
        print(f'Retrieved the unchunked file content {fc}')

    # Chunk the file content
    chunks = list(chunker(fc, chunk_length, num_files * chunk_length, 0x00))
    if verbose > 1:
        print(f'Retrieved the unencoded chunks {chunks}')

    # Create a number of files
    if verbose > 0:
        print(f'Creating {num_files} files')
    write_mode = 'xb' if not force else 'wb'
    for i in range(0, num_files):
        # Retrieve the current chunk
        chunk = chunks[i]

        # Determine the target file path
        file_path = assets_path.joinpath(file_name(i, chunk))
        if verbose > 2:
            print(f'Writing to the file at {file_path}')

        # Encode and write the chunk
        if not dry_run:
            with file_path.open(mode=write_mode) as f:
                if verbose > 2:
                    print(f'Writing the chunk {chunk}')
                f.write(chunk)


def write_payload(
        source_path: Path,
        destination_path: Path,
        target_pattern: re.Pattern,
        header_id: int,
        chunk_length: int,
        secondary_payload: Callable[[], bytes],
        apk_comment: Callable[[], bytes],
        file_comment: Callable[[int, str, bytes], bytes],
        dry_run: bool,
        force: bool,
        verbose: int
) -> None:
    '''Write the specified payload to the APK ZIP archive'''

    if dry_run and verbose > 0:
        print('Dry-run mode. I will not do anything irreversible, promise')

    if not force and destination_path.exists():
        raise ValueError(f'The path {destination_path} exists already')

    with ZipFile(source_path, mode='r') as s:
        # Verify the CRCs of all files in the archive
        result = s.testzip()
        if result is not None:
            raise ValueError(f'CRC mismatch at least for the file {result}')

        # Grab the ZipInfo objects only for those files we are interested in,
        # then sort the list
        source_infos = list(sorted(s.infolist(), key=lambda i: i.filename))

        target_source_infos = [i for i in source_infos if target_pattern.search(i.filename) is not None]
        target_source_infos_len = len(target_source_infos)
        if verbose > 0:
            print(f'Spreading the payload over {target_source_infos_len} files')

        # Prepare the payload
        pl = secondary_payload()
        payload_len = len(pl)
        if verbose > 0:
            print(f'The payload is {payload_len} bytes long')

        # Split the payload up into chunks
        chunk_length = math.floor(min(MAX_CHUNK_LENGTH, max(1, chunk_length)) * 0.333)
        chunks = list(chunker(pl, chunk_length, target_source_infos_len * chunk_length, secrets.token_bytes))
        if verbose > 1:
            print(f'The chunked payload is {len(chunks)} chunks long')

        # Base64-encode the payload
        b64_chunks = [base64.b64encode(c) for c in chunks]

        # Create the extra field data
        extra_fields = [struct.pack(f'<2H{len(c)}s', header_id, len(c), c) for c in b64_chunks]
        if verbose > 1:
            print(f'The extra fields are: {extra_fields}')

        # Write the payload
        if not dry_run:
            with tempfile.TemporaryDirectory() as tmp:
                write_mode = 'x' if not force else 'w'
                with ZipFile(destination_path, mode=write_mode) as d:
                    # Assign the ZIP comment
                    ac = apk_comment()
                    if len(ac) > 0:
                        if len(d.comment) > 0 and not force:
                            raise ValueError('There is already data stored in the ZIP archive comment')
                        d.comment = base64.b64encode(ac)

                    # Clone the archive
                    i = 0
                    for zipinfo in source_infos:
                        # Write the extra field only to the selected files
                        if target_pattern.search(zipinfo.filename) is not None:
                            # Retrieve the current chunk
                            chunk = extra_fields[i]

                            # Assign the file comment
                            fc = file_comment(i, zipinfo.filename, chunk)
                            if len(zipinfo.comment) > 0 and not force:
                                raise ValueError(f'There is already data stored in the comment field of the file {zipinfo.filename}')
                                zipinfo.comment = base64.b64encode(fc)

                            # Assign the extra field
                            if len(zipinfo.extra) > 0 and not force:
                                raise ValueError(f'There is already data stored in the ZIP extra field of file {zipinfo.filename}')
                            zipinfo.extra = chunk

                            # Increment the index
                            i += 1

                        # Extract and recompress the file
                        tmp_output_path = s.extract(zipinfo, tmp)
                        with open(tmp_output_path, 'rb') as f:
                            d.writestr(zipinfo, f.read())


                    # Verify the CRCs of all files in the archive
                    result = d.testzip()
                    if result is not None:
                        raise ValueError(f'CRC mismatch at least for the file {result}')


def read_payload(
        source_path: Path,
        header_id: int,
        primary_payload_decoder: Callable[[bytes, bytes], bytes],
        secondary_payload_decoder: Callable[[bytes], bytes],
        apk_comment_decoder: Callable[[bytes], bytes],
        file_comment_decoder: Callable[[int, str, bytes], bytes],
        verbose: int
) -> None:
    '''Decode the payload stored in the Extra field of the APK ZIP archive'''

    with ZipFile(source_path, mode='r') as s:
        # Retrieve the archive comment
        comment = apk_comment_decoder(base64.b64decode(s.comment))
        if verbose > 0:
            print(f'Retrieved the archive comment: {comment!r}')

        # Grab the ZipInfo objects only for those files we are interested in,
        # then sort the list
        source_infos = list(sorted(s.infolist(), key=lambda i: i.filename))

        if verbose > 1:
            print('Retrieved the extra fields (partially filtered):')
            for zipinfo in source_infos:
                print(f'(filename: {zipinfo.filename}, comment: {zipinfo.comment.hex()!r}, extra: {zipinfo.extra.hex()!r})')

        # Grab all relevant extra fields
        header_id_packed = struct.pack('<H', header_id)
        extra_fields = (z.extra for z in source_infos if len(z.extra) > 0 and z.extra.startswith(header_id_packed))

        # Parse the extra field and the comment for every relevant file
        with tempfile.TemporaryDirectory() as tmp:
            file_data = list()
            i = 0
            for z in source_infos:
                # Skip any uninteresting files
                if not (len(z.extra) > 0 and z.extra.startswith(header_id_packed)):
                    continue

                # Retrieve the file comment
                fc = file_comment_decoder(i, z.filename, base64.b64decode(z.comment))

                # Retrieve the extra field
                (_, length) = struct.unpack('<2H', z.extra[:4])
                (extra_data, ) = struct.unpack(f'<{length}s', z.extra[4:4+length])

                # Retrieve the file contents
                tmp_output_path = s.extract(z, tmp)
                with open(tmp_output_path, 'rb') as f:
                    file_contents = f.read()

                file_data.append((fc, extra_data, file_contents))

                i += 1

        if verbose > 1:
            fcs = [fd[0] for fd in file_data]
            print(f'Retrieved the file comments {fcs}')

        # Decode the secondary payload
        joined_raw_b64_payload = bytes((b for fd in file_data for b in fd[1]))
        if verbose > 1:
            print(f'Retrieved the joined raw payload: {joined_raw_b64_payload!r}')
        secondary_payload = secondary_payload_decoder(base64.b64decode(joined_raw_b64_payload))
        if verbose > 1:
            print(f'Retrieved the secondary payload {secondary_payload!r}')

        # Extract the primary payload
        pp = bytes((b for fd in file_data for b in fd[2]))
        primary_payload = primary_payload_decoder(pp, secondary_payload)
        if verbose > 0:
            print(f'Retrieved the primary payload {primary_payload!r}')

