#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import base64
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

if len(sys.argv) > 1:
    source_path = Path(sys.argv[1])
else:
    source_path = Path('gaiainvaders.apk')

with ZipFile(source_path, mode='r') as s:
    # Grab the ZipInfo objects only for those files we are interested in,
    # then sort the list
    source_infos = list(sorted(s.infolist(), key=lambda i: i.filename))

    # Since we are only interested in files whose Extra fields have the header
    # ID 1337, we need to convert that number to binary representation first.
    header_id_packed = struct.pack('<H', 0x1337)

    # Parse the Extra field for every relevant file
    extra_fields = list()
    i = 0
    for z in source_infos:
        # Skip any uninteresting files
        if not (len(z.extra) > 0 and z.extra.startswith(header_id_packed)):
            continue

        # Retrieve the extra field by first reading the data length, and then
        # parsing the binary data into python
        (_, length) = struct.unpack('<2H', z.extra[:4])
        (extra_field, ) = struct.unpack(f'<{length}s', z.extra[4:4+length])

        extra_fields.append(extra_field)

    # Join the bytes from each extra field into one long string
    joined_raw_b64_payload = bytes((b for ef in extra_fields for b in ef))
    extra_field_data = base64.b64decode(joined_raw_b64_payload)
    print(extra_field_data.decode('ascii'))
