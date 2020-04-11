# -*- coding: utf-8 -*-

TGHACK_HEADER_ID: int = 0x1337
TGHACK_EXTRA_DATA: bytes = b'TG00{DummyFlag}'
TGHACK_APK_COMMENT: bytes = b'Dummy APK ZIP Comment'
TGHACK_FILE_NAME: str = 'archive.{i:04}.dat'
TGHACK_FILE_CONTENT: bytes = b'Dummy File Content'
TGHACK_FILE_COMMENT: bytes = b'Dummy ZIP File Comment'
TGHACK_TARGET_PATTERN: str = 'archive\.[0-9]+\.dat'
TGHACK_NUM_FILES: int = 1024
EXTRA_MAX_LENGTH: int = 32
MAX_CHUNK_LENGTH: int = EXTRA_MAX_LENGTH - 4
ASSETS_DIR: str = 'app/src/main/assets'

