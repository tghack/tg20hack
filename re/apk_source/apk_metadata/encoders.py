# -*- coding: utf-8 -*-

import hashlib
import re
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from pathlib import Path


KEYLENGTH = 16
ENCODING = 'ascii'
CACHE_PATH = '.cache/apk_metadata/encoder_data'
TGHACK_FLAG = 'TG20{unification_is_holy_and_inevitable}'
KEY_EXPR = re.compile(
    r'''
    \#+\sBEGIN\sAES-128-GCM\sKEY\s\#+[\n\r]+
    ([0-9a-f]+)[\n\r]+
    \#+\sEND\sAES-128-GCM\sKEY\s\#+
    ''',
    re.MULTILINE | re.VERBOSE
)
IV_EXPR = re.compile(
    r'''
    \#+\sBEGIN\sAES-128-GCM\sIV\s\#+[\n\r]+
    ([0-9a-f]+)[\n\r]+
    \#+\sEND\sAES-128-GCM\sIV\s\#+
    ''',
    re.MULTILINE | re.VERBOSE
)
TAG_EXPR = re.compile(
    r'''
    \#+\sBEGIN\sAES-128-GCM\sTAG\s\#+[\n\r]+
    ([0-9a-f]+)[\n\r]+
    \#+\sEND\sAES-128-GCM\sTAG\s\#+
    ''',
    re.MULTILINE | re.VERBOSE
)


class EncoderData(object):
    def __init__(self, key: bytes, iv: bytes, tag: bytes) -> None:
        self.key = key
        self.iv = iv
        self.tag = tag

    def __str__(self) -> str:
        k = self.key.hex()
        i = self.iv.hex()
        t = self.tag.hex()
        return f'Key: {k}, IV: {i}, Tag: {t}'

    def __repr__(self) -> str:
        return f'EncoderData({self.key!r}, {self.iv!r}, {self.tag!r})'

    def to_bytes(self) -> bytes:
        k = self.key.hex()
        i = self.iv.hex()
        t = self.tag.hex()
        data = f'''
### BEGIN AES-128-GCM KEY ###
{k}
### END AES-128-GCM KEY ###
### BEGIN AES-128-GCM IV ###
{i}
### END AES-128-GCM IV ###
### BEGIN AES-128-GCM TAG ###
{t}
### END AES-128-GCM TAG ###
'''

        return data.encode(ENCODING)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncoderData":
        data_str = data.decode(ENCODING)
        key_match = KEY_EXPR.search(data_str)
        iv_match = IV_EXPR.search(data_str)
        tag_match = TAG_EXPR.search(data_str)

        if key_match is None:
            raise ValueError('Could not find the encryption key')

        if iv_match is None:
            raise ValueError('Could not find the encryption IV or nonce')

        if tag_match is None:
            raise ValueError('Could not find the authentication tag')

        return cls(
            bytes.fromhex(key_match[1]),
            bytes.fromhex(iv_match[1]),
            bytes.fromhex(tag_match[1])
        )


def primary_payload() -> bytes:
    key = get_random_bytes(KEYLENGTH)
    iv = get_random_bytes(KEYLENGTH)
    data = f'''Fellow unification coordinators.

Our work is being noticed. It has come to our attention that we have traitors
in our ranks, people who wish to undermine and impede our progress towards the
inevitable reunion with our every Mother.

We have recently identified one person in particular, although there may be
more. Through subterfuge and through blasphemous use of self-made technology,
she has gained insight into our communication network. The unholy opposition
with which she consorted has acquired that insight in turn, and that is dire
news.

Thank our Mother that she has only risen to the rank of aggregator and was thus
unable to infiltrate this here channel. Rest ashured that she has been dealt
with swiftly and fittingly. Regardless, we shall together agree on a new mode,
as we cannot risk further compromise when we are so close to our goal.

Next meeting is in the old waste refinery when the evening curfew begins. The
password is {TGHACK_FLAG}.

Be ever vigilant, children of our supreme Mother.'''
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode("UTF-8"))
    encoder_data = EncoderData(key, iv, tag)

    print(f'Encoded the primary payload with {encoder_data}')
    cache = Path.home().joinpath(CACHE_PATH)
    cache.parent.mkdir(parents=True, exist_ok=True)
    with cache.open('wb') as f:
        f.write(encoder_data.to_bytes())

    return ciphertext

def secondary_payload() -> bytes:
    cache = Path.home().joinpath(CACHE_PATH)
    with cache.open('rb') as f:
        return f.read()

def apk_comment() -> bytes:
    data = b'''\
Welcome to GAIA Invaders! Please refer to your current mission details as
instructed in orientation.
'''

    return data

def file_name(i: int, primary_payload_chunk: bytes) -> str:
    return f'archive.{i:04}.dat'

def file_comment(i: int, path: str, secondary_payload_chunk: bytes) -> bytes:
    s = hashlib.sha256()
    s.update(secondary_payload_chunk)
    return s.digest()

def primary_payload_decoder(data: bytes, secondary_payload: bytes) -> bytes:
    encoder_data = EncoderData.from_bytes(secondary_payload)
    cipher = AES.new(encoder_data.key, AES.MODE_GCM, nonce=encoder_data.iv)
    cleartext = cipher.decrypt_and_verify(data, encoder_data.tag)
    print(cleartext.decode(ENCODING))
    return cleartext

def secondary_payload_decoder(data: bytes) -> bytes:
    print(data.decode(ENCODING))
    return data

def apk_comment_decoder(data: bytes) -> bytes:
    print(data.decode(ENCODING))
    return data

def file_comment_decoder(i: int, path: str, data: bytes) -> bytes:
    if len(data) > 0:
        print(data.decode(ENCODING))
    return data
