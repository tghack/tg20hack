# -*- coding: utf-8 -*-

from typing import Iterable, Callable, Union


def chunker(data: bytes, chunk_len: int, total_len: int, fill_byte: Union[int, Callable[[int], bytes]] = 0x00) -> Iterable[bytes]:
    '''Collect data into fixed-length chunks, while padding for incomplete chunks'''

    # Pad the input data
    data_len = len(data)
    total_len = max(total_len, data_len)
    if isinstance(fill_byte, int):
        padded_data = data.ljust(total_len, bytes([fill_byte]))
    else:
        padding_len = total_len - data_len
        padded_data = data.join([fill_byte(padding_len)])

    # Split the data into equal-length chunks
    chunks = list()
    for i in range(0, total_len, chunk_len):
        chunk = data[i:min(total_len, i + chunk_len)];
        chunks.append(chunk)

    return (data[i:min(total_len, i + chunk_len)] for i in range(0, total_len, chunk_len))

