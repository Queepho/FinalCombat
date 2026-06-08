#!/usr/bin/env python3
"""DCF BS body transform helpers.

Runtime reverse notes:
- transform object vtable: 0xd33fdc
- send/encrypt function: 0xbb21f0, state at object +4
- recv/decrypt function: 0xbb2240, state at object +8
- initial state set by 0xbb21d0/0xbb2280: 0x42574954

The feedback table is the standard CRC32 table. The wire byte is XORed with the
low byte of the current state, then the state is advanced using the plaintext
byte as the CRC table index.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


INITIAL_STATE = 0x42574954


def build_crc32_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        table.append(crc & 0xFFFFFFFF)
    return tuple(table)


CRC32_TABLE = build_crc32_table()


DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]
DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]
DES_E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]
DES_P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]
DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]
DES_PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]
DES_ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
DES_SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


@dataclass(frozen=True)
class TransformResult:
    data: bytes
    state: int


def encrypt_body(plain: bytes, state: int = INITIAL_STATE) -> TransformResult:
    out = bytearray()
    for byte in plain:
        out.append(byte ^ (state & 0xFF))
        state = ((state >> 8) ^ CRC32_TABLE[byte]) & 0xFFFFFFFF
    return TransformResult(bytes(out), state)


def decrypt_body(cipher: bytes, state: int = INITIAL_STATE) -> TransformResult:
    out = bytearray()
    for byte in cipher:
        plain = byte ^ (state & 0xFF)
        out.append(plain)
        state = ((state >> 8) ^ CRC32_TABLE[plain]) & 0xFFFFFFFF
    return TransformResult(bytes(out), state)


def _permute(value: int, table: list[int], input_bits: int) -> int:
    out = 0
    for bit in table:
        out = (out << 1) | ((value >> (input_bits - bit)) & 1)
    return out


def _rotl28(value: int, count: int) -> int:
    return ((value << count) | (value >> (28 - count))) & 0x0FFFFFFF


def _des_subkeys(key: bytes) -> list[int]:
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    key_int = int.from_bytes(key, "big")
    permuted = _permute(key_int, DES_PC1, 64)
    c = (permuted >> 28) & 0x0FFFFFFF
    d = permuted & 0x0FFFFFFF
    subkeys = []
    for rotation in DES_ROTATIONS:
        c = _rotl28(c, rotation)
        d = _rotl28(d, rotation)
        subkeys.append(_permute((c << 28) | d, DES_PC2, 56))
    return subkeys


def _des_f(right: int, subkey: int) -> int:
    expanded = _permute(right, DES_E, 32) ^ subkey
    value = 0
    for index, sbox in enumerate(DES_SBOXES):
        chunk = (expanded >> (42 - 6 * index)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 1)
        col = (chunk >> 1) & 0x0F
        value = (value << 4) | sbox[row][col]
    return _permute(value, DES_P, 32)


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 8:
        raise ValueError("DES block must be 8 bytes")
    value = _permute(int.from_bytes(block, "big"), DES_IP, 64)
    left = (value >> 32) & 0xFFFFFFFF
    right = value & 0xFFFFFFFF
    for subkey in _des_subkeys(key):
        left, right = right, left ^ _des_f(right, subkey)
    final = _permute((right << 32) | left, DES_FP, 64)
    return final.to_bytes(8, "big")


def des_cfb64_encrypt(plain: bytes, key: bytes, iv: bytes = b"\x00" * 8) -> bytes:
    if len(iv) != 8:
        raise ValueError("DES CFB64 IV must be 8 bytes")
    out = bytearray()
    current_iv = iv
    for offset in range(0, len(plain), 8):
        chunk = plain[offset : offset + 8]
        stream = des_encrypt_block(current_iv, key)
        cipher = bytes(byte ^ stream[index] for index, byte in enumerate(chunk))
        out.extend(cipher)
        current_iv = cipher if len(cipher) == 8 else current_iv
    return bytes(out)


def des_cfb64_decrypt(cipher: bytes, key: bytes, iv: bytes = b"\x00" * 8) -> bytes:
    if len(iv) != 8:
        raise ValueError("DES CFB64 IV must be 8 bytes")
    out = bytearray()
    current_iv = iv
    for offset in range(0, len(cipher), 8):
        chunk = cipher[offset : offset + 8]
        stream = des_encrypt_block(current_iv, key)
        plain = bytes(byte ^ stream[index] for index, byte in enumerate(chunk))
        out.extend(plain)
        current_iv = chunk if len(chunk) == 8 else current_iv
    return bytes(out)


def frame_body(body: bytes) -> bytes:
    total_len = len(body) + 4
    if total_len > 0xFFFF:
        raise ValueError(f"BS frame too large: {total_len}")
    return b"BS" + struct.pack("<H", total_len) + body


def read_cstring_packet_field(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 4 > len(data):
        raise ValueError(f"missing string length at {offset}")
    size = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    end = offset + size
    if end > len(data):
        raise ValueError(f"string at {offset} exceeds packet length: {size}")
    return data[offset:end].decode("utf-8", errors="replace"), end


def parse_initial_login_plain(body: bytes) -> dict[str, object]:
    """Parse the confirmed C-client initial login packet plaintext.

    Confirmed from runtime builder at 0x8b19e0 and captures where the encrypted
    99-byte frame decrypts to this structure.
    """
    if len(body) < 4:
        raise ValueError("initial login body too short")
    opcode = struct.unpack_from("<I", body, 0)[0]
    offset = 4
    version, offset = read_cstring_packet_field(body, offset)
    reserved, offset = read_cstring_packet_field(body, offset)
    account, offset = read_cstring_packet_field(body, offset)
    ticket, offset = read_cstring_packet_field(body, offset)
    challenge_response = body[offset : offset + 8]
    offset += len(challenge_response)
    return {
        "opcode": opcode,
        "version": version,
        "reserved": reserved,
        "account": account,
        "ticket": ticket,
        "challenge_response_hex": challenge_response.hex(" "),
        "trailing_bytes": body[offset:].hex(" "),
        "total_len": len(body),
    }
