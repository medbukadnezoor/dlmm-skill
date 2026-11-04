"""Tiny dependency-free Solana helpers: base58 validation and the on-curve test.

An address that is NOT a valid ed25519 point cannot have a private key, so it is
a program-derived address (pool vault authority, escrow, ...). Holders like that
are infrastructure, not people.
"""

from __future__ import annotations

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: i for i, char in enumerate(_ALPHABET)}
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P

BURN_ADDRESSES = {
    "1nc1nerator11111111111111111111111111111111": "burn",
    "11111111111111111111111111111111": "burn",
}


def b58decode(value: str) -> bytes:
    number = 0
    for char in value:
        if char not in _INDEX:
            raise ValueError("invalid base58 character")
        number = number * 58 + _INDEX[char]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    pad = len(value) - len(value.lstrip("1"))
    return b"\x00" * pad + body


def is_solana_address(value: object) -> bool:
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return False
    try:
        return len(b58decode(value)) == 32
    except ValueError:
        return False


def is_on_curve(address: str) -> bool:
    raw = b58decode(address)
    if len(raw) != 32:
        raise ValueError("not a 32-byte address")
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    y %= _P
    numerator = (y * y - 1) % _P
    denominator = (_D * y * y + 1) % _P
    x2 = numerator * pow(denominator, _P - 2, _P) % _P
    if x2 == 0:
        return True
    return pow(x2, (_P - 1) // 2, _P) == 1
