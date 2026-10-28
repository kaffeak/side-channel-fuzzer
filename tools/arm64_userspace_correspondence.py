"""Passive B3.4a location policy, not instruction admission or a live-address check.

PC arguments are normalized offsets, never absolute addresses. Main-memory
arguments use an explicitly supplied main base in the same coordinate system:
4096 for model C-trace offsets, model.layout's MAIN address for model absolute
addresses, or a caller-supplied native main address. No other region is mapped.
All intervals are half-open; even their end must fit unsigned 64-bit arithmetic.
This policy is not integrated into any executor or trace conversion path.
"""

from rvzr.input_format import MAIN_SIZE


_MODEL_BODY = (12, 16, 20, 24, 28, 32, 36, 40)
_NATIVE_BODY = (0, 4, 8, 12, 16, 20, 24, 28)
_U64_MAX = (1 << 64) - 1


def _u64(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _U64_MAX:
        raise ValueError("Expected an unsigned 64-bit Python integer")


def model_pc_to_native_offset(offset: int) -> int:
    """Translate one normalized model body PC; exclude macros and exit events."""
    _u64(offset)
    if offset not in _MODEL_BODY:
        raise ValueError("Unsupported normalized model body PC")
    return _NATIVE_BODY[_MODEL_BODY.index(offset)]


def native_pc_to_model_offset(offset: int) -> int:
    """Translate one native body offset; RET at 32 has no body correspondence."""
    _u64(offset)
    if offset not in _NATIVE_BODY:
        raise ValueError("Unsupported normalized native body PC")
    return _MODEL_BODY[_NATIVE_BODY.index(offset)]


def main_access_to_offset(address: int, size: int, main_base: int) -> int:
    """Return a logical main offset only for a fully contained nonempty access.

    The supplied base is a coordinate declaration, not proof of mapping ownership,
    liveness, alignment or origin. Wrong-domain values are rejected when outside
    that declared range; numerically aliased domains cannot be distinguished.
    """
    for value in (address, size, main_base):
        _u64(value)
    if (size == 0 or size > MAIN_SIZE or main_base > _U64_MAX - MAIN_SIZE
            or address < main_base or address - main_base > MAIN_SIZE - size):
        raise ValueError("Access is outside the supported logical main region")
    return address - main_base
