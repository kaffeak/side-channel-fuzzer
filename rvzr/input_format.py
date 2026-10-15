"""Fixed byte dimensions of the existing per-actor serialized input fragment.

These describe input bytes, not runtime sandbox offsets or kernel pages. The
12288-byte fragment contains 8512 data bytes and 3776 padding bytes; existing
RDBF metadata reports the data size. Runtime placement may change independently.
NumPy's existing native uint64 payload byte order is intentionally unchanged.
"""

from typing import Final


WORD_SIZE: Final = 8
MAIN_SIZE: Final = 4096
FAULTY_SIZE: Final = 4096
GPR_SIZE: Final = 64
SIMD_SIZE: Final = 256
REGISTER_INIT_SIZE: Final = GPR_SIZE + SIMD_SIZE
REGISTER_BLOCK_SIZE: Final = 4096
PADDING_SIZE: Final = REGISTER_BLOCK_SIZE - REGISTER_INIT_SIZE

MAIN_OFFSET: Final = 0
FAULTY_OFFSET: Final = MAIN_OFFSET + MAIN_SIZE
GPR_OFFSET: Final = FAULTY_OFFSET + FAULTY_SIZE
SIMD_OFFSET: Final = GPR_OFFSET + GPR_SIZE
PADDING_OFFSET: Final = SIMD_OFFSET + SIMD_SIZE
FRAGMENT_SIZE: Final = PADDING_OFFSET + PADDING_SIZE
DATA_SIZE: Final = PADDING_OFFSET
