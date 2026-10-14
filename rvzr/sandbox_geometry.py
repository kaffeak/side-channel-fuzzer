"""Pure actor-data geometry for explicitly selected 4 KB and 16 KB kernel pages.

This module is a design aid, independent of the existing SandboxLayout and
executor. Logical payload sizes are fixed; kernel pages determine placement
and permission granularity. No host page size or CPU information is consulted.

Offsets and half-open mapping ranges are relative to a kernel-page-aligned
actor base. The 4 KB profile reproduces the existing actor structure. The
16 KB profile is proposed, not validated for runtime use: its main address
cannot satisfy the executor's current 8 KB alignment assertion. The entire
faulty mapping, including its padding, would receive faulty permissions.

Utility and code allocations, input serialization, and instruction encodings
are outside this representation.
"""

from dataclasses import dataclass
from typing import ClassVar, Tuple


ByteRange = Tuple[int, int]
_LOGICAL_REGION_SIZE = 4096


@dataclass(frozen=True)
class SandboxGeometry:
    """Immutable actor-data placement; kernel_page_size must be supplied explicitly.

    Main and faulty payloads form one contiguous 8 KB window whose midpoint
    lies on a kernel-page boundary. Registers occupy a separate normal page.
    Leading and trailing space is placement padding, not additional input.
    """

    kernel_page_size: int

    macro_stack_size: ClassVar[int] = 64
    underflow_pad_size: ClassVar[int] = _LOGICAL_REGION_SIZE - 64
    main_size: ClassVar[int] = _LOGICAL_REGION_SIZE
    faulty_size: ClassVar[int] = _LOGICAL_REGION_SIZE
    register_init_size: ClassVar[int] = 320
    overflow_pad_size: ClassVar[int] = _LOGICAL_REGION_SIZE - 320

    def __post_init__(self) -> None:
        if isinstance(self.kernel_page_size, bool) or not isinstance(self.kernel_page_size, int):
            raise TypeError("kernel_page_size must be an integer")
        if self.kernel_page_size not in (4096, 16384):
            raise ValueError("kernel_page_size must be 4096 or 16384 bytes")

    @property
    def faulty_offset(self) -> int:
        """Start of the faulty payload and its kernel-page permission mapping."""
        size = 2 * _LOGICAL_REGION_SIZE
        return ((size + self.kernel_page_size - 1) // self.kernel_page_size) \
            * self.kernel_page_size

    @property
    def main_offset(self) -> int:
        """Start of the main payload, immediately before the faulty payload."""
        return self.faulty_offset - self.main_size

    @property
    def macro_stack_offset(self) -> int:
        """Start of the fixed macro-stack and underflow-padding block."""
        return self.main_offset - _LOGICAL_REGION_SIZE

    @property
    def underflow_pad_offset(self) -> int:
        """Start of the existing underflow padding immediately after the macro stack."""
        return self.macro_stack_offset + self.macro_stack_size

    @property
    def register_init_offset(self) -> int:
        """Start of registers on the normal page following the whole faulty mapping."""
        return self.faulty_offset + self.kernel_page_size

    @property
    def overflow_pad_offset(self) -> int:
        """Start of the existing logical overflow padding after register storage."""
        return self.register_init_offset + self.register_init_size

    @property
    def local_stack_offset(self) -> int:
        """Prescribed local stack address: the final eight bytes of the main payload."""
        return self.faulty_offset - 8

    @property
    def actor_stride(self) -> int:
        """Allocated span per actor, including placement padding."""
        return self.register_init_offset + self.kernel_page_size

    @property
    def main_mapping(self) -> ByteRange:
        """Kernel page containing the main payload, as a half-open byte range."""
        start = (self.main_offset // self.kernel_page_size) * self.kernel_page_size
        return start, start + self.kernel_page_size

    @property
    def faulty_mapping(self) -> ByteRange:
        """Whole faulty kernel page, including padding beyond the 4 KB payload."""
        return self.faulty_offset, self.register_init_offset

    @property
    def register_mapping(self) -> ByteRange:
        """Normal kernel page containing register storage and overflow padding."""
        return self.register_init_offset, self.actor_stride

    def actor_base_offset(self, actor_id: int) -> int:
        """Return an actor's offset within a sequence of equally sized actor spans."""
        if isinstance(actor_id, bool) or not isinstance(actor_id, int):
            raise TypeError("actor_id must be an integer")
        if actor_id < 0:
            raise ValueError("actor_id must be nonnegative")
        return actor_id * self.actor_stride
