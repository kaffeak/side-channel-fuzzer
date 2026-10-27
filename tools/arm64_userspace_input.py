"""Restricted InputData transport for the fixed ARM64 userspace fixture.

The wire payload is exactly the production one-actor raw fragment, not RDBF.
Only main memory and X0 may be nonzero. In particular, input NZCV/SP slots
are rejected rather than used as X6/X7 or as host state/pointers. The C reader
independently validates these restrictions before allocating executable memory.
This is an experiment adapter, not a registered Executor or a kernel ABI.
"""

import sys

from rvzr import input_format
from rvzr.tc_components.test_case_data import InputData


INPUT_FORMAT = "rvzr-inputdata-raw-v1"
# Reuse the actual dtype without recreating its field definitions. No data read.
_INPUT_DTYPE = InputData(1).dtype


def encode_input(input_: InputData) -> bytes:
    """Return unchanged serialized bytes for the supported one-actor subset.

    Caller owns the immutable bytes and must close stdin after passing exactly
    one fragment to ``--input-format rvzr-inputdata-raw-v1``. There are no path,
    pointer or executable-code fields. Invalid/unsupported input raises ValueError.
    """
    if sys.byteorder != "little":
        raise ValueError("The fixed fixture transport requires little-endian InputData")
    if not isinstance(input_, InputData) or input_.shape != (1,) or input_.dtype != _INPUT_DTYPE:
        raise ValueError("Expected the production InputData dtype with exactly one actor")
    wire = input_.tobytes()
    if len(wire) != input_format.FRAGMENT_SIZE:
        raise ValueError("Unexpected serialized actor fragment size")
    selector_end = input_format.GPR_OFFSET + input_format.WORD_SIZE
    if any(wire[input_format.MAIN_SIZE:input_format.GPR_OFFSET]) or any(wire[selector_end:]):
        raise ValueError("Only main memory and X0 are supported; other fields must be zero")
    return wire
