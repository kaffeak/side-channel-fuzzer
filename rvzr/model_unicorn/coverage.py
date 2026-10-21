"""
File: Class for tracking instruction coverage in fuzzing campaigns with Unicorn backend.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from collections import defaultdict

from typing import Dict, Optional, Set
from typing_extensions import assert_never

from ..tc_components.instruction import Instruction, RegisterOp, MemoryOp, \
    ImmediateOp, LabelOp, AgenOp, FlagsOp, CondOp
from ..config import CONF


def _get_instruction_signature(instruction: Instruction) -> str:
    """
    Get a brief string representation of the instruction's current shape.
    Used as a unique identifier for the instruction when tracking coverage.
    Compute it on demand: operand lists can change, and object IDs can be reused.
    """
    brief = instruction.name
    for o in instruction.operands:
        if isinstance(o, RegisterOp):
            brief += f" R{o.width}"
        elif isinstance(o, MemoryOp):
            brief += f" M{o.width}"
        elif isinstance(o, ImmediateOp):
            brief += f" I{o.width}"
        elif isinstance(o, LabelOp):
            brief += " L"
        elif isinstance(o, AgenOp):
            brief += f" A{o.width}"
        elif isinstance(o, FlagsOp):
            brief += " F"
        elif isinstance(o, CondOp):
            brief += " C"

        else:
            assert_never(o)

    return brief


class InstructionCoverage:
    """
    Tracks coverage of instructions executed on the model during a fuzzing campaign.
    """
    _cov: Dict[str, int]
    """ Number of committed test-case intervals containing each instruction signature. """

    _local_cov: Optional[Dict[str, int]] = None
    """ Execution counts within the current test-case load interval; None when disabled. """

    _finalized_signatures: Set[str]
    """ Signatures already committed from the current interval, cleared on the next start. """

    def __init__(self) -> None:
        self._cov = defaultdict(int)
        self._finalized_signatures = set()

    def start_test_case(self) -> None:
        """
        Start tracking coverage for a new test case when CONF.coverage_type == "model_instructions".
        Otherwise, disable coverage tracking.
        The caller must finish the preceding interval before starting another.
        """

        self._finalized_signatures.clear()
        if CONF.coverage_type == "model_instructions":
            self._local_cov = defaultdict(int)
            return

        self._local_cov = None

    def add_instruction(self, inst: Instruction) -> None:
        """ Record the given instruction as covered (if coverage tracking is enabled) """
        if self._local_cov is None:
            return
        if inst.is_instrumentation:
            return
        self._local_cov[_get_instruction_signature(inst)] += 1

    def finish_test_case(self) -> None:
        """ Commit each observed signature at most once per test-case load interval.

        Further observations before the next start remain in the same interval:
        only previously uncommitted signatures can contribute on a later finish.
        """
        if self._local_cov is None:
            return

        for inst_name in self._local_cov:
            if inst_name in self._finalized_signatures:
                continue
            self._cov[inst_name] += 1
            self._finalized_signatures.add(inst_name)

    def report(self, path: str) -> None:
        """ Write committed history plus pending signature presence without changing state. """
        counts = self._cov.copy()
        if self._local_cov is not None:
            for inst_name in self._local_cov:
                if inst_name in self._finalized_signatures:
                    continue
                counts[inst_name] = counts.get(inst_name, 0) + 1

        # Sort the instructions by coverage count and write them to the file
        inst_names = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        with open(path, "w") as f:
            for inst_name, count in inst_names:
                f.write(f"{inst_name:<20} {count}\n")
            if not inst_names:
                f.write("    No coverage data available")
