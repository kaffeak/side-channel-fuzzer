"""Real typed seq/cond traces and passive location policy; no native execution.

Only the existing binutils/CPU-identification software fixture is reused. Program
generation, ELF extraction, InputData, Unicorn execution and CTrace are real.
Equivalence assertions compare complete ordered typed tuples, never hashes.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from typing import NamedTuple
import unittest

import numpy as np
import unicorn.arm64_const as ucc  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.config import CONF
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.model_unicorn.speculators_basic import ARM64CondSpeculator, SeqSpeculator
from rvzr.model_unicorn.tracer import CTTracer
from rvzr.sandbox import DataArea, SandboxLayout
from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTraceEntry
from tests import unit_arm64_contract_slice as slice_tests
from tools.arm64_userspace_correspondence import (
    main_access_to_offset, model_pc_to_native_offset, native_pc_to_model_offset)
from tools.arm64_userspace_input import encode_input
from tools.arm64_userspace_program import APPROVED_PROGRAM, export_approved_program


_MODEL_DATA, _MODEL_CODE, _NATIVE_MAIN = 0x109000, 0x200000, 0x70000000
_MAX = (1 << 64) - 1
_MATRIX = (("A", 0, 7), ("B", 0, 19), ("C", 1, 7),
           ("D", 1, 18), ("E", 2, 7), ("F", 0, 7))
_PREFIX = (CTraceEntry("pc", 12), CTraceEntry("pc", 16))
_JOIN = (CTraceEntry("pc", 32), CTraceEntry("mem", 4096), CTraceEntry("pc", 36),
         CTraceEntry("pc", 40), CTraceEntry("mem", 4096), CTraceEntry("pc", 44))
_TAKEN = (CTraceEntry("pc", 28),) + _JOIN
_FALL = (CTraceEntry("pc", 20), CTraceEntry("pc", 24)) + _JOIN


class _Observation(NamedTuple):
    typed: tuple[CTraceEntry, ...]
    registers: tuple[int, ...]
    nzcv: int
    main: bytes


class LocationPolicyTest(unittest.TestCase):
    def test_all_body_instruction_offsets_in_both_directions(self) -> None:
        for model, native in ((12, 0), (16, 4), (20, 8), (24, 12),
                              (28, 16), (32, 20), (36, 24), (40, 28)):
            self.assertEqual(model_pc_to_native_offset(model), native)
            self.assertEqual(native_pc_to_model_offset(native), model)
            self.assertEqual(native_pc_to_model_offset(model_pc_to_native_offset(model)), model)

    def test_placeholders_boundaries_ret_unknown_and_absolute_pcs_rejected(self) -> None:
        for offset in (0, 4, 8, 13, 42, 44, 48, 52, 56, 60, _MODEL_CODE + 12, -1, 1 << 64):
            with self.subTest(model=offset), self.assertRaises(ValueError):
                model_pc_to_native_offset(offset)
        for offset in (-1, 1, 30, 32, 36, 44, _NATIVE_MAIN, 1 << 64):
            with self.subTest(native=offset), self.assertRaises(ValueError):
                native_pc_to_model_offset(offset)
        for invalid in (True, 12.0, "12", None):
            for mapper in (model_pc_to_native_offset, native_pc_to_model_offset):
                with self.assertRaises(ValueError):
                    mapper(invalid)  # type: ignore[arg-type]

    def test_each_logical_main_byte_in_both_coordinate_systems(self) -> None:
        for offset in range(4096):
            self.assertEqual(main_access_to_offset(4096 + offset, 1, 4096), offset)
            self.assertEqual(main_access_to_offset(_NATIVE_MAIN + offset, 1, _NATIVE_MAIN), offset)
        for base in (4096, _NATIVE_MAIN):
            for offset in range(4089):
                self.assertEqual(main_access_to_offset(base + offset, 8, base), offset)
            self.assertEqual(main_access_to_offset(base, 4096, base), 0)

    def test_whole_access_bounds_and_unsupported_regions(self) -> None:
        for base in (4096, _NATIVE_MAIN):
            for address, size in ((base - 1, 1), (base + 4096, 1), (base + 4089, 8),
                                  (base + 4095, 2), (base, 4097), (base, 0)):
                with self.subTest(base=base, address=address, size=size), \
                        self.assertRaises(ValueError):
                    main_access_to_offset(address, size, base)
        # Model macro stack/underflow, faulty, registers, code/utility-like address,
        # and a synthetic host stack have no main mapping. These are NOT live addresses.
        for address in (0, 64, 4095, 8192, 12288, _MODEL_CODE, 0x7fff0000):
            with self.assertRaises(ValueError):
                main_access_to_offset(address, 8, 4096)
        for address in (_MODEL_DATA + 4096, _NATIVE_MAIN):
            with self.assertRaises(ValueError):
                main_access_to_offset(address, 8, 4096)  # Absolute is not a trace offset.

    def test_unsigned_arithmetic_and_types(self) -> None:
        for request in ((-1, 8, 4096), (4096, -1, 4096), (4096, 8, -1),
                        (1 << 64, 8, 4096), (4096, 1 << 64, 4096),
                        (4096, 8, 1 << 64), (_MAX - 3, 8, _MAX - 4096),
                        (_MAX - 4095, 1, _MAX - 4095)):
            with self.subTest(request=request), self.assertRaises(ValueError):
                main_access_to_offset(*request)
        self.assertEqual(main_access_to_offset(_MAX - 8, 8, _MAX - 4096), 4088)
        for invalid in (False, 8.0, "8", None):
            for index in range(3):
                invalid_request = [4096, 8, 4096]
                invalid_request[index] = invalid  # type: ignore[assignment]
                with self.assertRaises(ValueError):
                    main_access_to_offset(*invalid_request)

    def test_real_sandbox_normalization_precedes_mapping(self) -> None:
        layout = SandboxLayout((_MODEL_DATA, _MODEL_CODE), 1)
        main = layout.get_data_addr(DataArea.MAIN, 0)
        self.assertEqual(main, _MODEL_DATA + 4096)
        self.assertEqual(layout.data_area_size(DataArea.MAIN), 4096)
        for offset in (0, 8, 4088):
            normalized = layout.data_addr_to_offset(main + offset)
            self.assertEqual(normalized, 4096 + offset)
            self.assertEqual(main_access_to_offset(normalized, 8, 4096), offset)
            self.assertEqual(main_access_to_offset(main + offset, 8, main), offset)
        self.assertEqual(model_pc_to_native_offset(
            layout.code_addr_to_offset(_MODEL_CODE + 12)), 0)


class ARM64LocationContractTest(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="rvzr-b35i-")))
        stack.enter_context(slice_tests.software_environment(directory))
        CONF.model_max_spec_window = 32
        self.case = slice_tests.ARM64ContractSliceTest().assemble_case(directory)
        self.assertEqual(export_approved_program(self.case), APPROVED_PROGRAM)
        self.inputs = {}
        for name, selector, word in _MATRIX:
            input_ = InputData(1)
            input_.view(np.uint8).fill(0)
            input_[0]["gpr"][0], input_[0]["main"][0] = selector, word
            expected = bytearray(12288)
            struct.pack_into("<Q", expected, 0, word)
            struct.pack_into("<Q", expected, 8192, selector)
            self.assertEqual(encode_input(input_), bytes(expected))
            self.inputs[name] = input_
        self.assertEqual(encode_input(self.inputs["A"]), encode_input(self.inputs["F"]))
        self.assertNotEqual(encode_input(self.inputs["A"]), encode_input(self.inputs["B"]))

    def make_model(self, clause: str) -> ARM64UnicornModel:
        CONF.contract_execution_clause = [clause]
        model = factory.get_model((_MODEL_DATA, _MODEL_CODE))
        assert isinstance(model, ARM64UnicornModel)
        self.assertIsInstance(model.tracer, CTTracer)
        self.assertIsInstance(model.speculator, SeqSpeculator if clause == "seq"
                              else ARM64CondSpeculator)
        self.assertFalse(model._enable_mismatch_check_mode)
        model.load_test_case(self.case)
        return model

    def collect(self, clause: str) -> dict[str, _Observation]:
        model = self.make_model(clause)
        snapshots = {name: encode_input(value) for name, value in self.inputs.items()}
        observations: dict[str, _Observation] = {}
        for iteration, names in enumerate((list(self.inputs), list(reversed(self.inputs)))):
            for name in names:
                self.assertEqual((CONF.instruction_set, CONF.model_backend,
                                  CONF.contract_execution_clause, CONF.contract_observation_clause,
                                  CONF.model_max_spec_window, CONF._handled_faults),
                                 ("arm64", "unicorn", [clause], "ct", 32, []))
                trace = model.trace_test_case([self.inputs[name]], nesting=1)[0]
                actual = _Observation(tuple(trace.get_typed()), tuple(
                    int(model.emulator.reg_read(reg)) for reg in (
                        ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1,
                        ucc.UC_ARM64_REG_X2, ucc.UC_ARM64_REG_X3)),
                    int(model.emulator.reg_read(ucc.UC_ARM64_REG_NZCV)),
                    bytes(model.emulator.mem_read(_MODEL_DATA + 4096, 4096)))
                self.assertEqual(model.speculator._max_nesting, 1)
                self.assertEqual(model.speculator._max_spec_window, 32)
                self.assertEqual(model.speculator.nesting(), 0)
                self.assertFalse(model.speculator.in_speculation())
                self.assertEqual(model.state.pending_fault, 0)
                self.assertEqual(encode_input(self.inputs[name]), snapshots[name])
                selector, word = (int(self.inputs[name][0]["gpr"][0]),
                                  int(self.inputs[name][0]["main"][0]))
                marker = 22 if selector == 0 else 11
                self.assertEqual(actual.registers, (selector, marker, word, word + marker))
                self.assertEqual(actual.nzcv, 0x60000000 if selector == 0 else 0x20000000)
                self.assertEqual(actual.main, struct.pack("<Q", word + marker) + bytes(4088))
                if iteration:
                    self.assertEqual(actual, observations[name])
                else:
                    observations[name] = actual
                    print("B3.5i actual model observation:", json.dumps({
                        "input": name, "selector": int(self.inputs[name][0]["gpr"][0]),
                        "word": int(self.inputs[name][0]["main"][0]), "execution": clause,
                        "input_sha256": hashlib.sha256(snapshots[name]).hexdigest(),
                        "observation": "ct", "nesting": 1, "window": 32,
                        "program_sha256": hashlib.sha256(export_approved_program(self.case))
                        .hexdigest(), "typed_trace": actual.typed,
                        "x0_x3": actual.registers, "nzcv": actual.nzcv,
                        "stored_word": struct.unpack_from("<Q", actual.main)[0],
                    }, sort_keys=True))
        return observations

    def assert_equivalence_matrix(self, rows: dict[str, _Observation]) -> None:
        for first, selector, _ in _MATRIX:
            for second, other_selector, _ in _MATRIX:
                self.assertEqual(rows[first].typed == rows[second].typed,
                                 (selector == 0) == (other_selector == 0))
        self.assertEqual(rows["A"], rows["F"])
        self.assertEqual(rows["A"].typed, rows["B"].typed)
        self.assertNotEqual(rows["A"].main, rows["B"].main)  # Equal trace, different results.
        self.assertEqual(rows["C"].typed, rows["E"].typed)
        self.assertNotEqual(rows["C"].registers, rows["E"].registers)
        self.assertEqual(rows["A"].main, rows["D"].main)  # Equal stored/full main result.
        self.assertNotEqual(rows["A"].registers, rows["D"].registers)
        self.assertNotEqual(rows["A"].typed, rows["D"].typed)

    def test_sequential_typed_equivalence_and_architectural_distinctions(self) -> None:
        rows = self.collect("seq")
        self.assert_equivalence_matrix(rows)
        for name, selector, _ in _MATRIX:
            self.assertEqual(rows[name].typed, _PREFIX + (_TAKEN if selector == 0 else _FALL))

    def test_conditional_equivalence_is_computed_independently(self) -> None:
        sequential = self.collect("seq")
        conditional = self.collect("cond")
        self.assert_equivalence_matrix(conditional)
        for name, selector, _ in _MATRIX:
            wrong, correct = (_FALL, _TAKEN) if selector == 0 else (_TAKEN, _FALL)
            expected = _PREFIX + wrong + (CTraceEntry("pc", 56),) + correct
            self.assertEqual(conditional[name].typed, expected)
            self.assertNotEqual(conditional[name].typed, sequential[name].typed)
            self.assertEqual(conditional[name][1:], sequential[name][1:])
            # Actual model exit-NOP observation has no native body counterpart.
            self.assertIn(CTraceEntry("pc", 56), conditional[name].typed)
            with self.assertRaises(ValueError):
                model_pc_to_native_offset(56)

    def test_real_elf_and_trace_use_body_offsets_and_an_explicit_end_boundary(self) -> None:
        model = self.make_model("seq")
        instructions = self.case.get_obj().instruction_map()[0]
        obj = Path(self.case.get_obj().obj_path).read_bytes()
        section_start = self.case.get_sections()[0].get_elf_data()["offset"]
        for pc in (12, 16, 20, 24, 28, 32, 36, 40):
            self.assertIn(pc, instructions)
            native = model_pc_to_native_offset(pc)
            self.assertEqual(obj[section_start + pc:section_start + pc + 4],
                             export_approved_program(self.case)[native:native + 4])
            self.assertEqual(native_pc_to_model_offset(native), pc)
        trace = model.trace_test_case([self.inputs["A"]], nesting=1)[0]
        raw, typed = tuple(model.tracer.trace), tuple(trace.get_typed())
        self.assertEqual(len(raw), len(typed))
        for absolute, normalized in zip(raw, typed):
            if normalized.type_ == "pc":
                self.assertEqual(absolute.value, _MODEL_CODE + normalized.value)
                if normalized.value == 44:
                    with self.assertRaises(ValueError):
                        model_pc_to_native_offset(normalized.value)
                else:
                    self.assertLess(model_pc_to_native_offset(normalized.value), 32)
            else:
                self.assertEqual(normalized.type_, "mem")
                self.assertEqual(absolute.value, _MODEL_DATA + normalized.value)
                self.assertEqual(main_access_to_offset(normalized.value, 8, 4096), 0)
        self.assertEqual(typed.count(CTraceEntry("pc", 44)), 1)
        self.assertEqual(APPROVED_PROGRAM[32:], bytes.fromhex("c0035fd6"))
        with self.assertRaises(ValueError):
            native_pc_to_model_offset(32)
