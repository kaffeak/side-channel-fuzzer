"""Byte-level regression tests for the existing serialized input format.

Expected offsets, lengths and metadata are independent of runtime sandbox
placement and production format constants. Payload words retain native NumPy
byte order; metadata is explicitly little-endian. No kernel page size is used.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import struct
import tempfile
from typing import List
import unittest
from unittest.mock import patch

import numpy as np

from rvzr import input_format
from rvzr.sandbox import SandboxLayout
from rvzr.tc_components import test_case_data
from rvzr.tc_components.test_case_data import InputData, InputTaint, save_input_sequence_as_rdbf


# name, byte offset, byte size, uint64 field shape: pin the existing wire format.
_FIELDS = (
    ("main", 0, 4096, (512,)),
    ("faulty", 4096, 4096, (512,)),
    ("gpr", 8192, 64, (8,)),
    ("simd", 8256, 256, (32,)),
    ("padding", 8512, 3776, (472,)),
)


def _word(input_id: int, actor_id: int, field_id: int, index: int) -> int:
    # Distinguish inputs, actors, fields, words and byte order; padding is nonzero.
    return 0x0123456789ABCDEF + ((input_id * 10 + actor_id * 5 + field_id) << 48) + index


def _expected_fragment(input_id: int, actor_id: int) -> bytes:
    # Explicit wire-order fields and word counts, independent of dtype/constants.
    # '=' preserves native byte order without C alignment, matching existing payloads.
    return b"".join(struct.pack("=Q", _word(input_id, actor_id, field_id, index))
                    for field_id, count in enumerate((512, 512, 8, 32, 472))
                    for index in range(count))


def _patterned_inputs() -> List[InputData]:
    inputs = []
    for input_id in range(2):
        input_ = InputData(2)
        for actor_id in range(2):
            for field_id, (name, _, _, shape) in enumerate(_FIELDS):
                input_[actor_id][name] = [
                    _word(input_id, actor_id, field_id, index) for index in range(shape[0])]
        inputs.append(input_)
    return inputs


class InputFormatRegressionTest(unittest.TestCase):

    def test_fixed_format_constants_match_independent_wire_expectations(self) -> None:
        for name, offset, size, _ in _FIELDS:
            with self.subTest(field=name):
                self.assertEqual(getattr(input_format, name.upper() + "_OFFSET"), offset)
                self.assertEqual(getattr(input_format, name.upper() + "_SIZE"), size)
        self.assertEqual(input_format.WORD_SIZE, 8)
        self.assertEqual(input_format.REGISTER_INIT_SIZE, 320)
        self.assertEqual(input_format.REGISTER_BLOCK_SIZE, 4096)
        self.assertEqual(input_format.FRAGMENT_SIZE, 12288)
        self.assertEqual(input_format.DATA_SIZE, 8512)

    def test_dtype_construction_is_independent_of_runtime_layout(self) -> None:
        # Execute a fresh module without reloading or replacing the imported class.
        # Patching after ordinary import alone would miss the old import-time coupling.
        spec = spec_from_file_location("rvzr.tc_components._input_format_probe",
                                       test_case_data.__file__)
        assert spec is not None and spec.loader is not None
        fresh = module_from_spec(spec)
        with patch.object(SandboxLayout, "data_area_size",
                          side_effect=AssertionError("runtime layout queried")), \
                patch("os.sysconf", side_effect=AssertionError("host page size queried")):
            spec.loader.exec_module(fresh)
            self.assertEqual(fresh.InputData(2).dtype, InputData(2).dtype)
            self.assertEqual(fresh.InputData.data_size_per_actor(), 8512)

    def test_exact_field_offsets_sizes_shapes_and_native_word_type(self) -> None:
        input_ = InputData(2)
        self.assertEqual(input_.shape, (2,))
        self.assertEqual(input_.dtype.names, tuple(field[0] for field in _FIELDS))
        self.assertEqual(input_.itemsize, 12288)
        self.assertEqual(input_.nbytes, 24576)
        self.assertFalse(input_.dtype.isalignedstruct)
        fields = input_.dtype.fields
        assert fields is not None
        for name, offset, size, shape in _FIELDS:
            with self.subTest(field=name):
                field_dtype, field_offset = fields[name][:2]
                self.assertEqual(field_offset, offset)
                self.assertEqual(field_dtype.itemsize, size)
                self.assertEqual(field_dtype.shape, shape)
                self.assertEqual(field_dtype.base, np.dtype(np.uint64))
                self.assertTrue(field_dtype.base.isnative)

    def test_public_sizes_exclude_serialized_padding(self) -> None:
        self.assertEqual(InputData.data_size_per_actor(), 8512)
        self.assertEqual(InputData.n_data_entries_per_actor(), 1064)
        self.assertEqual(InputData(1).itemsize // 8, 1536)

    def test_complete_rdbf_bytes_for_two_inputs_and_two_actors(self) -> None:
        inputs = _patterned_inputs()
        # Literal little-endian counts (2, 2), then per-actor (8512, reserved=0).
        header = b"\x02\x00\x00\x00\x00\x00\x00\x00" * 2
        metadata = (b"\x40\x21\x00\x00\x00\x00\x00\x00" + b"\x00" * 8) * 2
        fragments = [_expected_fragment(0, 0), _expected_fragment(0, 1),
                     _expected_fragment(1, 0), _expected_fragment(1, 1)]
        expected = header + metadata + b"".join(fragments)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inputs.rdbf"
            save_input_sequence_as_rdbf(inputs, str(path))
            actual = path.read_bytes()
        self.assertEqual(len(actual), 49200)
        self.assertEqual(actual[:16], header)
        self.assertEqual(actual[16:48], metadata)
        # Explicit offsets establish input-first, actor-second ordering.
        for offset, fragment in zip((48, 12336, 24624, 36912), fragments):
            with self.subTest(fragment_start=offset):
                self.assertEqual(actual[offset:offset + 12288], fragment)
        self.assertEqual(actual, expected)

    def test_raw_save_load_round_trip_preserves_nonzero_padding(self) -> None:
        original = _patterned_inputs()[1]
        expected = _expected_fragment(1, 0) + _expected_fragment(1, 1)
        with tempfile.TemporaryDirectory() as directory:
            saved = Path(directory) / "saved.bin"
            original.save(str(saved))
            self.assertEqual(saved.read_bytes(), expected)
            # Load independently specified bytes, not just output from save().
            fixture = Path(directory) / "fixture.bin"
            fixture.write_bytes(expected)
            restored = InputData(2)
            restored.load(str(fixture))
            self.assertEqual(restored.tobytes(), expected)
            for actor_id in (0, 1):
                self.assertTrue(np.all(restored[actor_id]["padding"] != 0))
            round_trip = Path(directory) / "round-trip.bin"
            restored.save(str(round_trip))
            self.assertEqual(round_trip.read_bytes(), expected)

    def test_set_actor_data_zeroes_only_destination_padding(self) -> None:
        original = _expected_fragment(1, 1)
        source = np.frombuffer(original, dtype=np.uint64).copy()
        input_ = InputData(2)
        input_.view(np.uint8).fill(0x7D)
        input_.set_actor_data(1, source)
        self.assertEqual(input_[0].tobytes(), b"\x7d" * 12288)
        self.assertEqual(input_[1].tobytes(), original[:8512] + b"\x00" * 3776)
        self.assertEqual(source.tobytes(), original)

    def test_taint_field_shapes_follow_fixed_input_word_counts(self) -> None:
        taint = InputTaint(2)
        self.assertEqual(InputTaint.per_actor_taint_size, 1536)
        fields = taint.dtype.fields
        assert fields is not None
        for name, _, _, shape in _FIELDS:
            with self.subTest(field=name):
                self.assertEqual(fields[name][0].shape, shape)
        self.assertFalse(taint.full_linear_view().any())

    def test_serialization_does_not_query_host_kernel_page_size(self) -> None:
        with patch("os.sysconf", side_effect=AssertionError("host page size queried")):
            inputs = _patterned_inputs()
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "inputs.rdbf"
                save_input_sequence_as_rdbf(inputs, str(path))
                self.assertEqual(len(path.read_bytes()), 49200)
                raw = Path(directory) / "input.bin"
                inputs[0].save(str(raw))
                restored = InputData(2)
                restored.load(str(raw))
                self.assertEqual(restored.tobytes(),
                                 _expected_fragment(0, 0) + _expected_fragment(0, 1))


if __name__ == "__main__":
    unittest.main()
