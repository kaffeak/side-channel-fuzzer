"""Host-independent tests for proposed actor-data sandbox geometry."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-many-public-methods

from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from rvzr.sandbox import DataArea, SandboxLayout
from rvzr.sandbox_geometry import SandboxGeometry


class SandboxGeometryTest(unittest.TestCase):

    def test_required_4k_profile(self) -> None:
        geometry = SandboxGeometry(4096)
        self.assertEqual(geometry.macro_stack_offset, 0)
        self.assertEqual(geometry.main_offset, 4096)
        self.assertEqual(geometry.faulty_offset, 8192)
        self.assertEqual(geometry.register_init_offset, 12288)
        self.assertEqual(geometry.actor_stride, 16384)

    def test_proposed_16k_profile(self) -> None:
        geometry = SandboxGeometry(16384)
        self.assertEqual(geometry.macro_stack_offset, 8192)
        self.assertEqual(geometry.main_offset, 12288)
        self.assertEqual(geometry.faulty_offset, 16384)
        self.assertEqual(geometry.register_init_offset, 32768)
        self.assertEqual(geometry.actor_stride, 49152)
        self.assertEqual(geometry.main_mapping, (0, 16384))
        self.assertEqual(geometry.faulty_mapping, (16384, 32768))
        self.assertEqual(geometry.register_mapping, (32768, 49152))

    def test_4k_matches_existing_sandbox_layout(self) -> None:
        geometry = SandboxGeometry(4096)
        offsets = {
            DataArea.MACRO_STACK: geometry.macro_stack_offset,
            DataArea.UNDERFLOW_PAD: geometry.underflow_pad_offset,
            DataArea.MAIN: geometry.main_offset,
            DataArea.FAULTY: geometry.faulty_offset,
            DataArea.REG_INIT: geometry.register_init_offset,
            DataArea.GPR: geometry.register_init_offset,
            DataArea.SIMD: geometry.register_init_offset + 64,
            DataArea.OVERFLOW_PAD: geometry.overflow_pad_offset,
            DataArea.RSP_INIT: geometry.local_stack_offset,
        }
        legacy = SandboxLayout((4096, 0), 3)
        self.assertEqual(geometry.actor_stride, legacy.data_size_per_actor())
        for actor_id in range(3):
            for area, offset in offsets.items():
                with self.subTest(actor_id=actor_id, area=area):
                    self.assertEqual(
                        4096 + geometry.actor_base_offset(actor_id) + offset,
                        legacy.get_data_addr(area, actor_id))

    def test_payload_sizes_do_not_grow_with_kernel_pages(self) -> None:
        for page_size in (4096, 16384):
            with self.subTest(page_size=page_size):
                geometry = SandboxGeometry(page_size)
                self.assertEqual(geometry.main_size, 4096)
                self.assertEqual(geometry.faulty_size, 4096)
                self.assertEqual(geometry.macro_stack_size, 64)
                self.assertEqual(geometry.underflow_pad_size, 4032)
                self.assertEqual(geometry.register_init_size, 320)
                self.assertEqual(geometry.overflow_pad_size, 3776)

    def test_main_faulty_window_and_stack_are_preserved(self) -> None:
        for page_size in (4096, 16384):
            with self.subTest(page_size=page_size):
                geometry = SandboxGeometry(page_size)
                self.assertEqual(geometry.main_offset + geometry.main_size,
                                 geometry.faulty_offset)
                self.assertEqual(geometry.faulty_offset + geometry.faulty_size
                                 - geometry.main_offset, 8192)
                self.assertEqual(geometry.local_stack_offset - geometry.main_offset, 4088)
                self.assertEqual(geometry.underflow_pad_offset + geometry.underflow_pad_size,
                                 geometry.main_offset)

    def test_permission_mappings_are_aligned_disjoint_and_contain_payloads(self) -> None:
        for page_size in (4096, 16384):
            with self.subTest(page_size=page_size):
                geometry = SandboxGeometry(page_size)
                regions = (
                    (geometry.main_mapping, geometry.main_offset, geometry.main_size),
                    (geometry.faulty_mapping, geometry.faulty_offset, geometry.faulty_size),
                    (geometry.register_mapping, geometry.register_init_offset,
                     geometry.register_init_size + geometry.overflow_pad_size),
                )
                for (start, end), offset, size in regions:
                    self.assertEqual(start % page_size, 0)
                    self.assertEqual(end % page_size, 0)
                    self.assertEqual(end - start, page_size)
                    self.assertLessEqual(start, offset)
                    self.assertLessEqual(offset + size, end)
                    self.assertLessEqual(end, geometry.actor_stride)
                self.assertLessEqual(geometry.main_mapping[1], geometry.faulty_mapping[0])
                self.assertEqual(geometry.faulty_mapping[1], geometry.register_mapping[0])

    def test_all_logical_regions_fit_inside_actor_span(self) -> None:
        for page_size in (4096, 16384):
            with self.subTest(page_size=page_size):
                geometry = SandboxGeometry(page_size)
                regions = (
                    (geometry.macro_stack_offset, geometry.macro_stack_size),
                    (geometry.underflow_pad_offset, geometry.underflow_pad_size),
                    (geometry.main_offset, geometry.main_size),
                    (geometry.faulty_offset, geometry.faulty_size),
                    (geometry.register_init_offset, geometry.register_init_size),
                    (geometry.overflow_pad_offset, geometry.overflow_pad_size),
                )
                previous_end = 0
                for start, size in regions:
                    self.assertGreaterEqual(start, previous_end)
                    self.assertLessEqual(start + size, geometry.actor_stride)
                    previous_end = start + size

    def test_actor_strides_preserve_page_alignment_and_isolation(self) -> None:
        for page_size in (4096, 16384):
            geometry = SandboxGeometry(page_size)
            for actor_id in (0, 1, 2, 17):
                with self.subTest(page_size=page_size, actor_id=actor_id):
                    base = geometry.actor_base_offset(actor_id)
                    next_base = geometry.actor_base_offset(actor_id + 1)
                    self.assertEqual(base % page_size, 0)
                    self.assertEqual(next_base - base, geometry.actor_stride)
                    self.assertEqual(base + geometry.register_mapping[1], next_base)
                    for start, end in (geometry.main_mapping, geometry.faulty_mapping,
                                       geometry.register_mapping):
                        self.assertEqual((base + start) % page_size, 0)
                        self.assertLessEqual(base + end, next_base)

    def test_16k_requires_review_of_existing_8k_main_alignment(self) -> None:
        geometry = SandboxGeometry(16384)
        for base in (0, 16384, 49152, 65536):
            with self.subTest(base=base):
                self.assertEqual((base + geometry.faulty_offset) % 16384, 0)
                self.assertEqual((base + geometry.main_offset) % 8192, 4096)
                self.assertEqual((base + geometry.main_offset) % 4096, 0)

    def test_explicit_profiles_do_not_query_host_page_size(self) -> None:
        with patch("os.sysconf", side_effect=AssertionError("host page size queried")):
            small = SandboxGeometry(4096)
            large = SandboxGeometry(16384)
            self.assertEqual(small.actor_stride, 16384)
            self.assertEqual(large.actor_stride, 49152)

    def test_profiles_are_independent_and_immutable(self) -> None:
        small = SandboxGeometry(4096)
        large = SandboxGeometry(16384)
        self.assertEqual(small.main_offset, 4096)
        self.assertEqual(large.main_offset, 12288)
        with self.assertRaises(FrozenInstanceError):
            setattr(small, "kernel_page_size", 16384)

    def test_unsupported_page_sizes_are_rejected(self) -> None:
        for page_size in (-4096, 0, 8192, 65536):
            with self.subTest(page_size=page_size):
                with self.assertRaises(ValueError):
                    SandboxGeometry(page_size)

    def test_noninteger_page_sizes_are_rejected(self) -> None:
        for page_size in (True, False, 4096.0, "4096", None):
            with self.subTest(page_size=page_size):
                with self.assertRaises(TypeError):
                    SandboxGeometry(page_size)  # type: ignore[arg-type]

    def test_invalid_actor_ids_are_rejected(self) -> None:
        geometry = SandboxGeometry(16384)
        with self.assertRaises(ValueError):
            geometry.actor_base_offset(-1)
        for actor_id in (True, 1.0, "1", None):
            with self.subTest(actor_id=actor_id):
                with self.assertRaises(TypeError):
                    geometry.actor_base_offset(actor_id)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
