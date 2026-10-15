"""Host-independent tests for proposed actor-data sandbox geometry.

Boundary tests specify half-open byte ranges and kernel-page coverage for
page-aligned actor bases, including unaligned accesses and accesses spanning
logical regions. They guarantee placement and coverage only: touching a
faulty mapping is not itself a fault. PTE permissions, access type, ARM64
alignment/atomicity rules, padding contents, and the executor/Unicorn handling
of partial or speculative accesses require separate validation. In particular,
16 KB faulty-page padding would share permissions with the faulty payload without
being input data, and actor strides do not enforce access bounds.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-many-public-methods

from dataclasses import FrozenInstanceError
from typing import Dict, Tuple
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


class SandboxGeometryBoundaryTest(unittest.TestCase):

    # Explicit page-range expectations, independent of geometry's mapping calculations.
    profiles = (
        (4096, (4096, 8192), (8192, 12288), (12288, 16384)),
        (16384, (0, 16384), (16384, 32768), (32768, 49152)),
    )
    widths = (1, 2, 4, 8, 16)

    # Keep named region boundaries explicit so this byte-by-byte oracle is easy to audit.
    # pylint: disable-next=too-many-locals
    def _assert_access_coverage(
        self, geometry: SandboxGeometry, start: int, width: int,
        expected_regions: Dict[str, Tuple[int, int]],
        expected_pages: Tuple[Tuple[int, int], ...], actor_id: int = 0,
    ) -> None:
        """Classify individual bytes, without assuming permissions or simulating a fault."""
        base = geometry.actor_base_offset(actor_id)
        main = base + geometry.main_offset
        faulty = base + geometry.faulty_offset
        registers = base + geometry.register_init_offset
        overflow = base + geometry.overflow_pad_offset
        actor_end = base + geometry.actor_stride
        regions = {
            "leading_padding": (base, base + geometry.macro_stack_offset),
            "macro_stack": (base + geometry.macro_stack_offset,
                            base + geometry.underflow_pad_offset),
            "underflow_pad": (base + geometry.underflow_pad_offset, main),
            "main": (main, main + geometry.main_size),
            "faulty": (faulty, faulty + geometry.faulty_size),
            "faulty_padding": (faulty + geometry.faulty_size, registers),
            "register_init": (registers, registers + geometry.register_init_size),
            "overflow_pad": (overflow, overflow + geometry.overflow_pad_size),
            "trailing_padding": (overflow + geometry.overflow_pad_size, actor_end),
        }
        accessed_bytes = set(range(start, start + width))
        actual_regions = {}
        for name, (region_start, region_end) in regions.items():
            covered = {byte for byte in accessed_bytes if region_start <= byte < region_end}
            if covered:
                actual_regions[name] = (min(covered), max(covered) + 1)
        outside = {byte for byte in accessed_bytes if not base <= byte < actor_end}
        if outside:
            actual_regions["outside_actor"] = (min(outside), max(outside) + 1)
        self.assertEqual(actual_regions, expected_regions)
        self.assertEqual(sum(end - begin for begin, end in actual_regions.values()), width)

        page_starts = {byte - byte % geometry.kernel_page_size for byte in accessed_bytes}
        actual_pages = tuple((page, page + geometry.kernel_page_size)
                             for page in sorted(page_starts))
        self.assertEqual(actual_pages, expected_pages)

    def test_accesses_at_payload_starts(self) -> None:
        for page_size, main_page, faulty_page, _ in self.profiles:
            geometry = SandboxGeometry(page_size)
            for name, start, page in (("main", geometry.main_offset, main_page),
                                      ("faulty", geometry.faulty_offset, faulty_page)):
                for width in self.widths:
                    with self.subTest(page_size=page_size, region=name, width=width):
                        self._assert_access_coverage(
                            geometry, start, width, {name: (start, start + width)}, (page,))

    def test_accesses_ending_exactly_at_payload_ends(self) -> None:
        # The exclusive endpoint must not count as touching the following region/page.
        for page_size, main_page, faulty_page, _ in self.profiles:
            geometry = SandboxGeometry(page_size)
            for name, end, page in (
                ("main", geometry.main_offset + geometry.main_size, main_page),
                ("faulty", geometry.faulty_offset + geometry.faulty_size, faulty_page),
            ):
                for width in self.widths:
                    with self.subTest(page_size=page_size, region=name, width=width):
                        self._assert_access_coverage(
                            geometry, end - width, width, {name: (end - width, end)}, (page,))

    def test_accesses_crossing_into_main_from_underflow(self) -> None:
        for page_size, main_page, _, _ in self.profiles:
            geometry = SandboxGeometry(page_size)
            main = geometry.main_offset
            for width in self.widths:
                with self.subTest(page_size=page_size, width=width):
                    expected = {"underflow_pad": (main - 1, main)}
                    if width > 1:
                        expected["main"] = (main, main - 1 + width)
                    # Only the 4 KB layout has a page boundary at main's start.
                    pages = ((0, 16384),)
                    if page_size == 4096:
                        pages = ((0, 4096),) if width == 1 else ((0, 4096), main_page)
                    self._assert_access_coverage(geometry, main - 1, width, expected, pages)

    def test_accesses_crossing_main_faulty_boundary(self) -> None:
        for page_size, main_page, faulty_page, _ in self.profiles:
            geometry = SandboxGeometry(page_size)
            boundary = geometry.faulty_offset
            self.assertEqual(geometry.main_offset + geometry.main_size, boundary)
            self.assertEqual(geometry.main_mapping, main_page)
            self.assertEqual(geometry.faulty_mapping, faulty_page)
            self.assertEqual(main_page[1], faulty_page[0])
            for width in self.widths:
                with self.subTest(page_size=page_size, width=width):
                    expected = {"main": (boundary - 1, boundary)}
                    pages = (main_page,)
                    if width > 1:
                        expected["faulty"] = (boundary, boundary - 1 + width)
                        pages = (main_page, faulty_page)
                    self._assert_access_coverage(geometry, boundary - 1, width, expected, pages)

    def test_accesses_crossing_faulty_payload_end(self) -> None:
        for page_size, _, faulty_page, register_page in self.profiles:
            geometry = SandboxGeometry(page_size)
            boundary = geometry.faulty_offset + geometry.faulty_size
            for width in self.widths:
                with self.subTest(page_size=page_size, width=width):
                    expected = {"faulty": (boundary - 1, boundary)}
                    pages = (faulty_page,)
                    if width > 1:
                        next_region = "register_init" if page_size == 4096 else "faulty_padding"
                        expected[next_region] = (boundary, boundary - 1 + width)
                        if page_size == 4096:
                            pages = (faulty_page, register_page)
                    self._assert_access_coverage(geometry, boundary - 1, width, expected, pages)

    def test_accesses_after_faulty_payload_distinguish_payload_from_mapping(self) -> None:
        for page_size, _, faulty_page, register_page in self.profiles:
            geometry = SandboxGeometry(page_size)
            start = geometry.faulty_offset + geometry.faulty_size
            for width in self.widths:
                with self.subTest(page_size=page_size, width=width):
                    if page_size == 4096:
                        self.assertEqual(start, geometry.register_init_offset)
                        expected = {"register_init": (start, start + width)}
                        pages = (register_page,)
                    else:
                        self.assertEqual(geometry.register_init_offset - start, 12288)
                        expected = {"faulty_padding": (start, start + width)}
                        pages = (faulty_page,)
                    self._assert_access_coverage(geometry, start, width, expected, pages)
                    # These bytes are outside the logical faulty payload in both profiles.
                    # Their page classification alone says nothing about read/write success.
                    self.assertNotIn("faulty", expected)

    def test_16k_accesses_crossing_padding_register_boundary(self) -> None:
        geometry = SandboxGeometry(16384)
        boundary = geometry.register_init_offset
        for width in self.widths:
            with self.subTest(width=width):
                expected = {"faulty_padding": (boundary - 1, boundary)}
                pages = ((16384, 32768),)
                if width > 1:
                    expected["register_init"] = (boundary, boundary - 1 + width)
                    pages = ((16384, 32768), (32768, 49152))
                self._assert_access_coverage(geometry, boundary - 1, width, expected, pages)

    def test_actor_allocations_and_their_last_in_bounds_accesses_do_not_overlap(self) -> None:
        for page_size, _, _, _ in self.profiles:
            geometry = SandboxGeometry(page_size)
            for actor_id in (0, 1, 2, 17):
                base = geometry.actor_base_offset(actor_id)
                end = base + geometry.actor_stride
                next_base = geometry.actor_base_offset(actor_id + 1)
                self.assertEqual(end, next_base)
                own_pages = set(range(base, end, page_size))
                next_pages = set(range(next_base, next_base + geometry.actor_stride, page_size))
                self.assertTrue(own_pages.isdisjoint(next_pages))
                for width in self.widths:
                    with self.subTest(page_size=page_size, actor_id=actor_id, width=width):
                        region = "overflow_pad" if page_size == 4096 else "trailing_padding"
                        self._assert_access_coverage(
                            geometry, end - width, width, {region: (end - width, end)},
                            ((end - page_size, end),), actor_id)

    def test_actor_stride_does_not_prevent_accesses_crossing_into_next_actor(self) -> None:
        for page_size, _, _, _ in self.profiles:
            geometry = SandboxGeometry(page_size)
            for actor_id in (0, 1, 2):
                boundary = geometry.actor_base_offset(actor_id + 1)
                for width in self.widths:
                    with self.subTest(page_size=page_size, actor_id=actor_id, width=width):
                        region = "overflow_pad" if page_size == 4096 else "trailing_padding"
                        expected = {region: (boundary - 1, boundary)}
                        pages = ((boundary - page_size, boundary),)
                        if width > 1:
                            expected["outside_actor"] = (boundary, boundary - 1 + width)
                            pages += ((boundary, boundary + page_size),)
                            self.assertLessEqual(boundary - 1 + width,
                                                 boundary + geometry.actor_stride)
                        self._assert_access_coverage(
                            geometry, boundary - 1, width, expected, pages, actor_id)


if __name__ == "__main__":
    unittest.main()
