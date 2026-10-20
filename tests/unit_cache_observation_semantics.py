"""Host-only characterization of existing Python cache-observation semantics.

These expectations preserve legacy behavior, not a claim that 64-byte observations
are correct for M3 Pro. Real tracers, layouts, traces, executor postprocessing, and
analysers run with synthetic addresses/words. No emulator, assembler, kernel, or
measurement interface is used. Model context and taint notifications are mocked.

The tcto tables deliberately distinguish current output from independent half-open
byte coverage. Duplicates and observations beyond an exactly ending access are
existing risks, not desired regression requirements. Their expectations must change
when boundary handling is deliberately fixed. A future configurable observation
granularity must preserve byte-level ct and input bytes, while explicitly reviewing
tct/tcto equivalence classes, diagnostic labels, and hardware trace encoding.

Python word preservation cannot validate assembly packing, rotation/overflow, the
kernel's validity marker, physical set indexing, eviction, or M3 counter behavior.
The 128-byte arithmetic below is geometry only, not a hardware measurement.
"""
# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access
# pylint: disable=too-many-public-methods

from collections import Counter
from typing import List, Type
import unittest
from unittest.mock import MagicMock, patch

import numpy as np
from unicorn import UC_MEM_READ, UC_MEM_WRITE

from rvzr.analyser import ChiSquaredAnalyser, MergedBitmapAnalyser, SetAnalyser
from rvzr.config import CONF
from rvzr.executor import Executor
from rvzr.model_unicorn.model import UnicornModel
from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker
from rvzr.model_unicorn.tracer import CTTracer, L1DTracer, TruncatedCTTracer, \
    TruncatedCTWithOverflowsTracer, UnicornTracer
from rvzr.sandbox import BaseAddrTuple, SandboxLayout
from rvzr.target_desc import TargetDesc
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTrace, CTraceEntry, HTrace, RawHTraceSample


BASES: BaseAddrTuple = (0x1000000, 0x2000000)


def _new_tracer(cls: Type[UnicornTracer], bases: BaseAddrTuple = BASES) -> UnicornTracer:
    model = MagicMock(spec=UnicornModel)
    model.layout = SandboxLayout(bases, 1)
    target = MagicMock(spec=TargetDesc)
    target.uc_target_desc = MagicMock()
    tracker = MagicMock(spec=UnicornTaintTracker)
    tracer = cls(target, model, tracker)
    tracer.enable_tracing = True
    return tracer


def _memory_trace(cls: Type[UnicornTracer], offsets: List[int]) -> CTrace:
    tracer = _new_tracer(cls)
    for offset in offsets:
        tracer.observe_mem_access(UC_MEM_READ, BASES[0] + offset, 1, 0)
    return tracer.get_trace()


def _hardware_trace(words: List[int]) -> HTrace:
    samples = np.zeros(len(words), dtype=RawHTraceSample)
    samples["trace"] = words
    return HTrace(samples, "cache")


class ContractObservationSemanticsTest(unittest.TestCase):
    def test_ct_keeps_byte_addresses_and_normalizes_data_and_code_separately(self) -> None:
        offsets = [0, 1, 56, 57, 63, 64, 120, 127, 128, 4096]
        for bases in (BASES, (0x3000000, 0x4000000)):
            with self.subTest(bases=bases):
                tracer = _new_tracer(CTTracer, bases)
                for offset in offsets:
                    tracer.observe_instruction(bases[1] + offset, 4)
                    tracer.observe_mem_access(UC_MEM_READ, bases[0] + offset, 8, 0)
                expected = [entry for offset in offsets for entry in (
                    CTraceEntry("pc", offset), CTraceEntry("mem", offset))]
                self.assertEqual(tracer.get_trace().get_typed(), expected)
                self.assertEqual(tracer.trace[0], CTraceEntry("pc", bases[1]))
                self.assertEqual(tracer.trace[1], CTraceEntry("mem", bases[0]))
        self.assertNotEqual(_memory_trace(CTTracer, [0]), _memory_trace(CTTracer, [1]))

    def test_ct_records_access_starts_without_expanding_or_rounding_accesses(self) -> None:
        for access in (UC_MEM_READ, UC_MEM_WRITE):
            for width in (1, 2, 8, 16):
                with self.subTest(access=access, width=width):
                    tracer = _new_tracer(CTTracer)
                    tracer.observe_mem_access(access, BASES[0] + 63, width, 0)
                    self.assertEqual(tracer.get_trace().get_typed(), [CTraceEntry("mem", 63)])

    def test_tct_uses_legacy_64_byte_buckets_for_memory_and_pc(self) -> None:
        buckets = [(0, 0), (56, 0), (57, 0), (63, 0),
                   (64, 64), (120, 64), (127, 64), (128, 128)]
        for offset, expected in buckets:
            for width in (1, 2, 8, 16):
                with self.subTest(offset=offset, width=width):
                    tracer = _new_tracer(TruncatedCTTracer)
                    tracer.observe_instruction(BASES[1] + offset, 4)
                    tracer.observe_mem_access(UC_MEM_READ, BASES[0] + offset, width, 0)
                    self.assertEqual(tracer.get_trace().get_typed(), [
                        CTraceEntry("pc", expected), CTraceEntry("mem", expected)])
        self.assertEqual(_memory_trace(TruncatedCTTracer, [0]),
                         _memory_trace(TruncatedCTTracer, [63]))
        self.assertNotEqual(_memory_trace(TruncatedCTTracer, [0]),
                            _memory_trace(TruncatedCTTracer, [64]))

    def test_legacy_tcto_memory_output_versus_half_open_coverage(self) -> None:
        # Literal outputs, not a copy of tcto's modulo predicate. Coverage is
        # independently computed by enumerating the actual accessed bytes below.
        cases = [
            (0, 1, [0, 0]), (0, 2, [0, 0]), (0, 8, [0, 0]), (0, 16, [0, 0]),
            (56, 1, [0, 0]), (56, 2, [0, 0]), (56, 8, [0, 64]), (56, 16, [0, 64]),
            (57, 1, [0, 0]), (57, 2, [0, 0]), (57, 8, [0, 64]), (57, 16, [0, 64]),
            (63, 1, [0, 64]), (63, 2, [0, 64]), (63, 8, [0, 64]), (63, 16, [0, 64]),
            (64, 1, [64, 64]), (64, 2, [64, 64]), (64, 8, [64, 64]), (64, 16, [64, 64]),
            (120, 1, [64, 64]), (120, 2, [64, 64]),
            (120, 8, [64, 128]), (120, 16, [64, 128]),
            (127, 1, [64, 128]), (127, 2, [64, 128]),
            (127, 8, [64, 128]), (127, 16, [64, 128]),
            (128, 1, [128, 128]), (128, 2, [128, 128]),
            (128, 8, [128, 128]), (128, 16, [128, 128]),
        ]
        categories: Counter[str] = Counter()
        for offset, width, legacy in cases:
            covered = sorted({byte - byte % 64 for byte in range(offset, offset + width)})
            if len(covered) > 1:
                category = "crosses"
                self.assertEqual(legacy, covered)
            elif (offset + width) % 64 == 0:
                category = "ends_exactly"
                self.assertEqual(legacy, [covered[0], offset + width])
                self.assertNotIn(legacy[-1], covered)
            else:
                category = "within"
                self.assertEqual(legacy, covered * 2)
            categories[category] += 1
            for access in (UC_MEM_READ, UC_MEM_WRITE):
                with self.subTest(offset=offset, width=width, access=access, category=category):
                    tracer = _new_tracer(TruncatedCTWithOverflowsTracer)
                    tracer.observe_mem_access(access, BASES[0] + offset, width, 0)
                    self.assertEqual(tracer.get_trace().get_typed(),
                                     [CTraceEntry("mem", value) for value in legacy])
        self.assertEqual(categories, {"within": 18, "ends_exactly": 4, "crosses": 10})

    def test_legacy_tcto_pc_adds_next_bucket_at_an_exact_endpoint(self) -> None:
        # Four-byte aligned instruction callbacks; no instructions are executed.
        cases = [(0, [0]), (60, [0, 64]), (64, [64]), (124, [64, 128]), (128, [128])]
        for offset, legacy in cases:
            with self.subTest(offset=offset):
                tracer = _new_tracer(TruncatedCTWithOverflowsTracer)
                tracer.observe_instruction(BASES[1] + offset, 4)
                self.assertEqual(tracer.get_trace().get_typed(),
                                 [CTraceEntry("pc", value) for value in legacy])
                covered = {byte - byte % 64 for byte in range(offset, offset + 4)}
                self.assertEqual(covered, {legacy[0]})

    def test_legacy_tcto_duplicates_change_equality_even_when_display_is_identical(self) -> None:
        legacy = _memory_trace(TruncatedCTWithOverflowsTracer, [0])
        single = _memory_trace(CTTracer, [0])
        self.assertEqual(legacy.get_untyped(), [0, 0])
        self.assertEqual(single.get_untyped(), [0])
        self.assertNotEqual(legacy, single)
        for trace in (legacy, single):
            trace.set_printed_as_l1d()
        self.assertEqual(str(legacy), str(single))

    def test_l1d_diagnostic_positions_at_zero_64_128_and_4096(self) -> None:
        for offset, expected in [(0, "^" + "." * 63), (64, ".^" + "." * 62),
                                 (128, "..^" + "." * 61), (4096, "^" + "." * 63)]:
            with self.subTest(offset=offset):
                trace = _memory_trace(L1DTracer, [offset])
                self.assertEqual(trace.get_typed(), [CTraceEntry("mem", offset)])
                self.assertEqual(str(trace), expected)

    def test_l1d_map_aliases_do_not_merge_contract_equality_or_hashes(self) -> None:
        for offsets in ([0, 1], [0, 4096]):
            with self.subTest(offsets=offsets):
                first = _memory_trace(L1DTracer, offsets[:1])
                second = _memory_trace(L1DTracer, offsets[1:])
                self.assertEqual(str(first), str(second))
                self.assertNotEqual(first.get_typed(), second.get_typed())
                self.assertNotEqual(first, second)
                self.assertEqual(len({first, second}), 2)
        first = _memory_trace(L1DTracer, [0, 64])
        second = _memory_trace(L1DTracer, [64, 0])
        self.assertEqual(str(first), str(second))
        self.assertNotEqual(first, second)


class HardwareWordSemanticsTest(unittest.TestCase):
    def test_storage_and_accessors_preserve_all_64_bits(self) -> None:
        words = [0, 1, 1 << 63, (1 << 63) | 1, (1 << 64) - 1]
        trace = _hardware_trace(words)
        self.assertEqual(trace.get_raw_traces().dtype, np.dtype(np.uint64))
        self.assertEqual(trace.get_raw_traces().dtype.itemsize, 8)
        self.assertEqual(trace.get_raw_traces().tolist(), words)
        self.assertEqual(trace.get_raw_readings()["trace"].tolist(), words)
        self.assertFalse(trace.is_corrupted_or_ignored())

    def test_high_bit_is_printed_and_participates_in_identity(self) -> None:
        high = _hardware_trace([1 << 63])
        low = _hardware_trace([1])
        self.assertEqual(high.full_str(), "^" + "." * 63 + " [1]\n")
        self.assertNotEqual(high, low)
        self.assertEqual(len({high, low}), 2)
        self.assertFalse(high.is_corrupted_or_ignored())
        self.assertFalse(low.is_corrupted_or_ignored())  # Python does not require the high marker.
        self.assertTrue(_hardware_trace([0]).is_corrupted_or_ignored())

    def test_merging_preserves_high_bits_without_interpreting_them(self) -> None:
        first = _hardware_trace([1 << 63])
        second = _hardware_trace([(1 << 64) - 1])
        merged = first.merge(second)
        self.assertEqual(merged.get_raw_traces().tolist(), [1 << 63, (1 << 64) - 1])
        self.assertEqual(merged.type_, "cache")

    def test_executor_cache_postprocessing_preserves_supplied_word(self) -> None:
        # skip_setup avoids all kernel/environment discovery; only the pure
        # postprocessing method is called, never executor loading or tracing.
        with patch("rvzr.executor.warning"):
            executor = Executor(skip_setup=True)
        words = [0, 1, 1 << 63, (1 << 63) | 1, (1 << 64) - 1]
        for mode in ("P+P", "F+R", "E+R"):
            with self.subTest(mode=mode), patch.object(CONF, "executor_mode", mode):
                readings = _hardware_trace(words).get_raw_readings().reshape(1, len(words))
                traces = executor._raw_readings_to_traces(readings, n_inputs=1)
                self.assertEqual(traces[0].get_raw_traces().tolist(), words)
                self.assertEqual(traces[0].type_, "cache")

    def test_executor_tsc_mask_is_mode_specific_not_a_cache_line_mask(self) -> None:
        with patch("rvzr.executor.warning"):
            executor = Executor(skip_setup=True)
        with patch.object(CONF, "executor_mode", "TSC"):
            readings = _hardware_trace([0x800000000000001f]).get_raw_readings().reshape(1, 1)
            traces = executor._raw_readings_to_traces(readings, n_inputs=1)
        self.assertEqual(traces[0].get_raw_traces().tolist(), [0x10])
        self.assertEqual(traces[0].type_, "tsc")


class CacheObservationAnalyserTest(unittest.TestCase):
    def setUp(self) -> None:
        for name, value in (("executor_sample_sizes", [16]),
                            ("analyser_outliers_threshold", 0.1),
                            ("analyser_stat_threshold", 0.5)):
            patcher = patch.object(CONF, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.test_case = TestCaseProgram("synthetic-unused.asm")
        self.inputs = [InputData(), InputData()]
        for input_ in self.inputs:
            input_.view(np.uint8).fill(0)
        # Arbitrary bits, deliberately unrelated to the contract memory address.
        self.hardware = [_hardware_trace([(1 << 63) | (1 << bit)] * 16) for bit in (3, 42)]

    def test_equal_contracts_with_different_hardware_words_produce_a_violation(self) -> None:
        contracts = [_memory_trace(CTTracer, [17]), _memory_trace(CTTracer, [17])]
        for cls in (MergedBitmapAnalyser, SetAnalyser, ChiSquaredAnalyser):
            for subsets in (False, True):
                with self.subTest(analyser=cls.__name__, subsets=subsets), \
                        patch.object(CONF, "analyser_subsets_is_violation", subsets):
                    analyser = cls()
                    violations = analyser.filter_violations(
                        contracts, self.hardware, self.test_case, self.inputs)
                    self.assertEqual(len(violations), 1)
                    self.assertEqual(violations[0].ctrace, contracts[0])
                    self.assertEqual({m.input_id for m in violations[0].measurements}, {0, 1})

    def test_identical_l1d_diagnostics_do_not_make_distinct_contracts_equivalent(self) -> None:
        contracts = [_memory_trace(L1DTracer, [0]), _memory_trace(L1DTracer, [4096])]
        self.assertEqual(str(contracts[0]), str(contracts[1]))
        self.assertNotEqual(contracts[0], contracts[1])
        for cls in (MergedBitmapAnalyser, SetAnalyser, ChiSquaredAnalyser):
            with self.subTest(analyser=cls.__name__):
                analyser = cls()
                self.assertEqual(analyser.filter_violations(
                    contracts, self.hardware, self.test_case, self.inputs), [])


class ObservationGeometryIllustrationTest(unittest.TestCase):
    def test_4k_at_64_byte_steps_has_32_distinct_128_byte_blocks(self) -> None:
        # Arithmetic on a synthetic, 128-byte-aligned region; no cache sets,
        # associativity, cache state, counters, or target page size are inferred.
        positions = list(range(0, 4096, 64))
        self.assertEqual(len(positions), 64)
        self.assertEqual(positions[0], 0)
        self.assertEqual(positions[-1], 4032)
        blocks = Counter(position - position % 128 for position in positions)
        self.assertEqual(set(blocks), set(range(0, 4096, 128)))
        self.assertEqual(len(blocks), 32)
        self.assertEqual(set(blocks.values()), {2})
        self.assertEqual([positions[i:i + 2] for i in range(0, 64, 2)],
                         [[block, block + 64] for block in range(0, 4096, 128)])
        self.assertEqual(4096 // 128, 32)


if __name__ == "__main__":
    unittest.main()
