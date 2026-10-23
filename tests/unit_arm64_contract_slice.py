"""Real ARM64 template -> GNU assembly/ELF -> sequential Unicorn -> C-trace.

Uses synthetic model addresses and CPU identification, never a kernel executor.
Native ARM64 uses its binutils; other hosts need binutils-aarch64-linux-gnu.
RVZR_ARM64_BINUTILS_PREFIX can select an absolute cross-tool prefix. No assembler,
ELF metadata, model execution, contract tracer or architectural results are mocked.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from contextlib import contextmanager
from copy import deepcopy
import os
from pathlib import Path
import platform
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Iterator, List
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile
import numpy as np
import unicorn.arm64_const as ucc  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.arch.arm64.generator import ARM64Generator
from rvzr.arch.arm64.target_desc import ARM64TargetDesc
from rvzr.config import CONF
from rvzr.isa_spec import InstructionSet
from rvzr.logs import update_logging_after_config_change
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.model_unicorn.speculators_basic import SeqSpeculator
from rvzr.model_unicorn.tracer import CTTracer
from rvzr.target_desc import CPUDesc
from rvzr.tc_components.test_case_binary import SymbolTableEntry
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData, save_input_sequence_as_rdbf
from rvzr.traces import CTraceEntry


_ARM_TESTS = Path(__file__).resolve().parent / "arm64"
_TAKEN = [CTraceEntry("pc", 12), CTraceEntry("pc", 16), CTraceEntry("pc", 28),
          CTraceEntry("pc", 32), CTraceEntry("mem", 4096), CTraceEntry("pc", 36),
          CTraceEntry("pc", 40), CTraceEntry("mem", 4096), CTraceEntry("pc", 44)]
_NOT_TAKEN = [CTraceEntry("pc", 12), CTraceEntry("pc", 16), CTraceEntry("pc", 20),
              CTraceEntry("pc", 24)] + _TAKEN[3:]


@contextmanager
def software_environment(directory: Path) -> Iterator[None]:
    """Test-only binutils/CPU adapter; also usable for existing ARM64 unit suites.

    Revizor invokes bare tool names and the template generator writes generated.*
    in the current directory. Isolate those files and restore process globals.
    This context changes PATH/CWD/CONF and is intended for serial unittest runs.
    """
    if sys.byteorder != "little":
        raise RuntimeError("This fixture requires the existing little-endian input payload")
    prefix = os.environ.get("RVZR_ARM64_BINUTILS_PREFIX")
    if prefix is None:
        prefix = "" if platform.machine().lower() in ("aarch64", "arm64") \
            else "aarch64-linux-gnu-"
    tools = {}
    for name in ("as", "objdump"):
        executable = shutil.which(prefix + name)
        if executable is None:
            raise RuntimeError(f"Missing {prefix + name}; install ARM64 binutils or set "
                               "RVZR_ARM64_BINUTILS_PREFIX (no synthetic fallback)")
        subprocess.run([executable, "--version"], capture_output=True, check=True, timeout=5)
        tools[name] = executable
    bin_dir = directory / "bin"
    bin_dir.mkdir()
    for name, executable in tools.items():
        (bin_dir / name).symlink_to(executable)
    previous_directory = Path.cwd()
    random_state = random.getstate()
    try:
        with patch.dict(CONF.__dict__, deepcopy(CONF.__dict__), clear=True), \
                patch.dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"]), \
                patch.object(ARM64TargetDesc, "_build_cpu_desc",
                             return_value=CPUDesc("ARM", 0, 8, 0)), \
                patch.object(factory, "get_executor",
                             side_effect=AssertionError("Unexpected hardware executor")), \
                patch.object(factory, "get_fuzzer",
                             side_effect=AssertionError("Unexpected fuzzer construction")):
            # set_to_arch_defaults updates this dictionary in place: detach class defaults first.
            CONF._option_values = deepcopy(CONF._option_values)
            CONF.instruction_set = "arm64"
            CONF.set_to_arch_defaults()
            CONF.model_backend = "unicorn"
            CONF.contract_execution_clause = ["seq"]
            CONF.contract_observation_clause = "ct"
            CONF._handled_faults = []
            CONF.coverage_type = "none"
            CONF.logging_modes = []
            update_logging_after_config_change()
            os.chdir(directory)
            yield
    finally:
        os.chdir(previous_directory)
        random.setstate(random_state)
        update_logging_after_config_change()


class ARM64ContractSliceTest(unittest.TestCase):
    def test_template_assembly_serialization_and_sequential_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rvzr-arm64-contract-") as temporary:
            directory = Path(temporary)
            with software_environment(directory):
                self.exercise_slice(directory)

    def assemble_case(self, directory: Path) -> TestCaseProgram:
        # Copy so parser patching and generated files never touch the source fixture.
        template = directory / "slice.asm"
        shutil.copyfile(_ARM_TESTS / "asm/contract_slice.asm", template)
        isa = InstructionSet(str(_ARM_TESTS / "min_arm64.json"))
        generator = factory.get_program_generator(1, isa)
        self.assertIsInstance(generator, ARM64Generator)
        case = generator.create_test_case_from_template(str(template))
        self.assertEqual(case.n_actors(), 1)
        obj = case.get_obj()
        with open(obj.obj_path, "rb") as file:
            elf = ELFFile(file)
            self.assertEqual(elf["e_machine"], "EM_AARCH64")
            self.assertTrue(elf.little_endian)
            section = elf.get_section_by_name(".data.main")
            assert section is not None
            payload = section.data()
        self.assertEqual(len(payload), 60)  # eight instructions, two 3-NOP macros, exit NOP
        self.assertEqual(obj.symbol_table(), [
            SymbolTableEntry(0, 0, 0, 0), SymbolTableEntry(0, 0, 1, 0),
            SymbolTableEntry(0, 44, 0, 1), SymbolTableEntry(0, 44, 2, 0),
        ])
        instructions = obj.instruction_map()[0]
        self.assertEqual([instructions[offset].name for offset in range(12, 44, 4)],
                         ["cmp", "b.", "mov", "b", "mov", "ldr", "add", "str"])

        rcbf = directory / "slice.rcbf"
        obj.save_rcbf(str(rcbf))
        wire = rcbf.read_bytes()
        self.assertEqual(len(wire), 276)
        self.assertEqual(wire[:16], struct.pack("<QQ", 1, 4))
        self.assertEqual(wire[192:216], struct.pack("<QQQ", 0, 60, 0))
        self.assertEqual(wire[216:], payload)
        return case

    def make_inputs(self, directory: Path) -> List[InputData]:
        inputs: List[InputData] = []
        for index, (selector, word) in enumerate(((0, 7), (1, 7), (2, 19))):
            input_ = InputData(1)
            input_.view(np.uint8).fill(0)  # constructor does not initialize its storage
            input_[0]["gpr"][0] = selector
            input_[0]["main"][0] = word
            expected = bytearray(12288)
            struct.pack_into("<Q", expected, 0, word)
            struct.pack_into("<Q", expected, 8192, selector)
            raw = directory / f"input-{index}.bin"
            input_.save(str(raw))
            self.assertEqual(raw.read_bytes(), bytes(expected))
            restored = InputData(1)
            restored.load(str(raw))
            self.assertEqual(restored.tobytes(), bytes(expected))
            inputs.append(restored)
        rdbf = directory / "inputs.rdbf"
        save_input_sequence_as_rdbf(inputs, str(rdbf))
        # Existing metadata reports meaningful bytes; serialized fragments include padding.
        self.assertEqual(rdbf.read_bytes(), struct.pack("<QQQQ", 1, 3, 8512, 0)
                         + b"".join(input_.tobytes() for input_ in inputs))
        return inputs

    def exercise_slice(self, directory: Path) -> None:
        case = self.assemble_case(directory)
        inputs = self.make_inputs(directory)
        original_inputs = [input_.tobytes() for input_ in inputs]

        model = factory.get_model((0x109000, 0x200000))  # synthetic emulated addresses only
        self.assertIsInstance(model, ARM64UnicornModel)
        assert isinstance(model, ARM64UnicornModel)
        self.assertIsInstance(model.speculator, SeqSpeculator)
        self.assertIsInstance(model.tracer, CTTracer)
        self.assertFalse(model.is_speculative)
        model.load_test_case(case)
        expected_traces = [_TAKEN, _NOT_TAKEN, _NOT_TAKEN]
        final_registers = [(0, 22, 7, 29), (1, 11, 7, 18), (2, 11, 19, 30)]
        traces = []
        for index, input_ in enumerate(inputs):
            with self.subTest(input=index):
                trace = model.trace_test_case([input_], nesting=1)[0]
                self.assertEqual(trace.get_typed(), expected_traces[index])
                registers = (ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1,
                             ucc.UC_ARM64_REG_X2, ucc.UC_ARM64_REG_X3)
                self.assertEqual(tuple(model.emulator.reg_read(reg) for reg in registers),
                                 final_registers[index])
                self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_NZCV),
                                 0x60000000 if index == 0 else 0x20000000)
                self.assertEqual(bytes(model.emulator.mem_read(0x10A000, 16)),
                                 struct.pack("<QQ", final_registers[index][3], 0))
                traces.append(trace)
        self.assertNotEqual(traces[0], traces[1])
        self.assertEqual(traces[1], traces[2])  # ct observes addresses, not these data values
        repeated = model.trace_test_case(inputs + [inputs[0]], nesting=1)
        self.assertEqual([trace.get_typed() for trace in repeated],
                         expected_traces + [_TAKEN])
        self.assertEqual([input_.tobytes() for input_ in inputs], original_inputs)
