"""Fixed native architectural smoke test; no HTrace or random-code execution.

Host tests assemble the real fixture and emulate only the ABI boundary, in
addition to explicit mocked-syscall ownership tests. Only the native test
executes AArch64 on a processor. RVZR_REQUIRE_NATIVE=1 makes an absent native
environment an error, so the CI step cannot silently skip execution.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile
import numpy as np
import unicorn as uc  # type: ignore[import-untyped]
import unicorn.arm64_const as ucc  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.isa_spec import InstructionSet
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.tc_components.test_case_data import InputData, save_input_sequence_as_rdbf
from tests.unit_arm64_contract_slice import software_environment
from tools.arm64_userspace_input import INPUT_FORMAT, encode_input


_ROOT = Path(__file__).resolve().parents[1]
_TOOLS = _ROOT / "tools"
_ARM = _ROOT / "tests/arm64"
_NATIVE = platform.system() == "Linux" and platform.machine().lower() == "aarch64"
_FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
_U64 = (1 << 64) - 1
_INPUT_ARGS = ["--input-format", INPUT_FORMAT]
_BAD_ARGUMENTS: tuple[list[str], ...] = (
    [], ["untrusted.bin"], ["--input-format", "rdbf"],
    ["--input-format", "rvzr-inputdata-raw-v2"])


def restricted_inputs() -> list[InputData]:
    """Actual InputData, including a duplicate, addition wrap and a nonzero tail."""
    result = []
    for selector, word in ((0, 7), (1, 7), (2, 19), (0, 7), (1, 18), (0, _U64),
                           (_U64, 5), (0, 41)):
        input_ = InputData(1)
        input_.view(np.uint8).fill(0)
        input_[0]["gpr"][0] = selector
        input_[0]["main"][0] = word
        result.append(input_)
    result[-1][0]["main"][1:] = np.arange(1, 512, dtype=np.uint64) + 100
    return result


def expected_state(input_: InputData) -> tuple[list[int], int, bytes]:
    """Independent arithmetic/memory oracle using semantic fields, not adapter offsets."""
    selector, word = int(input_[0]["gpr"][0]), int(input_[0]["main"][0])
    marker = 22 if selector == 0 else 11
    registers = [selector, marker, word, (marker + word) & _U64, 0, 0, 0, 0]
    flags = 0x60000000 if selector == 0 else (0xa0000000 if selector >> 63 else 0x20000000)
    memory = bytearray(input_[0]["main"].tobytes())
    struct.pack_into("<Q", memory, 0, registers[3])
    return registers, flags, bytes(memory)


def malformed_payloads(wire: bytes) -> dict[str, bytes]:
    """Independent literal byte boundaries, never executable malformed programs."""
    result = {f"truncated-{size}": wire[:size] for size in (0, 1, 4096, 8192, 12287)}
    result.update(oversized=wire + b"\0", two_actors=wire * 2,
                  rdbf=struct.pack("<QQQQ", 1, 1, 8512, 0) + wire)
    for name, offset in (("faulty-first", 4096), ("faulty-last", 8191), ("x1", 8200),
                         ("nzcv", 8240), ("sp", 8248), ("simd", 8256),
                         ("padding-first", 8512), ("padding-last", 12287)):
        invalid = bytearray(wire)
        invalid[offset] = 1
        result[name] = bytes(invalid)
    return result


# Keep one reviewed harness shared across the host, model and native test matrix.
class ARM64UserspaceExecutionTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    host_binary: Path

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("RVZR_REQUIRE_NATIVE") == "1" and not _NATIVE:
            raise RuntimeError("Native AArch64 Linux execution required; no emulation fallback")
        # Class cleanup deliberately spans all test methods.
        # pylint: disable-next=consider-using-with
        temporary = tempfile.TemporaryDirectory(prefix="rvzr-arch-host-tests-")
        cls.addClassCleanup(temporary.cleanup)
        cls.host_binary = Path(temporary.name) / "host-ownership"
        subprocess.run(["gcc", *_FLAGS, str(_ARM / "userspace_host_harness.c"),
                        "-o", str(cls.host_binary)], check=True, timeout=30)

    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(
            prefix="rvzr-arm64-userspace-")))

    def host_scenario(self, scenario: int) -> subprocess.CompletedProcess[str]:
        result = subprocess.run([str(self.host_binary), str(scenario)], capture_output=True,
                                text=True, check=False, timeout=6)
        self.assertEqual(result.returncode, 1 if scenario == 11 else 0, result.stderr)
        return result

    def test_mapping_geometry_and_successful_release(self) -> None:
        self.host_scenario(0)

    def test_first_mapping_failure(self) -> None:
        self.host_scenario(1)

    def test_second_mapping_failure_releases_first(self) -> None:
        self.host_scenario(2)

    def test_data_protection_failure_releases_reservation(self) -> None:
        self.host_scenario(3)

    def test_code_protection_failure_releases_both(self) -> None:
        self.host_scenario(4)

    def test_rx_publication_failure_never_invokes(self) -> None:
        self.host_scenario(5)

    def test_failed_release_is_not_reported_as_complete(self) -> None:
        self.host_scenario(6)

    def test_owned_region_rejection_and_cleanup_idempotence(self) -> None:
        self.host_scenario(7)

    def test_16k_geometry_without_host_page_size_assumption(self) -> None:
        self.host_scenario(8)

    def test_abnormal_child_exit_is_preserved_and_reaped(self) -> None:
        self.host_scenario(9)

    def test_child_timeout_is_bounded_and_reaped(self) -> None:
        self.host_scenario(10)

    def test_error_output_is_explicit(self) -> None:
        result = self.host_scenario(11)
        self.assertEqual(json.loads(result.stdout), {
            "kind": "error", "status": "error", "stage": "host_mock", "errno": 13,
            "signal": 15, "timeout": True, "child_exit": -1,
        })

    def test_complete_main_initialization_4k(self) -> None:
        self.host_scenario(12)

    def test_complete_main_initialization_16k(self) -> None:
        self.host_scenario(13)

    def test_adapter_matches_production_raw_and_rdbf_payload_bytes(self) -> None:
        for index, input_ in enumerate(restricted_inputs()):
            with self.subTest(input=index):
                wire = encode_input(input_)
                self.assertEqual(len(wire), 12288)
                self.assertEqual(wire[:4096], input_[0]["main"].tobytes())
                self.assertEqual(wire[8192:8200], struct.pack("<Q", int(input_[0]["gpr"][0])))
                path = self.directory / "input.raw"
                input_.save(str(path))
                self.assertEqual(wire, path.read_bytes())
                save_input_sequence_as_rdbf([input_], str(path))
                self.assertEqual(path.read_bytes(), struct.pack("<QQQQ", 1, 1, 8512, 0) + wire)
                self.assertEqual(encode_input(input_), wire)  # no mutation

    def test_adapter_rejects_unsupported_fields_and_actor_shapes(self) -> None:
        for input_ in (InputData(0), InputData(2), InputData(1).view("V12288")):
            with self.assertRaises(ValueError):
                encode_input(input_)  # type: ignore[arg-type]
        wire = encode_input(restricted_inputs()[0])
        for offset in (4096, 8191, 8200, 8240, 8248, 8256, 8512, 12287):
            input_ = InputData(1)
            input_.view(np.uint8).reshape(-1)[:] = np.frombuffer(wire, dtype=np.uint8)
            input_.view(np.uint8).reshape(-1)[offset] = 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                encode_input(input_)
        ordinary_array = np.zeros(1, dtype=InputData(1).dtype)
        with self.assertRaises(ValueError):
            encode_input(ordinary_array)  # type: ignore[arg-type]
        with patch("tools.arm64_userspace_input.sys.byteorder", "big"), \
                self.assertRaises(ValueError):
            encode_input(restricted_inputs()[0])

    def test_real_c_decoder_matches_python_input_bytes(self) -> None:
        for input_ in restricted_inputs():
            result = subprocess.run([str(self.host_binary), "decode"], input=encode_input(input_),
                                    capture_output=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            row = json.loads(result.stdout)
            self.assertEqual(row["kind"], "decoded_input")  # no architectural measurement
            self.assertEqual(row["selector"], int(input_[0]["gpr"][0]))
            self.assertEqual(bytes.fromhex(row["main_hex"]), input_[0]["main"].tobytes())

    def test_real_c_admission_rejects_malformed_inputs_before_allocation(self) -> None:
        invalid = malformed_payloads(encode_input(restricted_inputs()[0]))
        self.assertEqual(len(invalid), 16)
        for name, payload in invalid.items():
            with self.subTest(input=name):
                result = subprocess.run([str(self.host_binary), "admission", *_INPUT_ARGS],
                                        input=payload, capture_output=True, check=False, timeout=5)
                self.assertEqual(result.returncode, 1, result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual((row["kind"], row["stage"]), ("error", "input"))
        for arguments in _BAD_ARGUMENTS:
            result = subprocess.run([str(self.host_binary), "admission", *arguments],
                                    input=b"", capture_output=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)["kind"], "error")
        print("Host actual-C admission: 16 malformed payloads + 4 argument/format rejections; "
              "zero allocations or invocations")

    def test_c_decoder_does_not_publish_invalid_partial_snapshots(self) -> None:
        for payload in malformed_payloads(encode_input(restricted_inputs()[0])).values():
            result = subprocess.run([str(self.host_binary), "decode"], input=payload,
                                    capture_output=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)["kind"], "error")

    def test_c_reader_accepts_chunked_input_and_requires_eof(self) -> None:
        wire = encode_input(restricted_inputs()[-1])
        with subprocess.Popen([str(self.host_binary), "decode"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            assert process.stdin is not None
            for chunk in (wire[:1], wire[1:8], wire[8:4096]):
                process.stdin.write(chunk)
                process.stdin.flush()
            output, error = process.communicate(wire[4096:], timeout=5)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(bytes.fromhex(json.loads(output)["main_hex"]), wire[:4096])
        for prefix in (b"", wire):
            with subprocess.Popen([str(self.host_binary), "admission", *_INPUT_ARGS],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as process:
                # Even a complete fragment cannot execute before EOF proves no excess bytes.
                assert process.stdin is not None
                if prefix:
                    process.stdin.write(prefix)
                    process.stdin.flush()
                process.wait(timeout=5)
                output, error = process.communicate(timeout=1)
                self.assertEqual(process.returncode, 1, error)
                self.assertEqual(json.loads(output)["errno"], errno.ETIMEDOUT)

    def assemble_fixture(self) -> tuple[bytes, bytes]:
        """Actual GNU assembly: fixture and trampoline are both relocation free."""
        obj = self.directory / "native-fixture.o"
        subprocess.run(["as", str(_TOOLS / "arm64_architectural_fixture.S"), "-o", str(obj)],
                       capture_output=True, check=True, timeout=10)
        with obj.open("rb") as file:
            elf = ELFFile(file)
            self.assertEqual(elf["e_machine"], "EM_AARCH64")
            self.assertTrue(elf.little_endian)
            self.assertFalse(any(section["sh_type"] in ("SHT_REL", "SHT_RELA")
                                 and section["sh_size"] for section in elf.iter_sections()))
            fixture_section = elf.get_section_by_name(".rodata.rvzr_fixture")
            text_section = elf.get_section_by_name(".text")
            size_section = elf.get_section_by_name(".rodata.rvzr_fixture_size")
            assert fixture_section is not None and text_section is not None
            assert size_section is not None
            fixture, trampoline = fixture_section.data(), text_section.data()
            self.assertEqual(size_section.data(), struct.pack("<Q", 36))
        self.assertEqual(len(fixture), 36)
        self.assertEqual(fixture[-4:], bytes.fromhex("c0035fd6"))  # RET X30
        return fixture, trampoline

    def test_native_fixture_matches_real_b34a_generator_elf_body(self) -> None:
        with software_environment(self.directory):
            fixture, _ = self.assemble_fixture()
            template = self.directory / "trusted.asm"
            shutil.copyfile(_ARM / "asm/contract_slice.asm", template)
            case = factory.get_program_generator(1, InstructionSet(
                str(_ARM / "min_arm64.json"))).create_test_case_from_template(str(template))
            self.assertEqual(case.n_actors(), 1)
            with open(case.get_obj().obj_path, "rb") as file:
                section = ELFFile(file).get_section_by_name(".data.main")
                assert section is not None
                payload = section.data()
            self.assertEqual(len(payload), 60)
            self.assertEqual(fixture[:-4], payload[12:44])
            self.assertEqual([case.get_obj().instruction_map()[0][pc].name
                              for pc in range(12, 44, 4)],
                             ["cmp", "b.", "mov", "b", "mov", "ldr", "add", "str"])

    def test_trampoline_abi_in_unicorn_not_native_evidence(self) -> None:
        # Keep register, stack and write-range oracles visible in the same test.
        # pylint: disable=too-many-locals
        with software_environment(self.directory):
            fixture, trampoline = self.assemble_fixture()
        em = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
        code, target, stack, output, main = 0x100000, 0x200000, 0x300000, 0x400000, 0x500000
        for base in (code, target, stack, output, main):
            em.mem_map(base, 4096)
        em.mem_write(code, trampoline)
        em.mem_write(target, fixture)
        em.mem_write(main, struct.pack("<Q", 7))
        saved = [ucc.UC_ARM64_REG_X18, ucc.UC_ARM64_REG_X19, ucc.UC_ARM64_REG_X20,
                 ucc.UC_ARM64_REG_X21, ucc.UC_ARM64_REG_X22, ucc.UC_ARM64_REG_X23,
                 ucc.UC_ARM64_REG_X24, ucc.UC_ARM64_REG_X25, ucc.UC_ARM64_REG_X26,
                 ucc.UC_ARM64_REG_X27, ucc.UC_ARM64_REG_X28, ucc.UC_ARM64_REG_X29]
        sentinels = {register: 0xabc000 + index for index, register in enumerate(saved)}
        for register, value in sentinels.items():
            em.reg_write(register, value)
        # SIMD registers are untouched (check the full Q value, stronger than low 64 bits).
        for register in range(ucc.UC_ARM64_REG_Q8, ucc.UC_ARM64_REG_Q15 + 1):
            em.reg_write(register, (1 << 120) + register)
        em.reg_write(ucc.UC_ARM64_REG_SP, stack + 4096)
        em.reg_write(ucc.UC_ARM64_REG_X30, code + 0x800)
        for register, value in zip((ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1,
                                    ucc.UC_ARM64_REG_X2, ucc.UC_ARM64_REG_X3),
                                   (target, main, 0, output)):
            em.reg_write(register, value)
        writes: list[tuple[int, int]] = []
        em.hook_add(uc.UC_HOOK_MEM_WRITE,
                    lambda _em, _access, address, size, _value, _context:
                    writes.append((address, size)))
        em.emu_start(code, code + 0x800, timeout=100000, count=100)
        allowed = ((stack + 4096 - 32, stack + 4096), (output, output + 80), (main, main + 8))
        self.assertTrue(writes)
        for address, size in writes:
            self.assertGreater(size, 0)
            self.assertTrue(any(start <= address and address + size <= end
                                for start, end in allowed), (address, size))
        self.assertEqual(em.reg_read(ucc.UC_ARM64_REG_PC), code + 0x800)
        self.assertEqual(em.reg_read(ucc.UC_ARM64_REG_SP), stack + 4096)
        self.assertEqual(em.reg_read(ucc.UC_ARM64_REG_X30), code + 0x800)
        for register, value in sentinels.items():
            self.assertEqual(em.reg_read(register), value)
        for register in range(ucc.UC_ARM64_REG_Q8, ucc.UC_ARM64_REG_Q15 + 1):
            self.assertEqual(em.reg_read(register), (1 << 120) + register)
        self.assertEqual(struct.unpack("<10Q", bytes(em.mem_read(output, 80))),
                         (0, 22, 7, 29, 0, 0, 0, 0, 0x60000000, 0))
        self.assertEqual(bytes(em.mem_read(main, 4096)), struct.pack("<Q", 29) + bytes(4088))

    def make_sequential_model(self) -> ARM64UnicornModel:
        """Within software_environment: production generator/ELF, fixture and seq model."""
        # Importing the class would collect its test again; module import just reuses input setup.
        # pylint: disable-next=import-outside-toplevel
        from tests import unit_arm64_contract_slice as slice_tests

        helper = slice_tests.ARM64ContractSliceTest()
        case = helper.assemble_case(self.directory)
        fixture, _ = self.assemble_fixture()
        with open(case.get_obj().obj_path, "rb") as file:
            section = ELFFile(file).get_section_by_name(".data.main")
            assert section is not None
            self.assertEqual(fixture[:-4], section.data()[12:44])
        model = factory.get_model((0x109000, 0x200000))
        assert isinstance(model, ARM64UnicornModel)
        model.load_test_case(case)
        return model

    def assert_model_state(self, model: ARM64UnicornModel, input_: InputData) -> None:
        expected_regs, expected_flags, expected_memory = expected_state(input_)
        model.trace_test_case([input_], nesting=1)
        registers = [ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1,
                     ucc.UC_ARM64_REG_X2, ucc.UC_ARM64_REG_X3,
                     ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_X5,
                     ucc.UC_ARM64_REG_X6, ucc.UC_ARM64_REG_X7]
        self.assertEqual([model.emulator.reg_read(reg) for reg in registers], expected_regs)
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_NZCV), expected_flags)
        self.assertEqual(bytes(model.emulator.mem_read(0x10a000, 4096)), expected_memory)

    def test_restricted_inputs_against_real_sequential_model_on_any_host(self) -> None:
        with software_environment(self.directory):
            model = self.make_sequential_model()
            inputs = restricted_inputs()
            snapshots = [encode_input(input_) for input_ in inputs]
            for _ in range(2):
                for input_ in inputs:
                    self.assert_model_state(model, input_)
            self.assertEqual([encode_input(input_) for input_ in inputs], snapshots)
            self.assertEqual(snapshots[0], snapshots[3])
            self.assertEqual(expected_state(inputs[0])[2], expected_state(inputs[4])[2])
            self.assertNotEqual(expected_state(inputs[0])[0], expected_state(inputs[4])[0])

    def native_result(self, binary: Path, input_: InputData,
                      model: ARM64UnicornModel) -> tuple[list[int], int, bytes]:
        run = subprocess.run([str(binary), *_INPUT_ARGS], input=encode_input(input_),
                             capture_output=True, check=False, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        records = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual([row["kind"] for row in records],
                         ["metadata", "architectural_state", "complete"])
        self.assertEqual(records[0]["page_size"], os.sysconf("SC_PAGESIZE"))
        self.assertEqual(records[0]["input_format"], INPUT_FORMAT)
        self.assertEqual(records[0]["fixture"], "b34a-fixed-body-v1")
        self.assertEqual(records[0]["architecture"], "aarch64")
        self.assertEqual(records[-1], {"kind": "complete", "status": "ok", "cases": 1})
        row = records[1]
        self.assertEqual(row["input"], 0)  # One fragment per process, not a campaign ordinal.
        self.assertEqual((row["selector"], row["initial_word"]),
                         (int(input_[0]["gpr"][0]), int(input_[0]["main"][0])))
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["sp_mod16"], 0)
        actual = (row["x0_x7"], row["nzcv"], bytes.fromhex(row["main_hex"]))
        self.assertEqual(actual, expected_state(input_))
        for name in ("data_base", "code_base"):
            address = int(row[name], 16)
            self.assertGreater(address, 0)
            self.assertEqual(address % records[0]["page_size"], 0)
        self.assertGreaterEqual(abs(int(row["code_base"], 16) - int(row["data_base"], 16)),
                                3 * records[0]["page_size"])
        self.assert_model_state(model, input_)
        print("Native architectural state:", json.dumps(
            {"selector": row["selector"], "initial_word": row["initial_word"],
             "x0_x7": row["x0_x7"], "nzcv": row["nzcv"], "sp_mod16": row["sp_mod16"],
             "kernel": records[0]["kernel"], "page_size": records[0]["page_size"]},
            sort_keys=True))
        return actual

    @unittest.skipUnless(_NATIVE, "Actual AArch64 Linux CPU required; no emulated native success")
    def test_native_fixed_execution_against_oracle_and_sequential_model(self) -> None:
        # pylint: disable=import-outside-toplevel
        from tests import unit_arm64_contract_slice as slice_tests

        binary = self.directory / "architectural-smoke"
        subprocess.run(["gcc", *_FLAGS, str(_TOOLS / "arm64_architectural_smoke.c"),
                        str(_TOOLS / "arm64_architectural_fixture.S"), "-o", str(binary)],
                       check=True, timeout=30)
        invalid = malformed_payloads(encode_input(restricted_inputs()[0]))
        for payload in invalid.values():
            run = subprocess.run([str(binary), *_INPUT_ARGS], input=payload,
                                 capture_output=True, check=False, timeout=5)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertEqual(json.loads(run.stdout)["kind"], "error")
        for arguments in _BAD_ARGUMENTS:
            run = subprocess.run([str(binary), *arguments], input=b"",
                                 capture_output=True, check=False, timeout=5)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertEqual(json.loads(run.stdout)["kind"], "error")
        with software_environment(self.directory):
            model = self.make_sequential_model()
            # Preserve all six B3.5d native executions; replace only their input source.
            legacy = slice_tests.ARM64ContractSliceTest().make_inputs(self.directory)
            inputs = legacy + restricted_inputs()
            first = [self.native_result(binary, input_, model) for input_ in inputs]
            repeated = [self.native_result(binary, input_, model) for input_ in inputs]
            self.assertEqual(first, repeated)  # Ignore allocation addresses, compare actual state.
            self.assertEqual(first[3], first[6])  # Identical serialized input.
            self.assertEqual(first[3][2], first[7][2])  # Equal stored result, distinct registers.
            self.assertNotEqual(first[3][0], first[7][0])
            completed = len(first) + len(repeated)
            self.assertEqual(completed, 22)
        print("Native InputData verification:", json.dumps({
            "native_fixture_executions": completed, "architectural_oracle_comparisons": completed,
            "sequential_model_comparisons": completed,
            "rejected_malformed_or_unsupported_inputs": len(invalid) + len(_BAD_ARGUMENTS),
        }, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
