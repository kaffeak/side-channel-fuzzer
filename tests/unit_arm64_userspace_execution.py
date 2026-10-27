"""Fixed native architectural smoke test; no HTrace or random-code execution.

Host tests assemble the real fixture and emulate only the ABI boundary, in
addition to explicit mocked-syscall ownership tests. Only the native test
executes AArch64 on a processor. RVZR_REQUIRE_NATIVE=1 makes an absent native
environment an error, so the CI step cannot silently skip execution.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from contextlib import ExitStack
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest

from elftools.elf.elffile import ELFFile
import unicorn as uc  # type: ignore[import-untyped]
import unicorn.arm64_const as ucc  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.isa_spec import InstructionSet
from rvzr.model_unicorn.model import ARM64UnicornModel
from tests.unit_arm64_contract_slice import software_environment


_ROOT = Path(__file__).resolve().parents[1]
_TOOLS = _ROOT / "tools"
_ARM = _ROOT / "tests/arm64"
_NATIVE = platform.system() == "Linux" and platform.machine().lower() == "aarch64"
_FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]


class ARM64UserspaceExecutionTest(unittest.TestCase):
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

    @unittest.skipUnless(_NATIVE, "Actual AArch64 Linux CPU required; no emulated native success")
    def test_native_fixed_execution_against_oracle_and_sequential_model(self) -> None:
        # Keep the independent register/memory oracles together for review.
        # pylint: disable=too-many-locals
        # Importing the class would collect its test again; module import just reuses input setup.
        # pylint: disable-next=import-outside-toplevel
        from tests import unit_arm64_contract_slice as slice_tests

        binary = self.directory / "architectural-smoke"
        subprocess.run(["gcc", *_FLAGS, str(_TOOLS / "arm64_architectural_smoke.c"),
                        str(_TOOLS / "arm64_architectural_fixture.S"), "-o", str(binary)],
                       check=True, timeout=30)
        reject = subprocess.run([str(binary), "untrusted.bin"], capture_output=True,
                                text=True, timeout=5, check=False)
        self.assertNotEqual(reject.returncode, 0)
        self.assertEqual(json.loads(reject.stdout)["kind"], "error")
        with software_environment(self.directory):
            helper = slice_tests.ARM64ContractSliceTest()
            case = helper.assemble_case(self.directory)
            fixture, _ = self.assemble_fixture()
            with open(case.get_obj().obj_path, "rb") as file:
                section = ELFFile(file).get_section_by_name(".data.main")
                assert section is not None
                self.assertEqual(fixture[:-4], section.data()[12:44])
            inputs = helper.make_inputs(self.directory)
            model = factory.get_model((0x109000, 0x200000))
            assert isinstance(model, ARM64UnicornModel)
            model.load_test_case(case)
            for repetition in range(2):
                run = subprocess.run([str(binary)], capture_output=True, text=True,
                                     check=False, timeout=10)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                records = [json.loads(line) for line in run.stdout.splitlines()]
                self.assertEqual([row["kind"] for row in records],
                                 ["metadata"] + ["architectural_state"] * 3 + ["complete"])
                self.assertEqual(records[0]["page_size"], os.sysconf("SC_PAGESIZE"))
                self.assertEqual(records[-1], {"kind": "complete", "status": "ok", "cases": 3})
                for index, (input_, row) in enumerate(zip(inputs, records[1:4])):
                    marker, word = (22 if index == 0 else 11), (19 if index == 2 else 7)
                    expected_regs = [index, marker, word, marker + word, 0, 0, 0, 0]
                    expected_memory = struct.pack("<Q", marker + word) + bytes(4088)
                    self.assertEqual(row["input"], index)
                    self.assertEqual((row["selector"], row["initial_word"]), (index, word))
                    self.assertEqual(row["status"], "ok")
                    self.assertEqual(row["x0_x7"], expected_regs)
                    self.assertEqual(row["nzcv"], 0x60000000 if index == 0 else 0x20000000)
                    self.assertEqual(row["sp_mod16"], 0)
                    self.assertEqual(bytes.fromhex(row["main_hex"]), expected_memory)
                    for name in ("data_base", "code_base"):
                        address = int(row[name], 16)
                        self.assertGreater(address, 0)
                        self.assertEqual(address % records[0]["page_size"], 0)
                    self.assertGreaterEqual(abs(int(row["code_base"], 16)
                                                - int(row["data_base"], 16)),
                                            3 * records[0]["page_size"])
                    model.trace_test_case([input_], nesting=1)
                    registers = [ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1,
                                 ucc.UC_ARM64_REG_X2, ucc.UC_ARM64_REG_X3,
                                 ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_X5,
                                 ucc.UC_ARM64_REG_X6, ucc.UC_ARM64_REG_X7]
                    self.assertEqual([model.emulator.reg_read(reg) for reg in registers],
                                     expected_regs)
                    self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_NZCV), row["nzcv"])
                    self.assertEqual(bytes(model.emulator.mem_read(0x10a000, 4096)),
                                     expected_memory)
                    print("Native architectural state:", json.dumps(
                        {"input": row["input"], "x0_x7": row["x0_x7"], "nzcv": row["nzcv"],
                         "sp_mod16": row["sp_mod16"]}, sort_keys=True))
                print(f"Native fixed architectural run {repetition}: 3 oracle/seq matches; "
                      f"kernel={records[0]['kernel']} page={records[0]['page_size']}")


if __name__ == "__main__":
    unittest.main()
