"""Eight fixed seeds through real ARM64 RANDOM expansion, Unicorn and boosting.

Only CPU identification and tool lookup use B3.4a's host adapter. Generation,
GNU assembly/ELF parsing, execution, taints and boosting are production code.
Failure artifacts persist under /tmp; optional successful artifacts can be
written to a new RVZR_ARM64_CAMPAIGN_OUTPUT directory. No H-traces are produced.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from collections import Counter
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
from typing import Any, Dict, List, Tuple
import unittest

from elftools.elf.elffile import ELFFile
import numpy as np
import unicorn as uc  # type: ignore[import-untyped]
import unicorn.arm64_const as ucc  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.config import CONF
from rvzr.instruction_spec import OT
from rvzr.isa_spec import InstructionSet
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.tc_components.instruction import RegisterOp
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTrace
from tests.unit_arm64_contract_slice import software_environment
from tests.unit_arm64_conditional_contract import make_input, make_model


_ARM = Path(__file__).resolve().parent / "arm64"
_SEEDS = tuple(range(1, 9))  # Never use zero: the generator interprets it as a random seed.
_REGISTERS = {"x1", "x2", "x3", "x5"}
_FORMS = {"mov": 2, "add": 3}  # Explicit REG64 operand counts; no shifts/immediates/flags.
_RANDOM_OFFSETS = tuple(range(12, 44, 4)) + tuple(range(56, 72, 4)) \
    + tuple(range(92, 108, 4))
_FIXED = {
    0: ("macro", (".measurement_start", ".noarg")),
    4: ("nop", ()), 8: ("nop", ()),
    44: ("add", ("x4", "x20", "#128")), 48: ("cmp", ("x0", "#0")),
    52: ("b.", ("eq", ".taken")),
    72: ("mov", ("x1", "#11")), 76: ("ldr", ("x2", "x20", "#0")),
    80: ("str", ("x1", "x20", "#0")), 84: ("cmp", ("x1", "#12")),
    88: ("b", (".join",)),
    108: ("mov", ("x1", "#22")), 112: ("ldr", ("x2", "x4", "#0")),
    116: ("str", ("x1", "x4", "#0")), 120: ("cmp", ("x1", "#22")),
    124: ("add", ("x3", "x1", "x2")),
    128: ("macro", (".measurement_end", ".noarg")),
    132: ("nop", ()), 136: ("nop", ()), 140: ("nop", ()),
}


class ARM64GeneratedCampaignTest(unittest.TestCase):
    current_seed: int = 0

    def test_add_preserves_flags_branch_taints_and_checkpointed_result(self) -> None:
        """CMP -> ADD (not ADDS) -> B.EQ: actual result/flags and taint dependencies.

        Read hooks witness X3 before the join, including after real
        conditional rollback. This is architectural-state evidence, not a CT value.
        """
        # Keep the real template/model/hook/input observations visible in one test.
        # pylint: disable=too-many-locals
        with tempfile.TemporaryDirectory(prefix="rvzr-arm64-add-") as temporary:
            directory = Path(temporary)
            with software_environment(directory):
                CONF.model_max_spec_window = 32
                source = (_ARM / "asm/conditional_contract_slice.asm").read_text(encoding="ascii")
                needle = "cmp x0, #0\n    b.eq .taken"
                self.assertEqual(source.count(needle), 1)
                template = directory / "add-flags.asm"
                source = source.replace(needle, "cmp x0, #0\n"
                                        "    add x3, x1, x2\n    b.eq .taken")
                # Retain X3 as a final architectural result. Wrong-path join ADD
                # changes X5; rollback must restore X5 before the next path's load.
                join = ".join:\n    add x3, x1, x2"
                self.assertEqual(source.count(join), 1)
                template.write_text(source.replace(join, ".join:\n    add x5, x1, x2"),
                                    encoding="ascii")
                isa = InstructionSet(str(_ARM / "min_arm64.json"))
                case = factory.get_program_generator(1, isa).create_test_case_from_template(
                    str(template))
                observations: List[Tuple[int, int, int]] = []

                def observe_read(emulator: uc.Uc, _access: int, _address: int, _size: int,
                                 _value: int, _context: object) -> None:
                    observations.append((int(emulator.reg_read(ucc.UC_ARM64_REG_X3)),
                                         int(emulator.reg_read(ucc.UC_ARM64_REG_NZCV)),
                                         int(emulator.reg_read(ucc.UC_ARM64_REG_X5))))

                for clause in ("seq", "cond"):
                    model = make_model(clause, case)
                    hook = model.emulator.hook_add(uc.UC_HOOK_MEM_READ, observe_read)
                    traces = []
                    try:
                        for selector, left, right in ((0, 7, 9), (1, (1 << 64)-1, 1), (1, 7, 9)):
                            with self.subTest(clause=clause, selector=selector,
                                              operands=(left, right)):
                                observations.clear()
                                input_ = make_input(selector)
                                input_[0]["gpr"][1:3] = (left, right)
                                result, taints = model.trace_test_case_with_taints(
                                    [input_], nesting=1)
                                expected = ((left+right) & ((1 << 64)-1),
                                            0x60000000 if selector == 0 else 0x20000000, 0)
                                self.assertEqual(observations, [expected] * (2 if clause == "cond"
                                                                             else 1))
                                self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X3),
                                                 expected[0])
                                self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X5),
                                                 41 if selector == 0 else 18)
                                # ADD's sources do not control this CT; X0 still does.
                                mask = taints[0][0]["gpr"]
                                self.assertTrue(mask[0])
                                self.assertFalse(mask[1])
                                self.assertFalse(mask[2])
                                self.assertFalse(model.state.had_arch_fault)
                                self.assertEqual(model._taint_tracker._checkpoints, [])
                                self.assertEqual(model.speculator.nesting(), 0)
                                traces.append(result[0].get_typed())
                    finally:
                        model.emulator.hook_del(hook)
                    self.assertNotEqual(traces[0], traces[1])
                    self.assertEqual(traces[1], traces[2])  # different sums, identical CT addresses

    def configure_pool(self) -> InstructionSet:
        CONF.contract_execution_clause = ["cond"]
        CONF.model_max_spec_window = 32
        CONF.data_generator_entropy_bits = 8
        CONF.input_gen_probability_of_special_value = 0.0
        CONF.register_allowlist = []
        CONF.register_blocklist += ["x0", "x4", "w0", "w4"]
        isa = InstructionSet(str(_ARM / "min_arm64.json"))
        # Keep the complete parser vocabulary; restrict only the public random pool
        # to the existing MOV/ADD register forms, using the corrected fixture flags.
        pool = [spec for spec in isa.non_memory_access_specs if spec.name in _FORMS
                and len(spec.operands) == _FORMS[spec.name]
                and all(op.type == OT.REG and op.width == 64 for op in spec.operands)]
        self.assertEqual(Counter(spec.name for spec in pool), Counter({"mov": 1, "add": 1}))
        for spec in pool:
            self.assertEqual(spec.implicit_operands, [])
            for index, operand in enumerate(spec.operands):
                self.assertEqual(set(operand.values), _REGISTERS)
                self.assertEqual((operand.src, operand.dest), (index != 0, index == 0))
            self.assertNotIn(spec.name, CONF.get_actors_conf()["main"]["instruction_blocklist"])
        isa.non_memory_access_specs = pool
        return isa

    def generate(self, seed: int, directory: Path,
                 isa: InstructionSet) -> Tuple[TestCaseProgram, bytes]:
        directory.mkdir()
        template = directory / "template.asm"
        shutil.copyfile(_ARM / "asm/generated_contract_campaign.asm", template)
        previous = Path.cwd()
        try:
            os.chdir(directory)  # Production template generation writes generated.* here.
            case = factory.get_program_generator(seed, isa).create_test_case_from_template(
                str(template))
        finally:
            os.chdir(previous)
        with open(directory / case.get_obj().obj_path, "rb") as file:
            elf = ELFFile(file)
            self.assertEqual(elf["e_machine"], "EM_AARCH64")
            self.assertTrue(elf.little_endian)
            section = elf.get_section_by_name(".data.main")
            assert section is not None
            payload = section.data()
        return case, payload

    def validate_stream(self, case: TestCaseProgram, payload: bytes) -> List[Dict[str, Any]]:
        self.assertEqual(case.n_actors(), 1)
        self.assertEqual(len(payload), 144)
        instructions = case.get_obj().instruction_map()[0]
        self.assertEqual(sorted(instructions), list(range(0, 144, 4)))
        self.assertEqual(case.generator_seed, self.current_seed)
        generated = []
        for offset, instruction in sorted(instructions.items()):
            if offset not in _RANDOM_OFFSETS:
                self.assertEqual((instruction.name, tuple(op.value for op in instruction.operands)),
                                 _FIXED[offset])
                continue
            self.assertIn(instruction.name, _FORMS)
            self.assertFalse(instruction.is_from_template)
            self.assertFalse(instruction.is_instrumentation)
            self.assertFalse(instruction.is_control_flow)
            self.assertEqual(instruction.implicit_operands, [])
            self.assertIsNone(instruction.get_flags_operand())
            self.assertEqual(len(instruction.operands), _FORMS[instruction.name])
            for index, operand in enumerate(instruction.operands):
                self.assertIsInstance(operand, RegisterOp)
                assert isinstance(operand, RegisterOp)
                self.assertEqual(operand.width, 64)
                self.assertIn(operand.value, _REGISTERS)
                self.assertEqual((operand.src, operand.dest), (index != 0, index == 0))
            generated.append({"offset": offset, "name": instruction.name,
                              "operands": [op.value for op in instruction.operands], "width": 64,
                              "operand_roles": [{"read": op.src, "write": op.dest}
                                                for op in instruction.operands], "flags": None})
        self.assertEqual(len(generated), 16)
        return generated

    def check_execution(self, model: ARM64UnicornModel, trace: CTrace,
                        input_: InputData, selector: int) -> None:
        self.assertFalse(model.state.pending_fault)
        self.assertFalse(model.state.had_arch_fault)
        self.assertFalse(model.speculator.in_speculation())
        self.assertEqual(model.speculator.nesting(), 0)
        self.assertEqual(model._taint_tracker._checkpoints, [])
        memory = [entry.value for entry in trace.get_typed() if entry.type_ == "mem"]
        self.assertEqual(memory, [4096, 4096, 4224, 4224] if selector == 0
                         else [4224, 4224, 4096, 4096])
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X0), selector)
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X4), 0x10a080)
        stored = 22 if selector == 0 else 11
        loaded = int(input_[0]["main"][16 if selector == 0 else 0])
        for register, value in ((ucc.UC_ARM64_REG_X1, stored), (ucc.UC_ARM64_REG_X2, loaded),
                                (ucc.UC_ARM64_REG_X3, (stored+loaded) & ((1 << 64)-1)),
                                (ucc.UC_ARM64_REG_NZCV,
                                 0x60000000 if selector == 0 else 0x80000000)):
            self.assertEqual(model.emulator.reg_read(register), value)
        expected = bytearray(input_.tobytes()[:4096])
        struct.pack_into("<Q", expected, 128 if selector == 0 else 0, 22 if selector == 0 else 11)
        self.assertEqual(bytes(model.emulator.mem_read(0x10a000, 4096)), expected)

    def exercise_case(self, case: TestCaseProgram, directory: Path,
                      record: Dict[str, Any]) -> None:
        # pylint: disable=too-many-locals
        inputs = [make_input(0), make_input(1)]
        for input_ in inputs:
            input_[0]["main"][0] = self.current_seed + 7
            input_[0]["main"][16] = self.current_seed + 19
        originals = [input_.tobytes() for input_ in inputs]
        for index, input_ in enumerate(inputs):
            input_.save(str(directory / f"original-{index}.bin"))
        previous = Path.cwd()
        try:
            os.chdir(directory / "primary")  # The production object path is relative.
            model = make_model("cond", case)
        finally:
            os.chdir(previous)
        traces, taints = model.trace_test_case_with_taints(inputs, nesting=1)
        self.assertEqual(len(traces), len(inputs))
        self.assertEqual(len(taints), len(inputs))
        record["original_traces"] = [trace.get_typed() for trace in traces]
        record["tainted_words"] = [np.flatnonzero(t.linear_view(0)).tolist() for t in taints]
        self.check_execution(model, traces[-1], inputs[-1], 1)
        self.assertNotEqual(traces[0], traces[1])
        for taint in taints:
            self.assertTrue(taint[0]["gpr"][0])
        repeated, repeated_taints = model.trace_test_case_with_taints(inputs, nesting=1)
        record["repeat_traces"] = [trace.get_typed() for trace in repeated]
        self.assertEqual([trace.get_typed() for trace in repeated],
                         [trace.get_typed() for trace in traces])
        self.assertEqual(len(repeated_taints), len(taints))
        for first, second in zip(taints, repeated_taints):
            np.testing.assert_array_equal(first, second)

        data_seed = 1000 + self.current_seed * 10
        record["data_seed"] = data_seed
        generator = factory.get_data_generator(data_seed)
        boosted = generator.generate_boosted(inputs, taints, inputs_per_class=3)
        self.assertEqual(len(boosted), 6)
        record["boosts"] = []
        for index, input_ in enumerate(boosted):
            parent = index % 2  # Production ordering: A,B,A',B',A'',B''.
            identity = f"boosted-{index}-parent-{parent}"
            record["active_input"] = identity
            input_.save(str(directory / f"{identity}.bin"))
            mask = taints[parent].linear_view(0)
            np.testing.assert_array_equal(input_.linear_view(0)[mask],
                                          inputs[parent].linear_view(0)[mask])
            if index >= 2:
                self.assertTrue(np.any(input_.linear_view(0)[~mask]
                                       != inputs[parent].linear_view(0)[~mask]))
            actual = model.trace_test_case([input_], nesting=1)[0]
            record["boosts"].append({"input": identity, "parent": parent,
                                     "sha256": sha256(input_.tobytes()).hexdigest(),
                                     "trace": actual.get_typed(),
                                     "matches": actual.get_typed() == traces[parent].get_typed()})
            self.assertEqual(actual.get_typed(), traces[parent].get_typed(), identity)
            self.check_execution(model, actual, input_, parent)
        self.assertEqual([input_.tobytes() for input_ in inputs], originals)
        record.pop("active_input")
        record.update(original_inputs=len(inputs),
                      additional_boosted_inputs=len(boosted)-len(inputs),
                      expanded_input_instances=len(boosted),
                      successful_model_executions=len(traces)+len(repeated)+len(record["boosts"]),
                      independent_ctraces=len(traces)+len(repeated)+len(record["boosts"]))

    def test_eight_seed_software_campaign(self) -> None:
        # pylint: disable=too-many-locals
        records: List[Dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="rvzr-arm64-generated-") as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            campaign.mkdir()
            with software_environment(root):
                try:
                    isa = self.configure_pool()
                    for seed in _SEEDS:
                        self.current_seed = seed
                        record: Dict[str, Any] = {"seed": seed, "status": "generating",
                                                  "assembly_runs": 0}
                        records.append(record)
                        directory = campaign / f"seed-{seed}"
                        directory.mkdir()
                        case, payload = self.generate(seed, directory / "primary", isa)
                        record["assembly_runs"] += 1
                        record["generated"] = self.validate_stream(case, payload)
                        record["instruction_counts"] = dict(Counter(
                            entry["name"] for entry in record["generated"]))
                        record["machine_code_sha256"] = sha256(payload).hexdigest()
                        duplicate, duplicate_payload = self.generate(seed, directory / "repeat",
                                                                     isa)
                        record["assembly_runs"] += 1
                        self.assertEqual(duplicate_payload, payload)
                        self.assertEqual(self.validate_stream(duplicate, duplicate_payload),
                                         record["generated"])
                        record["status"] = "executing"
                        self.exercise_case(case, directory, record)
                        record["status"] = "complete"
                    distinct = len({row["machine_code_sha256"] for row in records})
                    self.assertEqual(distinct, len(_SEEDS))
                    frequencies: Counter[str] = Counter()
                    for row in records:
                        frequencies.update(row["instruction_counts"])
                    self.assertEqual(set(frequencies), set(_FORMS))
                    self.assertEqual(sum(frequencies.values()), len(_SEEDS)*16)
                except (Exception, SystemExit) as error:
                    failure_report = {"seed": self.current_seed, "error": repr(error),
                                      "records": records}
                    (campaign / "report.json").write_text(
                        json.dumps(failure_report, indent=2) + "\n", encoding="utf-8")
                    failure = Path(tempfile.mkdtemp(prefix="rvzr-arm64-campaign-failure-"))
                    shutil.copytree(campaign, failure / "campaign")
                    raise AssertionError(f"Seed {self.current_seed} failed; artifacts: "
                                         f"{failure / 'campaign'}; {error!r}") from error
                summary = {"seeds": len(records), "distinct_machine_code_streams": distinct,
                           "unicorn_version": version("unicorn"), "records": records,
                           "instruction_counts": dict(frequencies),
                           "configuration": {"execution": "cond", "observation": "ct",
                                             "nesting": 1, "window": 32, "layout": "legacy-4k",
                                             "random_forms": ["mov-reg64-reg64",
                                                              "add-reg64-reg64-reg64"],
                                             "registers": sorted(_REGISTERS),
                                             "data_entropy_bits": 8,
                                             "special_value_probability": 0.0,
                                             "inputs_per_class": 3}}
                for field in ("assembly_runs", "original_inputs", "additional_boosted_inputs",
                              "expanded_input_instances", "successful_model_executions",
                              "independent_ctraces"):
                    summary[field] = sum(row[field] for row in records)
                (campaign / "report.json").write_text(json.dumps(summary, indent=2) + "\n",
                                                      encoding="utf-8")
                output = os.environ.get("RVZR_ARM64_CAMPAIGN_OUTPUT")
                if output:
                    if not Path(output).is_absolute():
                        raise ValueError("RVZR_ARM64_CAMPAIGN_OUTPUT must be absolute")
                    shutil.copytree(campaign, output)  # Refuse to overwrite an existing directory.
                print("ARM64 software campaign: " + json.dumps({
                    key: value for key, value in summary.items() if key != "records"
                }, sort_keys=True))
