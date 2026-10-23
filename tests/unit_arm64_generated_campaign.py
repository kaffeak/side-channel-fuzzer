"""Eight fixed seeds through real ARM64 RANDOM expansion, Unicorn and boosting.

Only CPU identification and tool lookup use B3.4a's host adapter. Generation,
GNU assembly/ELF parsing, execution, taints and boosting are production code.
Failure artifacts persist under /tmp; optional successful artifacts can be
written to a new RVZR_ARM64_CAMPAIGN_OUTPUT directory. No H-traces are produced.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

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

    def configure_pool(self) -> InstructionSet:
        CONF.contract_execution_clause = ["cond"]
        CONF.model_max_spec_window = 32
        CONF.data_generator_entropy_bits = 8
        CONF.input_gen_probability_of_special_value = 0.0
        CONF.register_allowlist = []
        CONF.register_blocklist += ["x0", "x4", "w0", "w4"]
        isa = InstructionSet(str(_ARM / "min_arm64.json"))
        # Keep the complete parser vocabulary; restrict only the public random pool
        # to the existing, unmodified MOV REG64,REG64 specification.
        pool = [spec for spec in isa.non_memory_access_specs if spec.name == "mov"
                and len(spec.operands) == 2
                and all(op.type == OT.REG and op.width == 64 for op in spec.operands)]
        self.assertEqual(len(pool), 1)
        self.assertEqual(pool[0].implicit_operands, [])
        for operand in pool[0].operands:
            self.assertEqual(set(operand.values), _REGISTERS)
        isa.non_memory_access_specs = pool
        self.assertNotIn("mov", CONF.get_actors_conf()["main"]["instruction_blocklist"])
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
            self.assertEqual(instruction.name, "mov")
            self.assertFalse(instruction.is_from_template)
            self.assertFalse(instruction.is_instrumentation)
            self.assertFalse(instruction.is_control_flow)
            self.assertEqual(instruction.implicit_operands, [])
            self.assertEqual(len(instruction.operands), 2)
            for index, operand in enumerate(instruction.operands):
                self.assertIsInstance(operand, RegisterOp)
                assert isinstance(operand, RegisterOp)
                self.assertEqual(operand.width, 64)
                self.assertIn(operand.value, _REGISTERS)
                self.assertEqual((operand.src, operand.dest), (index == 1, index == 0))
            generated.append({"offset": offset, "name": instruction.name,
                              "operands": [op.value for op in instruction.operands], "width": 64})
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
                    self.assertGreater(distinct, 1)
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
                           "configuration": {"execution": "cond", "observation": "ct",
                                             "nesting": 1, "window": 32, "layout": "legacy-4k",
                                             "random_form": "mov-reg64-reg64",
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
