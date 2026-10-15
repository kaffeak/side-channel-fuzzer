"""Synthetic descriptor tests: no kernel, executor, host page size or sysfs ABI.

Fixtures pin the draft schema independently of the production geometry formulas.
The candidate code stride is provisional and never establishes execution support.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-many-public-methods

from dataclasses import FrozenInstanceError
import json
from typing import Any, Dict, List, Optional, Tuple
import unittest
from unittest.mock import patch

from rvzr.sandbox_descriptor import (
    DescriptorParseError, ExecutionEligibilityError, ProfileConsistencyError,
    SandboxDescriptor, parse_descriptor, validate_execution_eligibility,
    validate_profile_consistency,
)


def _fixture(candidate: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "descriptor_version": 1, "input_format_version": 1,
        "architecture": "arm64", "payload_byte_order": "little",
        "layout_profile": "legacy-4k-v1", "kernel_page_size": 4096,
        "executor_instance": "0123456789abcdef0123456789abcdef", "generation": 7,
        "ready": True, "execution_enabled": True, "actor_count": 2,
        "bases": {"data": "0x0000000000109000", "code": "0x0000000000200000",
                  "entry": "0x0000000000200000", "utility": "0x0000000000100000"},
        "utility_span": 36864,
        "data": {
            "actor_stride": 16384, "macro_stack": [0, 64], "underflow_pad": [64, 4096],
            "main": [4096, 8192], "faulty": [8192, 12288],
            "register_init": [12288, 12608], "overflow_pad": [12608, 16384],
            "local_stack_offset": 8184,
            "permission_mappings": {"main": [4096, 8192], "faulty": [8192, 12288],
                                    "register_init": [12288, 16384]},
        },
        "code": {"actor_stride": 12288, "section": [0, 8192], "macros": [8192, 12288],
                 "permission_mapping": [0, 12288]},
    }
    if candidate:
        result.update({"layout_profile": "arm64-16k-candidate-v1", "kernel_page_size": 16384,
                       "execution_enabled": False, "utility_span": 49152})
        result["bases"]["data"] = "0x000000000010c000"
        result["data"] = {
            "actor_stride": 49152, "macro_stack": [8192, 8256],
            "underflow_pad": [8256, 12288], "main": [12288, 16384],
            "faulty": [16384, 20480], "register_init": [32768, 33088],
            "overflow_pad": [33088, 36864], "local_stack_offset": 16376,
            "permission_mappings": {"main": [0, 16384], "faulty": [16384, 32768],
                                    "register_init": [32768, 49152]},
        }
        result["code"] = {"actor_stride": 16384, "section": [0, 8192],
                          "macros": [8192, 12288], "permission_mapping": [0, 16384]}
    return result


def _document(value: Dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"))


def _parse(value: Optional[Dict[str, Any]] = None) -> SandboxDescriptor:
    return parse_descriptor(_document(_fixture() if value is None else value))


def _set(value: Dict[str, Any], path: str, replacement: object) -> None:
    keys = path.split(".")
    for key in keys[:-1]:
        value = value[key]
    value[keys[-1]] = replacement


def _eligible(descriptor: SandboxDescriptor, **expectations: Any) -> None:
    arguments: Dict[str, Any] = {
        "expected_architecture": "arm64", "expected_payload_byte_order": "little",
        "expected_actor_count": 2}
    arguments.update(expectations)
    validate_execution_eligibility(descriptor, **arguments)


class SandboxDescriptorTest(unittest.TestCase):

    def test_legacy_parsing_consistency_and_eligibility_are_separate(self) -> None:
        descriptor = _parse()
        self.assertEqual(descriptor.data.main, (4096, 8192))
        self.assertEqual(descriptor.data.actor_stride, 16384)
        self.assertEqual(descriptor.code.actor_stride, 12288)
        self.assertIsNotNone(descriptor.bases)
        if descriptor.bases is not None:
            self.assertEqual(descriptor.bases.data, 0x109000)
        validate_profile_consistency(descriptor)
        _eligible(descriptor)
        self.assertEqual(parse_descriptor(_document(_fixture()).encode("utf-8")), descriptor)

    def test_records_and_nested_ranges_are_immutable(self) -> None:
        descriptor = _parse()
        with self.assertRaises(FrozenInstanceError):
            setattr(descriptor, "generation", 8)
        with self.assertRaises(FrozenInstanceError):
            setattr(descriptor.data, "main", (0, 4096))
        self.assertIsInstance(descriptor.data.main, tuple)

    def test_candidate_is_consistent_but_never_eligible(self) -> None:
        for enabled in (False, True):
            value = _fixture(candidate=True)
            value["execution_enabled"] = enabled
            with self.subTest(execution_enabled=enabled):
                descriptor = _parse(value)
                validate_profile_consistency(descriptor)
                with self.assertRaises(ExecutionEligibilityError):
                    _eligible(descriptor)

    def test_legacy_on_16k_is_not_relabelled(self) -> None:
        value = _fixture()
        value["kernel_page_size"] = 16384
        value["execution_enabled"] = False
        descriptor = _parse(value)
        self.assertEqual(descriptor.layout_profile, "legacy-4k-v1")
        self.assertEqual(descriptor.data.main, (4096, 8192))
        with self.assertRaises(ProfileConsistencyError):
            validate_profile_consistency(descriptor)
        with self.assertRaises(ExecutionEligibilityError):
            _eligible(descriptor)

    def test_malformed_json_and_nonobject_roots(self) -> None:
        for text in ("", "{", "{}", "[]", "null", "true", "1", "{} trailing", '{"a":1,}'):
            with self.subTest(text=text):
                with self.assertRaises(DescriptorParseError):
                    parse_descriptor(text)

    def test_duplicate_fields_at_root_and_nested_levels(self) -> None:
        text = _document(_fixture())
        for duplicated in ('{"generation":8,' + text[1:],
                           text.replace('"permission_mappings":{',
                                        '"permission_mappings":{"main":[0,4096],')):
            with self.subTest(document=duplicated):
                with self.assertRaises(DescriptorParseError):
                    parse_descriptor(duplicated)

    def test_unknown_and_missing_fields_at_every_object_level(self) -> None:
        for path in ("", "data", "code", "bases", "data.permission_mappings"):
            for missing in (False, True):
                value = _fixture()
                record = value
                for key in path.split(".") if path else ():
                    record = record[key]
                if missing:
                    del record[next(iter(record))]
                else:
                    record["unknown"] = 0
                with self.subTest(path=path, missing=missing):
                    with self.assertRaises(DescriptorParseError):
                        _parse(value)

    def test_unsupported_descriptor_versions(self) -> None:
        for version in (0, 2, (1 << 64) - 1):
            value = _fixture()
            value["descriptor_version"] = version
            with self.subTest(version=version):
                with self.assertRaises(DescriptorParseError):
                    _parse(value)

    def test_input_version_and_unknown_profiles_are_semantic_errors(self) -> None:
        for path, replacement in (("input_format_version", 2), ("layout_profile", "future-v1"),
                                  ("architecture", "unknown"), ("kernel_page_size", 65536)):
            value = _fixture()
            _set(value, path, replacement)
            descriptor = _parse(value)
            with self.subTest(path=path):
                with self.assertRaises(ProfileConsistencyError):
                    validate_profile_consistency(descriptor)

    def test_integer_fields_reject_wrong_types_and_out_of_range_numbers(self) -> None:
        fields = ("descriptor_version", "input_format_version", "kernel_page_size", "generation",
                  "actor_count", "utility_span", "data.actor_stride", "data.local_stack_offset",
                  "code.actor_stride")
        invalid: Tuple[object, ...] = (True, False, "1", None, [], {}, 1.0, -1, 1 << 64,
                                       float("nan"), float("inf"), -float("inf"))
        for path in fields:
            for replacement in invalid:
                value = _fixture()
                _set(value, path, replacement)
                with self.subTest(path=path, value=replacement):
                    with self.assertRaises(DescriptorParseError):
                        _parse(value)

    def test_negative_zero_exponents_and_huge_integer_tokens_are_rejected(self) -> None:
        text = _document(_fixture())
        for token in ("-0", "7e0", "7.0", "9" * 1000):
            with self.subTest(token=token[:20]):
                with self.assertRaises(DescriptorParseError):
                    parse_descriptor(text.replace('"generation":7', '"generation":' + token))

    def test_maximum_generation_is_representable_without_wrapping(self) -> None:
        value = _fixture()
        value["generation"] = (1 << 64) - 1
        descriptor = _parse(value)
        _eligible(descriptor)
        self.assertEqual(descriptor.generation, (1 << 64) - 1)

    def test_boolean_fields_require_booleans(self) -> None:
        invalid: Tuple[object, ...] = (0, 1, "true", None, [], {})
        for field in ("ready", "execution_enabled"):
            for replacement in invalid:
                value = _fixture()
                value[field] = replacement
                with self.subTest(field=field, value=replacement):
                    with self.assertRaises(DescriptorParseError):
                        _parse(value)

    def test_string_fields_and_identity_syntax(self) -> None:
        invalid: Tuple[object, ...] = ("", None, 1, True, [], "\ud800")
        for path in ("architecture", "layout_profile", "payload_byte_order", "executor_instance"):
            for replacement in invalid:
                value = _fixture()
                value[path] = replacement
                with self.subTest(path=path, value=replacement):
                    with self.assertRaises(DescriptorParseError):
                        _parse(value)
        for path, replacement in (("payload_byte_order", "native"),
                                  ("executor_instance", "a" * 31),
                                  ("executor_instance", "A" * 32),
                                  ("executor_instance", "g" * 32)):
            value = _fixture()
            value[path] = replacement
            with self.subTest(path=path, value=replacement):
                with self.assertRaises(DescriptorParseError):
                    _parse(value)

    def test_address_syntax_is_strict_for_all_bases(self) -> None:
        for name in ("data", "code", "entry", "utility"):
            for address in (None, 0, True, "0x1", "0000000000109000", "0X0000000000109000",
                            "0x0000000000109ABC", "0x00000000001090000", "0x000000000010900g"):
                value = _fixture()
                value["bases"][name] = address
                with self.subTest(name=name, address=address):
                    with self.assertRaises(DescriptorParseError):
                        _parse(value)

    def test_range_shapes_endpoints_and_integer_types(self) -> None:
        paths = ("data.main", "data.permission_mappings.faulty", "code.permission_mapping")
        invalid: Tuple[object, ...] = (
            None, {}, "0:4096", [], [0], [0, 1, 2], [1, 1], [5, 4],
            [-1, 1], [0, 1 << 64], [False, 4096], [0, 1.0])
        for path in paths:
            for replacement in invalid:
                # Mapping nullability is tested separately; logical ranges are mandatory.
                if replacement is None and path != "data.main":
                    continue
                value = _fixture()
                _set(value, path, replacement)
                with self.subTest(path=path, value=replacement):
                    with self.assertRaises(DescriptorParseError):
                        _parse(value)

    def test_utf8_byte_limit_includes_whitespace_and_multibyte_characters(self) -> None:
        text = _document(_fixture())
        exact = text + " " * (4096 - len(text.encode("utf-8")))
        self.assertEqual(parse_descriptor(exact), _parse())
        for oversized in (exact + " ", (exact + " ").encode("utf-8")):
            with self.assertRaises(DescriptorParseError):
                parse_descriptor(oversized)
        value = _fixture()
        value["layout_profile"] = "é" * 1800
        multibyte = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        self.assertLess(len(multibyte), 4096)
        self.assertGreater(len(multibyte.encode("utf-8")), 4096)
        with self.assertRaises(DescriptorParseError):
            parse_descriptor(multibyte)

    def test_invalid_utf8_input_types_and_excessive_nesting(self) -> None:
        invalid: Tuple[object, ...] = (
            b"\xff", "\ud800", None, {}, 7, "[" * 1500 + "0" + "]" * 1500)
        for document in invalid:
            with self.subTest(document_type=type(document)):
                with self.assertRaises(DescriptorParseError):
                    parse_descriptor(document)  # type: ignore[arg-type]

    def test_every_logical_region_must_match_profile(self) -> None:
        for candidate in (False, True):
            for name in ("macro_stack", "underflow_pad", "main", "faulty", "register_init",
                         "overflow_pad"):
                value = _fixture(candidate)
                value["data"][name] = [endpoint + 8 for endpoint in value["data"][name]]
                with self.subTest(candidate=candidate, region=name):
                    with self.assertRaises(ProfileConsistencyError):
                        validate_profile_consistency(_parse(value))

    def test_overlapping_or_unaligned_permission_mappings_are_rejected(self) -> None:
        for path, replacement in (
            ("data.permission_mappings.main", [8192, 12288]),
            ("data.permission_mappings.faulty", [4096, 12288]),
            ("data.permission_mappings.register_init", [8192, 16384]),
            ("data.permission_mappings.faulty", [8192, 12289]),
            ("code.permission_mapping", [0, 12289]),
            ("code.permission_mapping", [0, 16384]),
        ):
            value = _fixture()
            _set(value, path, replacement)
            with self.subTest(path=path, range=replacement):
                with self.assertRaises(ProfileConsistencyError):
                    validate_profile_consistency(_parse(value))

    def test_code_capacities_and_strides_are_profile_specific(self) -> None:
        for candidate in (False, True):
            for path, replacement in (("code.actor_stride", 12289),
                                      ("code.actor_stride", 32768),
                                      ("code.section", [0, 16384]),
                                      ("code.macros", [4096, 12288]),
                                      ("data.actor_stride", 65536),
                                      ("data.local_stack_offset", 4096)):
                value = _fixture(candidate)
                _set(value, path, replacement)
                with self.subTest(candidate=candidate, path=path, value=replacement):
                    with self.assertRaises(ProfileConsistencyError):
                        validate_profile_consistency(_parse(value))
        value = _fixture(True)
        value["code"]["actor_stride"] = 12288
        with self.assertRaises(ProfileConsistencyError):
            validate_profile_consistency(_parse(value))

    def test_null_mappings_are_only_allowed_in_disabled_unready_snapshots(self) -> None:
        value = _fixture()
        value.update(ready=False, actor_count=0, bases=None, execution_enabled=False, generation=0)
        value["data"]["permission_mappings"] = None
        value["code"]["permission_mapping"] = None
        descriptor = _parse(value)
        validate_profile_consistency(descriptor)
        with self.assertRaises(ExecutionEligibilityError):
            _eligible(descriptor)
        value["execution_enabled"] = True
        with self.assertRaises(ProfileConsistencyError):
            validate_profile_consistency(_parse(value))

    def test_ready_snapshots_require_bases_actors_generation_and_mappings(self) -> None:
        for path, replacement in (("bases", None), ("actor_count", 0), ("generation", 0),
                                  ("data.permission_mappings", None),
                                  ("code.permission_mapping", None)):
            value = _fixture()
            _set(value, path, replacement)
            with self.subTest(path=path):
                with self.assertRaises(ExecutionEligibilityError):
                    _eligible(_parse(value))

    def test_unready_snapshots_must_hide_bases_and_active_actor_count(self) -> None:
        for hide_bases, clear_actors in ((False, True), (True, False), (False, False)):
            value = _fixture()
            value["ready"] = False
            if hide_bases:
                value["bases"] = None
            if clear_actors:
                value["actor_count"] = 0
            with self.subTest(hide_bases=hide_bases, clear_actors=clear_actors):
                with self.assertRaises(ProfileConsistencyError):
                    validate_profile_consistency(_parse(value))

    def test_address_alignment_utility_relationship_and_overlap(self) -> None:
        for path, replacement in (("bases.data", "0x0000000000109001"),
                                  ("bases.code", "0x0000000000200001"),
                                  ("bases.utility", "0x0000000000100001"),
                                  ("bases.utility", "0x0000000000000000"),
                                  ("bases.entry", "0x0000000000200004"),
                                  ("utility_span", 0), ("utility_span", 36865),
                                  ("utility_span", 40960)):
            value = _fixture()
            _set(value, path, replacement)
            with self.subTest(path=path, value=replacement):
                with self.assertRaises(ProfileConsistencyError):
                    validate_profile_consistency(_parse(value))
        value = _fixture()
        value["bases"].update(code=value["bases"]["data"], entry=value["bases"]["data"])
        with self.assertRaises(ProfileConsistencyError):
            validate_profile_consistency(_parse(value))

    def test_allocation_multiplication_and_address_addition_overflow(self) -> None:
        for area in ("actor_count", "utility", "data", "code"):
            value = _fixture()
            if area == "actor_count":
                value["actor_count"] = (1 << 64) - 1
            elif area == "utility":
                value["utility_span"] = (1 << 64) - 4096
            elif area == "data":
                value["bases"]["data"] = "0xffffffffffffd000"
                value["bases"]["utility"] = f"0x{0xffffffffffffd000 - 36864:016x}"
            else:
                value["bases"].update(code="0xfffffffffffff000", entry="0xfffffffffffff000")
            with self.subTest(area=area):
                with self.assertRaises(ProfileConsistencyError):
                    validate_profile_consistency(_parse(value))

    def test_legacy_main_8k_alignment_is_an_execution_requirement(self) -> None:
        value = _fixture()
        value["bases"].update(data="0x000000000010a000", utility="0x0000000000101000")
        descriptor = _parse(value)
        validate_profile_consistency(descriptor)
        with self.assertRaisesRegex(ExecutionEligibilityError, "8 KB"):
            _eligible(descriptor)

    def test_disabled_execution_is_distinct_from_profile_consistency(self) -> None:
        value = _fixture()
        value["execution_enabled"] = False
        descriptor = _parse(value)
        validate_profile_consistency(descriptor)
        with self.assertRaises(ExecutionEligibilityError):
            _eligible(descriptor)

    def test_expected_architecture_byte_order_and_actor_count(self) -> None:
        descriptor = _parse()
        expectations: List[Dict[str, Any]] = [
            {"expected_architecture": "x86-64"}, {"expected_payload_byte_order": "big"},
            {"expected_payload_byte_order": "native"}]
        expectations.extend({"expected_actor_count": count}
                            for count in (0, -1, True, "2", 1, 3, 1 << 64))
        for expectation in expectations:
            with self.subTest(expectation=expectation):
                with self.assertRaises(ExecutionEligibilityError):
                    _eligible(descriptor, **expectation)
        value = _fixture()
        value["architecture"] = "x86-64"
        descriptor = _parse(value)
        validate_profile_consistency(descriptor)
        with self.assertRaises(ExecutionEligibilityError):
            _eligible(descriptor, expected_architecture="x86-64")

    def test_matching_earlier_preparation_is_accepted(self) -> None:
        _eligible(_parse(), earlier_preparation=_parse())

    def test_instance_and_generation_changes_invalidate_earlier_preparation(self) -> None:
        earlier = _parse()
        for path, replacement in (("executor_instance", "a" * 32), ("generation", 8)):
            value = _fixture()
            value[path] = replacement
            with self.subTest(path=path):
                with self.assertRaises(ExecutionEligibilityError):
                    _eligible(_parse(value), earlier_preparation=earlier)

    def test_same_identity_with_changed_addresses_is_rejected(self) -> None:
        value = _fixture()
        value["bases"].update(data="0x000000000010b000", utility="0x0000000000102000")
        descriptor = _parse(value)
        _eligible(descriptor)
        with self.assertRaisesRegex(ExecutionEligibilityError, "without a generation change"):
            _eligible(descriptor, earlier_preparation=_parse())

    def test_validation_has_no_io_or_host_page_size_dependency(self) -> None:
        text = _document(_fixture())
        with patch("os.sysconf", side_effect=AssertionError("host page size queried")), \
                patch("builtins.open", side_effect=AssertionError("file access attempted")):
            descriptor = parse_descriptor(text)
            validate_profile_consistency(descriptor)
            _eligible(descriptor, earlier_preparation=descriptor)


if __name__ == "__main__":
    unittest.main()
