"""Passive, transport-independent sandbox descriptor draft; no kernel ABI or I/O.

Use parse_descriptor for untrusted JSON, then validate_profile_consistency and,
separately, validate_execution_eligibility. Frozen records contain integer
addresses and immutable half-open byte ranges. Data/code offsets are relative
to the corresponding actor allocation base, never the main payload address.

Input format version 1 names the unchanged Stage B1 format (12288 serialized
bytes, 8512 data bytes). It adds no version bytes to that format. The candidate
16 KB data profile follows SandboxGeometry; its 16384-byte padded code stride
is a provisional descriptor convention, not a result established by Stage A.
Candidate execution is always rejected. No host page size is consulted.

ready means allocations, mapping bookkeeping and code preparation are complete,
not that inputs are loaded or hardware compatibility is established. A module
instance gets a new executor_instance; generation identifies a prepared epoch
and must change before invalidation, even on failed preparation or address reuse.
Generation zero is reserved for initial unready state. Unready snapshots hide
bases and report zero actors; null mapping descriptions are diagnostic only.

These checks cannot prove address liveness, actual PTE permissions, ownership,
or atomicity with execution. There is no acknowledgment or synchronization here.
Construct records through the parser: direct dataclass construction is typed
Python representation, not an alternative untrusted-input parsing API.
"""

# pylint: disable=too-many-instance-attributes

from dataclasses import dataclass
import json
import re
from typing import Dict, List, Optional, Tuple, Union, cast

from . import input_format
from .sandbox_geometry import ByteRange, SandboxGeometry


MAX_DESCRIPTOR_BYTES = 4096
UINT64_MAX = (1 << 64) - 1
DESCRIPTOR_VERSION = 1
INPUT_FORMAT_VERSION = 1
LEGACY_PROFILE = "legacy-4k-v1"
CANDIDATE_PROFILE = "arm64-16k-candidate-v1"


class DescriptorError(ValueError):
    """Base error for descriptor parsing or validation."""


class DescriptorParseError(DescriptorError):
    """Malformed or unsupported descriptor schema."""


class ProfileConsistencyError(DescriptorError):
    """Descriptor disagrees with a known profile or allocation invariants."""


class ExecutionEligibilityError(DescriptorError):
    """Descriptor cannot be used for the requested preparation."""


@dataclass(frozen=True)
class SandboxBases:
    """Unsigned virtual addresses, decoded from fixed-width hexadecimal strings."""

    data: int
    code: int
    entry: int
    utility: int


@dataclass(frozen=True)
class PermissionMappings:
    """Actor-relative page coverage, not PTE values or predictions of faults."""

    main: ByteRange
    faulty: ByteRange
    register_init: ByteRange


@dataclass(frozen=True)
class ActorDataLayout:
    """Logical actor-relative regions and the complete allocated stride."""

    actor_stride: int
    macro_stack: ByteRange
    underflow_pad: ByteRange
    main: ByteRange
    faulty: ByteRange
    register_init: ByteRange
    overflow_pad: ByteRange
    local_stack_offset: int
    permission_mappings: Optional[PermissionMappings]


@dataclass(frozen=True)
class CodeLayout:
    """Actor-relative capacities and page coverage, including allocation padding."""

    actor_stride: int
    section: ByteRange
    macros: ByteRange
    permission_mapping: Optional[ByteRange]


@dataclass(frozen=True)
class SandboxDescriptor:
    """Immutable parsed snapshot; parsing alone does not make it executable."""

    descriptor_version: int
    input_format_version: int
    payload_byte_order: str
    architecture: str
    layout_profile: str
    kernel_page_size: int
    executor_instance: str
    generation: int
    ready: bool
    execution_enabled: bool
    actor_count: int
    bases: Optional[SandboxBases]
    utility_span: int
    data: ActorDataLayout
    code: CodeLayout


def _uint(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT64_MAX:
        raise DescriptorParseError(f"{path}: expected unsigned 64-bit integer")
    return value


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise DescriptorParseError(f"{path}: expected boolean")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise DescriptorParseError(f"{path}: expected nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise DescriptorParseError(f"{path}: invalid Unicode string") from error
    return value


def _record(value: object, keys: str, path: str) -> Dict[str, object]:
    if not isinstance(value, dict):
        raise DescriptorParseError(f"{path}: expected object")
    record = cast(Dict[str, object], value)
    expected = set(keys.split())
    if set(record) != expected:
        raise DescriptorParseError(f"{path}: missing fields {sorted(expected - set(record))}; "
                                   f"unknown fields {sorted(set(record) - expected)}")
    return record


def _range(value: object, path: str) -> ByteRange:
    if not isinstance(value, list) or len(value) != 2:
        raise DescriptorParseError(f"{path}: expected [start, end]")
    start, end = (_uint(value[0], path + ".start"), _uint(value[1], path + ".end"))
    if start >= end:
        raise DescriptorParseError(f"{path}: expected nonempty half-open range")
    return start, end


def _address(value: object, path: str) -> int:
    text = _string(value, path)
    if re.fullmatch(r"0x[0-9a-f]{16}", text) is None:
        raise DescriptorParseError(f"{path}: expected 0x and 16 lowercase hexadecimal digits")
    return int(text, 16)


def _unique_object(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DescriptorParseError(f"duplicate field: {key}")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    # Bound before int conversion, including on Python versions with no digit limit.
    if text.startswith("-") or len(text) > 20:
        raise DescriptorParseError("JSON integer outside unsigned 64-bit range")
    return _uint(int(text), "JSON integer")


def _reject_number(text: str) -> object:
    raise DescriptorParseError(f"floating-point/nonfinite JSON number is forbidden: {text}")


def _parse_data(value: object) -> ActorDataLayout:
    record = _record(value, "actor_stride macro_stack underflow_pad main faulty register_init "
                     "overflow_pad local_stack_offset permission_mappings", "data")
    mappings = None
    if record["permission_mappings"] is not None:
        item = _record(record["permission_mappings"], "main faulty register_init",
                       "data.permission_mappings")
        mappings = PermissionMappings(*(_range(item[name], "data.permission_mappings." + name)
                                        for name in ("main", "faulty", "register_init")))
    macro, underflow, main, faulty, registers, overflow = (
        _range(record[name], "data." + name) for name in
        ("macro_stack", "underflow_pad", "main", "faulty", "register_init", "overflow_pad"))
    return ActorDataLayout(
        _uint(record["actor_stride"], "data.actor_stride"),
        macro, underflow, main, faulty, registers, overflow,
        _uint(record["local_stack_offset"], "data.local_stack_offset"), mappings)


def parse_descriptor(document: Union[str, bytes]) -> SandboxDescriptor:
    """Strictly parse bounded UTF-8 JSON; no profile or readiness acceptance implied."""
    if not isinstance(document, (str, bytes)):
        raise DescriptorParseError("descriptor must be JSON text or UTF-8 bytes")
    try:
        if len(document) > MAX_DESCRIPTOR_BYTES:
            raise DescriptorParseError("descriptor exceeds 4096 UTF-8 bytes")
        raw = document.encode("utf-8") if isinstance(document, str) else document
        if len(raw) > MAX_DESCRIPTOR_BYTES:
            raise DescriptorParseError("descriptor exceeds 4096 UTF-8 bytes")
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                             parse_int=_json_integer, parse_float=_reject_number,
                             parse_constant=_reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise DescriptorParseError(f"invalid UTF-8 JSON descriptor: {error}") from error
    record = _record(decoded, "descriptor_version input_format_version payload_byte_order "
                     "architecture layout_profile kernel_page_size executor_instance generation "
                     "ready execution_enabled actor_count bases utility_span data code",
                     "descriptor")
    version = _uint(record["descriptor_version"], "descriptor_version")
    if version != DESCRIPTOR_VERSION:
        raise DescriptorParseError(f"unsupported descriptor version: {version}")
    byte_order = _string(record["payload_byte_order"], "payload_byte_order")
    if byte_order not in ("little", "big"):
        raise DescriptorParseError("payload_byte_order must be little or big")
    instance = _string(record["executor_instance"], "executor_instance")
    if re.fullmatch(r"[0-9a-f]{32}", instance) is None:
        raise DescriptorParseError("executor_instance must be 32 lowercase hexadecimal digits")
    bases = None
    if record["bases"] is not None:
        item = _record(record["bases"], "data code entry utility", "bases")
        bases = SandboxBases(*(_address(item[name], "bases." + name)
                               for name in ("data", "code", "entry", "utility")))
    code = _record(record["code"], "actor_stride section macros permission_mapping", "code")
    return SandboxDescriptor(
        version, _uint(record["input_format_version"], "input_format_version"), byte_order,
        _string(record["architecture"], "architecture"),
        _string(record["layout_profile"], "layout_profile"),
        _uint(record["kernel_page_size"], "kernel_page_size"), instance,
        _uint(record["generation"], "generation"), _boolean(record["ready"], "ready"),
        _boolean(record["execution_enabled"], "execution_enabled"),
        _uint(record["actor_count"], "actor_count"), bases,
        _uint(record["utility_span"], "utility_span"), _parse_data(record["data"]),
        CodeLayout(_uint(code["actor_stride"], "code.actor_stride"),
                   _range(code["section"], "code.section"), _range(code["macros"], "code.macros"),
                   None if code["permission_mapping"] is None else
                   _range(code["permission_mapping"], "code.permission_mapping")))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileConsistencyError(message)


def _add(left: int, right: int) -> int:
    _require(left <= UINT64_MAX - right, "allocation address addition overflows uint64")
    return left + right


def _multiply(left: int, right: int) -> int:
    _require(right > 0 and left <= UINT64_MAX // right, "allocation size overflows uint64")
    return left * right


def _validate_addresses(descriptor: SandboxDescriptor) -> None:
    bases = descriptor.bases
    if bases is None:
        return
    page = descriptor.kernel_page_size
    for name in ("data", "code", "utility"):
        address = getattr(bases, name)
        _require(address > 0 and address % page == 0, f"bases.{name} must be nonzero/page-aligned")
    _require(bases.entry == bases.code, "known profiles require entry at actor zero's code base")
    utility_end = _add(bases.utility, descriptor.utility_span)
    _require(utility_end == bases.data, "utility span must end at actor zero's data base")
    data_end = _add(bases.data, _multiply(descriptor.actor_count, descriptor.data.actor_stride))
    code_end = _add(bases.code, _multiply(descriptor.actor_count, descriptor.code.actor_stride))
    spans = sorted(((bases.utility, utility_end), (bases.data, data_end), (bases.code, code_end)))
    _require(all(first[1] <= second[0] for first, second in zip(spans, spans[1:])),
             "utility/data/code allocation spans overlap")


def validate_profile_consistency(descriptor: SandboxDescriptor) -> None:
    """Check a parsed snapshot against known profiles, independently of execution policy.

    Canonical unready snapshots have no bases and zero actors. They may omit
    mapping descriptions only while execution_enabled is false. The legacy
    layout on a 16 KB kernel is parseable diagnostic data, not a consistent
    supported profile, and is never relabeled as the candidate.
    """
    _require(descriptor.descriptor_version == DESCRIPTOR_VERSION, "unsupported descriptor version")
    _require(descriptor.input_format_version == INPUT_FORMAT_VERSION, "unsupported input format")
    _require(descriptor.architecture in ("arm64", "x86-64"), "unknown architecture")
    if descriptor.layout_profile == LEGACY_PROFILE:
        page, code_stride = 4096, 12288
    elif descriptor.layout_profile == CANDIDATE_PROFILE:
        page, code_stride = 16384, 16384
        _require(descriptor.architecture == "arm64", "candidate profile requires ARM64")
    else:
        raise ProfileConsistencyError("unknown layout profile")
    _require(descriptor.kernel_page_size == page, "layout profile and kernel page size disagree")
    geometry = SandboxGeometry(page)
    _require(
        (geometry.main_size, geometry.faulty_size, geometry.register_init_size,
         geometry.overflow_pad_size)
        == (input_format.MAIN_SIZE, input_format.FAULTY_SIZE, input_format.REGISTER_INIT_SIZE,
            input_format.PADDING_SIZE), "geometry disagrees with fixed input format")
    data = descriptor.data
    _require(data.actor_stride == geometry.actor_stride, "incorrect actor-data stride")
    regions = (
        ("macro_stack", geometry.macro_stack_offset, geometry.macro_stack_size),
        ("underflow_pad", geometry.underflow_pad_offset, geometry.underflow_pad_size),
        ("main", geometry.main_offset, geometry.main_size),
        ("faulty", geometry.faulty_offset, geometry.faulty_size),
        ("register_init", geometry.register_init_offset, geometry.register_init_size),
        ("overflow_pad", geometry.overflow_pad_offset, geometry.overflow_pad_size),
    )
    for name, offset, size in regions:
        region = getattr(data, name)
        _require(region == (offset, offset + size), f"incorrect data.{name} range")
        _require(region[1] <= data.actor_stride, f"data.{name} escapes actor allocation")
    _require(data.main[1] == data.faulty[0], "main/faulty payloads must be contiguous")
    _require(data.local_stack_offset == geometry.local_stack_offset, "incorrect local stack offset")
    mappings = data.permission_mappings
    if mappings is None:
        _require(not descriptor.ready and not descriptor.execution_enabled,
                 "mapping descriptions required for ready or enabled snapshots")
    else:
        for name, expected in (("main", geometry.main_mapping),
                               ("faulty", geometry.faulty_mapping),
                               ("register_init", geometry.register_mapping)):
            mapping = getattr(mappings, name)
            logical = getattr(data, name)
            _require(mapping[0] % page == 0 and mapping[1] % page == 0,
                     f"unaligned {name} permission mapping")
            _require(mapping == expected, f"incorrect {name} permission mapping")
            _require(mapping[0] <= logical[0] < logical[1] <= mapping[1] <= data.actor_stride,
                     f"{name} payload escapes permission mapping")
        _require(mappings.main[1] <= mappings.faulty[0], "main/faulty mappings overlap")
        _require(mappings.faulty[1] <= mappings.register_init[0],
                 "register initialization shares faulty mapping")
    code = descriptor.code
    _require(code.actor_stride == code_stride, "incorrect code actor stride")
    _require(code.section == (0, 8192) and code.macros == (8192, 12288),
             "incorrect logical code capacities")
    _require(code.macros[1] <= code.actor_stride, "code escapes actor allocation")
    _require(data.actor_stride % page == 0 and code.actor_stride % page == 0,
             "actor strides must be page-aligned")
    if code.permission_mapping is None:
        _require(not descriptor.ready and not descriptor.execution_enabled,
                 "code mapping required for ready or enabled snapshots")
    else:
        _require(all(endpoint % page == 0 for endpoint in code.permission_mapping),
                 "unaligned code permission mapping")
        _require(code.permission_mapping == (0, code.actor_stride), "incorrect code mapping")
    _require(descriptor.utility_span > 0 and descriptor.utility_span % page == 0,
             "utility span must be positive/page-aligned")
    if descriptor.ready:
        _require(descriptor.actor_count > 0 and descriptor.bases is not None,
                 "ready snapshot requires positive actor count and bases")
        _require(descriptor.generation > 0, "ready snapshot requires a prepared generation")
    else:
        _require(descriptor.actor_count == 0 and descriptor.bases is None,
                 "unready snapshot must hide bases and report zero actors")
    _validate_addresses(descriptor)


def validate_execution_eligibility(
    descriptor: SandboxDescriptor, *, expected_architecture: str,
    expected_payload_byte_order: str, expected_actor_count: int,
    earlier_preparation: Optional[SandboxDescriptor] = None,
) -> None:
    """Accept only legacy 4 KB ARM64; this performs no execution or kernel enforcement.

    Expectations are explicit, not inferred from the host. An earlier snapshot
    must itself be eligible and match the entire current snapshot: unchanged
    identity with changed contents is also a protocol violation.
    """
    try:
        validate_profile_consistency(descriptor)
    except ProfileConsistencyError as error:
        raise ExecutionEligibilityError(str(error)) from error
    if descriptor.layout_profile != LEGACY_PROFILE or descriptor.kernel_page_size != 4096:
        raise ExecutionEligibilityError("only the legacy 4 KB profile is execution-eligible")
    if expected_architecture != "arm64" or descriptor.architecture != expected_architecture:
        raise ExecutionEligibilityError("execution requires matching ARM64 architecture")
    if expected_payload_byte_order not in ("little", "big") or \
            descriptor.payload_byte_order != expected_payload_byte_order:
        raise ExecutionEligibilityError("payload byte order does not match expectation")
    if isinstance(expected_actor_count, bool) or not isinstance(expected_actor_count, int) or \
            not 0 < expected_actor_count <= UINT64_MAX or \
            descriptor.actor_count != expected_actor_count:
        raise ExecutionEligibilityError("expected positive actor count does not match")
    if not descriptor.ready or not descriptor.execution_enabled or descriptor.bases is None:
        raise ExecutionEligibilityError("snapshot must be ready and execution-enabled")
    if (descriptor.bases.data + descriptor.data.main[0]) % 8192 != 0:
        raise ExecutionEligibilityError("legacy main address must be 8 KB aligned")
    if earlier_preparation is not None:
        validate_execution_eligibility(
            earlier_preparation, expected_architecture=expected_architecture,
            expected_payload_byte_order=expected_payload_byte_order,
            expected_actor_count=expected_actor_count)
        if descriptor.executor_instance != earlier_preparation.executor_instance:
            raise ExecutionEligibilityError("executor instance changed")
        if descriptor.generation != earlier_preparation.generation:
            raise ExecutionEligibilityError("prepared generation changed")
        if descriptor != earlier_preparation:
            raise ExecutionEligibilityError("descriptor changed without a generation change")
