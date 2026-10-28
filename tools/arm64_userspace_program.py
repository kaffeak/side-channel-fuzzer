"""Export a reviewed Revizor template; not a general ELF/code validator.

The approved concrete bytes establish the register, branch and memory properties
documented in README.arm64-userspace.md. Python rejects relocation entries/deviating
artifacts; C independently enforces the selected concrete encoding policy.
No public program-path or generic ELF execution interface is provided.
"""

from io import BytesIO

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from rvzr.tc_components.test_case_code import TestCaseProgram


PROGRAM_FORMAT = "rvzr-b34a-body-v1"
FAMILY_FORMAT = "rvzr-b34a-movz16-v1"
APPROVED_PROGRAM = bytes.fromhex(
    "1f0000f1 60000054 610180d2 02000014 c10280d2 "
    "820640f8 2300028b 830600f8 c0035fd6")
_NOP = bytes.fromhex("1f2003d5")
_MAX_ELF_BYTES = 65536


def validate_program(program: bytes, program_format: str = PROGRAM_FORMAT) -> None:
    """Admit 36 bytes only; family varies imm16 at offsets 8/16, nothing else.

    MOVZ X1, #imm16, LSL #0 has word 0xd2800001 | (imm16 << 5).
    sf/opc/hw/Rd remain fixed. The legacy format still requires exact identity.
    """
    if program_format not in (PROGRAM_FORMAT, FAMILY_FORMAT) or len(program) != 36:
        raise ValueError("Unsupported program format or length")
    for offset in range(0, 36, 4):
        word = int.from_bytes(program[offset:offset + 4], "little")
        reference = int.from_bytes(APPROVED_PROGRAM[offset:offset + 4], "little")
        mask = 0x001fffe0 if program_format == FAMILY_FORMAT and offset in (8, 16) else 0
        if (word & ~mask) != (reference & ~mask):
            raise ValueError("Program violates the selected concrete encoding policy")


def _approved_section(raw: bytes, program_format: str) -> tuple[int, bytes]:
    if len(raw) < 64 or len(raw) > _MAX_ELF_BYTES or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Expected a bounded little-endian ELF64 object")
    elf = ELFFile(BytesIO(raw))
    if elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_REL":
        raise ValueError("Expected an AArch64 relocatable object")
    if elf.num_segments() != 0 or not 1 <= elf.num_sections() <= 16:
        raise ValueError("Unsupported ELF structure")
    candidates = []
    for section in elf.iter_sections():
        if section["sh_type"] in ("SHT_REL", "SHT_RELA") and section["sh_size"]:
            raise ValueError("Relocations are unsupported, including unresolved symbols")
        if section["sh_flags"] & 0x800:  # SHF_COMPRESSED: never decompress input.
            raise ValueError("Compressed sections are unsupported")
        if section.name == ".data.main":
            candidates.append(section)
        elif section["sh_flags"] & 2 and section["sh_size"]:  # SHF_ALLOC
            raise ValueError("Extra allocated sections are unsupported")
    if len(candidates) != 1:
        raise ValueError("Expected exactly one .data.main section")
    section = candidates[0]
    if section["sh_type"] != "SHT_PROGBITS" or section["sh_size"] != 60:
        raise ValueError("Unsupported section type/extent")
    payload = section.data()
    if payload[:12] != _NOP * 3 or payload[44:] != _NOP * 4:
        raise ValueError("Only the reviewed B3.4a template envelope is approved")
    validate_program(payload[12:44] + APPROVED_PROGRAM[-4:], program_format)
    return section["sh_offset"], payload


def export_approved_program(test_case: TestCaseProgram,
                            program_format: str = PROGRAM_FORMAT) -> bytes:
    """Return actual ELF body bytes [12,44), plus the approved RET X30.

    Accept only an assembled one-actor B3.4a TestCaseProgram and a bounded,
    little-endian AArch64 ET_REL object with no relocations or extra allocations.
    Template envelope, metadata and measurement symbols must match; body bytes
    must satisfy the explicit format (legacy exact identity by default).
    Unsupported/malformed artifacts raise ValueError, never execute.
    """
    if not isinstance(test_case, TestCaseProgram) or test_case.n_actors() != 1:
        raise ValueError("Exactly one actor is supported")
    sections = test_case.get_sections()
    if len(sections) != 1 or sections[0].name != "main" or sections[0].owner.get_id() != 0:
        raise ValueError("Exactly the main actor section is supported")
    try:
        obj = test_case.get_obj()
        if obj.symbol_table() != [(0, 0, 0, 0), (0, 0, 1, 0), (0, 44, 0, 1), (0, 44, 2, 0)]:
            raise ValueError("Unsupported measurement/function symbols")
        with open(obj.obj_path, "rb") as file:
            raw = file.read(_MAX_ELF_BYTES + 1)
        offset, payload = _approved_section(raw, program_format)
        metadata = sections[0].get_elf_data()
        if metadata["offset"] != offset or metadata["size"] != 60:
            raise ValueError("Stale or incompatible section metadata")
        program = payload[12:44] + APPROVED_PROGRAM[-4:]
        validate_program(program, program_format)
        return program
    except (OSError, ELFError, AssertionError, IndexError, KeyError, OverflowError) as error:
        raise ValueError("Invalid or unassembled program artifact") from error
