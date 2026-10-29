"""Fail-closed verification of fixed GNU ELF / Apple otool preparation and probes.

Not an AArch64 decoder or evidence of cache state. Unknown renderings require
native preflight review; no instruction, destination or function suffix is skipped.
"""
import re


def _function(text: str, name: str) -> tuple[str, list[tuple[int, str]]]:
    """Read the entire symbol body, including any unexpected trailing instruction."""
    elf = list(re.finditer(rf"^([0-9a-fA-F]+) <{name}>:\s*$", text, re.M))
    macho = list(re.finditer(rf"^_{name}:\s*$", text, re.M))
    if len(elf) + len(macho) != 1:
        raise ValueError(f"Missing/duplicate disassembled symbol {name}")
    dialect, label = ("elf", elf[0]) if elf else ("macho", macho[0])
    boundary = (r"^[0-9a-fA-F]+ <[^>]+>:\s*$" if dialect == "elf"
                else r"^[_A-Za-z][\w.$]*:\s*$")
    following = text[label.end():]
    next_symbol = re.search(boundary, following, re.M)
    body = following[:next_symbol.start()] if next_symbol else following
    pattern = (r"\s*([0-9a-fA-F]+):\s+[0-9a-fA-F]{8}\s+([a-z][a-z0-9.]*\b.*)"
               if dialect == "elf" else
               r"\s*([0-9a-fA-F]+)\s+([a-z][a-z0-9.]*\b.*)")
    instructions = []
    for line in body.splitlines():
        if not line.strip():
            continue
        found = re.fullmatch(pattern, line)
        if found is None or re.fullmatch(
                r"(?:dsb|isb|mrs|ldr|stp|str|ret|mov|cbz|cbnz|add|cmp|b(?:\.lo|\.cc)?)"
                r"(?:\s+.*)?", found[2]) is None:
            raise ValueError(f"Unexpected instruction/rendering in {name}: {line}")
        value = re.sub(r"\s+", "", found[2].split("//")[0]).lower()
        value = value.replace("#0x10", "#16").replace("s3_3_c14_c0_2", "cntvct_el0")
        value = {"isbsy": "isb", "retx30": "ret", "movx6,#0x0": "movx6,#0"}.get(value, value)
        instructions.append((int(found[1], 16), value))
    if not instructions or any(address != instructions[0][0] + 4 * i
                               for i, (address, _) in enumerate(instructions)):
        raise ValueError(f"Non-contiguous/empty instruction sequence: {name}")
    if dialect == "elf" and int(label[1], 16) != instructions[0][0]:
        raise ValueError(f"Symbol/instruction address mismatch: {name}")
    return dialect, instructions


def _destination(operand: str, dialect: str, probe: int) -> int:
    """Resolve only reviewed absolute branch renderings; no offset guessing."""
    pattern = (r"([0-9a-f]+)(?:<[^>]+>)?" if dialect == "elf"
               else r"(?:0x)?([0-9a-f]+)")
    found = re.fullmatch(pattern, operand)
    if found:
        return int(found[1], 16)
    if dialect == "macho" and operand == "_g3_probe":
        return probe
    raise ValueError(f"Unknown {dialect} branch destination: {operand}")


def check(text: str) -> None:
    """Require complete probe bodies and the eleven-instruction preparation body."""
    functions = {name: _function(text, name) for name in ("g3_probe", "g3_empty", "g3_trial")}
    dialect = functions["g3_probe"][0]
    if any(value[0] != dialect for value in functions.values()):
        raise ValueError("Mixed ELF/Mach-O symbol renderings")
    for name, operation in (("g3_probe", "ldrx4,[x0]"), ("g3_empty", "movx4,xzr")):
        expected_probe = ["dsbish", "isb", "mrsx2,cntvct_el0", "isb", operation,
                          "dsbish", "isb", "mrsx3,cntvct_el0", "isb", "stpx2,x3,[x1]",
                          "strx4,[x1,#16]", "ret"]
        actual_probe = [value for _, value in functions[name][1]]
        if actual_probe != expected_probe:
            raise ValueError(f"Probe instruction mismatch: {name}: {actual_probe}")
    trial = functions["g3_trial"][1]
    probe = functions["g3_probe"][1][0][0]
    expected_trial = ["cbzw5,", "ldrx8,[x0]", "movx6,#0", "ldrx7,[x1,x6]",
                      "addx6,x6,x3", "cmpx6,x2", "b.lo", "cbnzw5,", "ldrx8,[x0]",
                      "movx1,x4", "b"]
    if len(trial) != len(expected_trial):
        raise ValueError("Preparation instruction count mismatch")
    destinations = {0: trial[2][0], 6: trial[3][0], 7: trial[9][0], 10: probe}
    for index, ((_, actual), expected) in enumerate(zip(trial, expected_trial)):
        if index == 6 and actual.startswith("b.cc"):
            actual = "b.lo" + actual[4:]  # GNU alias: unsigned lower / carry clear.
        if index in destinations:
            if not actual.startswith(expected) or _destination(
                    actual[len(expected):], dialect, probe) != destinations[index]:
                raise ValueError(f"Preparation branch mismatch at instruction {index}: {actual}")
        elif actual != expected:
            raise ValueError(f"Preparation instruction mismatch at {index}: {actual}")
    ranges = sorted((rows[0][0], rows[-1][0] + 4) for _, rows in functions.values())
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        raise ValueError("Overlapping function addresses")
