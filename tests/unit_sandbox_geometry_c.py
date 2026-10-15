"""Host C/Python parity for passive actor-data geometry, not executor validation.

Run with: python -m unittest tests.unit_sandbox_geometry_c tests.unit_sandbox_geometry -v
Requires a native C11 compiler (cc by default; CC may select a compiler/flags).
No kernel headers, target processor, host-page-size query or kernel module is used.
A constants-only assembly probe also checks that the public macros remain usable
by an assembler preprocessor. Temporary probes are built outside the source tree.

The 16 KB profile remains a candidate: parity establishes placement agreement,
not allocation alignment, PTE correctness, faults, cache behavior or model parity.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from typing import Dict, List
import unittest

from rvzr.sandbox_geometry import SandboxGeometry


_INCLUDE_DIR = Path(__file__).resolve().parents[1] / "rvzr" / "executor_km" / "include"
_PROFILES = ((4096, "RVZR_SG_PAGE_SIZE_4K"), (16384, "RVZR_SG_PAGE_SIZE_16K"))

# This maps API names only; expected values come from Python, never from a second
# handwritten table of C offsets. C's own static assertions pin the exact profiles.
_SCALARS = (
    "macro_stack_size", "underflow_pad_size", "main_size", "faulty_size",
    "register_init_size", "overflow_pad_size",
)
_OFFSETS = (
    "macro_stack_offset", "underflow_pad_offset", "main_offset", "faulty_offset",
    "register_init_offset", "overflow_pad_offset", "local_stack_offset", "actor_stride",
)
_MAPPINGS = ("main_mapping", "faulty_mapping", "register_mapping")


def _c_expressions(page_macro: str) -> Dict[str, str]:
    expressions = {"kernel_page_size": page_macro}
    expressions.update((name, "RVZR_SG_" + name.upper()) for name in _SCALARS)
    expressions.update((name, f"RVZR_SG_{name.upper()}({page_macro})") for name in _OFFSETS)
    for name in _MAPPINGS:
        for endpoint in ("start", "end"):
            expressions[f"{name}_{endpoint}"] = f"RVZR_SG_{name.upper()}_{endpoint.upper()}" \
                f"({page_macro})"
    return expressions


def _python_values(page_size: int) -> Dict[str, int]:
    geometry = SandboxGeometry(page_size)
    values = {name: getattr(geometry, name) for name in ("kernel_page_size",) + _SCALARS + _OFFSETS}
    for name in _MAPPINGS:
        values[f"{name}_start"], values[f"{name}_end"] = getattr(geometry, name)
    return values


class SandboxGeometryCParityTest(unittest.TestCase):
    compiler: List[str]
    build_dir: Path
    c_values: Dict[int, Dict[str, int]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = shlex.split(os.environ.get("CC", "cc"))
        if not cls.compiler or shutil.which(cls.compiler[0]) is None:
            raise RuntimeError("C geometry validation requires a native C11 compiler; "
                               "install cc or set CC (cross compilers cannot run the probe).")
        # Class cleanup also runs if probe compilation fails during setUpClass.
        # pylint: disable-next=consider-using-with
        temporary_dir = tempfile.TemporaryDirectory(prefix="rvzr-geometry-")
        cls.addClassCleanup(temporary_dir.cleanup)
        cls.build_dir = Path(temporary_dir.name)

        source = ['#include <stdio.h>', '#include "sandbox_geometry.h"', 'int main(void) {']
        for page_size, page_macro in _PROFILES:
            for name, expression in _c_expressions(page_macro).items():
                source.append(f'    printf("{page_size} {name} %d\\n", {expression});')
        source.append('    return 0;\n}')
        executable = cls.build_dir / "geometry"
        cls._compile(["-std=c11", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
                      "-x", "c", "-", "-o", str(executable)], "\n".join(source))
        result = subprocess.run([str(executable)], check=True, capture_output=True,
                                text=True, timeout=30)
        cls.c_values = {page_size: {} for page_size, _ in _PROFILES}
        for line in result.stdout.splitlines():
            page, name, value = line.split()
            cls.c_values[int(page)][name] = int(value)

    @classmethod
    def _compile(cls, arguments: List[str], source: str) -> None:
        result = subprocess.run(cls.compiler + ["-I", str(_INCLUDE_DIR)] + arguments,
                                input=source, capture_output=True, text=True,
                                check=False, timeout=30)
        if result.returncode:
            raise AssertionError("Geometry probe compilation failed:\n"
                                 f"{result.stdout}{result.stderr}")

    def test_4k_c_constants_match_python(self) -> None:
        self.assertEqual(self.c_values[4096], _python_values(4096))

    def test_16k_c_constants_match_python(self) -> None:
        self.assertEqual(self.c_values[16384], _python_values(16384))

    def test_constants_are_usable_in_assembly(self) -> None:
        # Assemble integer expressions only: no architecture-specific instructions
        # and no executable code. C declarations/assertions must stay out of .S input.
        source = ['#include "sandbox_geometry.h"']
        for page_size, page_macro in _PROFILES:
            values = _python_values(page_size)
            for name, expression in _c_expressions(page_macro).items():
                source.extend((f".if ({expression}) != {values[name]}",
                               f'.error "{page_size} {name} differs from Python"', ".endif"))
        self._compile(["-x", "assembler-with-cpp", "-c", "-", "-o",
                       str(self.build_dir / "geometry.o")], "\n".join(source) + "\n")


if __name__ == "__main__":
    unittest.main()
