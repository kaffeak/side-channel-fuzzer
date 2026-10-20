"""Isolated ARM64 Unicorn preparation; not connected to the fuzzer or executor.

Descriptors must come through the descriptor parser before this typed API.
Validation establishes Python-side legacy-layout consistency only: it cannot
prove kernel address liveness, PTE state, allocation ownership or atomicity.
The returned model has fresh campaign coverage and no state from an older model.
Coverage preservation belongs to later orchestration integration.
"""

from .. import factory
from ..config import CONF, ConfigException
from ..sandbox_descriptor import (
    ExecutionEligibilityError, SandboxDescriptor, validate_execution_eligibility,
)
from ..tc_components.test_case_code import TestCaseProgram
from .model import ARM64UnicornModel


def prepare_unicorn_model(
    test_case: TestCaseProgram,
    allocation: SandboxDescriptor,
    *,
    expected_payload_byte_order: str,
    enable_mismatch_check_mode: bool = False,
) -> ARM64UnicornModel:
    """Build and load a fresh candidate using the current, caller-stable CONF.

    Expected byte order is caller-trusted, never inferred from the descriptor.
    The active ARM64 model uses little-endian emulation; matching big-endian
    expectations do not make that configuration supported. Inputs are initialized
    later by the usual trace methods. No tracing, publication, retry, executor I/O
    or hardware-execution authorization is performed. Construction/loading errors,
    including existing SystemExit failures, propagate without returning a model.
    """
    validate_execution_eligibility(
        allocation, expected_architecture="arm64",
        expected_payload_byte_order=expected_payload_byte_order,
        expected_actor_count=test_case.n_actors())
    if expected_payload_byte_order != "little":
        raise ExecutionEligibilityError(
            "the active ARM64 Unicorn model requires little-endian input")
    if CONF.instruction_set != "arm64" or CONF.model_backend != "unicorn":
        raise ConfigException("model preparation requires ARM64 and the Unicorn backend")
    bases = allocation.bases
    if bases is None:
        raise ExecutionEligibilityError("model preparation requires allocation bases")
    candidate = factory.get_model(
        (bases.data, bases.code), enable_mismatch_check_mode=enable_mismatch_check_mode)
    if not isinstance(candidate, ARM64UnicornModel):
        raise TypeError("model factory did not return an ARM64 Unicorn model")
    candidate.load_test_case(test_case)
    # Loading replaces the emulator. Normally this reference is refreshed at
    # input start; refresh now so the returned candidate already has one engine.
    candidate.speculator.reset()
    return candidate
