"""GHSA-g38g-8gr9-h9xp class: innocuous-looking stdlib globals that execute
commands when *invoked*.

Precision contract (the entire point of the rule):
- a payload that invokes one of these globals via REDUCE is flagged
  PICKLE-INVOKED-DANGEROUS-GLOBAL at critical;
- a payload that merely *references* one (GLOBAL / STACK_GLOBAL, no call)
  is NOT flagged high or above.

Payloads are hand-built protocol-0 / protocol-4 byte strings, never
unpickled, so no target global is ever imported or executed here.
"""
import os

import pytest

from pickle_sentry.inspector import inspect_pickle_bytes

CANARY = "/tmp/pickle_sentry_ghsa_canary_must_not_exist"

# (module, name) exactly as a pickle stream would name the global.
TARGETS = [
    ("uuid", "_get_command_stdout"),
    ("_osx_support", "_read_output"),
    ("_osx_support", "_find_build_tool"),
    ("_aix_support", "_read_cmd_output"),
    ("_pyrepl.pager", "pipe_pager"),
    ("_pyrepl.pager", "tempfile_pager"),
    ("imaplib", "IMAP4_stream"),
    ("test.support.script_helper", "assert_python_ok"),
]


@pytest.fixture(autouse=True)
def clean_canary():
    if os.path.exists(CANARY):
        os.remove(CANARY)
    yield
    assert not os.path.exists(CANARY), "inspector EXECUTED the pickle — catastrophic failure"


def _invoking_payload(module: str, name: str, arg: str = "id") -> bytes:
    # protocol 0: GLOBAL, MARK, arg string, TUPLE, REDUCE, STOP
    return (f"c{module}\n{name}\n".encode("utf-8")
            + b"(V" + arg.encode("utf-8") + b"\ntR.")


def _referencing_payload(module: str, name: str) -> bytes:
    # protocol 0: GLOBAL, STOP — the global is named but never called
    return f"c{module}\n{name}\n.".encode("utf-8")


def _stack_global_invoking_payload(module: str, name: str, arg: str = "id") -> bytes:
    # protocol 4: two unicode strings, STACK_GLOBAL, arg, TUPLE1, REDUCE, STOP
    def u(s: str) -> bytes:
        b = s.encode("utf-8")
        return b"\x8c" + bytes([len(b)]) + b
    return b"\x80\x04" + u(module) + u(name) + b"\x93" + u(arg) + b"\x85R."


@pytest.mark.parametrize("module,name", TARGETS)
def test_invoked_target_global_is_critical(module, name):
    findings = inspect_pickle_bytes(_invoking_payload(module, name), "ghsa.pkl")
    hits = [f for f in findings if f.rule_id == "PICKLE-INVOKED-DANGEROUS-GLOBAL"]
    assert hits, f"{module}.{name} invoked but not flagged: {findings}"
    assert hits[0].severity == "critical"
    assert f"{module}.{name}" in hits[0].evidence


@pytest.mark.parametrize("module,name", TARGETS)
def test_referenced_target_global_is_not_flagged_high(module, name):
    findings = inspect_pickle_bytes(_referencing_payload(module, name), "ref.pkl")
    assert all(f.severity not in ("high", "critical") for f in findings), findings
    assert not any(f.rule_id == "PICKLE-INVOKED-DANGEROUS-GLOBAL" for f in findings)


def test_invoked_target_global_via_stack_global_is_critical():
    findings = inspect_pickle_bytes(
        _stack_global_invoking_payload("uuid", "_get_command_stdout"), "sg.pkl")
    assert any(f.rule_id == "PICKLE-INVOKED-DANGEROUS-GLOBAL"
               and f.severity == "critical" for f in findings)


def test_canary_invoked_payload_flagged_but_never_executed():
    payload = _invoking_payload("uuid", "_get_command_stdout", f"touch {CANARY}")
    findings = inspect_pickle_bytes(payload, "canary.pkl")
    assert any(f.rule_id == "PICKLE-INVOKED-DANGEROUS-GLOBAL" for f in findings)
    assert not os.path.exists(CANARY)


def test_benign_uuid_invocation_still_not_flagged():
    # uuid.uuid4 is an ordinary reconstruction global under the benign uuid.
    # prefix: invoking it must stay below high (invocation precision cuts
    # both ways — only the command-execution entry point is dangerous).
    findings = inspect_pickle_bytes(_invoking_payload("uuid", "uuid4"), "u.pkl")
    assert all(f.severity not in ("high", "critical") for f in findings), findings
