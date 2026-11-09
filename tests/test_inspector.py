import os
import pickle

import pytest

from pickle_sentry.inspector import inspect_pickle_bytes, inspect_file

CANARY = "/tmp/pickle_sentry_canary_must_not_exist"


class _Evil:
    """Classic pickle payload: would run a shell command IF ever unpickled.

    pickle.dumps() on this object does NOT execute it — execution only happens
    on load. The inspector must flag it via disassembly alone, and the canary
    file must never appear.
    """
    def __reduce__(self):
        return (os.system, (f"touch {CANARY}",))


@pytest.fixture(autouse=True)
def clean_canary():
    if os.path.exists(CANARY):
        os.remove(CANARY)
    yield
    assert not os.path.exists(CANARY), "inspector EXECUTED the pickle — catastrophic failure"


def test_malicious_pickle_flagged_critical_without_execution():
    payload = pickle.dumps(_Evil())
    findings = inspect_pickle_bytes(payload, "evil.pkl")
    assert findings[0].rule_id == "PICKLE-DANGEROUS-REDUCE"
    assert findings[0].severity == "critical"
    # pickle normalises os.system to posix.system on Linux
    assert "system" in findings[0].evidence


def test_benign_pickle_is_medium_presence_only():
    payload = pickle.dumps({"a": [1, 2, 3], "b": "hello"})
    findings = inspect_pickle_bytes(payload, "data.pkl")
    assert len(findings) == 1
    assert findings[0].rule_id == "PICKLE-FILE-PRESENT"
    assert findings[0].severity == "medium"


def test_inspect_file_roundtrip(tmp_path):
    p = tmp_path / "evil.pkl"
    p.write_bytes(pickle.dumps(_Evil()))
    findings = inspect_file(str(p))
    assert findings[0].severity == "critical"


def test_eval_payload_flagged():
    class Eval:
        def __reduce__(self):
            return (eval, ("1+1",))
    findings = inspect_pickle_bytes(pickle.dumps(Eval()), "e.pkl")
    assert any(f.severity == "critical" for f in findings)
