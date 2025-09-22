import datetime
import json
from types import SimpleNamespace

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import baseline
import camcheck


def test_progress_preserved_after_credentials_not_found(monkeypatch, tmp_path):
    # Redirect baseline storage to a temporary directory used for this test
    monkeypatch.setattr(baseline, "AUDIT_DIR", tmp_path)
    # Ensure camcheck helpers use the patched baseline directory
    monkeypatch.setattr(camcheck, "load_progress", baseline.load_progress)
    monkeypatch.setattr(camcheck, "save_progress", baseline.save_progress)
    monkeypatch.setattr(camcheck, "remove_progress", baseline.remove_progress)
    monkeypatch.setattr(camcheck, "load_baseline", baseline.load_baseline)
    monkeypatch.setattr(camcheck, "save_baseline", baseline.save_baseline)

    # Provide deterministic CLI arguments
    args = SimpleNamespace(
        address="192.0.2.1",
        debug=False,
        logfile=None,
        username=None,
        password=None,
        ping_timeout=1,
    )
    monkeypatch.setattr(camcheck, "parse_args", lambda: args)

    # Avoid real network and binary checks
    monkeypatch.setattr(camcheck, "is_reachable", lambda *a, **k: True)
    monkeypatch.setattr(camcheck.shutil, "which", lambda name: "/usr/bin/fake")

    # Capture JSON output
    outputs = []
    monkeypatch.setattr(camcheck, "emit_json", lambda data, **kwargs: outputs.append(data))

    # Simulate find_working_credentials recording a lockout/backoff window
    next_allowed = (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).replace(microsecond=0)
    next_allowed_iso = next_allowed.isoformat()

    def fake_find_working_credentials(*_args, **_kwargs):
        camcheck.save_progress(
            args.address,
            {"tried_passwords": ["admin"], "next_allowed": next_allowed_iso},
        )
        return None, None, None

    monkeypatch.setattr(camcheck, "find_working_credentials", fake_find_working_credentials)

    camcheck.main()

    assert outputs[-1]["status"] == "credentials_not_found"
    assert outputs[-1]["next_attempt_after"] == next_allowed_iso

    progress_path = tmp_path / f"{args.address}_progress.json"
    assert progress_path.exists()
    stored_progress = json.loads(progress_path.read_text())
    assert stored_progress["next_allowed"] == next_allowed_iso

    # Reconfigure output capture and ensure no new attempts are made before backoff expires
    outputs_second_run = []
    monkeypatch.setattr(camcheck, "emit_json", lambda data, **kwargs: outputs_second_run.append(data))

    def should_not_be_called(*_args, **_kwargs):  # pragma: no cover - safety net
        raise AssertionError("find_working_credentials should not be invoked during backoff")

    monkeypatch.setattr(camcheck, "find_working_credentials", should_not_be_called)

    camcheck.main()

    assert outputs_second_run[0]["status"] == "skipped_due_to_lockout"
    assert outputs_second_run[0]["next_attempt_after"] == next_allowed_iso
    assert progress_path.exists()
    stored_progress_second = json.loads(progress_path.read_text())
    assert stored_progress_second["next_allowed"] == next_allowed_iso
