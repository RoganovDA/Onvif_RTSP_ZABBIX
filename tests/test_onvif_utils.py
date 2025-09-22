import onvif_utils


def test_find_working_credentials_reuses_blank_password(monkeypatch):
    ip = "192.0.2.10"
    baseline_data = {"password": "", "port": 8000}
    progress_data = {"tried_passwords": [], "next_allowed": None}

    monkeypatch.setattr(onvif_utils, "load_baseline", lambda _: baseline_data)
    monkeypatch.setattr(onvif_utils, "load_progress", lambda _: progress_data)

    save_calls = []
    monkeypatch.setattr(onvif_utils, "save_progress", lambda *_args, **_kwargs: save_calls.append(True))

    remove_called = []
    monkeypatch.setattr(onvif_utils, "remove_baseline", lambda *_args: remove_called.append(True))

    report = {"final_verdict": "AUTH_OK"}
    monkeypatch.setattr(onvif_utils, "try_onvif_connection", lambda *args, **kwargs: report)

    def unexpected(*_args, **_kwargs):  # pragma: no cover - defensive guard
        raise AssertionError("find_onvif_port should not be called when baseline works")


    monkeypatch.setattr(onvif_utils, "find_onvif_port", unexpected)

    port, password, result = onvif_utils.find_working_credentials(ip, ports=[8000])

    assert port == 8000
    assert password == ""
    assert result is report
    assert progress_data["tried_passwords"] == [""]
    assert remove_called == []
    assert save_calls  # progress was recorded
