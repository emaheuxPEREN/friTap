#!/usr/bin/env python3
"""Unit tests for the iOS crash-report retrieval / decoding module.

``friTap.ios`` is the iOS counterpart of the Android crash plumbing in
``friTap.android`` (tombstone + ``logcat -b crash``): when an instrumented iOS
target dies (friTap discussion #65: iOS 16 on a palera1n jailbreak), the
post-mortem artifact is a ReportCrash ``.ips`` file pulled over
libimobiledevice. Since the module runs from inside a crash handler it must
never raise, never destroy on-device evidence, and must survive a missing
``idevicecrashreport``.

Device-free by construction: ``shutil.which`` / ``subprocess.run`` are
monkeypatched and fake report trees are built in ``tmp_path``, following the
style of ``test_crash_attribution.py`` / ``test_android_crash_diagnostics.py``.
No ``ios`` marker — these are host tests and must run in CI.
"""

import json
import logging
import os
import subprocess
from datetime import datetime, timezone

import pytest

from friTap import ios as ios_module
from friTap.ios import (
    CRASH_REPORT_RETRIES,
    CRASH_REPORT_RETRY_DELAY,
    IOS,
    IOSCrashReport,
    decode_terminator,
    parse_crash_report,
    parse_crash_report_text,
    parse_report_timestamp,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic report bodies, written inline so nothing depends on files
# from a real device.
# ---------------------------------------------------------------------------
# iOS 16+ ``.ips``: one JSON header line followed by a JSON payload body.
# This is the discussion-#65 shape: the gated app was never resumed, so the
# watchdog killed it (0x8badf00d == 2343432205) under FRONTBOARD.
IPS_HEADER = {
    "app_name": "MyApp",
    "timestamp": "2026-08-03 12:00:00.00 +0000",
    "app_version": "1.2.3",
    "slice_uuid": "1e4a6e4d-1111-2222-3333-444455556666",
    "build_version": "42",
    "platform": 2,
    "bundleID": "com.example.MyApp",
    "share_with_app_devs": 0,
    "is_first_party": 0,
    "bug_type": "309",
    "os_version": "iPhone OS 16.6 (20G75)",
    "incident_id": "ABCDEF01-2345-6789-ABCD-EF0123456789",
    "name": "MyApp",
}
IPS_PAYLOAD = {
    "uptime": 5300,
    "procRole": "Foreground",
    "procName": "MyApp",
    "procPath": "/private/var/containers/Bundle/Application/AAAA/MyApp.app/MyApp",
    "pid": 1234,
    "faultingThread": 0,
    "exception": {
        "codes": "0x0000000000000000, 0x0000000000000000",
        "rawCodes": [0, 0],
        "type": "EXC_CRASH",
        "signal": "SIGKILL",
    },
    "termination": {
        "code": 2343432205,
        "flags": 6,
        "namespace": "FRONTBOARD",
        "indicator": "Failed to scene-create in time",
        "reasons": [
            "<FBSTerminateContext| domain:10 code:0x8BADF00D "
            "explanation:scene-create watchdog transgression>",
        ],
    },
    "asi": {"libsystem_c.dylib": ["abort() called"]},
    "vmSummary": "ReadOnly portion of Libraries: Total=512.1M resident=0K(0%)",
    "threads": [{"id": 1, "triggered": True, "frames": []}],
}


def _ips_text(header=None, payload=None):
    """Serialize a two-part ``.ips``: header line + payload body."""
    return "{}\n{}\n".format(
        json.dumps(header if header is not None else IPS_HEADER),
        json.dumps(payload if payload is not None else IPS_PAYLOAD, indent=2),
    )


LEGACY_CRASH_TEXT = """Incident Identifier: 11112222-3333-4444-5555-666677778888
CrashReporter Key:   a1b2c3d4e5f6a7b8c9d0
Hardware Model:      iPhone12,1
Process:             MyApp [4321]
Identifier:          com.example.MyApp
Version:             1.2.3 (42)
Code Type:           ARM-64 (Native)
Role:                Foreground
Parent Process:      launchd [1]
Date/Time:           2026-08-03 12:00:00.000 +0000
Launch Time:         2026-08-03 11:59:57.000 +0000
OS Version:          iPhone OS 14.8 (18H17)
Report Version:      104

Exception Type:  EXC_BAD_ACCESS (SIGSEGV)
Exception Subtype: KERN_INVALID_ADDRESS at 0x0000000000000010
Exception Note:  EXC_CORPSE_NOTIFY
VM Region Info: 0x10 is not in any region.
Termination Reason: SIGNAL 11 Segmentation fault: 11
Triggered by Thread: 3

Application Specific Information:
frida-agent: hook installation failed
abort() called

Thread 3 name: Dispatch queue: com.apple.main-thread
Thread 3 Crashed:
0   libboringssl.dylib   0x0000000180000000 SSL_read + 40
"""

JETSAM_IPS_TEXT = _ips_text(
    header={
        "bug_type": "298",
        "timestamp": "2026-08-03 12:05:00.00 +0000",
        "os_version": "iPhone OS 16.6 (20G75)",
        "incident_id": "99998888-7777-6666-5555-444433332222",
    },
    payload={
        "cpuHighWaterMark": 0,
        "largestProcess": "MyApp",
        "memoryStatus": {"compressorSize": 12345, "pageSize": 16384},
        "processes": [
            {
                "name": "MyApp",
                "pid": 1234,
                "reason": "per-process-limit",
                "rpages": 500000,
                "states": ["frontmost"],
            },
        ],
    },
)


def _ios(device_id=None):
    """An :class:`IOS` bound to a test logger so caplog sees its messages."""
    obj = IOS(device_id=device_id)
    obj.logger = logging.getLogger("test.ios.crash")
    obj.logger.setLevel(logging.DEBUG)
    return obj


@pytest.fixture
def tools_present(monkeypatch):
    """Pretend libimobiledevice is installed."""
    monkeypatch.setattr(
        ios_module.shutil, "which", lambda name: f"/opt/homebrew/bin/{name}")


@pytest.fixture
def tools_missing(monkeypatch):
    """Pretend libimobiledevice is not installed."""
    monkeypatch.setattr(ios_module.shutil, "which", lambda name: None)


def _write_report(directory, name, text):
    path = os.path.join(str(directory), name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
class TestParseIps:
    def test_parses_ios16_two_part_ips(self):
        report = parse_crash_report_text(_ips_text(), path="/tmp/MyApp-2026-08-03-120000.ips")

        assert report.path == "/tmp/MyApp-2026-08-03-120000.ips"
        assert report.process_name == "MyApp"
        assert report.pid == 1234
        assert report.bug_type == "309"
        assert report.incident_id == "ABCDEF01-2345-6789-ABCD-EF0123456789"
        assert report.timestamp == "2026-08-03 12:00:00.00 +0000"
        assert report.os_version == "iPhone OS 16.6 (20G75)"
        assert report.exception_type == "EXC_CRASH"
        assert report.signal == "SIGKILL"
        assert report.exception_subtype == ""  # absent for EXC_CRASH
        assert report.termination_namespace == "FRONTBOARD"
        # The JSON carries the code as an int; we normalize to the hex form the
        # well-known terminators are recognised by.
        assert report.termination_code == "0x8badf00d"
        assert report.termination_indicator == "Failed to scene-create in time"
        assert len(report.termination_reasons) == 1
        assert "watchdog transgression" in report.termination_reasons[0]
        assert "FRONTBOARD" in report.termination_reason
        assert "0x8badf00d" in report.termination_reason
        assert report.triggered_thread == 0
        assert report.asi == "libsystem_c.dylib: abort() called"
        assert "ReadOnly portion of Libraries" in report.vm_summary
        assert report.raw == _ips_text()
        assert report.is_jetsam is False

    def test_summary_is_one_informative_line(self):
        summary = parse_crash_report_text(_ips_text(), path="/tmp/MyApp.ips").summary
        assert "\n" not in summary
        assert "MyApp [1234]" in summary
        assert "EXC_CRASH SIGKILL" in summary
        assert "0x8badf00d" in summary

    def test_parses_exception_subtype(self):
        payload = dict(IPS_PAYLOAD)
        payload["exception"] = {
            "type": "EXC_BAD_ACCESS",
            "signal": "SIGSEGV",
            "subtype": "KERN_INVALID_ADDRESS at 0x0000000000000010",
        }
        report = parse_crash_report_text(_ips_text(payload=payload))
        assert report.exception_type == "EXC_BAD_ACCESS"
        assert report.signal == "SIGSEGV"
        assert report.exception_subtype.startswith("KERN_INVALID_ADDRESS")

    def test_parses_jetsam_ips(self):
        report = parse_crash_report_text(
            JETSAM_IPS_TEXT, path="/tmp/JetsamEvent-2026-08-03-120500.ips")
        assert report.bug_type == "298"
        assert report.is_jetsam is True
        assert report.timestamp == "2026-08-03 12:05:00.00 +0000"


class TestParseLegacyText:
    def test_parses_legacy_crash_report(self):
        report = parse_crash_report_text(
            LEGACY_CRASH_TEXT, path="/tmp/MyApp-2026-08-03-120000.crash")

        assert report.process_name == "MyApp"
        assert report.pid == 4321
        assert report.incident_id == "11112222-3333-4444-5555-666677778888"
        assert report.timestamp == "2026-08-03 12:00:00.000 +0000"
        assert report.os_version == "iPhone OS 14.8 (18H17)"
        assert report.exception_type == "EXC_BAD_ACCESS"
        assert report.signal == "SIGSEGV"
        assert report.exception_subtype == "KERN_INVALID_ADDRESS at 0x0000000000000010"
        assert report.termination_reason == "SIGNAL 11 Segmentation fault: 11"
        assert report.termination_namespace == "SIGNAL"
        assert report.termination_code == "0xb"
        assert report.triggered_thread == 3
        assert "hook installation failed" in report.asi
        assert report.raw == LEGACY_CRASH_TEXT

    def test_legacy_watchdog_termination_reason(self):
        text = LEGACY_CRASH_TEXT.replace(
            "Termination Reason: SIGNAL 11 Segmentation fault: 11",
            "Termination Reason: SPRINGBOARD 2343432205 "
            "<FBSTerminateContext| explanation:watchdog transgression>",
        )
        report = parse_crash_report_text(text)
        assert report.termination_namespace == "SPRINGBOARD"
        assert report.termination_code == "0x8badf00d"


class TestParseRobustness:
    def test_truncated_ips_returns_safe_result(self):
        # Header line present, payload cut off mid-object (a report caught while
        # ReportCrash was still writing it).
        truncated = json.dumps(IPS_HEADER) + '\n{"procName":"MyApp","pid":12'
        report = parse_crash_report_text(truncated, path="/tmp/MyApp.ips")
        assert isinstance(report, IOSCrashReport)
        # The header still parses, so we keep what we can...
        assert report.bug_type == "309"
        assert report.process_name == "MyApp"
        # ...and the unreadable payload simply yields empty fields.
        assert report.exception_type == ""
        assert report.termination_reason == ""
        assert report.raw == truncated

    def test_garbage_returns_safe_result(self):
        report = parse_crash_report_text("\x00\x01not a crash report at all")
        assert isinstance(report, IOSCrashReport)
        assert report.exception_type == ""
        assert decode_terminator(report).verdict

    def test_empty_returns_safe_result(self):
        report = parse_crash_report_text("")
        assert report.raw == ""
        assert report.process_name == ""

    def test_parse_missing_file_returns_none(self, tmp_path):
        assert parse_crash_report(str(tmp_path / "does-not-exist.ips")) is None

    def test_parse_report_timestamp_variants(self):
        # 2026-08-03T12:00:00Z, i.e. offset-aware and therefore independent of
        # the host time zone.
        epoch_utc = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        assert parse_report_timestamp("2026-08-03 12:00:00.00 +0000") == epoch_utc
        assert parse_report_timestamp("2026-08-03 12:00:00 +0000") == epoch_utc
        # A non-UTC offset is honoured rather than silently treated as local.
        assert parse_report_timestamp("2026-08-03 14:00:00.00 +0200") == epoch_utc
        assert parse_report_timestamp("not a timestamp") is None
        assert parse_report_timestamp("") is None
        assert parse_report_timestamp(None) is None


# ---------------------------------------------------------------------------
# Terminator decoding — the pure function, one verdict per test.
# ---------------------------------------------------------------------------
class TestDecodeTerminator:
    def test_watchdog_8badf00d(self):
        report = parse_crash_report_text(_ips_text())
        verdict = decode_terminator(report)
        assert "watchdog timeout" in verdict.verdict
        assert "0x8badf00d" in verdict.verdict
        # The actionable part for a gated friTap spawn.
        assert "resume" in verdict.next_step

    def test_jetsam(self):
        report = parse_crash_report_text(
            JETSAM_IPS_TEXT, path="/tmp/JetsamEvent-2026-08-03-120500.ips")
        assert "memory pressure" in decode_terminator(report).verdict

    def test_exc_bad_access(self):
        report = IOSCrashReport(
            exception_type="EXC_BAD_ACCESS", signal="SIGSEGV",
            exception_subtype="KERN_INVALID_ADDRESS at 0x10")
        verdict = decode_terminator(report)
        assert "EXC_BAD_ACCESS" in verdict.verdict
        assert "wrong hook offset" in verdict.verdict
        assert verdict.next_step

    def test_exc_crash_with_springboard(self):
        report = IOSCrashReport(
            exception_type="EXC_CRASH", signal="SIGKILL",
            termination_namespace="SPRINGBOARD", termination_code="0x1",
            termination_reason="SPRINGBOARD 1 process-exit watchdog")
        verdict = decode_terminator(report)
        assert "launch services" in verdict.verdict
        assert "SPRINGBOARD" in verdict.verdict

    def test_dead10cc(self):
        report = IOSCrashReport(
            exception_type="EXC_CRASH", signal="SIGKILL",
            termination_namespace="SPRINGBOARD", termination_code="0xdead10cc",
            termination_reason="SPRINGBOARD 3735883980")
        verdict = decode_terminator(report)
        assert "0xdead10cc" in verdict.verdict
        assert "file lock" in verdict.verdict

    def test_codesigning(self):
        report = IOSCrashReport(
            exception_type="EXC_BAD_ACCESS", signal="SIGKILL",
            termination_reason="CODESIGNING 2 Invalid Page",
            termination_namespace="CODESIGNING")
        verdict = decode_terminator(report)
        assert "codesigning" in verdict.verdict
        # Wins over the generic EXC_BAD_ACCESS reading, and points at the usual
        # jailbreak cause.
        assert "EXC_BAD_ACCESS" not in verdict.verdict
        assert "frida-server" in verdict.next_step

    def test_unknown_falls_back_to_exception(self):
        report = IOSCrashReport(exception_type="EXC_ARITHMETIC", signal="SIGFPE")
        assert decode_terminator(report).verdict == "terminated with EXC_ARITHMETIC SIGFPE"

    def test_no_information_never_raises(self):
        assert decode_terminator(IOSCrashReport()).verdict


# ---------------------------------------------------------------------------
# Tooling gate
# ---------------------------------------------------------------------------
class TestToolingGate:
    def test_missing_idevicecrashreport_is_not_fatal(self, tools_missing, tmp_path, caplog):
        obj = _ios()
        with caplog.at_level(logging.WARNING, logger="test.ios.crash"):
            assert obj.check_idevicecrashreport_availability() is False
            assert obj.pull_crash_reports(str(tmp_path)) is False
            assert obj.get_latest_crash_report("MyApp", pid=1234) is None
        assert "brew install libimobiledevice" in caplog.text
        assert "idevicecrashreport" in caplog.text

    def test_missing_idevice_id_yields_no_devices(self, tools_missing, caplog):
        obj = _ios()
        with caplog.at_level(logging.WARNING, logger="test.ios.crash"):
            assert obj.list_devices() == []
        assert "brew install libimobiledevice" in caplog.text


class TestDeviceListing:
    def test_lists_udids(self, tools_present, monkeypatch):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="udid-one\nudid-two\n\n", stderr="")

        monkeypatch.setattr(ios_module.subprocess, "run", fake_run)
        assert _ios().list_devices() == ["udid-one", "udid-two"]
        assert calls[0][0] == ["idevice_id", "-l"]
        # Every subprocess call is bounded.
        assert calls[0][1]["timeout"] > 0

    def test_resolve_udid_prefers_configured_device(self, tools_present, monkeypatch):
        monkeypatch.setattr(IOS, "list_devices", lambda self, **kw: ["other"])
        assert _ios(device_id="my-udid").resolve_udid() == "my-udid"

    def test_resolve_udid_falls_back_to_single_device(self, tools_present, monkeypatch):
        monkeypatch.setattr(IOS, "list_devices", lambda self, **kw: ["only-udid"])
        assert _ios().resolve_udid() == "only-udid"

    def test_resolve_udid_without_device(self, tools_present, monkeypatch):
        monkeypatch.setattr(IOS, "list_devices", lambda self, **kw: [])
        assert _ios().resolve_udid() is None


class TestPullCrashReports:
    def test_uses_keep_and_extract_flags(self, tools_present, monkeypatch, tmp_path):
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            return subprocess.CompletedProcess(argv, 0, stdout="Done.", stderr="")

        monkeypatch.setattr(ios_module.subprocess, "run", fake_run)
        assert _ios(device_id="my-udid").pull_crash_reports(str(tmp_path)) is True
        argv = seen["argv"]
        assert argv[0] == "idevicecrashreport"
        assert "-k" in argv                       # keep the reports on the device
        assert "-e" in argv                       # extract/decode them
        assert argv[argv.index("-u") + 1] == "my-udid"
        assert argv[-1] == str(tmp_path)
        assert seen["kwargs"]["timeout"] > 0

    def test_omits_udid_when_unknown(self, tools_present, monkeypatch, tmp_path):
        seen = {}
        monkeypatch.setattr(IOS, "list_devices", lambda self, **kw: [])

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(ios_module.subprocess, "run", fake_run)
        assert _ios().pull_crash_reports(str(tmp_path)) is True
        assert "-u" not in seen["argv"]

    def test_nonzero_exit_is_not_fatal(self, tools_present, monkeypatch, tmp_path):
        monkeypatch.setattr(
            ios_module.subprocess, "run",
            lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout="", stderr="ERROR"))
        assert _ios(device_id="u").pull_crash_reports(str(tmp_path)) is False

    def test_subprocess_timeout_is_handled(self, tools_present, monkeypatch, tmp_path, caplog):
        def fake_run(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 1))

        monkeypatch.setattr(ios_module.subprocess, "run", fake_run)
        obj = _ios(device_id="u")
        with caplog.at_level(logging.WARNING, logger="test.ios.crash"):
            assert obj.pull_crash_reports(str(tmp_path)) is False
            assert obj.list_devices() == []
            assert obj.get_latest_crash_report(
                "MyApp", dest_dir=str(tmp_path), retries=1) is None
        assert "timed out" in caplog.text

    def test_missing_binary_at_exec_time_is_handled(self, tools_present, monkeypatch, tmp_path):
        def fake_run(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        monkeypatch.setattr(ios_module.subprocess, "run", fake_run)
        assert _ios(device_id="u").pull_crash_reports(str(tmp_path)) is False


# ---------------------------------------------------------------------------
# Report matching
# ---------------------------------------------------------------------------
class TestFindCrashReports:
    def _tree(self, tmp_path):
        """An old and a new report for MyApp, plus an unrelated one."""
        old = _write_report(
            tmp_path, "MyApp-2020-01-01-000000.ips",
            _ips_text(header=dict(IPS_HEADER, timestamp="2020-01-01 00:00:00.00 +0000")))
        new = _write_report(
            tmp_path, "MyApp-2026-08-03-120000.ips",
            _ips_text(header=dict(IPS_HEADER, timestamp="2026-08-03 12:00:00.00 +0000")))
        other = _write_report(
            tmp_path, "Mail-2026-08-03-130000.ips",
            _ips_text(
                header=dict(IPS_HEADER, name="Mail", timestamp="2026-08-03 13:00:00.00 +0000"),
                payload=dict(IPS_PAYLOAD, procName="Mail", pid=999)))
        return old, new, other

    def test_prefers_newest_and_ignores_unrelated(self, tmp_path):
        old, new, _other = self._tree(tmp_path)
        found = _ios().find_crash_reports(str(tmp_path), "MyApp")
        assert found == [new, old]

    def test_ignores_reports_older_than_timestamp(self, tmp_path):
        old, new, _other = self._tree(tmp_path)
        cutoff = parse_report_timestamp("2025-01-01 00:00:00.00 +0000")
        found = _ios().find_crash_reports(str(tmp_path), "MyApp", newer_than=cutoff)
        assert found == [new]
        assert old not in found

    def test_matches_bundle_id_target(self, tmp_path):
        _old, new, _other = self._tree(tmp_path)
        # friTap targets are usually bundle ids; the report is named after the
        # executable.
        found = _ios().find_crash_reports(str(tmp_path), "com.example.MyApp")
        assert new in found

    def test_matches_jetsam_event_report(self, tmp_path):
        jetsam = _write_report(tmp_path, "JetsamEvent-2026-08-03-120500.ips", JETSAM_IPS_TEXT)
        found = _ios().find_crash_reports(str(tmp_path), "MyApp")
        assert jetsam in found

    def test_jetsam_report_for_another_process_is_ignored(self, tmp_path):
        _write_report(
            tmp_path, "JetsamEvent-2026-08-03-120500.ips",
            JETSAM_IPS_TEXT.replace("MyApp", "Mail"))
        assert _ios().find_crash_reports(str(tmp_path), "MyApp") == []

    def test_pid_match_is_preferred(self, tmp_path):
        with_pid = _write_report(
            tmp_path, "MyApp-2020-01-01-000000.ips",
            _ips_text(header=dict(IPS_HEADER, timestamp="2020-01-01 00:00:00.00 +0000")))
        _write_report(
            tmp_path, "MyApp-2026-08-03-120000.ips",
            _ips_text(payload=dict(IPS_PAYLOAD, pid=4242)))
        found = _ios().find_crash_reports(str(tmp_path), "MyApp", pid=1234)
        assert found[0] == with_pid

    def test_missing_directory_returns_empty(self, tmp_path):
        assert _ios().find_crash_reports(str(tmp_path / "nope"), "MyApp") == []

    def test_empty_process_name_returns_empty(self, tmp_path):
        self._tree(tmp_path)
        assert _ios().find_crash_reports(str(tmp_path), "") == []

    def test_non_report_files_are_ignored(self, tmp_path):
        _write_report(tmp_path, "MyApp.txt", _ips_text())
        assert _ios().find_crash_reports(str(tmp_path), "MyApp") == []


# ---------------------------------------------------------------------------
# Bounded retry (ReportCrash writes the .ips asynchronously)
# ---------------------------------------------------------------------------
class TestRetryLoop:
    def test_defaults_are_three_attempts_two_seconds(self):
        assert CRASH_REPORT_RETRIES == 3
        assert CRASH_REPORT_RETRY_DELAY == 2.0

    def test_succeeds_on_third_attempt(self, tools_present, monkeypatch, tmp_path):
        attempts = {"pull": 0}
        sleeps = []

        def fake_pull(self, dest_dir, timeout=None):
            attempts["pull"] += 1
            if attempts["pull"] >= 3:
                _write_report(tmp_path, "MyApp-2026-08-03-120000.ips", _ips_text())
            return True

        monkeypatch.setattr(IOS, "pull_crash_reports", fake_pull)
        monkeypatch.setattr(IOS, "_sleep", lambda self, seconds: sleeps.append(seconds))

        report = _ios(device_id="u").get_latest_crash_report(
            "MyApp", pid=1234, dest_dir=str(tmp_path))

        assert report is not None
        assert report.process_name == "MyApp"
        assert report.termination_code == "0x8badf00d"
        # Bounded: at most CRASH_REPORT_RETRIES attempts, and we never sleep
        # after the successful one.
        assert attempts["pull"] == 3
        assert attempts["pull"] <= CRASH_REPORT_RETRIES
        assert sleeps == [CRASH_REPORT_RETRY_DELAY, CRASH_REPORT_RETRY_DELAY]

    def test_stops_immediately_when_report_is_already_there(self, tools_present,
                                                            monkeypatch, tmp_path):
        attempts = {"pull": 0}
        _write_report(tmp_path, "MyApp-2026-08-03-120000.ips", _ips_text())

        def fake_pull(self, dest_dir, timeout=None):
            attempts["pull"] += 1
            return True

        monkeypatch.setattr(IOS, "pull_crash_reports", fake_pull)
        monkeypatch.setattr(
            IOS, "_sleep",
            lambda self, seconds: pytest.fail("must not sleep after a hit"))

        assert _ios(device_id="u").get_latest_crash_report(
            "MyApp", dest_dir=str(tmp_path)) is not None
        assert attempts["pull"] == 1

    def test_gives_up_after_the_bound(self, tools_present, monkeypatch, tmp_path):
        attempts = {"pull": 0}

        def fake_pull(self, dest_dir, timeout=None):
            attempts["pull"] += 1
            return True

        monkeypatch.setattr(IOS, "pull_crash_reports", fake_pull)
        monkeypatch.setattr(IOS, "_sleep", lambda self, seconds: None)

        assert _ios(device_id="u").get_latest_crash_report(
            "MyApp", dest_dir=str(tmp_path)) is None
        assert attempts["pull"] == CRASH_REPORT_RETRIES

    def test_never_raises_when_everything_explodes(self, tools_present, monkeypatch, tmp_path):
        def boom(self, dest_dir, timeout=None):
            raise RuntimeError("usbmuxd died")

        monkeypatch.setattr(IOS, "pull_crash_reports", boom)
        monkeypatch.setattr(IOS, "_sleep", lambda self, seconds: None)
        assert _ios(device_id="u").get_latest_crash_report(
            "MyApp", dest_dir=str(tmp_path)) is None


class TestDescribeCrash:
    def test_returns_summary_and_verdict(self):
        report = parse_crash_report_text(_ips_text(), path="/tmp/MyApp.ips")
        summary, verdict = _ios().describe_crash(report)
        assert "MyApp [1234]" in summary
        assert "watchdog timeout" in verdict.verdict

    def test_handles_missing_report(self):
        assert _ios().describe_crash(None) == ("", None)
