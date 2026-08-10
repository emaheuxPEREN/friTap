"""Source-level invariants for the agent's startup path (fkie-cad/friTap#65).

friTap killed spawned Apple targets before installing a single hook. Two causes,
both invisible to any runtime test we can run in CI (no iOS device, and the failure
is a NATIVE death with no JS exception):

1. every platform module snapshotted ``getModuleNames()`` at module scope, so
   ``script.load()`` performed six full ``Process.enumerateModules()`` walks — on
   every platform, before the config handshake;
2. platform detection messaged Foundation
   (``-[NSProcessInfo operatingSystemVersionString]``), which kills a spawned,
   not-yet-resumed process. Measured on macOS 26: the agent died 14 ms after
   pipeline init, before the platform branch logged anything.

These are cheap, mechanical properties of the source, so they are asserted here —
in ``tests/unit`` because that is the directory CI runs. Style follows
``tests/unit/test_pattern_fallback_gate.py``, which likewise makes source-level
assertions over ``agent/**/*.ts`` plus a check on the shipped bundle.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = REPO_ROOT / "agent"
ENTRY = AGENT_DIR / "fritap_agent.ts"
BUNDLE = REPO_ROOT / "friTap" / "fritap_agent.js"

PLATFORM_MODULES = [
    AGENT_DIR / "platforms" / f"{name}.ts"
    for name in ("android", "ios", "macos", "linux", "windows", "wine")
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_comments(source: str) -> str:
    """Drop // and /* */ comments.

    These assertions are about statement ORDER, and the comments explaining each
    fix necessarily name the symbols involved (e.g. the comment above isAndroid()
    explains why `Java.available` must not be read first). Matching prose would
    make the tests report the explanation as the defect.
    """
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def _agent_sources() -> list[Path]:
    return [p for p in AGENT_DIR.rglob("*.ts") if not p.name.endswith(".test.ts")]


@pytest.mark.parametrize("module_path", PLATFORM_MODULES, ids=lambda p: p.name)
def test_platform_module_does_not_enumerate_modules_at_module_scope(module_path):
    """No platform module may snapshot the loaded-module list at import time.

    All six are imported unconditionally by fritap_agent.ts, so a module-scope
    snapshot runs on every platform at agent load. It is also stale for spawned
    apps, whose libraries load after the snapshot is taken.
    """
    for lineno, line in enumerate(_read(module_path).splitlines(), start=1):
        if re.match(r"^(?:var|let|const)\s+\w+.*=\s*getModuleNames\s*\(", line):
            pytest.fail(
                f"{module_path.relative_to(REPO_ROOT)}:{lineno} snapshots getModuleNames() "
                f"at module scope; call it fresh at each consumer instead:\n  {line.strip()}"
            )
        if re.match(r"^(?:var|let|const)\s+\w+.*=\s*Process\.enumerateModules\s*\(", line):
            pytest.fail(
                f"{module_path.relative_to(REPO_ROOT)}:{lineno} enumerates modules at "
                f"module scope:\n  {line.strip()}"
            )


def test_detection_prefers_sysctl_over_foundation_messaging():
    """isiOS()/isMacOS() must consult sysctl before messaging Foundation.

    In spawn mode neither UIKit nor AppKit is mapped yet, so detection reaches its
    fallback — and the Foundation fallback is what kills the process. sysctl needs
    no ObjC or Swift runtime and is safe at that point.
    """
    source = _strip_comments(_read(AGENT_DIR / "util" / "process_infos.ts"))
    for func in ("isiOS", "isMacOS"):
        body = source.split(f"export function {func}(", 1)[1].split("\nexport function", 1)[0]
        assert "isIOSFamilyBySysctl" in body, f"{func}() has no sysctl-based fallback"
        sysctl_at = body.index("isIOSFamilyBySysctl")
        objc_fallback_at = body.index("is_macos_based_version_string")
        assert sysctl_at < objc_fallback_at, (
            f"{func}() reaches the Foundation version-string fallback before sysctl; "
            "that ordering kills spawned Apple targets"
        )


def test_detailed_platform_info_is_not_on_the_startup_path():
    """getDetailedPlatformInfo() does live ObjC messaging plus six file-existence
    checks. It is debug-only output and must not run before platform dispatch."""
    lines = _strip_comments(_read(ENTRY)).splitlines()
    calls = [i for i, line in enumerate(lines) if "getDetailedPlatformInfo()" in line]
    assert calls, "expected getDetailedPlatformInfo() to still be reachable for diagnostics"
    for i in calls:
        context = "\n".join(lines[max(0, i - 12):i + 1])
        guarded = "debug_output" in context or "unknown platform" in context.lower()
        assert guarded, (
            f"agent/fritap_agent.ts:{i + 1} calls getDetailedPlatformInfo() on the startup "
            "path; it must be gated behind debug_output or the unknown-platform branch"
        )


def test_isandroid_checks_platform_before_java_available():
    """`Java.available` walks the whole module list on every read off Android, and
    isAndroid() is on the pattern-lookup hot path via currentPlatformKey()."""
    source = _strip_comments(_read(AGENT_DIR / "util" / "process_infos.ts"))
    body = source.split("export function isAndroid(", 1)[1].split("\nexport function", 1)[0]
    assert body.index("Process.platform") < body.index("Java.available"), (
        "isAndroid() reads Java.available before the cheap platform guard"
    )


def test_rpc_exports_declared_before_the_platform_load():
    """If startup fails, the host must still be able to call agent_abi_version()
    and graceful_detach(); otherwise it reports an obscure error instead of a
    diagnosis."""
    source = _strip_comments(_read(ENTRY))
    assert source.index("rpc.exports") < source.index("load_os_specific_agent()"), (
        "rpc.exports is assigned after the platform load, so a startup failure "
        "leaves the host with no RPC surface"
    )


@pytest.mark.parametrize(
    "stage", ["config-handshake", "anti-handshake", "pipeline-init", "platform-detect", "platform-load"]
)
def test_startup_stage_is_breadcrumbed(stage):
    """A breadcrumb per stage is the only thing that survives a native death, and
    it is what lets the host name the failing stage in its crash message."""
    assert f'initStage("{stage}"' in _read(ENTRY), f"startup stage '{stage}' is not wrapped by initStage()"


@pytest.mark.parametrize("module_path", [AGENT_DIR / "platforms" / "ios.ts", AGENT_DIR / "platforms" / "macos.ts"],
                         ids=["ios", "macos"])
def test_apple_hook_installation_is_phased(module_path):
    """iOS/macOS installs must be contained + breadcrumbed + yielded, as Android
    already was, so one failing library cannot cost every later hook."""
    assert "runInstallPhases(" in _read(module_path), (
        f"{module_path.name} installs hooks in one unguarded synchronous block"
    )


def test_no_nonnull_asserted_null_module_export_lookup():
    """`Module.findExportByName(null, x)!` throws on a miss and the assertion hides
    the null from the type system; the codebase's idiom is
    findGlobalExportByName + an explicit null check."""
    offenders = []
    for path in _agent_sources():
        for lineno, line in enumerate(_strip_comments(_read(path)).splitlines(), start=1):
            if re.search(r"findExportByName\(\s*null\s*,[^)]*\)\s*!", line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}")
    assert not offenders, "throwing null-module export lookups: " + ", ".join(offenders)


def test_shipped_bundle_was_built_from_these_sources():
    """The Python host loads the pre-compiled bundle, not agent/*.ts. A stale bundle
    silently ships none of the above — which is exactly why the original reporter's
    experiment appeared to change nothing."""
    bundle = _read(BUNDLE)
    for marker in ("agent-init: ", "install-phase: ", "isIOSFamilyBySysctl", "kern.osproductversion"):
        assert marker in bundle, (
            f"friTap/fritap_agent.js does not contain {marker!r} — rebuild it with "
            "./dev/compile_agent.sh and commit the result"
        )
