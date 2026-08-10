#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Derive the BoringSSL ``SSL_CTX`` keylog-callback offset from iOS Simulator runtimes.

Why
---
friTap's legacy iOS/macOS BoringSSL keylog hook writes a function pointer directly
into the live ``SSL_CTX`` heap struct at a byte offset. A wrong offset corrupts a
neighbouring field and kills the target process (fkie-cad/friTap#65), so the offset
has to be right.

Two things about that offset have moved since this script was written, and both
matter for reading the ``--check`` output below:

* **Where it lives.** The offset tables are now in
  ``agent/legacy/tls/shared/apple_keylog_offset.ts`` — one for iOS, one for macOS —
  keyed on the OS **major version**, obtained via ``sysctl kern.osproductversion``.
  The old ``CALLBACK_OFFSET`` variable and the ``kCFCoreFoundationVersionNumber``
  ladder are gone from ``agent/legacy/tls/platforms/ios/openssl_boringssl_ios.ts``
  and ``agent/legacy/tls/platforms/macos/openssl_boringssl_macos.ts``. A coarse
  CF-number mapping survives only as a third-tier fallback, behind sysctl and
  ``NSProcessInfo``.
* **The table is no longer the primary source.** ``resolveKeylogCallbackOffset()``
  first calls ``deriveOffsetFromBinary()``, which decodes the offset out of the
  target's *own* ``libboringssl.dylib`` at runtime — the same one-instruction body
  this script reads statically. The tables are the fallback for when that
  derivation fails.

So this script's job is to keep the fallback tables honest, not to feed the only
mechanism friTap has.

The ground truth can be derived statically, with no device: iOS Simulator runtimes
ship ``/usr/lib/libboringssl.dylib`` as a standalone Mach-O (not inside a stripped
dyld shared cache), and ``_SSL_CTX_set_keylog_callback`` is present as a *local*
symbol whose entire body is::

    str  x1, [x0, #OFFSET]
    ret

That ``#OFFSET`` *is* the offset friTap needs. ``_SSL_CTX_set_info_callback`` has
the same 2-instruction shape and is exported; its offset is recorded as a cheap
struct-layout fingerprint (it has been stable at 0x188 across iOS 17-26).

Usage
-----
    python dev/derive_boringssl_keylog_offset.py            # readable table
    python dev/derive_boringssl_keylog_offset.py --json      # machine-readable
    python dev/derive_boringssl_keylog_offset.py --check      # compare vs friTap sources

Exit codes: 0 = OK (or cleanly skipped), 1 = ``--check`` found a contradiction.
The script *skips* (exit 0) when not on macOS, when ``xcrun``/``nm``/``otool`` are
missing, or when no simulator runtimes are installed — so it is safe to run on a
Linux CI runner.

More runtimes = better coverage. Install extra ones with::

    xcodebuild -downloadPlatform iOS -buildVersion 16.4

What ``--check`` compares against
--------------------------------
friTap keeps the offset table in one of two shapes, and this script reads both:

1. the current shape — ``IOS_OFFSETS`` / ``MACOS_OFFSETS`` in
   ``agent/legacy/tls/shared/apple_keylog_offset.ts``, a list of
   ``{ minMajor, offset }`` buckets where the first bucket with
   ``minMajor <= osMajor`` wins;
2. the legacy shape — an inline ``CALLBACK_OFFSET`` if/else-if ladder keyed on
   ``kCFCoreFoundationVersionNumber`` inside the per-platform executors
   (``openssl_boringssl_ios.ts`` / ``openssl_boringssl_macos.ts``). Any such
   surviving ladder is *also* parsed and checked, because it is the code that
   actually runs on that platform until it is migrated.

Known limitations
-----------------
* ``simctl`` reports only the marketing iOS version (e.g. "18.6"), never a
  ``kCFCoreFoundationVersionNumber``. A legacy CF-number ladder can therefore not
  be *evaluated*; instead its ``devlog("Installing callback for iOS >= N")`` label
  is paired with the ``CALLBACK_OFFSET = 0x...`` assigned in the same branch and
  treated as a ``(major -> offset)`` bucket. That catches a wrong or missing offset
  bucket, but not a wrong CF-number *threshold*.
* Simulator runtimes only prove the *iOS* layout. macOS buckets are keyed by macOS
  majors, so they are compared through the documented era mapping (macOS 11 <-> iOS
  14 ... macOS 15 <-> iOS 18, macOS 26 <-> iOS 26). A macOS-only divergence cannot
  be proven from simulator runtimes alone.
* A derived major with no bucket of its own is only a *warning* when it inherits a
  matching offset from a lower bucket: an open-ended top bucket is the intended
  design (a capped top bucket is what stranded late iOS 16.x releases). A genuine
  offset contradiction is always a hard failure.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

IOS_SOURCE = PROJECT_ROOT / "agent" / "legacy" / "tls" / "platforms" / "ios" / "openssl_boringssl_ios.ts"
MACOS_SOURCE = PROJECT_ROOT / "agent" / "legacy" / "tls" / "platforms" / "macos" / "openssl_boringssl_macos.ts"
SHARED_TABLE_SOURCE = PROJECT_ROOT / "agent" / "legacy" / "tls" / "shared" / "apple_keylog_offset.ts"

# Per-platform legacy executors that may still carry an inline CALLBACK_OFFSET ladder.
LEGACY_LADDER_SOURCES: dict[str, Path] = {
    "ios": IOS_SOURCE,
    "macos": MACOS_SOURCE,
}

# TS identifier of the bucket table in the shared module, per platform.
SHARED_TABLE_IDENTIFIERS: dict[str, str] = {
    "ios": "IOS_OFFSETS",
    "macos": "MACOS_OFFSETS",
}

# Apple ships the same libboringssl revision to the iOS and macOS releases of a
# given year, so a macOS bucket is compared against the iOS release of its era.
# iOS 19 does not exist — Apple jumped from 18 to 26 on both platforms in 2025.
IOS_TO_MACOS_ERA: dict[int, int] = {14: 11, 15: 12, 16: 13, 17: 14, 18: 15}

# libboringssl.dylib is a fat binary (x86_64 + arm64) on most runtimes — always
# pin the slice, otherwise otool/nm pick the host slice on Intel Macs.
ARCH = "arm64"
DYLIB_RELATIVE_PATH = Path("usr") / "lib" / "libboringssl.dylib"
KEYLOG_SYMBOL = "_SSL_CTX_set_keylog_callback"
INFO_SYMBOL = "_SSL_CTX_set_info_callback"
REQUIRED_TOOLS = ("xcrun", "nm", "otool")

# Fallback discovery when `xcrun simctl list runtimes -j` is unusable. The volume
# directories are named by *build* (iOS_22G86), never by version — glob, never guess.
RUNTIME_BUNDLE_GLOBS = (
    "/Library/Developer/CoreSimulator/Volumes/*/Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime",
    "/Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime",
)

SUBPROCESS_TIMEOUT = 60

# `<addr>\tstr\tx1, [x0, #0x310]`  (a zero offset is emitted as `[x0]`)
_STORE_RE = re.compile(
    r"^\s*[0-9a-fA-F]+\s+str\s+x1,\s*\[x0(?:,\s*#(?P<offset>0x[0-9a-fA-F]+|\d+))?\]\s*$"
)
_RET_RE = re.compile(r"^\s*[0-9a-fA-F]+\s+ret\s*$")

# `} else if (foundationNumber >= 1854 && foundationNumber < 1946.102) {`
_BRANCH_RE = re.compile(r"\bif\s*\(\s*(?P<cond>[^{}]*?)\s*\)\s*\{", re.DOTALL)
_OFFSET_ASSIGN_RE = re.compile(r"CALLBACK_OFFSET\s*=\s*(0x[0-9a-fA-F]+)")
_MAJOR_GE_RE = re.compile(r"(?:iOS|macOS|MacOS|OSX)\s*>=\s*(\d+)")
_MAJOR_LT_RE = re.compile(r"(?:iOS|macOS|MacOS|OSX)\s*<\s*(\d+)")
_LOWER_BOUND_RE = re.compile(r"foundationNumber\s*(>=|>)\s*([0-9]+(?:\.[0-9]+)?)")
_UPPER_BOUND_RE = re.compile(r"foundationNumber\s*(<=|<)\s*([0-9]+(?:\.[0-9]+)?)")

# `{ minMajor: 18, offset: 0x310, provenance: "derived", note: "..." },`
_BUCKET_ENTRY_RE = re.compile(
    r"minMajor\s*:\s*(?P<major>\d+)\s*,\s*offset\s*:\s*(?P<offset>0x[0-9a-fA-F]+)"
    r"(?:\s*,\s*provenance\s*:\s*\"(?P<provenance>[^\"]*)\")?"
)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class SimRuntime:
    """An installed simulator runtime and the BoringSSL dylib inside it."""

    version: str
    build: str
    dylib: Path

    @property
    def major(self) -> int | None:
        head = self.version.split(".", 1)[0]
        return int(head) if head.isdigit() else None

    @property
    def sort_key(self) -> tuple[int, ...]:
        parts = []
        for chunk in self.version.split("."):
            parts.append(int(chunk) if chunk.isdigit() else 0)
        return tuple(parts)


@dataclass
class DerivedOffsets:
    """Offsets derived from one runtime's libboringssl.dylib."""

    runtime: SimRuntime
    keylog_offset: int | None = None
    info_offset: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.keylog_offset is not None

    def to_dict(self) -> dict:
        return {
            "version": self.runtime.version,
            "major": self.runtime.major,
            "build": self.runtime.build,
            "dylib": str(self.runtime.dylib),
            "keylog_offset": _hex_or_none(self.keylog_offset),
            "info_offset": _hex_or_none(self.info_offset),
            "notes": list(self.notes),
        }


@dataclass
class OffsetBucket:
    """One bucket of an offset table: "this offset applies from ``major`` upwards"."""

    offset: int
    major: int | None
    #: Free-form provenance of the bucket ("derived", "legacy", or the raw condition).
    detail: str = ""
    #: True for the catch-all branch (``minMajor: 0`` / the ``foundationNumber == undefined`` arm).
    is_catch_all: bool = False
    #: Upper bound, only meaningful for legacy CF-number ladders.
    lower_bound: float | None = None
    lower_inclusive: bool = True
    upper_bound: float | None = None
    upper_inclusive: bool = False

    @property
    def label(self) -> str:
        if self.is_catch_all:
            return "catch-all"
        return "?" if self.major is None else f">={self.major}"

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "major": self.major,
            "offset": _hex_or_none(self.offset),
            "detail": self.detail,
            "is_catch_all": self.is_catch_all,
            "lower_bound": self.lower_bound,
            "lower_inclusive": self.lower_inclusive,
            "upper_bound": self.upper_bound,
            "upper_inclusive": self.upper_inclusive,
        }


@dataclass
class OffsetTable:
    """A parsed offset table, whichever shape friTap currently stores it in."""

    name: str
    source: Path
    #: "min-major-table" (shared module) or "cf-ladder" (legacy inline if/else).
    style: str
    #: Which version axis the buckets are keyed by: "iOS" or "macOS".
    version_axis: str
    buckets: list[OffsetBucket] = field(default_factory=list)

    @property
    def by_major(self) -> dict[int, int]:
        """``{major: offset}`` for every version-keyed bucket (catch-all excluded)."""
        return {b.major: b.offset for b in self.buckets if b.major is not None and not b.is_catch_all}

    @property
    def catch_all_offset(self) -> int | None:
        for bucket in self.buckets:
            if bucket.is_catch_all:
                return bucket.offset
        return None

    @property
    def top_bucket(self) -> OffsetBucket | None:
        ranked = [b for b in self.buckets if b.major is not None and not b.is_catch_all]
        return max(ranked, key=lambda b: b.major) if ranked else None

    @property
    def top_bucket_is_open_ended(self) -> bool:
        """True when no OS release can fall *past* the highest bucket.

        A capped top bucket is the defect that stranded late iOS 16.x releases in the
        iOS 17 bucket; ``minMajor`` tables are open-ended by construction.
        """
        top = self.top_bucket
        if top is None:
            return False
        return top.upper_bound is None

    @property
    def source_label(self) -> str:
        try:
            return str(self.source.relative_to(PROJECT_ROOT))
        except ValueError:
            return str(self.source)

    def offset_for_major(self, major: int) -> tuple[int | None, int | None]:
        """Resolve the offset this table would use for an OS major version.

        Mirrors "first bucket whose minMajor <= major wins". Returns
        ``(offset, bucket_major)``, falling back to ``(catch_all, None)``.
        """
        buckets = self.by_major
        candidates = [m for m in buckets if m <= major]
        if not candidates:
            return self.catch_all_offset, None
        chosen = max(candidates)
        return buckets[chosen], chosen

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source": self.source_label,
            "style": self.style,
            "version_axis": self.version_axis,
            "top_bucket_is_open_ended": self.top_bucket_is_open_ended,
            "buckets": [bucket.to_dict() for bucket in self.buckets],
        }


class SkipDerivation(Exception):
    """Raised when derivation cannot run in this environment (never an error)."""


def _hex_or_none(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


# --------------------------------------------------------------------------- #
# Environment probing
# --------------------------------------------------------------------------- #


def missing_tools() -> list[str]:
    """Return the required command-line tools that are not on PATH."""
    return [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]


def environment_skip_reason() -> str | None:
    """Return why derivation must be skipped here, or None if it can run."""
    if platform.system() != "Darwin":
        return f"not macOS (platform is {platform.system() or 'unknown'})"
    missing = missing_tools()
    if missing:
        return "missing required tool(s): " + ", ".join(missing)
    return None


def _run(cmd: list[str]) -> str | None:
    """Run a command, returning stdout, or None if it failed in any way."""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


# --------------------------------------------------------------------------- #
# Runtime discovery
# --------------------------------------------------------------------------- #


def _dylib_for_runtime_root(runtime_root: Path) -> Path:
    return runtime_root / DYLIB_RELATIVE_PATH


def _runtimes_from_simctl() -> list[SimRuntime]:
    """Discover runtimes via `xcrun simctl list runtimes -j` (preferred)."""
    stdout = _run(["xcrun", "simctl", "list", "runtimes", "-j"])
    if not stdout:
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    runtimes: list[SimRuntime] = []
    for entry in payload.get("runtimes", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("isAvailable") is False:
            continue
        identifier = str(entry.get("identifier", ""))
        name = str(entry.get("name", ""))
        # `platform` was added in newer Xcodes; fall back to the identifier.
        plat = entry.get("platform") or ("iOS" if "SimRuntime.iOS" in identifier else "")
        if plat != "iOS" and not name.startswith("iOS"):
            continue

        runtime_root = entry.get("runtimeRoot")
        if runtime_root:
            root = Path(runtime_root)
        elif entry.get("bundlePath"):
            root = Path(entry["bundlePath"]) / "Contents" / "Resources" / "RuntimeRoot"
        else:
            continue

        dylib = _dylib_for_runtime_root(root)
        if not dylib.exists():
            continue
        runtimes.append(
            SimRuntime(
                version=str(entry.get("version") or name.replace("iOS", "").strip()),
                build=str(entry.get("buildversion") or "unknown"),
                dylib=dylib,
            )
        )
    return runtimes


def _build_from_volume_path(bundle_path: Path) -> str:
    """Recover the build id from a `/Volumes/iOS_22G86/...` bundle path."""
    for part in bundle_path.parts:
        if part.startswith("iOS_") and len(part) > 4:
            return part[4:]
    return "unknown"


def _runtimes_from_glob() -> list[SimRuntime]:
    """Fallback discovery: glob the well-known .simruntime locations."""
    runtimes: list[SimRuntime] = []
    seen: set[Path] = set()
    root = Path("/")
    for pattern in RUNTIME_BUNDLE_GLOBS:
        for bundle in sorted(root.glob(pattern.lstrip("/"))):
            name = bundle.stem  # "iOS 18.6"
            if not name.startswith("iOS"):
                continue
            dylib = _dylib_for_runtime_root(bundle / "Contents" / "Resources" / "RuntimeRoot")
            if not dylib.exists() or dylib in seen:
                continue
            seen.add(dylib)
            runtimes.append(
                SimRuntime(
                    version=name[len("iOS"):].strip(),
                    build=_build_from_volume_path(bundle),
                    dylib=dylib,
                )
            )
    return runtimes


def discover_runtimes() -> list[SimRuntime]:
    """Return every installed iOS simulator runtime that ships libboringssl.dylib."""
    runtimes = _runtimes_from_simctl()
    if not runtimes:
        runtimes = _runtimes_from_glob()
    # Deduplicate on the dylib path (simctl and the glob can overlap).
    unique: dict[Path, SimRuntime] = {}
    for runtime in runtimes:
        unique.setdefault(runtime.dylib, runtime)
    return sorted(unique.values(), key=lambda r: r.sort_key)


# --------------------------------------------------------------------------- #
# Static offset derivation
# --------------------------------------------------------------------------- #


def symbol_present(dylib: Path, symbol: str) -> bool:
    """True if `nm -arch arm64` lists the (local or exported) symbol."""
    stdout = _run(["nm", "-arch", ARCH, str(dylib)])
    if stdout is None:
        return False
    needle = f" {symbol}"
    return any(line.endswith(needle) or line.strip() == symbol for line in stdout.splitlines())


def parse_store_offset(disassembly: str, symbol: str) -> tuple[int | None, str | None]:
    """Extract ``#OFFSET`` from a ``str x1, [x0, #OFFSET]`` + ``ret`` function body.

    Returns ``(offset, error)``; exactly one of the two is None. Anything that does
    not match the expected 2-instruction shape yields an error instead of a guess —
    a mis-parsed offset would corrupt the target's SSL_CTX.
    """
    lines = disassembly.splitlines()
    label = f"{symbol}:"
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == label)
    except StopIteration:
        return None, f"{symbol} label not found in disassembly"

    body = lines[start + 1: start + 3]
    if len(body) < 2:
        return None, f"{symbol} body truncated (<2 instructions)"

    store = _STORE_RE.match(body[0])
    if store is None:
        return None, f"{symbol} first instruction is not `str x1, [x0, #imm]`: {body[0].strip()!r}"
    if _RET_RE.match(body[1]) is None:
        return None, f"{symbol} second instruction is not `ret`: {body[1].strip()!r}"

    raw = store.group("offset")
    offset = 0 if raw is None else int(raw, 16 if raw.lower().startswith("0x") else 10)
    return offset, None


def derive_symbol_offset(dylib: Path, symbol: str) -> tuple[int | None, str | None]:
    """Derive the SSL_CTX field offset written by a one-line setter function."""
    if not symbol_present(dylib, symbol):
        return None, f"{symbol} not present in {ARCH} slice"
    stdout = _run(["otool", "-arch", ARCH, "-tvV", "-p", symbol, str(dylib)])
    if stdout is None:
        return None, f"otool failed for {symbol}"
    return parse_store_offset(stdout, symbol)


def derive_for_runtime(runtime: SimRuntime) -> DerivedOffsets:
    """Derive keylog + info offsets for a single runtime, never raising."""
    result = DerivedOffsets(runtime=runtime)
    for symbol, attr in ((KEYLOG_SYMBOL, "keylog_offset"), (INFO_SYMBOL, "info_offset")):
        offset, error = derive_symbol_offset(runtime.dylib, symbol)
        if error:
            result.notes.append(error)
        setattr(result, attr, offset)
    return result


def derive_all(runtimes: list[SimRuntime] | None = None) -> list[DerivedOffsets]:
    """Derive offsets for every installed runtime.

    Raises ``SkipDerivation`` when the environment cannot support derivation at all
    (non-macOS, missing tools, no runtimes installed).
    """
    reason = environment_skip_reason()
    if reason:
        raise SkipDerivation(reason)
    if runtimes is None:
        runtimes = discover_runtimes()
    if not runtimes:
        raise SkipDerivation(
            "no iOS simulator runtimes with usr/lib/libboringssl.dylib found "
            "(install one: xcodebuild -downloadPlatform iOS -buildVersion 16.4)"
        )
    return [derive_for_runtime(runtime) for runtime in runtimes]


# --------------------------------------------------------------------------- #
# Ladder parsing (friTap sources)
# --------------------------------------------------------------------------- #


def parse_min_major_table(source: str, identifier: str) -> list[OffsetBucket]:
    """Parse a ``const <identifier>: OffsetBucket[] = [ ... ]`` bucket table.

    Returns the buckets in source order; an empty list means the identifier is not
    present (e.g. the module predates the platform's migration).
    """
    start = source.find(f"{identifier}")
    if start == -1:
        return []
    open_bracket = source.find("[", start)
    close_bracket = source.find("];", open_bracket)
    if open_bracket == -1 or close_bracket == -1:
        return []

    buckets: list[OffsetBucket] = []
    for match in _BUCKET_ENTRY_RE.finditer(source[open_bracket:close_bracket]):
        major = int(match.group("major"))
        buckets.append(
            OffsetBucket(
                offset=int(match.group("offset"), 16),
                major=None if major == 0 else major,
                detail=match.group("provenance") or "",
                is_catch_all=major == 0,
            )
        )
    return buckets


def parse_callback_offset_ladder(source: str) -> list[OffsetBucket]:
    """Parse a legacy inline ``CALLBACK_OFFSET`` if/else-if ladder.

    Handles both orderings friTap has used (log *then* assign, or assign *then* log)
    and every spelling of the platform label in the devlog message. Buckets are
    returned in source order; an empty list means the file has no such ladder.
    """
    buckets: list[OffsetBucket] = []
    matches = [m for m in _BRANCH_RE.finditer(source) if "foundationNumber" in m.group("cond")]
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        body = source[match.end():end]
        assign = _OFFSET_ASSIGN_RE.search(body)
        if assign is None:
            continue
        condition = " ".join(match.group("cond").split())

        major: int | None = None
        is_catch_all = "undefined" in condition
        ge_major = _MAJOR_GE_RE.search(body)
        if ge_major:
            major = int(ge_major.group(1))
        elif not is_catch_all and _MAJOR_LT_RE.search(body):
            is_catch_all = True

        bucket = OffsetBucket(
            offset=int(assign.group(1), 16),
            major=major,
            detail=condition,
            is_catch_all=is_catch_all,
        )
        lower = _LOWER_BOUND_RE.search(condition)
        if lower:
            bucket.lower_bound = float(lower.group(2))
            bucket.lower_inclusive = lower.group(1) == ">="
        upper = _UPPER_BOUND_RE.search(condition)
        if upper:
            bucket.upper_bound = float(upper.group(2))
            bucket.upper_inclusive = upper.group(1) == "<="
        buckets.append(bucket)
    return buckets


def load_offset_tables() -> dict[str, OffsetTable]:
    """Load every offset table friTap currently ships, keyed by table name.

    Names are ``ios`` / ``macos`` for the shared ``minMajor`` tables and
    ``<platform>-legacy`` for a surviving inline CF-number ladder. A legacy ladder is
    reported alongside the shared table on purpose: until it is removed it is the
    code that actually executes on that platform.
    """
    tables: dict[str, OffsetTable] = {}

    if SHARED_TABLE_SOURCE.exists():
        shared_src = SHARED_TABLE_SOURCE.read_text(encoding="utf-8")
        for platform_name, identifier in SHARED_TABLE_IDENTIFIERS.items():
            buckets = parse_min_major_table(shared_src, identifier)
            if buckets:
                tables[platform_name] = OffsetTable(
                    name=platform_name,
                    source=SHARED_TABLE_SOURCE,
                    style="min-major-table",
                    version_axis="iOS" if platform_name == "ios" else "macOS",
                    buckets=buckets,
                )

    for platform_name, path in LEGACY_LADDER_SOURCES.items():
        if not path.exists():
            continue
        buckets = parse_callback_offset_ladder(path.read_text(encoding="utf-8"))
        if not buckets:
            continue
        # A surviving CF ladder is keyed by iOS CF-number thresholds even in the
        # macOS file (its inline comments read "// >= iOS 15.x"), so its axis is iOS.
        name = platform_name if platform_name not in tables else f"{platform_name}-legacy"
        tables[name] = OffsetTable(
            name=name,
            source=path,
            style="cf-ladder",
            version_axis="iOS",
            buckets=buckets,
        )
    return tables


def ios_major_to_axis_major(ios_major: int, version_axis: str) -> int | None:
    """Translate a derived iOS major onto a table's version axis.

    macOS majors are era-matched to iOS ones (macOS 11 <-> iOS 14 ... macOS 15 <->
    iOS 18); from 26 onwards both platforms share the same number. Returns None when
    no defensible mapping exists (e.g. iOS 13 has no macOS twin in the table).
    """
    if version_axis == "iOS":
        return ios_major
    if ios_major >= 26:
        return ios_major
    return IOS_TO_MACOS_ERA.get(ios_major)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def format_table(derived: list[DerivedOffsets]) -> str:
    """Render the human-readable per-runtime table."""
    lines = []
    for item in derived:
        keylog = _hex_or_none(item.keylog_offset) or "unknown"
        info = _hex_or_none(item.info_offset) or "unknown"
        lines.append(
            f"iOS {item.runtime.version} ({item.runtime.build})  "
            f"keylog={keylog}  info={info}  {item.runtime.dylib}"
        )
        for note in item.notes:
            lines.append(f"    ! {note}")
    return "\n".join(lines)


def group_by_major(derived: list[DerivedOffsets]) -> dict[int, dict[int, list[str]]]:
    """Group derived keylog offsets by iOS major version.

    Returns ``{major: {offset: [versions...]}}`` — more than one offset key for a
    major means the runtimes disagree and a single ladder bucket cannot cover it.
    """
    grouped: dict[int, dict[int, list[str]]] = {}
    for item in derived:
        major = item.runtime.major
        if major is None or item.keylog_offset is None:
            continue
        grouped.setdefault(major, {}).setdefault(item.keylog_offset, []).append(item.runtime.version)
    return grouped


def format_suggested_ladder(derived: list[DerivedOffsets]) -> str:
    """Render the 'suggested ladder' summary grouped by major version."""
    grouped = group_by_major(derived)
    if not grouped:
        return "Suggested ladder: no offsets could be derived."
    lines = ["Suggested ladder (grouped by iOS major version):"]
    for major in sorted(grouped):
        for offset, versions in sorted(grouped[major].items()):
            lines.append(
                f"  iOS >= {major}  ->  {_hex_or_none(offset)}"
                f"   (from {', '.join(sorted(versions))})"
            )
        if len(grouped[major]) > 1:
            lines.append(
                f"  ! iOS {major}.x runtimes disagree — one bucket cannot cover this major"
            )
    return "\n".join(lines)


def format_info_fingerprint(derived: list[DerivedOffsets]) -> str:
    """Summarise the SSL_CTX_set_info_callback offsets (struct-layout fingerprint)."""
    offsets: dict[int, list[str]] = {}
    for item in derived:
        if item.info_offset is not None:
            offsets.setdefault(item.info_offset, []).append(item.runtime.version)
    if not offsets:
        return "info_callback fingerprint: unknown"
    parts = [
        f"{_hex_or_none(offset)} ({', '.join(sorted(versions))})"
        for offset, versions in sorted(offsets.items())
    ]
    prefix = "info_callback fingerprint: " if len(offsets) == 1 else "info_callback fingerprint DIFFERS: "
    return prefix + "; ".join(parts)


@dataclass
class CheckResult:
    """Outcome of comparing the derived ground truth against the checked-in tables."""

    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.problems)


def format_table_buckets(table: OffsetTable) -> str:
    """One-line rendering of a table's buckets, for the --check header."""
    buckets = table.by_major
    parts = [f">={m}->{_hex_or_none(buckets[m])}" for m in sorted(buckets, reverse=True)]
    catch_all = table.catch_all_offset
    if catch_all is not None:
        parts.append(f"catch-all->{_hex_or_none(catch_all)}")
    return ", ".join(parts) or "no buckets parsed"


def check_table_structure(table: OffsetTable) -> list[str]:
    """Structural defects of one table that are visible without any device.

    Both checks describe the same failure mode: a bucket that stops applying at a
    hardcoded ceiling, so an OS release past that ceiling silently inherits a
    neighbouring — wrong — offset (fkie-cad/friTap#65).
    """
    problems: list[str] = []
    if not table.by_major:
        problems.append(f"{table.name}: no version-keyed bucket could be parsed from {table.source_label}")
    if not table.top_bucket_is_open_ended:
        top = table.top_bucket
        problems.append(
            f"{table.name}: highest bucket (>={top.major if top else '?'}) is capped at "
            f"{top.upper_bound if top else '?'} — a newer OS release falls through to a "
            "neighbouring offset instead of inheriting this one"
        )
    for bucket in table.buckets:
        if bucket.upper_bound is not None and bucket.upper_inclusive:
            problems.append(
                f"{table.name}: bucket {bucket.label} is capped inclusively at {bucket.upper_bound} "
                "— an inclusive cap pins the bucket to one observed build number, so later "
                "releases of the same major version are stranded in the next bucket"
            )
    return problems


def check_tables_agree(tables: dict[str, OffsetTable]) -> list[str]:
    """Every table must describe the same libboringssl layout for the same era."""
    problems: list[str] = []
    ios_table = tables.get("ios")
    if ios_table is None:
        return problems
    for name in sorted(tables):
        if name == "ios":
            continue
        other = tables[name]
        for ios_major, ios_offset in sorted(ios_table.by_major.items()):
            axis_major = ios_major_to_axis_major(ios_major, other.version_axis)
            if axis_major is None or axis_major not in other.by_major:
                continue
            other_offset = other.by_major[axis_major]
            if other_offset != ios_offset:
                problems.append(
                    f"tables disagree for the iOS {ios_major} era: ios(>={ios_major})="
                    f"{_hex_or_none(ios_offset)} vs {name}(>={axis_major})="
                    f"{_hex_or_none(other_offset)} — the same libboringssl revision cannot "
                    "have two layouts"
                )
    return problems


def check_info_fingerprint(derived: list[DerivedOffsets]) -> list[str]:
    """Runtimes that share a keylog offset must share the info_callback offset too."""
    fingerprints: dict[int, set[int]] = {}
    for item in derived:
        if item.keylog_offset is None or item.info_offset is None:
            continue
        fingerprints.setdefault(item.keylog_offset, set()).add(item.info_offset)
    warnings: list[str] = []
    for keylog_offset, infos in sorted(fingerprints.items()):
        if len(infos) > 1:
            rendered = ", ".join(sorted(_hex_or_none(i) for i in infos))
            warnings.append(
                f"runtimes sharing keylog offset {_hex_or_none(keylog_offset)} report different "
                f"SSL_CTX_set_info_callback offsets ({rendered}) — the struct layout is not "
                "what this table assumes"
            )
    return warnings


def check_against_tables(
    derived: list[DerivedOffsets],
    tables: dict[str, OffsetTable],
    verbose: bool = True,
) -> CheckResult:
    """Compare derived offsets against every checked-in offset table.

    Contradictions (a table would write a different offset than Apple's binary
    stores) are problems and make ``--check`` fail. A derived major that merely
    inherits a *matching* offset from a lower bucket is a warning: an open-ended top
    bucket is intended, a capped one is the bug it replaced.
    """
    result = CheckResult()

    if not tables:
        result.problems.append(
            "no offset table found — neither the shared apple_keylog_offset.ts tables "
            "nor a legacy CALLBACK_OFFSET ladder could be parsed"
        )
        return result

    for name in sorted(tables):
        table = tables[name]
        if verbose:
            print(f"{name} table [{table.style}, keyed by {table.version_axis} major] "
                  f"({table.source_label}): {format_table_buckets(table)}")
        result.problems.extend(check_table_structure(table))
    if verbose:
        print()

    for item in derived:
        major = item.runtime.major
        label = f"iOS {item.runtime.version} ({item.runtime.build})"
        derived_hex = _hex_or_none(item.keylog_offset)

        if item.keylog_offset is None:
            if verbose:
                print(f"  {label}: derived=unknown -> not compared "
                      f"({'; '.join(item.notes) or 'no reason given'})")
            continue
        if major is None:
            result.problems.append(f"{label}: cannot determine major version from '{item.runtime.version}'")
            continue

        for name in sorted(tables):
            table = tables[name]
            axis_major = ios_major_to_axis_major(major, table.version_axis)
            if axis_major is None:
                if verbose:
                    print(f"  {label}: derived={derived_hex}  {name}=<no {table.version_axis} "
                          f"counterpart for iOS {major}>  SKIPPED")
                continue

            offset, bucket = table.offset_for_major(axis_major)
            if offset is None:
                if verbose:
                    print(f"  {label}: derived={derived_hex}  {name}=<no bucket>  GAP")
                result.problems.append(
                    f"{label}: {name} has no bucket at or below {table.version_axis} major {axis_major}"
                )
                continue

            verdict = "OK" if offset == item.keylog_offset else "MISMATCH"
            bucket_label = "catch-all" if bucket is None else f">={bucket}"
            if verbose:
                print(f"  {label}: derived={derived_hex}  "
                      f"{name}({bucket_label})={_hex_or_none(offset)}  {verdict}")
            if offset != item.keylog_offset:
                result.problems.append(
                    f"{label}: {name} bucket {bucket_label} would write {_hex_or_none(offset)} "
                    f"but libboringssl.dylib stores the callback at {derived_hex}"
                )
            elif bucket != axis_major:
                result.warnings.append(
                    f"{label}: {name} has no bucket of its own for {table.version_axis} major "
                    f"{axis_major}; it inherits {bucket_label} (offset matches)"
                )

    result.problems.extend(check_tables_agree(tables))
    result.warnings.extend(check_info_fingerprint(derived))
    return result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _emit_skip(reason: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"status": "skipped", "reason": reason}, indent=2))
    else:
        print(f"SKIP: {reason}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Derive the BoringSSL SSL_CTX keylog callback offset from iOS Simulator runtimes",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the readable table",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare the derived offsets against friTap's checked-in offset tables (for CI)",
    )
    args = parser.parse_args()

    try:
        derived = derive_all()
    except SkipDerivation as exc:
        _emit_skip(str(exc), args.json)
        sys.exit(0)

    tables = load_offset_tables()

    if args.json:
        payload = {
            "status": "ok",
            "arch": ARCH,
            "runtimes": [item.to_dict() for item in derived],
            "by_major": {
                str(major): {_hex_or_none(off): sorted(vers) for off, vers in offsets.items()}
                for major, offsets in sorted(group_by_major(derived).items())
            },
            "tables": {name: table.to_dict() for name, table in sorted(tables.items())},
        }
        if args.check:
            result = check_against_tables(derived, tables, verbose=False)
            payload["problems"] = result.problems
            payload["warnings"] = result.warnings
            print(json.dumps(payload, indent=2))
            sys.exit(1 if result.failed else 0)
        print(json.dumps(payload, indent=2))
        sys.exit(0)

    print(f"Derived from {len(derived)} iOS simulator runtime(s) ({ARCH} slice of {DYLIB_RELATIVE_PATH}):")
    print(format_table(derived))
    print()
    print(format_suggested_ladder(derived))
    print(format_info_fingerprint(derived))

    if not args.check:
        sys.exit(0)

    print()
    print("--check: comparing against friTap's checked-in offset tables")
    print("(buckets are matched by major version, not by CF number — see module docstring)")
    print()
    result = check_against_tables(derived, tables)
    print()
    for warning in result.warnings:
        print(f"  note: {warning}")
    if result.failed:
        if result.warnings:
            print()
        print(f"FAIL: {len(result.problems)} contradiction(s) between the derived ground truth "
              "and the checked-in tables:")
        for problem in result.problems:
            print(f"  - {problem}")
        sys.exit(1)
    print("OK: every derived offset matches the checked-in tables.")
    sys.exit(0)


if __name__ == "__main__":
    main()
