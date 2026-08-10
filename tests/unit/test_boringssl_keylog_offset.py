"""Regression tests for the Apple BoringSSL ``SSL_CTX.keylog_callback`` offset.

Background
----------
Apple does not export ``SSL_CTX_set_keylog_callback``, so friTap hooks the exported
``SSL_CTX_set_info_callback`` and writes its keylog callback *directly into the
SSL_CTX heap struct* at a version-dependent offset (``agent/legacy/tls/shared/
apple_keylog_offset.ts``). A wrong offset clobbers a neighbouring field and kills
the target process — this is what made friTap unusable on iOS (fkie-cad/friTap#65)
while a read-only keylogger kept working. The offset table therefore needs a test.

Ground truth without a device
-----------------------------
iOS Simulator runtimes ship ``/usr/lib/libboringssl.dylib`` as a standalone Mach-O
(on-device it lives inside the stripped dyld shared cache), and
``SSL_CTX_set_keylog_callback`` is a local symbol whose whole body is
``str x1, [x0, #OFFSET]`` + ``ret``. ``dev/derive_boringssl_keylog_offset.py``
extracts that ``#OFFSET`` with ``nm``/``otool``; these tests compare it against the
checked-in table.

Two groups of tests
-------------------
* **Structural** (always run, no macOS needed): parse the checked-in tables and
  assert the invariants that keep the table from rotting — an open-ended top bucket,
  no inclusive version cap, a catch-all, and iOS/macOS agreement era by era.
* **Derived** (macOS + Xcode only, skipped everywhere else): compare every installed
  simulator runtime's real offset against the table. CI runs ``ubuntu-latest``, so
  this group skips there rather than failing.

Install more runtimes to widen the derived coverage::

    xcodebuild -downloadPlatform iOS -buildVersion 16.4
"""

import importlib.util
import os
import shutil
import sys

import pytest

_SCRIPT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "dev",
                 "derive_boringssl_keylog_offset.py")
)


def _load_module():
    spec = importlib.util.spec_from_file_location("derive_boringssl_keylog_offset", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve its module under
    # `from __future__ import annotations`.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


derive = _load_module()

# Platform executors that must NOT reintroduce their own inline offset ladder.
PLATFORM_EXECUTORS = [
    "agent/legacy/tls/platforms/ios/openssl_boringssl_ios.ts",
    "agent/legacy/tls/platforms/macos/openssl_boringssl_macos.ts",
]

# The two tables that ship today. Names come from load_offset_tables().
EXPECTED_TABLE_NAMES = ["ios", "macos"]

_REQUIRED_TOOLS = ("xcrun", "nm", "otool")


#: Populated by _derivation_skip_reason() so the (subprocess-heavy) derivation that
#: decides whether to skip is reused as the test data instead of being redone.
_DERIVED: list | None = None


def _derivation_skip_reason() -> str | None:
    """Why the derived-offset tests cannot run here (None == they can)."""
    global _DERIVED
    if sys.platform != "darwin":
        return f"derivation needs macOS (running on {sys.platform})"
    missing = [tool for tool in _REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        return "missing Xcode command line tool(s): " + ", ".join(missing)
    try:
        _DERIVED = derive.derive_all()
    except derive.SkipDerivation as exc:
        return str(exc)
    if not any(item.ok for item in _DERIVED):
        return "no simulator runtime yielded a keylog offset"
    return None


_SKIP_REASON = _derivation_skip_reason()
requires_simulator_runtimes = pytest.mark.skipif(
    _SKIP_REASON is not None,
    reason=_SKIP_REASON or "",
)


@pytest.fixture(scope="module")
def tables():
    """The offset tables as checked into the repository."""
    return derive.load_offset_tables()


@pytest.fixture(scope="module")
def derived():
    """Offsets derived from every installed iOS simulator runtime."""
    return _DERIVED if _DERIVED is not None else derive.derive_all()


# --------------------------------------------------------------------------- #
# Structural tests — no macOS, no Xcode, no device
# --------------------------------------------------------------------------- #


def test_offset_tables_are_parsable(tables):
    """Both platform tables must be discoverable and non-empty.

    If this fails the table was renamed or reshaped, and every other check in this
    file silently stops testing anything.
    """
    for name in EXPECTED_TABLE_NAMES:
        assert name in tables, (
            f"no '{name}' offset table found; expected "
            f"{derive.SHARED_TABLE_IDENTIFIERS[name]} in "
            f"{derive.SHARED_TABLE_SOURCE.name} or a CALLBACK_OFFSET ladder in the "
            f"{name} executor"
        )
        assert tables[name].by_major, f"'{name}' table has no version-keyed bucket"


@pytest.mark.parametrize("rel_path", PLATFORM_EXECUTORS)
def test_offset_selection_stays_centralized(fritap_root, rel_path):
    """No platform executor may carry its own inline ``CALLBACK_OFFSET`` ladder.

    The per-platform ladders drifted apart (macOS used 0x2F8 where iOS used 0x308 for
    the same libboringssl revision) and neither validated the write. Offset selection
    belongs in ``apple_keylog_offset.ts``, which this suite can check as one table.
    """
    src = (fritap_root / rel_path).read_text(encoding="utf-8")
    assert "CALLBACK_OFFSET" not in src, (
        f"{rel_path} reintroduced an inline CALLBACK_OFFSET ladder; the keylog offset "
        "must come from apple_keylog_offset.ts so it is validated before the write and "
        "covered by dev/derive_boringssl_keylog_offset.py --check."
    )
    assert "installKeylogCallbackViaCtxWrite" in src, (
        f"{rel_path} no longer uses installKeylogCallbackViaCtxWrite; the guarded "
        "installer is what prevents a wrong offset from crashing the target."
    )


@pytest.mark.parametrize("name", EXPECTED_TABLE_NAMES)
def test_table_has_no_stranding_defect(tables, name):
    """The table must not cap a bucket at a hardcoded ceiling.

    Two shapes of the same bug: a capped *top* bucket lets a brand-new OS release
    fall through to a neighbouring offset, and an inclusive cap (``<= 1979.1``) pins a
    bucket to one observed build number so later releases of the same major version
    are stranded in the next bucket.

    Note on the historical case: the pre-fix ladders did NOT actually cap their top
    bucket — both ended in an open ``foundationNumber > 1979.1`` catch-all, which
    froze every later release onto one offset (measured: iOS 18.6/26.2 store at
    0x310 while that branch returned 0x308; macOS 26 at CF 4302.0 got 0x2F8 where
    0x310 was correct). Whether a shipped iOS 16.x also crossed the inclusive cap is
    UNVERIFIED — Apple stopped publishing the CF constants after iOS 9. This test
    guards against both shapes regardless, which is why it stays.
    """
    problems = derive.check_table_structure(tables[name])
    assert problems == [], "; ".join(problems)


@pytest.mark.parametrize("name", EXPECTED_TABLE_NAMES)
def test_table_top_bucket_is_open_ended(tables, name):
    """The newest bucket must apply to every later release, unconditionally."""
    table = tables[name]
    assert table.top_bucket_is_open_ended, (
        f"'{name}' table's highest bucket ({table.top_bucket.label if table.top_bucket else '?'}) "
        "is bounded above — a future OS release would inherit the wrong offset"
    )


@pytest.mark.parametrize("name", EXPECTED_TABLE_NAMES)
def test_table_has_catch_all_bucket(tables, name):
    """A version-detection failure must land on a defined offset, not on nothing."""
    assert tables[name].catch_all_offset is not None, (
        f"'{name}' table has no catch-all bucket; if the OS version cannot be detected "
        "the lookup has no defined result"
    )


@pytest.mark.parametrize("name", EXPECTED_TABLE_NAMES)
def test_table_bucket_majors_are_unique(tables, name):
    """A duplicated bucket boundary means one of the two entries is dead code."""
    majors = [b.major for b in tables[name].buckets if b.major is not None and not b.is_catch_all]
    assert len(majors) == len(set(majors)), f"'{name}' table has duplicate bucket boundaries: {majors}"


def test_ios_and_macos_tables_agree_era_by_era(tables):
    """Both platforms ship the same libboringssl revision per year — one layout.

    macOS 11 <-> iOS 14 ... macOS 15 <-> iOS 18, and both platforms share the number
    from 26 onwards. A disagreement means at least one of the two is wrong.
    """
    problems = derive.check_tables_agree(tables)
    assert problems == [], "; ".join(problems)


def test_ios_and_macos_tables_cover_the_same_eras(tables):
    """Neither platform may be missing a bucket the other one has.

    A missing bucket is not a compile error — it just silently resolves to the next
    lower offset — so the symmetry has to be asserted.
    """
    ios_eras = set(tables["ios"].by_major)
    macos_eras = {
        macos_major
        for ios_major in ios_eras
        if (macos_major := derive.ios_major_to_axis_major(ios_major, "macOS")) is not None
    }
    covered = set(tables["macos"].by_major)
    assert covered == macos_eras, (
        f"macOS table covers {sorted(covered)} but the iOS table's eras map to "
        f"{sorted(macos_eras)}; add the missing bucket(s) explicitly"
    )


def test_derivation_skips_cleanly_off_macos():
    """The deriver must never *fail* where it cannot run (e.g. Linux CI).

    ``--check`` runs in CI; on a non-macOS runner it has to skip with exit 0.
    """
    reason = derive.environment_skip_reason()
    if sys.platform != "darwin":
        assert reason is not None, "environment_skip_reason() must refuse to derive off macOS"
        with pytest.raises(derive.SkipDerivation):
            derive.derive_all()
    else:
        # On macOS the reason may still be set (no Xcode); it must be a string then.
        assert reason is None or isinstance(reason, str)


def test_store_offset_parser_rejects_unexpected_bodies():
    """A body that is not exactly ``str x1, [x0, #imm]`` + ``ret`` must not yield a guess.

    A mis-parsed offset would be written into a live SSL_CTX, so "unknown" is the only
    acceptable answer for anything unfamiliar.
    """
    good = (
        "lib.dylib:\n(__TEXT,__text) section\n"
        "_SSL_CTX_set_keylog_callback:\n"
        "0000000000055064\tstr\tx1, [x0, #0x308]\n"
        "0000000000055068\tret\n"
    )
    offset, error = derive.parse_store_offset(good, "_SSL_CTX_set_keylog_callback")
    assert (offset, error) == (0x308, None)

    wrong_register = good.replace("x1, [x0, #0x308]", "x2, [x0, #0x308]")
    offset, error = derive.parse_store_offset(wrong_register, "_SSL_CTX_set_keylog_callback")
    assert offset is None and error

    not_a_leaf = good.replace("0000000000055068\tret", "0000000000055068\tb\t0x1234")
    offset, error = derive.parse_store_offset(not_a_leaf, "_SSL_CTX_set_keylog_callback")
    assert offset is None and error

    missing_symbol = good.replace("_SSL_CTX_set_keylog_callback:", "_something_else:")
    offset, error = derive.parse_store_offset(missing_symbol, "_SSL_CTX_set_keylog_callback")
    assert offset is None and error


def test_legacy_cf_ladder_parser_still_understands_the_old_shape():
    """Keep the legacy-ladder parser honest so a revert cannot go unnoticed.

    If someone restores an inline ``CALLBACK_OFFSET`` ladder, ``--check`` must still be
    able to read it (and flag its inclusive cap) instead of reporting "no table".
    """
    ladder = """
            if(foundationNumber == undefined){
                devlog("Installing callback for iOS < 14");
                CALLBACK_OFFSET = 0x2A8;
            } else if (foundationNumber >= 1946.102 && foundationNumber <= 1979.1) {
                devlog("Installing callback for iOS >= 16");
                CALLBACK_OFFSET = 0x300;
            } else if (foundationNumber > 1979.1) {
                devlog("Installing callback for iOS >= 17");
                CALLBACK_OFFSET = 0x308;
            }
    """
    buckets = derive.parse_callback_offset_ladder(ladder)
    assert [b.major for b in buckets] == [None, 16, 17]
    assert [b.offset for b in buckets] == [0x2A8, 0x300, 0x308]
    assert buckets[0].is_catch_all
    assert buckets[1].upper_bound == 1979.1 and buckets[1].upper_inclusive

    table = derive.OffsetTable(
        name="legacy-sample",
        source=derive.IOS_SOURCE,
        style="cf-ladder",
        version_axis="iOS",
        buckets=buckets,
    )
    problems = derive.check_table_structure(table)
    assert any("capped inclusively" in p for p in problems), (
        "the inclusive CF cap that stranded late iOS 16.x releases must be reported"
    )


# --------------------------------------------------------------------------- #
# Derived tests — macOS with simulator runtimes only
# --------------------------------------------------------------------------- #


@requires_simulator_runtimes
def test_derived_runtimes_yield_offsets(derived):
    """Sanity check on the derivation itself before we compare anything."""
    assert derived, "derive_all() returned no runtimes"
    resolved = [item for item in derived if item.ok]
    assert resolved, "no runtime yielded a keylog offset"
    for item in resolved:
        assert item.runtime.major is not None
        # Offsets live inside the SSL_CTX struct; a wild value means a parse escape.
        assert 0x100 <= item.keylog_offset <= 0x1000, (
            f"iOS {item.runtime.version}: implausible keylog offset "
            f"{item.keylog_offset:#x}"
        )


@requires_simulator_runtimes
@pytest.mark.parametrize("name", EXPECTED_TABLE_NAMES)
def test_table_matches_every_derived_runtime(tables, derived, name):
    """The checked-in table must resolve to the offset Apple's binary actually uses.

    macOS buckets are compared through the era mapping (macOS 14 <-> iOS 17, ...),
    since simulator runtimes only prove the iOS layout.
    """
    table = tables[name]
    for item in derived:
        if not item.ok:
            continue
        axis_major = derive.ios_major_to_axis_major(item.runtime.major, table.version_axis)
        if axis_major is None:
            continue  # no defensible counterpart on this axis
        offset, bucket = table.offset_for_major(axis_major)
        assert offset is not None, (
            f"'{name}' table has no bucket for {table.version_axis} major {axis_major} "
            f"(iOS {item.runtime.version})"
        )
        assert offset == item.keylog_offset, (
            f"'{name}' table bucket >={bucket} would write {offset:#x} into SSL_CTX, but "
            f"iOS {item.runtime.version} ({item.runtime.build}) libboringssl.dylib stores "
            f"the keylog callback at {item.keylog_offset:#x}"
        )


@requires_simulator_runtimes
def test_every_derived_major_resolves_to_a_bucket(tables, derived):
    """No derived OS version may fall off the end of the table."""
    for name, table in tables.items():
        for item in derived:
            if not item.ok:
                continue
            axis_major = derive.ios_major_to_axis_major(item.runtime.major, table.version_axis)
            if axis_major is None:
                continue
            offset, _bucket = table.offset_for_major(axis_major)
            assert offset is not None, (
                f"'{name}' table cannot resolve an offset for {table.version_axis} major "
                f"{axis_major} (derived from iOS {item.runtime.version})"
            )


@requires_simulator_runtimes
def test_check_reports_no_contradiction(tables, derived):
    """The full ``--check`` comparison must be clean against the checked-in tables."""
    result = derive.check_against_tables(derived, tables, verbose=False)
    assert not result.failed, "\n".join(result.problems)


@requires_simulator_runtimes
def test_info_callback_offset_is_a_stable_fingerprint(derived):
    """Runtimes sharing a keylog offset must share the info_callback offset.

    ``SSL_CTX_set_info_callback`` is the function friTap hooks; its field offset is a
    cheap witness that the surrounding struct layout is the one the table assumes.
    """
    warnings = derive.check_info_fingerprint(derived)
    assert warnings == [], "; ".join(warnings)
