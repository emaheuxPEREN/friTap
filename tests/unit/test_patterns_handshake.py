"""
Unit tests for the Python -> Agent pattern handshake boundary.

The agent's `isPatternReplaced()` gate and `typeof === "string"` boundary
check rely on guarantees about what the host posts in `config_batch`
under the `patterns` key. These tests pin those guarantees so future
changes that would silently disable pattern hooking - or crash the agent
at startup - are caught at CI time.
"""

import json
import logging
from unittest.mock import MagicMock

import pytest

from friTap.patterns.loader import PatternLoader


# Mirrors the agent-side `PATTERNS_PLACEHOLDER` constant. Duplicated on
# purpose so a rename in the agent (which would change the boundary
# semantics) is caught here instead of silently shipping.
PATTERNS_PLACEHOLDER = "{PATTERNS}"


@pytest.fixture
def fritap_logger():
    return logging.getLogger("friTap")


@pytest.fixture(scope="module")
def default_payload():
    return PatternLoader.load(None, logging.getLogger("friTap"))


class TestPatternLoaderReturnType:

    def test_returns_string_or_none(self, fritap_logger):
        result = PatternLoader.load(None, fritap_logger)
        assert isinstance(result, (str, type(None)))

    def test_default_string_longer_than_agent_placeholder(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        assert len(default_payload) > len(PATTERNS_PLACEHOLDER)

    def test_returned_string_does_not_equal_placeholder(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        assert default_payload != PATTERNS_PLACEHOLDER


class TestDefaultPayloadIntegrity:

    def test_default_json_round_trips(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        parsed = json.loads(default_payload)
        assert isinstance(parsed, dict)

    def test_default_has_real_library_keys(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        parsed = json.loads(default_payload)
        non_meta_keys = [k for k in parsed.keys() if not k.startswith("_")]
        assert len(non_meta_keys) > 0


class TestPatternLoaderDegradation:

    def test_missing_user_file_does_not_raise(self, fritap_logger):
        result = PatternLoader.load(
            "/nonexistent/path/does/not/exist.json", fritap_logger
        )
        assert isinstance(result, (str, type(None)))

    def test_missing_user_file_warns(self):
        """A typo'd --patterns path must not be swallowed silently.

        Historically ``load`` guarded on ``patterns_path is not None and
        os.path.exists(...)`` with no ``else``, so a non-existent path produced
        no diagnostic at all - the run silently continued on defaults, looking
        exactly like a successful merge.
        """
        logger = MagicMock()
        missing = "/nonexistent/path/does/not/exist.json"

        PatternLoader.load(missing, logger)

        warnings = [call.args for call in logger.warning.call_args_list]
        assert any(
            missing in call_args and "does not exist" in call_args[0]
            for call_args in warnings
        ), f"no missing-path warning naming {missing!r}; got {warnings!r}"
        # A missing file is a user-facing mistake, not an exception path.
        logger.error.assert_not_called()

    def test_missing_user_file_does_not_claim_a_merge(self):
        logger = MagicMock()

        PatternLoader.load("/nonexistent/path/does/not/exist.json", logger)

        infos = [call.args for call in logger.info.call_args_list]
        assert not any("Merged user patterns" in a[0] for a in infos if a), infos

    def test_invalid_user_json_does_not_raise(self, fritap_logger, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ this is not valid JSON")
        result = PatternLoader.load(str(bad_file), fritap_logger)
        assert isinstance(result, (str, type(None)))


class TestUserOverrideMerge:

    def test_user_override_merges_into_defaults(
        self, fritap_logger, default_payload, tmp_path
    ):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        defaults_parsed = json.loads(default_payload)

        user_file = tmp_path / "user.json"
        # Modern Schema A requires an OS layer: library -> os -> arch -> function.
        user_file.write_text(json.dumps({
            "my_custom_lib": {
                "android": {
                    "x64": {"my_func": ["48 89 E5"]},
                }
            }
        }))

        merged = PatternLoader.load(str(user_file), fritap_logger)
        assert isinstance(merged, str)
        merged_parsed = json.loads(merged)

        assert "my_custom_lib" in merged_parsed
        assert merged_parsed["my_custom_lib"]["android"]["x64"]["my_func"] == ["48 89 E5"]

        for k in defaults_parsed:
            if k.startswith("_"):
                continue
            assert k in merged_parsed


class TestSSLLoggerWireContract:

    def test_pattern_data_is_str_or_none_after_init(self, ssl_logger_factory):
        logger = ssl_logger_factory()
        assert isinstance(logger.pattern_data, (str, type(None)))

    def test_pattern_data_default_is_distinguishable_from_placeholder(
        self, ssl_logger_factory
    ):
        logger = ssl_logger_factory()
        if logger.pattern_data is None:
            pytest.skip("pattern_data is None")
        assert logger.pattern_data != PATTERNS_PLACEHOLDER
        assert len(logger.pattern_data) > len(PATTERNS_PLACEHOLDER)


# A minimal but schema-valid modern pattern file: library -> os -> arch -> func.
_VALID_USER_PATTERNS = {
    "my_custom_lib": {"android": {"x64": {"my_func": ["48 89 E5"]}}}
}


@pytest.fixture
def user_patterns_file(tmp_path):
    path = tmp_path / "user_patterns.json"
    path.write_text(json.dumps(_VALID_USER_PATTERNS))
    return path


class TestPatternSourceAttribution:
    """``pattern_data`` being non-None does NOT mean the user supplied a file.

    ``PatternLoader.load`` unconditionally merges the shipped
    ``friTap/patterns/default_patterns.json``, so on any normal checkout
    ``pattern_data`` is a non-None string even with no ``--patterns`` flag. The
    instrument-time log line used to read "Using pattern provided by
    pattern.json for hooking", which credited the user with a file they never
    passed. A pattern scan genuinely *is* live in that case (the agent registers
    a PatternStrategy whenever patternData is truthy), so only the attribution
    was wrong - the message must stay, correctly labelled.
    """

    def test_default_run_names_the_bundled_defaults(self, ssl_logger_factory):
        logger = ssl_logger_factory()
        assert logger.patterns is None

        message = logger._describe_pattern_source()

        assert "bundled default" in message

    def test_default_run_does_not_claim_a_user_file(self, ssl_logger_factory):
        logger = ssl_logger_factory()

        message = logger._describe_pattern_source()

        # The historical wording named a file the user never passed.
        assert "pattern.json" not in message
        assert "provided by" not in message

    def test_user_patterns_run_names_the_user_file(
        self, ssl_logger_factory, user_patterns_file
    ):
        logger = ssl_logger_factory(patterns=str(user_patterns_file))
        assert logger.patterns == str(user_patterns_file)

        message = logger._describe_pattern_source()

        assert str(user_patterns_file) in message

    def test_user_patterns_run_still_mentions_the_defaults_merge(
        self, ssl_logger_factory, user_patterns_file
    ):
        """The user file is merged *over* the defaults, never a replacement."""
        logger = ssl_logger_factory(patterns=str(user_patterns_file))

        message = logger._describe_pattern_source()

        assert "default" in message

    def test_instrument_logs_the_attributed_message(self, fritap_root):
        """Lock the log site to the helper so the old wording cannot return."""
        source = (fritap_root / "friTap" / "legacy" / "ssl_logger_core.py").read_text()

        assert "Using pattern provided by pattern.json for hooking" not in source
        assert "self.logger.info(self._describe_pattern_source())" in source
