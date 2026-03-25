"""Tests for the CLI interface."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def run_ipanon(*args: str, stdin: str = "", check: bool = True) -> subprocess.CompletedProcess:
    """Run ipanon CLI with given arguments."""
    cmd = [sys.executable, "-m", "ipanon.cli", *args]
    result = subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return result


class TestCLIBasic:
    """Basic CLI operation."""

    def test_stdin_stdout(self):
        result = run_ipanon("--salt", "test", stdin="host 8.8.8.8\n")
        assert "8.8.8.8" not in result.stdout
        assert result.returncode == 0

    def test_file_input_output(self, tmp_path: Path):
        in_file = tmp_path / "input.txt"
        out_file = tmp_path / "output.txt"
        in_file.write_text("server 10.0.0.1\n")
        run_ipanon("--salt", "test", str(in_file), str(out_file))
        output = out_file.read_text()
        assert "10.0.0.1" not in output
        assert "server" in output

    def test_deterministic_with_salt(self):
        r1 = run_ipanon("--salt", "mysalt", stdin="host 8.8.8.8\n")
        r2 = run_ipanon("--salt", "mysalt", stdin="host 8.8.8.8\n")
        assert r1.stdout == r2.stdout

    def test_random_salt_printed_to_stderr(self):
        result = run_ipanon(stdin="host 8.8.8.8\n")
        assert "Generated salt:" in result.stderr


class TestCLIRemap:
    """--remap flag handling."""

    def test_remap_flag(self):
        result = run_ipanon("--salt", "test", "--remap", "172=42", stdin="host 172.15.0.1\n")
        assert "42." in result.stdout
        assert result.returncode == 0

    def test_remap_invalid_target(self):
        result = run_ipanon(
            "--salt", "test", "--remap", "172=10", stdin="host 172.15.0.1\n", check=False
        )
        assert result.returncode != 0
        assert "pure-public" in result.stderr

    def test_remap_invalid_source(self):
        result = run_ipanon(
            "--salt", "test", "--remap", "8=42", stdin="host 8.8.8.8\n", check=False
        )
        assert result.returncode != 0
        assert "mixed" in result.stderr

    def test_remap_bad_format(self):
        result = run_ipanon("--salt", "test", "--remap", "bad", stdin="test\n", check=False)
        assert result.returncode != 0


class TestCLIPassThrough:
    """--pass-through flag handling."""

    def test_pass_through(self):
        result = run_ipanon(
            "--salt", "test", "--pass-through", "8.8.8.0/24", stdin="host 8.8.8.8\n"
        )
        assert "8.8.8.8" in result.stdout

    def test_multiple_pass_through(self):
        result = run_ipanon(
            "--salt",
            "test",
            "--pass-through",
            "8.8.8.0/24",
            "--pass-through",
            "1.1.1.0/24",
            stdin="dns 8.8.8.8 and 1.1.1.1\n",
        )
        assert "8.8.8.8" in result.stdout
        assert "1.1.1.1" in result.stdout


class TestCLIMapping:
    """--mapping flag for JSON output."""

    def test_mapping_output(self, tmp_path: Path):
        mapping_file = tmp_path / "mapping.json"
        run_ipanon(
            "--salt", "test", "--mapping", str(mapping_file), stdin="host 10.0.0.1 and 10.0.0.2\n"
        )
        mapping = json.loads(mapping_file.read_text())
        assert "10.0.0.1" in mapping
        assert "10.0.0.2" in mapping


class TestCLIVerbose:
    """--verbose flag."""

    def test_verbose_stats(self):
        result = run_ipanon("--salt", "test", "-v", stdin="host 8.8.8.8 and 10.0.0.1\n")
        assert result.returncode == 0
        # Verbose should print stats to stderr
        assert "processed" in result.stderr.lower() or "ips" in result.stderr.lower()

    def test_very_verbose_prints_all_mappings(self):
        result = run_ipanon("--salt", "test", "-vv", stdin="host 8.8.8.8 and 10.0.0.1\n")
        assert result.returncode == 0
        # -vv should print each mapping to stderr
        assert "8.8.8.8 -> " in result.stderr or "8.8.8.8 → " in result.stderr
        assert "10.0.0.1 -> " in result.stderr or "10.0.0.1 → " in result.stderr

    def test_very_verbose_includes_stats(self):
        result = run_ipanon("--salt", "test", "-vv", stdin="host 8.8.8.8\n")
        assert result.returncode == 0
        # -vv should also include the stats line
        assert "processed" in result.stderr.lower() or "ips" in result.stderr.lower()

    def test_verbose_shows_short_prefix_warning(self):
        result = run_ipanon("--salt", "test", "-v", stdin="host 64.0.0.0/2\n")
        assert result.returncode == 0
        assert "Cannot anonymize short prefix" in result.stderr

    def test_no_short_prefix_warning_by_default(self):
        result = run_ipanon("--salt", "test", stdin="host 64.0.0.0/2\n")
        assert result.returncode == 0
        assert "WARNING" not in result.stderr


class TestCLIQuiet:
    """--quiet flag suppresses warnings."""

    def test_quiet_suppresses_mixed_octet_warning(self):
        result = run_ipanon("--salt", "test", "-q", stdin="host 172.15.0.1\n")
        assert result.returncode == 0
        assert "WARNING" not in result.stderr

    def test_quiet_suppresses_short_prefix_warning(self):
        result = run_ipanon("--salt", "test", "--quiet", "-v", stdin="host 64.0.0.0/2\n")
        assert result.returncode == 0
        assert "WARNING" not in result.stderr

    def test_quiet_does_not_suppress_errors(self):
        result = run_ipanon("--salt", "test", "-q", "--remap", "8=42", stdin="test\n", check=False)
        assert result.returncode != 0

    def test_quiet_overrides_verbose(self):
        """When both -q and -v are given, quiet wins — no stats output."""
        result = run_ipanon("--salt", "test", "-q", "-v", stdin="host 8.8.8.8\n")
        assert result.returncode == 0
        assert result.stderr == ""


class TestCLISaltEnv:
    """--salt-env flag reads salt from environment variable."""

    def test_salt_env_reads_from_env(self):
        env = os.environ.copy()
        env["MY_SALT"] = "envsalt"
        cmd = [sys.executable, "-m", "ipanon.cli", "--salt-env", "MY_SALT"]
        r1 = subprocess.run(
            cmd, input="host 8.8.8.8\n", capture_output=True, text=True, check=True, env=env
        )
        r2 = run_ipanon("--salt", "envsalt", stdin="host 8.8.8.8\n")
        assert r1.stdout == r2.stdout

    def test_salt_env_missing_var_errors(self):
        result = run_ipanon(
            "--salt-env", "NONEXISTENT_SALT_VAR_12345", stdin="test\n", check=False
        )
        assert result.returncode != 0
        assert "NONEXISTENT_SALT_VAR_12345" in result.stderr

    def test_salt_env_empty_var_errors(self):
        env = os.environ.copy()
        env["EMPTY_SALT"] = ""
        cmd = [sys.executable, "-m", "ipanon.cli", "--salt-env", "EMPTY_SALT"]
        result = subprocess.run(
            cmd, input="test\n", capture_output=True, text=True, check=False, env=env
        )
        assert result.returncode != 0
        assert "EMPTY_SALT" in result.stderr

    def test_salt_and_salt_env_mutually_exclusive(self):
        result = run_ipanon("--salt", "test", "--salt-env", "MY_SALT", stdin="test\n", check=False)
        assert result.returncode != 0


class TestCLIIgnoreSubnets:
    """--ignore-subnets flag handling."""

    def test_flag_accepted(self):
        result = run_ipanon("--salt", "test", "--ignore-subnets", stdin="host 8.8.8.8\n")
        assert result.returncode == 0

    def test_private_172_anonymized_as_public(self):
        result = run_ipanon("--salt", "test", "--ignore-subnets", stdin="host 172.16.0.1\n")
        assert result.returncode == 0
        assert "172.16.0.1" not in result.stdout

    def test_10_still_range_preserved(self):
        result = run_ipanon("--salt", "test", "--ignore-subnets", stdin="host 10.1.2.3\n")
        assert result.returncode == 0
        # Output should still have an IP starting with 10.
        assert "10." in result.stdout

    def test_remap_172_fails(self):
        result = run_ipanon(
            "--salt",
            "test",
            "--ignore-subnets",
            "--remap",
            "172=42",
            stdin="test\n",
            check=False,
        )
        assert result.returncode != 0
        assert "mixed" in result.stderr


class TestCLIIgnoreReserved:
    """--ignore-reserved flag handling."""

    def test_flag_accepted(self):
        result = run_ipanon("--salt", "test", "--ignore-reserved", stdin="host 8.8.8.8\n")
        assert result.returncode == 0

    def test_loopback_anonymized(self):
        result = run_ipanon("--salt", "test", "--ignore-reserved", stdin="host 127.0.0.1\n")
        assert result.returncode == 0
        assert "127.0.0.1" not in result.stdout

    def test_private_10_anonymized(self):
        result = run_ipanon("--salt", "test", "--ignore-reserved", stdin="host 10.1.2.3\n")
        assert result.returncode == 0
        assert "10.1.2.3" not in result.stdout

    def test_combined_with_pass_through(self):
        result = run_ipanon(
            "--salt",
            "test",
            "--ignore-reserved",
            "--pass-through",
            "10.0.0.0/8",
            stdin="host 10.1.2.3 and 127.0.0.1\n",
        )
        assert result.returncode == 0
        assert "10.1.2.3" in result.stdout  # Pass-through
        assert "127.0.0.1" not in result.stdout  # Anonymized
