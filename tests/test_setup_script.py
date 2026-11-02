"""scripts/setup-mcp.sh: prompts, validation, server check, registration, launch.

The real Claude Code CLI is replaced by a stub that records its arguments, so
these tests prove what the script *asks Claude Code to do* (and that secrets
never reach the terminal), not how a real Claude Code reacts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "setup-mcp.sh"

CLAUDE_STUB = """#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case "${1:-} ${2:-}" in
  "mcp get") [ -f "$STUB_STATE" ] && exit 0 || exit 1 ;;
  "mcp add") touch "$STUB_STATE" ;;
  "mcp remove") rm -f "$STUB_STATE" ;;
esac
exit 0
"""
FAILING_UV = "#!/usr/bin/env bash\necho 'uv: simulated failure' >&2\nexit 1\n"

ACCESS = "tenable-access-SECRET1"
SECRET = "tenable-secret-SECRET2"
GREY = "greynoise-key-SECRET3"


class Run:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        claude = self.bin / "claude"
        claude.write_text(CLAUDE_STUB)
        claude.chmod(0o755)
        self.log = tmp_path / "claude.log"
        self.state = tmp_path / "claude.state"
        self.import_dir = tmp_path / "data" / "imports"
        self.reports_dir = tmp_path / "data" / "reports"
        self.db = tmp_path / "data" / "riskproof.db"
        self.inventory = tmp_path / "data" / "assets.json"

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("RISKPROOF_", "TENABLE_", "GREYNOISE_"))
        }
        env["PATH"] = f"{self.bin}{os.pathsep}{env['PATH']}"
        env["STUB_LOG"] = str(self.log)
        env["STUB_STATE"] = str(self.state)
        env.update(
            RISKPROOF_IMPORT_DIR=str(self.import_dir),
            RISKPROOF_REPORTS_DIR=str(self.reports_dir),
            RISKPROOF_DB_PATH=str(self.db),
            RISKPROOF_ASSET_INVENTORY=str(self.inventory),
        )
        env.update(extra)
        return env

    def run(self, *args: str, stdin: str = "", **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            input=stdin,
            capture_output=True,
            text=True,
            env=self.env(**env),
            timeout=180,
            check=False,
        )

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def add_call(self) -> str:
        return next(c for c in self.calls() if c.startswith("mcp add"))


@pytest.fixture()
def sut(tmp_path: Path) -> Run:
    if shutil.which("uv") is None:
        pytest.skip("uv is required for the server check")
    return Run(tmp_path)


def test_yes_mode_registers_with_defaults_from_environment(sut: Run):
    result = sut.run("--yes", "--no-launch")
    assert result.returncode == 0, result.stderr
    add = sut.add_call()
    assert add.startswith("mcp add riskproof -s local")
    for expected in (
        f"RISKPROOF_IMPORT_DIR={sut.import_dir}",
        f"RISKPROOF_REPORTS_DIR={sut.reports_dir}",
        f"RISKPROOF_DB_PATH={sut.db}",
        f"RISKPROOF_ASSET_INVENTORY={sut.inventory}",
    ):
        assert expected in add
    assert "TENABLE_" not in add and "GREYNOISE_" not in add
    assert "RISKPROOF_ALLOWED_TARGETS" not in add and "RISKPROOF_OFFLINE" not in add
    assert add.endswith(f"-- uv --directory {REPO} run riskproof serve")
    assert "Server check passed" in result.stdout
    assert not any(c == "" or c.startswith("LAUNCH") for c in sut.calls())


def test_data_directories_created_owner_only(sut: Run):
    assert sut.run("--yes", "--no-launch").returncode == 0
    for d in (sut.import_dir, sut.reports_dir):
        assert d.is_dir() and (d.stat().st_mode & 0o777) == 0o700
    assert not sut.db.exists()  # the check uses a throwaway database, never the real one


def test_prompts_collect_every_setting_and_secrets_never_echo(sut: Run):
    custom_imports = sut.tmp / "my imports"
    answers = [
        str(custom_imports),  # import dir
        "",  # reports dir -> default
        "",  # database -> default
        "",  # asset inventory -> default
        "10.0.0.0/24, build-01.corp.example",  # allowlist (spaces tolerated)
        "y",  # offline
        ACCESS,
        SECRET,
        GREY,
        "n",  # open Claude Code now?
    ]
    result = sut.run(stdin="\n".join(answers) + "\n")
    assert result.returncode == 0, result.stderr
    add = sut.add_call()
    assert f"RISKPROOF_IMPORT_DIR={custom_imports}" in add
    assert "RISKPROOF_ALLOWED_TARGETS=10.0.0.0/24,build-01.corp.example" in add
    assert "RISKPROOF_OFFLINE=true" in add
    assert f"TENABLE_ACCESS_KEY={ACCESS}" in add  # handed to Claude Code's config only
    assert f"GREYNOISE_API_KEY={GREY}" in add
    for secret in (ACCESS, SECRET, GREY):
        assert secret not in result.stdout and secret not in result.stderr
    assert "LAUNCH" not in "\n".join(sut.calls())


def test_secrets_from_environment_skip_prompts(sut: Run):
    result = sut.run(
        "--yes",
        "--no-launch",
        TENABLE_ACCESS_KEY=ACCESS,
        TENABLE_SECRET_KEY=SECRET,
        GREYNOISE_API_KEY=GREY,
    )
    assert result.returncode == 0, result.stderr
    add = sut.add_call()
    assert f"TENABLE_SECRET_KEY={SECRET}" in add and f"GREYNOISE_API_KEY={GREY}" in add
    for secret in (ACCESS, SECRET, GREY):
        assert secret not in result.stdout and secret not in result.stderr
    assert "Tenable   : set" in result.stdout and "GreyNoise : set" in result.stdout


def test_only_one_tenable_key_is_refused(sut: Run):
    result = sut.run("--yes", "--no-launch", TENABLE_ACCESS_KEY=ACCESS)
    assert result.returncode != 0
    assert "both" in result.stderr.lower()
    assert ACCESS not in result.stderr
    assert not any(c.startswith("mcp add") for c in sut.calls())


@pytest.mark.parametrize(
    ("env", "needle"),
    [
        ({"RISKPROOF_ALLOWED_TARGETS": "10.0.0.1;rm -rf /"}, "allowlist"),
        ({"RISKPROOF_IMPORT_DIR": "relative/dir"}, "absolute"),
        ({"GREYNOISE_API_KEY": "has space"}, "whitespace"),
    ],
)
def test_invalid_input_is_refused_before_anything_is_registered(sut: Run, env, needle):
    result = sut.run("--yes", "--no-launch", **env)
    assert result.returncode != 0
    assert needle in result.stderr.lower()
    assert "has space" not in result.stderr
    assert not any(c.startswith("mcp add") for c in sut.calls())


def test_failed_server_check_stops_before_registering(sut: Run):
    uv = sut.bin / "uv"
    uv.write_text(FAILING_UV)
    uv.chmod(0o755)
    result = sut.run("--yes", "--no-launch")
    assert result.returncode != 0
    assert "server check failed" in result.stderr.lower()
    assert not any(c.startswith("mcp add") for c in sut.calls())


def test_rerun_replaces_existing_registration(sut: Run):
    assert sut.run("--yes", "--no-launch").returncode == 0
    assert sut.run("--yes", "--no-launch").returncode == 0
    kinds = [c.split()[1] for c in sut.calls() if c.startswith("mcp ") and c.split()[1] != "get"]
    assert kinds == ["add", "remove", "add"]


def test_launch_prompt_yes_starts_claude_in_the_same_folder(sut: Run):
    answers = ["", "", "", "", "", "", "", "", "y"]  # defaults, no keys, launch
    result = sut.run(stdin="\n".join(answers) + "\n")
    assert result.returncode == 0, result.stderr
    assert sut.calls()[-1] == ""  # `claude` run with no arguments


def test_no_launch_flag_never_starts_claude(sut: Run):
    result = sut.run("--no-launch", stdin="\n" * 8)
    assert result.returncode == 0, result.stderr
    assert "" not in sut.calls()


def test_help_and_unknown_flag(sut: Run):
    assert "--yes" in sut.run("--help").stdout
    assert sut.run("--bogus").returncode != 0
