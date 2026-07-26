"""Tests for the developer-experience CLI commands: `umbra init` + `umbra completion`."""
from __future__ import annotations

from umbra_core import load_contract
from umbra_core.cli import main as cli_main


def test_init_scaffolds_a_loadable_contract(tmp_path, capsys):
    rc = cli_main(["init", str(tmp_path)])
    assert rc == 0
    dest = tmp_path / ".umbra" / "admission.yaml"
    assert dest.is_file()
    out = capsys.readouterr().out
    assert "wrote" in out and str(dest) in out

    # The scaffolded contract parses through the real loader (no crash, real scope).
    c = load_contract(tmp_path)
    assert c.source == "repo"
    assert "package.json" in c.allowed_paths
    assert ".github/workflows/**" in c.forbidden_paths
    assert c.required_checks == ("npm test",)
    # The v2 capability graph is commented out in the starter → not active.
    assert c.has_capability_graph is False


def test_init_refuses_overwrite_without_force(tmp_path):
    assert cli_main(["init", str(tmp_path)]) == 0
    # Second run must not clobber the (possibly edited) contract.
    assert cli_main(["init", str(tmp_path)]) == 1


def test_init_force_overwrites(tmp_path):
    dest = tmp_path / ".umbra" / "admission.yaml"
    dest.parent.mkdir(parents=True)
    dest.write_text("version: 1\n")
    assert cli_main(["init", str(tmp_path), "--force"]) == 0
    assert "task_type" in dest.read_text()  # replaced with the starter


def test_init_defaults_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli_main(["init"]) == 0
    assert (tmp_path / ".umbra" / "admission.yaml").is_file()


def test_completion_emits_for_each_shell(capsys):
    for shell, marker in (("bash", "complete -"), ("zsh", "compdef"), ("fish", "complete -c umbra")):
        assert cli_main(["completion", shell]) == 0
        out = capsys.readouterr().out
        assert marker in out
        assert "admit" in out and "guard" in out
