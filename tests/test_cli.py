import logging
import os
import subprocess
import sys

import pytest

from aristotle import aristotle as mod
from aristotle.aristotle import AristotleException

from .conftest import REPO_ROOT, SMALL_RULES, strip_ansi


@pytest.fixture
def run_main(monkeypatch, capsys):
    """Run aristotle.main() with the given argv; returns (exit_code_or_None, stdout)."""
    def _run(*argv):
        monkeypatch.setattr(sys, "argv", ["aristotle"] + list(argv))
        code = None
        try:
            mod.main()
        except SystemExit as e:
            code = e.code
        return code, strip_ansi(capsys.readouterr().out)
    return _run


class TestParser:
    def test_defaults(self):
        args = mod.get_parser().parse_args(["-r", "x.rules"])
        assert args.rules == "x.rules"
        assert args.metadata_filter is None
        assert args.display_max == -1
        assert args.outfile == "<stdout>"
        assert args.stats is None
        assert args.enable_all_rules is False
        assert args.output_disabled_rules is False
        assert args.normalize is False
        assert args.enhance is False
        assert args.ignore_classtype_keyword is False
        assert args.ignore_filename is False
        assert args.modify_metadata is False
        assert args.pfmod_file is None
        assert args.suppress_warnings is False
        assert args.debug is False

    def test_rules_required(self, capsys):
        with pytest.raises(SystemExit):
            mod.get_parser().parse_args([])

    def test_summary_optional_value(self):
        assert mod.get_parser().parse_args(["-r", "x", "--summary"]).display_max is None
        assert mod.get_parser().parse_args(["-r", "x", "--summary", "5"]).display_max == 5

    def test_stats_optional_keys(self):
        assert mod.get_parser().parse_args(["-r", "x", "-s"]).stats == []
        assert mod.get_parser().parse_args(["-r", "x", "-s", "a", "b"]).stats == ["a", "b"]

    def test_long_aliases(self):
        args = mod.get_parser().parse_args(["--ruleset", "x", "--enable-all", "--better", "--pfmod-file", "p.yaml",
                                            "--ignore-classtype", "--suppress_warnings"])
        assert args.rules == "x"
        assert args.enable_all_rules is True
        assert args.normalize is True
        assert args.pfmod_file == "p.yaml"
        assert args.ignore_classtype_keyword is True
        assert args.suppress_warnings is True


class TestMain:
    def test_requires_filter_or_stats(self, run_main, small_rules_file):
        with pytest.raises(AristotleException, match="'metadata_filter' or 'stats' option required"):
            run_main("-r", small_rules_file)

    def test_stats_all_keys(self, run_main, small_rules_file):
        code, out = run_main("-r", small_rules_file, "-s")
        assert code == 0
        assert "All Rules: Total: 8; Enabled: 7; Disabled: 1" in out
        assert "priority (Total: 7; Enabled: 6; Disabled: 1)" in out
        assert "filename (Total: 8; Enabled: 7; Disabled: 1)" in out
        assert "\thigh" not in out  # summary mode is keyonly

    def test_stats_specific_keys(self, run_main, small_rules_file):
        code, out = run_main("-r", small_rules_file, "-s", "priority", "protocols")
        assert code == 0
        assert "\thigh (Total: 3; Enabled: 3; Disabled: 0)" in out
        assert "\tdns (Total: 1; Enabled: 1; Disabled: 0)" in out
        assert "malware (Total" not in out

    def test_stats_scoped_by_filter(self, run_main, small_rules_file):
        code, out = run_main("-r", small_rules_file, "-s", "priority", "-f", '"protocols tcp"')
        assert code == 0
        assert "All Rules: Total: 4; Enabled: 3; Disabled: 1" in out
        assert "\thigh (Total: 2; Enabled: 2; Disabled: 0)" in out

    def test_filter_to_stdout(self, run_main, small_rules_file):
        code, out = run_main("-r", small_rules_file, "-f", '"priority high"')
        assert code is None
        assert out.splitlines() == [SMALL_RULES[0], SMALL_RULES[1], SMALL_RULES[5]]

    def test_filter_from_file_to_output_file(self, run_main, small_rules_file, tmp_path):
        filt = tmp_path / "f.filter"
        filt.write_text('# comment\n"priority high" AND NOT "protocols http"\n')
        out_file = tmp_path / "out.rules"
        code, out = run_main("-r", small_rules_file, "-f", str(filt), "-o", str(out_file))
        assert code is None
        assert "Wrote 2 rules to file" in out
        assert out_file.read_text().splitlines() == [SMALL_RULES[1], SMALL_RULES[5]]

    def test_summary_default_max(self, run_main, small_rules_file):
        code, out = run_main("-r", small_rules_file, "-f", '"priority <ALL>"', "--summary")
        assert "Showing 6 of 6 enabled rules (7 rules total, including disabled)" in out
        assert "[sid:1]" in out
        assert SMALL_RULES[0] not in out

    def test_summary_with_max(self, run_main, small_rules_file):
        code, out = run_main("-r", small_rules_file, "-f", '"priority <ALL>"', "--summary", "2")
        assert "Showing 2 of 6 enabled rules" in out

    def test_summary_with_output_file_writes_full_ruleset(self, run_main, small_rules_file, tmp_path):
        out_file = tmp_path / "out.rules"
        code, out = run_main("-r", small_rules_file, "-f", '"priority high"', "--summary", "1", "-o", str(out_file))
        assert "Showing 1 of 3 enabled rules" in out
        assert "Wrote 3 rules to file" in out
        assert len(out_file.read_text().splitlines()) == 3

    def test_enable_all_and_output_disabled(self, run_main, small_rules_file):
        code, out = run_main("-r", small_rules_file, "-f", '"protocols smtp"', "-i")
        assert out.splitlines() == [SMALL_RULES[3].lstrip("#")]
        code, out = run_main("-r", small_rules_file, "-f", '"protocols smtp"', "-c")
        lines = out.splitlines()
        assert len(lines) == 8
        assert all(line.startswith("#") for line in lines)

    def test_pfmod_option(self, run_main, small_rules_file, write_yaml, caplog):
        path = write_yaml("rules:\n  - filter_string: '\"sid 1\"'\n    actions:\n      - set_priority: 4\n      - add_metadata: \"custom yes\"\n")
        code, out = run_main("-r", small_rules_file, "-f", '"priority high"', "-p", path, "--summary")
        assert "Enabling 'modify_metadata'" in caplog.text
        assert "SIDs modifed by PFMod: 1 of 3 (33.3%)" in out
        code, out = run_main("-r", small_rules_file, "-f", '"priority high"', "-p", path)
        lines = out.splitlines()
        assert "priority:4;" in lines[0]
        assert "custom yes" in lines[0]
        assert "priority:2;" in lines[1]

    def test_options_passed_to_ruleset(self, run_main, small_rules_file, monkeypatch):
        captured = {}
        real = mod.Ruleset

        def spy(*args, **kwargs):
            captured.update(kwargs)
            return real(*args, **kwargs)

        monkeypatch.setattr(mod, "Ruleset", spy)
        run_main("-r", small_rules_file, "-s", "-i", "-c", "-n", "-e", "-t", "-g", "-m", "--summary", "3")
        assert captured == {
            'rules': small_rules_file, 'metadata_filter': None, 'enable_all_rules': True, 'summary_max': 3,
            'output_disabled_rules': True, 'ignore_classtype_keyword': True, 'ignore_filename': True,
            'normalize': True, 'enhance': True, 'modify_metadata': True, 'pfmod_file': None,
        }

    def test_quiet_sets_error_level(self, run_main, small_rules_file):
        run_main("-r", small_rules_file, "-s", "-q")
        assert logging.getLogger("aristotle").level == logging.ERROR

    def test_debug_sets_debug_level(self, run_main, small_rules_file):
        run_main("-r", small_rules_file, "-s", "-d")
        assert logging.getLogger("aristotle").level == logging.DEBUG

    def test_default_log_level_is_info(self, run_main, small_rules_file):
        run_main("-r", small_rules_file, "-s")
        assert logging.getLogger("aristotle").level == logging.INFO

    def test_rules_as_string_argument(self, run_main):
        code, out = run_main("-r", SMALL_RULES[0] + "\n" + SMALL_RULES[4], "-f", '"protocols dns"')
        assert out.splitlines() == [SMALL_RULES[4]]


class TestSubprocess:
    """End-to-end runs of the real entry points in a separate interpreter."""

    def run(self, *args):
        return subprocess.run([sys.executable] + list(args), cwd=REPO_ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True, timeout=120)

    def test_module_entry_point_stats(self, small_rules_file):
        p = self.run("-m", "aristotle", "-r", small_rules_file, "-s", "protocols")
        assert p.returncode == 0, p.stderr
        assert "protocols (Total: 7; Enabled: 6; Disabled: 1)" in p.stdout

    def test_script_entry_point_filter(self, small_rules_file):
        p = self.run(os.path.join("aristotle", "aristotle.py"), "-r", small_rules_file, "-f", '"protocols dns"')
        assert p.returncode == 0, p.stderr
        assert p.stdout.strip() == SMALL_RULES[4]

    def test_script_fatal_error_exits_nonzero(self, small_rules_file):
        p = self.run(os.path.join("aristotle", "aristotle.py"), "-r", small_rules_file)
        assert p.returncode == 1
        assert "'metadata_filter' or 'stats' option required" in p.stderr
        assert "Cannot continue" in p.stderr

    def test_bad_filter_exits_nonzero(self, small_rules_file):
        p = self.run(os.path.join("aristotle", "aristotle.py"), "-r", small_rules_file, "-f", '("priority high"')
        assert p.returncode == 1
        assert "Problem processing metadata_filter" in p.stderr

    def test_help(self):
        p = self.run("-m", "aristotle", "--help")
        assert p.returncode == 0
        assert "usage:" in p.stdout
        assert "--pfmod" in p.stdout

    def test_quiet_suppresses_warnings(self, tmp_path):
        rules = tmp_path / "w.rules"
        rules.write_text(SMALL_RULES[0] + "\n" + SMALL_RULES[0] + "\n")
        p = self.run("-m", "aristotle", "-r", str(rules), "-s", "priority")
        assert "Duplicate sid" in p.stderr
        p = self.run("-m", "aristotle", "-r", str(rules), "-s", "priority", "-q")
        assert "Duplicate sid" not in p.stderr
        assert p.returncode == 0
