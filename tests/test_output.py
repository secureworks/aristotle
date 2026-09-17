import threading

import pytest

from aristotle.aristotle import AristotleException, Ruleset

from .conftest import SMALL_RULES, SMALL_RULES_STR, make_rule, strip_ansi


def out_lines(capsys):
    return [line.strip() for line in strip_ansi(capsys.readouterr().out).splitlines() if line.strip()]


class TestOutputRulesStdout:
    def test_only_enabled_rules_printed(self, small_ruleset, capsys):
        small_ruleset.output_rules([1, 4, 5])
        lines = out_lines(capsys)
        assert lines == [SMALL_RULES[0], SMALL_RULES[4]]

    def test_rules_unmodified_by_default(self, small_ruleset, capsys):
        small_ruleset.output_rules(small_ruleset.get_all_sids())
        assert out_lines(capsys) == [r for r in SMALL_RULES if not r.startswith("#")]

    def test_output_disabled_rules_prints_everything(self, small_rules_str, capsys):
        rs = Ruleset(small_rules_str, output_disabled_rules=True)
        rs.output_rules([1, 4, 5])
        lines = out_lines(capsys)
        assert len(lines) == 8
        assert lines[0] == SMALL_RULES[0]
        assert lines[4] == SMALL_RULES[4]
        for idx in (1, 2, 3, 5, 6, 7):
            assert lines[idx] == "#" + SMALL_RULES[idx].lstrip("#")
        # non-matching rules are now marked disabled internally
        assert set(rs.get_disabled_sids()) == {2, 3, 4, 6, 7, 8}

    def test_empty_sid_list(self, small_ruleset, capsys):
        small_ruleset.output_rules([])
        assert out_lines(capsys) == []


class TestOutputRulesFile:
    def test_writes_enabled_rules(self, small_ruleset, tmp_path, capsys):
        out = tmp_path / "out.rules"
        small_ruleset.output_rules([1, 4, 5], outfile=str(out))
        assert out.read_text() == SMALL_RULES[0] + "\n" + SMALL_RULES[4] + "\n"
        assert "Wrote 2 rules to file, '{}'".format(out) in strip_ansi(capsys.readouterr().out)

    def test_writes_disabled_rules_commented(self, small_rules_str, tmp_path, capsys):
        rs = Ruleset(small_rules_str, output_disabled_rules=True)
        out = tmp_path / "out.rules"
        rs.output_rules([1, 4], outfile=str(out))
        lines = out.read_text().splitlines()
        assert len(lines) == 8
        assert lines[0] == SMALL_RULES[0]
        assert lines[3] == "#" + SMALL_RULES[3].lstrip("#")
        assert lines[1].startswith("#alert ")
        assert "Wrote 8 rules (1 enabled, 7 disabled) to file" in strip_ansi(capsys.readouterr().out)

    def test_output_round_trips(self, small_ruleset, tmp_path):
        out = tmp_path / "out.rules"
        small_ruleset.output_rules(small_ruleset.get_all_sids(), outfile=str(out))
        rs2 = Ruleset(str(out))
        assert set(rs2.get_all_sids()) == set(small_ruleset.get_enabled_sids())

    def test_unwritable_path_raises(self, small_ruleset, tmp_path):
        with pytest.raises(AristotleException, match="Problem writing to file"):
            small_ruleset.output_rules([1], outfile=str(tmp_path))


class TestModifyMetadata:
    def metadata_of(self, rs, sid):
        import re
        m = re.search(r"metadata:([^;]+);", rs.metadata_dict[sid]['raw_rule'])
        return m.group(1) if m else None

    def test_metadata_rewritten_sorted_lowercase(self, small_rules_str, capsys):
        rs = Ruleset(small_rules_str, modify_metadata=True)
        rs.output_rules([1])
        assert self.metadata_of(rs, 1) == ("attack_target http-client, classtype trojan-activity, created_at 2018-03-19, "
                                           "cvss_v3_base 8.1, malware post-infection, priority high, protocols http, "
                                           "protocols tcp, risk_score 90, sid 1, updated_at 2018-03-20")
        printed = strip_ansi(capsys.readouterr().out).strip()
        assert printed == rs.metadata_dict[1]['raw_rule']
        assert printed.startswith('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Acme - Malware CnC Beacon"; flow:established,to_server; priority:1; classtype:trojan-activity; metadata:')
        assert printed.endswith("; sid:1; rev:1;)")

    def test_metadata_parameter_overrides_instance_setting(self, small_ruleset, capsys):
        small_ruleset.output_rules([1], modify_metadata=True)
        assert "sid 1" in self.metadata_of(small_ruleset, 1)

    def test_metadata_parameter_false_disables(self, small_rules_str, capsys):
        rs = Ruleset(small_rules_str, modify_metadata=True)
        rs.output_rules([1], modify_metadata=False)
        assert rs.metadata_dict[1]['raw_rule'] == SMALL_RULES[0]

    def test_filename_included_when_loaded_from_file(self, small_rules_file):
        rs = Ruleset(small_rules_file, modify_metadata=True)
        rs.output_rules([5])
        assert self.metadata_of(rs, 5) == "created_at 2020-02-29, filename small.rules, priority low, protocols dns, protocols udp, risk_score 10, sid 5"

    def test_normalize_drops_sid_and_normalizes_values(self, small_rules_str):
        rs = Ruleset(small_rules_str, modify_metadata=True, normalize=True)
        rs.output_rules([7])
        assert self.metadata_of(rs, 7) == "created_at 2019-12-31, priority medium, protocols http, sid 7, updated_at 2020-01-15".replace("sid 7, ", "")
        rs.output_rules([6])
        assert "mitre_attack t1190" in self.metadata_of(rs, 6)
        assert "mitre_technique_id" not in self.metadata_of(rs, 6)

    def test_enhance_includes_originally_disabled_and_enhancements(self, small_rules_str):
        rs = Ruleset(small_rules_str, modify_metadata=True, enhance=True, output_disabled_rules=True)
        rs.output_rules([4])
        md = self.metadata_of(rs, 4)
        assert "originally_disabled true" in md
        assert "detection_direction inbound" in md
        assert "flow to_server" in md
        assert "protocols smtp" in md

    def test_originally_disabled_omitted_without_enhance(self, small_rules_str):
        rs = Ruleset(small_rules_str, modify_metadata=True, output_disabled_rules=True)
        rs.output_rules([4])
        assert "originally_disabled" not in self.metadata_of(rs, 4)

    def test_metadata_keyword_added_when_absent(self, small_rules_str, capsys):
        rs = Ruleset(small_rules_str, modify_metadata=True)
        rs.output_rules([8])
        assert rs.metadata_dict[8]['raw_rule'].endswith("sid:8; rev:1; metadata:sid 8;)")

    def test_pfmod_changes_reflected(self, small_rules_str, write_yaml):
        path = write_yaml("rules:\n  - filter_string: '\"sid 1\"'\n    actions:\n      - add_metadata_exclusive: \"priority low\"\n      - set_priority: 4\n")
        rs = Ruleset(small_rules_str, pfmod_file=path)
        rs._pfmod_apply(path, [1])
        rs.output_rules([1])
        assert "priority low" in self.metadata_of(rs, 1)
        assert "priority high" not in self.metadata_of(rs, 1)
        assert "priority:4;" in rs.metadata_dict[1]['raw_rule']

    def test_modified_output_reloads_identically(self, small_rules_str, tmp_path):
        rs = Ruleset(small_rules_str, modify_metadata=True, enhance=True, normalize=True)
        out = tmp_path / "out.rules"
        rs.output_rules(rs.get_all_sids(), outfile=str(out))
        rs2 = Ruleset(str(out), ignore_filename=True)
        assert set(rs2.get_all_sids()) == set(rs.get_enabled_sids())
        for s in rs2.get_all_sids():
            expected = {k: sorted(v) for k, v in rs.metadata_dict[s]['metadata'].items()}
            actual = {k: sorted(v) for k, v in rs2.metadata_dict[s]['metadata'].items()}
            assert actual == expected


class TestStats:
    def test_get_stats_key_and_values(self, small_ruleset):
        s = strip_ansi(small_ruleset.get_stats("priority"))
        lines = s.splitlines()
        assert lines[0] == "priority (Total: 7; Enabled: 6; Disabled: 1)"
        assert "\thigh (Total: 3; Enabled: 3; Disabled: 0)" in lines
        assert "\tmedium (Total: 2; Enabled: 2; Disabled: 0)" in lines
        assert "\tlow (Total: 2; Enabled: 1; Disabled: 1)" in lines
        assert s.endswith("\n\n")

    def test_get_stats_keyonly(self, small_ruleset):
        assert strip_ansi(small_ruleset.get_stats("priority", keyonly=True)) == "priority (Total: 7; Enabled: 6; Disabled: 1)\n"

    def test_get_stats_scoped_to_sids(self, small_ruleset):
        s = strip_ansi(small_ruleset.get_stats("priority", sids=[1, 4, 8]))
        lines = s.splitlines()
        assert lines[0] == "priority (Total: 2; Enabled: 1; Disabled: 1)"
        assert "\thigh (Total: 1; Enabled: 1; Disabled: 0)" in lines
        assert "\tlow (Total: 1; Enabled: 0; Disabled: 1)" in lines
        assert not any(line.startswith("\tmedium") for line in lines)

    def test_get_stats_include_empty_substat(self, small_ruleset):
        s = strip_ansi(small_ruleset.get_stats("priority", sids=[1], include_empty_substat=True))
        assert "\tmedium (Total: 0; Enabled: 0; Disabled: 0)" in s.splitlines()

    def test_get_stats_unknown_key(self, small_ruleset, caplog):
        assert small_ruleset.get_stats("nosuchkey") is None
        assert "key 'nosuchkey' not found" in caplog.text

    def test_get_stats_sid_key(self, small_ruleset):
        assert strip_ansi(small_ruleset.get_stats("sid", keyonly=True)) == "sid (Total: 8; Enabled: 7; Disabled: 1)\n"

    def test_print_stats(self, small_ruleset, capsys):
        assert small_ruleset.print_stats("protocols", keyonly=True) is True
        assert strip_ansi(capsys.readouterr().out) == "protocols (Total: 7; Enabled: 6; Disabled: 1)\n"

    def test_print_stats_unknown_key(self, small_ruleset, capsys, caplog):
        assert small_ruleset.print_stats("nosuchkey") is False
        assert capsys.readouterr().out == ""
        assert "No statistics to print" in caplog.text

    def test_print_header(self, small_ruleset, capsys):
        small_ruleset.print_header()
        out = strip_ansi(capsys.readouterr().out)
        assert "Aristotle" in out
        assert "All Rules: Total: 8; Enabled: 7; Disabled: 1" in out

    def test_print_header_scoped(self, small_ruleset, capsys):
        small_ruleset.print_header(sids=[1, 4])
        assert "All Rules: Total: 2; Enabled: 1; Disabled: 1" in strip_ansi(capsys.readouterr().out)


class TestRulesetSummary:
    def test_summary_limited_to_summary_max(self, small_rules_str, capsys):
        rs = Ruleset(small_rules_str, summary_max=3)
        rs.print_ruleset_summary(rs.get_all_sids())
        lines = out_lines(capsys)
        assert lines[:3] == ["Acme - Malware CnC Beacon [sid:1]", "Acme - SMB Exploit Attempt CVE-2017-0144 [sid:2]",
                             "Acme - Phishing Landing Page TLS SNI [sid:3]"]
        assert lines[3] == "Showing 3 of 7 enabled rules (8 rules total, including disabled)"

    def test_summary_skips_disabled_rules(self, small_ruleset, capsys):
        small_ruleset.print_ruleset_summary([4, 5])
        lines = out_lines(capsys)
        assert lines == ["Acme - DNS Query Suspicious Domain [sid:5]", "Showing 1 of 1 enabled rules (2 rules total, including disabled)"]

    def test_summary_without_disabled_omits_total_note(self, small_ruleset, capsys):
        small_ruleset.print_ruleset_summary([1, 2])
        assert out_lines(capsys)[-1] == "Showing 2 of 2 enabled rules"

    def test_summary_empty(self, small_ruleset, capsys):
        small_ruleset.print_ruleset_summary([])
        assert out_lines(capsys) == ["Showing 0 of 0 enabled rules"]

    def test_summary_with_pfmod_sids(self, small_ruleset, capsys):
        small_ruleset.print_ruleset_summary([1, 2, 3, 4], pfmod_sids={1})
        assert "SIDs modifed by PFMod: 1 of 4 (25.0%)" in out_lines(capsys)

    def test_summary_max_zero(self, small_rules_str, capsys):
        rs = Ruleset(small_rules_str, summary_max=0)
        rs.print_ruleset_summary([1, 2])
        assert out_lines(capsys) == ["Showing 0 of 2 enabled rules"]

    def test_summary_with_unextractable_msg_terminates(self, capsys, caplog):
        # Regression: a rule whose msg could not be re-extracted caused an infinite loop
        rule = 'alert tcp any any -> any any (msg:"foo \\"bar\\" baz"; metadata:priority low; sid:7; rev:1;)\n'
        rs = Ruleset(rule + make_rule(9) + "\n")
        done = threading.Event()

        def run():
            rs.print_ruleset_summary([7, 9])
            done.set()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        assert done.wait(timeout=10), "print_ruleset_summary did not terminate"
        lines = out_lines(capsys)
        assert lines == ["[sid:7]", "Acme - Test Rule [sid:9]", "Showing 2 of 2 enabled rules"]
        assert "Unable to extract rule msg" in caplog.text
