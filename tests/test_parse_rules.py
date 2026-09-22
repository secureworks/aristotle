import logging
import os

import pytest

from aristotle.aristotle import AristotleException, Ruleset

from .conftest import SMALL_SIDS, make_rule


class TestBasicLoading:
    def test_loads_all_sids_from_string(self, small_ruleset):
        assert set(small_ruleset.get_all_sids()) == SMALL_SIDS

    def test_enabled_and_disabled_sids(self, small_ruleset):
        assert set(small_ruleset.get_enabled_sids()) == SMALL_SIDS - {4}
        assert small_ruleset.get_disabled_sids() == [4]
        assert small_ruleset.metadata_dict[4]['disabled'] is True
        assert small_ruleset.metadata_dict[1]['disabled'] is False

    def test_loads_from_file_and_adds_filename_key(self, small_rules_file):
        rs = Ruleset(small_rules_file)
        assert set(rs.get_all_sids()) == SMALL_SIDS
        assert rs.metadata_dict[1]['metadata']['filename'] == ['small.rules']
        assert set(rs.keys_dict['filename']['small.rules']) == SMALL_SIDS

    def test_string_input_has_no_filename_key(self, small_ruleset):
        assert 'filename' not in small_ruleset.keys_dict
        assert 'filename' not in small_ruleset.metadata_dict[1]['metadata']

    def test_ignore_filename(self, small_rules_file):
        rs = Ruleset(small_rules_file, ignore_filename=True)
        assert 'filename' not in rs.keys_dict

    def test_loads_directory_sorted_and_only_rules_extension(self, tmp_path):
        (tmp_path / "b.rules").write_text(make_rule(20) + "\n")
        (tmp_path / "a.rules").write_text(make_rule(10) + "\n")
        (tmp_path / "ignored.txt").write_text(make_rule(30) + "\n")
        rs = Ruleset(str(tmp_path))
        assert rs.get_all_sids() == [10, 20]
        assert rs.metadata_dict[10]['metadata']['filename'] == ['a.rules']
        assert rs.metadata_dict[20]['metadata']['filename'] == ['b.rules']

    def test_directory_without_rules_files_raises(self, tmp_path):
        with pytest.raises(AristotleException, match="No '.rules' files found"):
            Ruleset(str(tmp_path))

    def test_nonexistent_path_raises(self):
        with pytest.raises(AristotleException, match="not a valid file or directory"):
            Ruleset("/nonexistent/path/to/file.rules")

    def test_short_string_without_metadata_treated_as_bad_path(self):
        with pytest.raises(AristotleException, match="not a valid file or directory"):
            Ruleset("this is not a rules file")

    def test_raw_rule_stored_verbatim(self, small_ruleset):
        rule = small_ruleset.metadata_dict[1]['raw_rule']
        assert rule.startswith('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Acme - Malware CnC Beacon";')
        assert rule.endswith("sid:1; rev:1;)")

    def test_msg_extracted(self, small_ruleset):
        assert small_ruleset.metadata_dict[2]['msg'] == "Acme - SMB Exploit Attempt CVE-2017-0144"

    def test_summary_max_stored_as_int(self, small_rules_str):
        rs = Ruleset(small_rules_str, summary_max="5")
        assert rs.summary_max == 5

    def test_invalid_summary_max_raises(self, small_rules_str):
        with pytest.raises(AristotleException, match="summary_max"):
            Ruleset(small_rules_str, summary_max="lots")


class TestCommentsAndDisabledRules:
    @pytest.mark.parametrize("prefix", ["#", "# ", "#   ", "  #", "\t# "])
    def test_disabled_rule_detected_with_whitespace_variations(self, prefix):
        rs = Ruleset(prefix + make_rule(1) + "   \n")
        assert rs.get_all_sids() == [1]
        assert rs.metadata_dict[1]['disabled'] is True
        assert rs.metadata_dict[1]['originally_disabled'] is True
        # comment char and surrounding whitespace removed from stored rule
        assert rs.metadata_dict[1]['raw_rule'].startswith("alert ")

    def test_plain_comments_and_blank_lines_skipped(self, caplog):
        rules = "# this is a comment\n\n   \n#better-schema 1.0\n" + make_rule(1) + "\n"
        with caplog.at_level(logging.DEBUG, logger="aristotle"):
            rs = Ruleset(rules)
        assert rs.get_all_sids() == [1]
        assert "Skipping comment" in caplog.text

    def test_originally_disabled_metadata(self, small_ruleset):
        assert small_ruleset.metadata_dict[4]['metadata']['originally_disabled'] == ['true']
        assert small_ruleset.metadata_dict[1]['metadata']['originally_disabled'] == ['false']
        assert small_ruleset.keys_dict['originally_disabled']['true'] == [4]

    def test_enable_all_rules(self, small_rules_str):
        rs = Ruleset(small_rules_str, enable_all_rules=True)
        assert rs.get_disabled_sids() == []
        assert rs.metadata_dict[4]['disabled'] is False
        assert rs.metadata_dict[4]['originally_disabled'] is True
        assert rs.metadata_dict[4]['metadata']['originally_disabled'] == ['true']

    def test_originally_disabled_in_rule_metadata_is_overridden(self, caplog):
        rs = Ruleset(make_rule(1, metadata="originally_disabled true, priority low") + "\n")
        assert rs.metadata_dict[1]['metadata']['originally_disabled'] == ['false']
        assert rs.keys_dict['originally_disabled'].get('true', []) == []
        assert "internal metadata key" in caplog.text


class TestMetadataParsing:
    def test_metadata_values_lowercased_and_stripped(self):
        rs = Ruleset(make_rule(1, metadata="  Priority   HIGH ,Attack_Target   HTTP-Server ") + "\n")
        md = rs.metadata_dict[1]['metadata']
        assert md['priority'] == ['high']
        assert md['attack_target'] == ['http-server']
        assert rs.keys_dict['priority']['high'] == [1]

    def test_multi_value_keys(self, small_ruleset):
        assert set(small_ruleset.metadata_dict[1]['metadata']['protocols']) == {'http', 'tcp'}
        assert set(small_ruleset.keys_dict['protocols']['tcp']) == {1, 2, 3, 4}

    def test_duplicate_values_deduplicated(self):
        rs = Ruleset(make_rule(1, metadata="cve 2017-1, cve 2017-1, cve 2017-1") + "\n")
        assert rs.metadata_dict[1]['metadata']['cve'] == ['2017-1']
        assert rs.keys_dict['cve']['2017-1'] == [1]

    def test_single_word_metadata_ignored_with_warning(self, caplog):
        rs = Ruleset(make_rule(1, metadata="priority high, orphan") + "\n")
        assert rs.metadata_dict[1]['metadata']['priority'] == ['high']
        assert 'orphan' not in rs.keys_dict
        assert "Single word metadata value found" in caplog.text

    def test_missing_metadata_keyword_warns_but_loads(self, caplog):
        rs = Ruleset(make_rule(8, metadata=None) + "\n" + make_rule(9) + "\n", ignore_classtype_keyword=True)
        assert rs.get_all_sids() == [8, 9]
        assert set(rs.metadata_dict[8]['metadata'].keys()) == {'sid', 'originally_disabled'}
        assert "No 'metatdata' keyword found in sid 8" in caplog.text

    def test_sid_pseudo_key(self, small_ruleset):
        assert small_ruleset.metadata_dict[3]['metadata']['sid'] == ['3']
        assert small_ruleset.keys_dict['sid']['3'] == [3]

    def test_sid_metadata_key_present_and_matching(self):
        rs = Ruleset(make_rule(42, metadata="sid 42, priority low") + "\n")
        assert rs.metadata_dict[42]['metadata']['sid'] == ['42']
        assert rs.keys_dict['sid']['42'] == [42]

    def test_sid_metadata_key_mismatch_warns(self, caplog):
        Ruleset(make_rule(42, metadata="sid 43, priority low") + "\n")
        assert "'sid' metadata key value '43' does not match rule sid '42'" in caplog.text

    def test_classtype_keyword_added_as_metadata(self, small_ruleset):
        assert small_ruleset.metadata_dict[1]['metadata']['classtype'] == ['trojan-activity']
        assert small_ruleset.keys_dict['classtype']['trojan-activity'] == [1]
        assert 'classtype' not in small_ruleset.metadata_dict[5]['metadata']

    def test_classtype_keyword_only_first_used_and_merged_with_metadata(self):
        rule = make_rule(1, classtype="trojan-activity", body="classtype:first-one;",
                         metadata="classtype trojan-activity, priority low")
        rs = Ruleset(rule + "\n")
        # 'body' is inserted before the classtype= keyword so 'first-one' is seen first
        assert set(rs.metadata_dict[1]['metadata']['classtype']) == {'first-one', 'trojan-activity'}

    def test_ignore_classtype_keyword(self, small_rules_str):
        rs = Ruleset(small_rules_str, ignore_classtype_keyword=True)
        assert 'classtype' not in rs.metadata_dict[1]['metadata']
        assert 'classtype' not in rs.keys_dict

    def test_msg_with_escaped_quote_yields_empty_msg_and_warning(self, caplog):
        rule = 'alert tcp any any -> any any (msg:"foo \\"bar\\" baz"; metadata:priority low; sid:7; rev:1;)\n'
        rs = Ruleset(rule)
        assert rs.metadata_dict[7]['msg'] == ""
        assert "Unable to extract rule msg from SID '7'" in caplog.text


class TestInvalidRules:
    def test_rule_without_sid_raises(self):
        with pytest.raises(AristotleException, match="Invalid rule on line"):
            Ruleset('alert tcp any any -> any any (msg:"no sid"; metadata:priority low; rev:1;)\n')

    def test_non_integer_sid_metadata_raises(self):
        with pytest.raises(AristotleException):
            Ruleset(make_rule(1, metadata="sid abc, priority low") + "\n")


class TestDuplicateSids:
    def test_first_enabled_rule_wins(self, caplog):
        rules = make_rule(1, msg="first", metadata="priority low") + "\n" + \
            make_rule(1, msg="second", metadata="priority high") + "\n"
        rs = Ruleset(rules)
        assert rs.metadata_dict[1]['msg'] == "first"
        assert rs.metadata_dict[1]['metadata']['priority'] == ['low']
        assert "Duplicate sid '1' found" in caplog.text
        assert "Ignoring rule with duplicate sid" in caplog.text

    def test_disabled_duplicate_ignored_when_enabled_exists(self):
        rules = make_rule(1, msg="first", metadata="priority low") + "\n" + \
            make_rule(1, msg="second", metadata="priority high", disabled=True) + "\n"
        rs = Ruleset(rules)
        assert rs.metadata_dict[1]['msg'] == "first"
        assert rs.metadata_dict[1]['disabled'] is False

    def test_enabled_duplicate_replaces_disabled_one(self):
        rules = make_rule(1, msg="first", metadata="priority low", disabled=True) + "\n" + \
            make_rule(1, msg="second", metadata="priority high") + "\n"
        rs = Ruleset(rules)
        assert rs.metadata_dict[1]['msg'] == "second"
        assert rs.metadata_dict[1]['disabled'] is False
        assert rs.metadata_dict[1]['originally_disabled'] is False
        assert rs.metadata_dict[1]['metadata']['priority'] == ['high']

    def test_replaced_disabled_duplicate_does_not_leave_stale_index_entries(self):
        # Regression: keys_dict still referenced the replaced rule's metadata, so a
        # filter on the old value ("priority low") matched the new rule.
        rules = make_rule(1, msg="first", metadata="priority low, foo bar", disabled=True) + "\n" + \
            make_rule(1, msg="second", metadata="priority high") + "\n"
        rs = Ruleset(rules)
        assert rs.keys_dict['priority']['low'] == []
        assert rs.keys_dict['foo']['bar'] == []
        assert rs.keys_dict['priority']['high'] == [1]
        assert rs.keys_dict['originally_disabled']['true'] == []
        assert set(rs.filter_ruleset('"priority low"')) == set()
        assert set(rs.filter_ruleset('"foo bar"')) == set()
        assert set(rs.filter_ruleset('"priority high"')) == {1}
        assert set(rs.filter_ruleset('"originally_disabled true"')) == set()

    def test_all_disabled_duplicates_keeps_first(self):
        rules = make_rule(1, msg="first", disabled=True) + "\n" + make_rule(1, msg="second", disabled=True) + "\n"
        rs = Ruleset(rules)
        assert rs.metadata_dict[1]['msg'] == "first"
        assert rs.metadata_dict[1]['disabled'] is True

    def test_duplicate_warning_mentions_filename(self, tmp_path, caplog):
        p = tmp_path / "dup.rules"
        p.write_text(make_rule(1) + "\n" + make_rule(1) + "\n")
        Ruleset(str(p))
        assert "Duplicate sid '1' found in file 'dup.rules'" in caplog.text


@pytest.mark.examples
class TestExampleRuleset:
    def test_counts_match_documentation(self, example_ruleset):
        # numbers documented in docs/usage.rst
        assert len(example_ruleset.get_all_sids()) == 6799
        assert len(example_ruleset.get_enabled_sids()) == 4977
        assert len(example_ruleset.get_disabled_sids()) == 1822

    def test_expected_keys_present(self, example_ruleset):
        expected = {'attack_target', 'malware', 'cve', 'hostile', 'created_at', 'capec_id', 'updated_at', 'cwe_id',
                    'priority', 'cvss_v3_base', 'infected', 'sid', 'cvss_v2_base', 'rule_source', 'cvss_v3_temporal',
                    'filename', 'cvss_v2_temporal', 'protocols', 'originally_disabled'}
        assert set(example_ruleset.keys_dict.keys()) == expected

    def test_documented_key_totals(self, example_ruleset):
        assert len(example_ruleset.keys_dict['malware']['post-infection']) == 2647
        assert len(example_ruleset.keys_dict['protocols']['http']) == 5447
        assert len(example_ruleset.keys_dict['protocols']['tls']) == 145

    def test_filename_from_file_basename(self, example_ruleset, example_rules_path):
        # the example rules also carry their own 'filename <x>.rules' metadata values alongside the real filename
        assert len(example_ruleset.keys_dict['filename'][os.path.basename(example_rules_path)]) == 6799
        assert 'acme.rules' in example_ruleset.keys_dict['filename']
