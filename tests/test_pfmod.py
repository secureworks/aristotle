import os

import pytest

from aristotle.aristotle import AristotleException, Ruleset

from .conftest import SMALL_RULES_STR, make_rule


def pfmod_yaml(actions, filter_string='"priority <ALL>"', name="test-rule", extra=""):
    """Build a one-rule PFMod YAML document; ``actions`` is a list of YAML list items (strings)."""
    action_lines = "\n".join("      - {}".format(a) for a in actions)
    return "version: \"1.0\"\n{}rules:\n  - name: {}\n    filter_string: '{}'\n    actions:\n{}\n".format(extra, name, filter_string, action_lines)


@pytest.fixture
def apply(write_yaml):
    """Return helper: apply(actions, sids=None, filter_string=..., rules=SMALL_RULES_STR) -> (Ruleset, matched_sids)."""
    def _apply(actions, sids=None, filter_string='"priority <ALL>"', rules=SMALL_RULES_STR, yaml_text=None, **ruleset_kwargs):
        path = write_yaml(yaml_text if yaml_text is not None else pfmod_yaml(actions, filter_string=filter_string))
        rs = Ruleset(rules, modify_metadata=True, pfmod_file=path, **ruleset_kwargs)
        if sids is None:
            sids = rs.get_all_sids()
        matched = rs._pfmod_apply(path, sids)
        return rs, matched
    return _apply


class TestConstructor:
    def test_pfmod_file_enables_modify_metadata_with_warning(self, small_rules_str, write_yaml, caplog):
        path = write_yaml(pfmod_yaml(["disable"]))
        rs = Ruleset(small_rules_str, pfmod_file=path)
        assert rs.modify_metadata is True
        assert rs.pfmod_file == path
        assert "Enabling 'modify_metadata'" in caplog.text

    def test_no_warning_when_modify_metadata_set(self, small_rules_str, write_yaml, caplog):
        path = write_yaml(pfmod_yaml(["disable"]))
        Ruleset(small_rules_str, pfmod_file=path, modify_metadata=True)
        assert "Enabling 'modify_metadata'" not in caplog.text


class TestEnableDisable:
    def test_disable(self, apply):
        rs, matched = apply(["disable"], filter_string='"priority high"')
        assert matched == {1, 2, 6}
        assert set(rs.get_disabled_sids()) == {1, 2, 4, 6}

    def test_enable_disabled_rule(self, apply):
        rs, matched = apply(["enable"], filter_string='"protocols smtp"')
        assert matched == {4}
        assert rs.metadata_dict[4]['disabled'] is False
        assert rs.metadata_dict[4]['originally_disabled'] is True

    def test_only_sids_in_scope_are_modified(self, apply):
        rs, matched = apply(["disable"], sids=[1, 3], filter_string='"priority high"')
        assert matched == {1}
        assert rs.get_disabled_sids() == [1, 4]

    def test_returns_union_of_all_matches(self, apply, write_yaml):
        yaml_text = "rules:\n  - filter_string: '\"protocols dns\"'\n    actions: [disable]\n  - filter_string: '\"protocols smb\"'\n    actions: [disable]\n"
        rs, matched = apply(None, yaml_text=yaml_text)
        assert matched == {2, 5}

    def test_rules_applied_in_order(self, apply):
        yaml_text = "rules:\n  - filter_string: '\"sid 1\"'\n    actions: [disable]\n  - filter_string: '\"sid 1\"'\n    actions: [enable]\n"
        rs, _ = apply(None, yaml_text=yaml_text)
        assert rs.metadata_dict[1]['disabled'] is False

    def test_invalid_string_action_skipped(self, apply, caplog):
        rs, matched = apply(["explode", "disable"], filter_string='"sid 1"')
        assert "Invalid action 'explode'" in caplog.text
        assert rs.metadata_dict[1]['disabled'] is True

    def test_invalid_action_type_skipped(self, apply, caplog):
        rs, matched = apply(["[1, 2]", "disable"], filter_string='"sid 1"')
        assert "Invalid action data type" in caplog.text
        assert rs.metadata_dict[1]['disabled'] is True

    def test_invalid_dict_action_skipped(self, apply, caplog):
        rs, matched = apply(["frobnicate: yes", "disable"], filter_string='"sid 1"')
        assert "Invalid action found" in caplog.text
        assert rs.metadata_dict[1]['disabled'] is True


class TestMetadataActions:
    def test_add_metadata_new_key(self, apply):
        rs, _ = apply(['add_metadata: "confidence unknown"'], filter_string='"sid 1"')
        assert rs.metadata_dict[1]['metadata']['confidence'] == ['unknown']
        assert rs.keys_dict['confidence']['unknown'] == [1]

    def test_add_metadata_existing_key_keeps_both_values(self, apply):
        rs, _ = apply(['add_metadata: "confidence unknown"'], filter_string='"sid 3"')
        assert set(rs.metadata_dict[3]['metadata']['confidence']) == {'high', 'unknown'}

    def test_add_metadata_same_pair_not_duplicated(self, apply):
        rs, _ = apply(['add_metadata: "confidence high"'], filter_string='"sid 3"')
        assert rs.metadata_dict[3]['metadata']['confidence'] == ['high']

    def test_add_metadata_is_lowercased(self, apply):
        rs, _ = apply(['add_metadata: "Confidence  UNKNOWN"'], filter_string='"sid 1"')
        assert rs.metadata_dict[1]['metadata']['confidence'] == ['unknown']

    def test_add_metadata_exclusive_overwrites(self, apply):
        rs, _ = apply(['add_metadata_exclusive: "confidence unknown"'], filter_string='"sid 3"')
        assert rs.metadata_dict[3]['metadata']['confidence'] == ['unknown']
        assert rs.keys_dict['confidence']['high'] == []

    def test_add_metadata_single_word_raises(self, apply):
        with pytest.raises(AristotleException, match="Invalid value for action 'add_metadata'"):
            apply(['add_metadata: "confidence"'], filter_string='"sid 1"')

    def test_delete_metadata_key(self, apply):
        rs, _ = apply(['delete_metadata: "protocols"'], filter_string='"sid 1"')
        assert 'protocols' not in rs.metadata_dict[1]['metadata']
        assert 1 not in rs.keys_dict['protocols']['http']

    def test_delete_metadata_key_value(self, apply):
        rs, _ = apply(['delete_metadata: "protocols tcp"'], filter_string='"sid 1"')
        assert rs.metadata_dict[1]['metadata']['protocols'] == ['http']

    def test_delete_metadata_missing_key_is_noop(self, apply):
        rs, _ = apply(['delete_metadata: "nosuchkey"'], filter_string='"sid 1"')
        assert 'priority' in rs.metadata_dict[1]['metadata']

    def test_pfmod_changes_visible_to_subsequent_filters(self, apply):
        yaml_text = ("rules:\n"
                     "  - filter_string: '\"sid 1\"'\n    actions:\n      - add_metadata: \"stage one\"\n"
                     "  - filter_string: '\"stage one\"'\n    actions: [disable]\n")
        rs, matched = apply(None, yaml_text=yaml_text)
        assert rs.metadata_dict[1]['disabled'] is True
        assert matched == {1}

    def test_null_action_value_is_clean_error(self, apply):
        # Regression: a null YAML value crashed with AttributeError instead of an Aristotle error
        with pytest.raises(AristotleException, match="No value for action 'add_metadata'"):
            apply(['add_metadata:'], filter_string='"sid 1"')

    def test_empty_action_value_is_error(self, apply):
        with pytest.raises(AristotleException, match="No value for action 'add_metadata'"):
            apply(['add_metadata: "   "'], filter_string='"sid 1"')


class TestCopyKey:
    def test_copies_all_values(self, apply):
        rs, _ = apply(['copy_key: "protocols proto_orig"'], filter_string='"sid 1"')
        assert set(rs.metadata_dict[1]['metadata']['proto_orig']) == {'http', 'tcp'}
        assert rs.metadata_dict[1]['metadata']['protocols'] == rs.metadata_dict[1]['metadata']['protocols']
        assert rs.keys_dict['proto_orig']['http'] == [1]

    def test_existing_destination_not_overwritten(self, apply, caplog):
        rs, _ = apply(['copy_key: "risk_score priority"'], filter_string='"sid 1"')
        assert rs.metadata_dict[1]['metadata']['priority'] == ['high']
        assert "already exists" in caplog.text

    def test_missing_source_warns(self, apply, caplog):
        rs, _ = apply(['copy_key: "nosuchkey newkey"'], filter_string='"sid 1"')
        assert 'newkey' not in rs.metadata_dict[1]['metadata']
        assert "metadata key 'nosuchkey' not found in SID 1" in caplog.text

    def test_same_key_names_is_error(self, apply, caplog):
        rs, _ = apply(['copy_key: "priority priority"'], filter_string='"sid 1"')
        assert rs.metadata_dict[1]['metadata']['priority'] == ['high']
        assert "You are doing it wrong" in caplog.text

    @pytest.mark.parametrize("value", ["priority", "priority a b"])
    def test_wrong_argument_count_raises(self, apply, value):
        with pytest.raises(AristotleException, match="Expected 2 arguments"):
            apply(['copy_key: "{}"'.format(value)], filter_string='"sid 1"')


class TestRegexSub:
    def test_alert_to_drop(self, apply):
        rs, _ = apply(["regex_sub: '/^alert\\x20/drop /'"], filter_string='"sid 1"')
        assert rs.metadata_dict[1]['raw_rule'].startswith("drop http $HOME_NET")
        assert rs.metadata_dict[2]['raw_rule'].startswith("alert ")

    def test_case_insensitive_flag(self, apply):
        rs, _ = apply(["regex_sub: '/acme/Zeta/i'"], filter_string='"sid 1"')
        assert 'msg:"Zeta - Malware CnC Beacon";' in rs.metadata_dict[1]['raw_rule']

    def test_case_sensitive_by_default(self, apply):
        rs, _ = apply(["regex_sub: '/acme/Zeta/'"], filter_string='"sid 1"')
        assert 'msg:"Acme - Malware CnC Beacon";' in rs.metadata_dict[1]['raw_rule']

    def test_replaces_all_occurrences(self, apply):
        rs, _ = apply(["regex_sub: '/tcp/udp/'"], filter_string='"sid 1"')
        assert "tcp" not in rs.metadata_dict[1]['raw_rule']

    def test_backreferences(self, apply):
        rs, _ = apply(["regex_sub: '/priority:(\\d);/priority:\\1; gid:1;/'"], filter_string='"sid 1"')
        assert "priority:1; gid:1;" in rs.metadata_dict[1]['raw_rule']

    def test_escaped_slashes_in_pattern(self, apply):
        # Regression: strip('/') removed the trailing escaped slash from the pattern
        rs, _ = apply(["regex_sub: '/techniques\\/T1190\\//techniques/T9999//'"], filter_string='"sid 6"')
        assert "attack.mitre.org/techniques/T9999/;" in rs.metadata_dict[6]['raw_rule']

    def test_replacement_may_contain_slashes(self, apply):
        # only the first unescaped '/' separates pattern from replacement, so the replacement may contain plain slashes
        rs, _ = apply(["regex_sub: '/content:\"\\/both\"/content:\"/both/path\"/'"], filter_string='"sid 7"')
        assert 'content:"/both/path";' in rs.metadata_dict[7]['raw_rule']

    @pytest.mark.parametrize("value", ["alert/drop", "/alert/drop", "alert/drop/", "/alert/drop/x"])
    def test_bad_format_is_error_and_skipped(self, apply, caplog, value):
        rs, _ = apply(["regex_sub: '{}'".format(value), "disable"], filter_string='"sid 1"')
        assert "Bad regex_sub value" in caplog.text
        assert rs.metadata_dict[1]['raw_rule'].startswith("alert ")
        assert rs.metadata_dict[1]['disabled'] is True

    def test_missing_replacement_is_error(self, apply, caplog):
        rs, _ = apply(["regex_sub: '/alert/'"], filter_string='"sid 1"')
        assert "Problem processing 'regex_sub'" in caplog.text
        assert rs.metadata_dict[1]['raw_rule'].startswith("alert ")

    def test_invalid_regex_is_error(self, apply, caplog):
        rs, _ = apply(["regex_sub: '/(alert/drop/'"], filter_string='"sid 1"')
        assert "Problem processing 'regex_sub'" in caplog.text
        assert rs.metadata_dict[1]['raw_rule'].startswith("alert ")


class TestSetKeyword:
    def raw(self, rs, sid):
        return rs.metadata_dict[sid]['raw_rule']

    def test_set_priority_absolute(self, apply):
        rs, _ = apply(["set_priority: 4"], filter_string='"sid 1"')
        assert "priority:4;" in self.raw(rs, 1)
        assert "priority:1;" not in self.raw(rs, 1)

    def test_set_priority_relative_up(self, apply):
        rs, _ = apply(['set_priority: "+2"'], filter_string='"sid 1"')
        assert "priority:3;" in self.raw(rs, 1)

    def test_set_priority_relative_down(self, apply):
        rs, _ = apply(['set_priority: "-1"'], filter_string='"sid 2"')
        assert "priority:1;" in self.raw(rs, 2)

    def test_set_priority_relative_clamped_to_minimum(self, apply, caplog):
        rs, _ = apply(['set_priority: "-5"'], filter_string='"sid 1"')
        assert "priority:1;" in self.raw(rs, 1)
        assert "setting to minimum value of '1'" in caplog.text

    def test_set_gid_relative_clamped_to_zero(self, apply, caplog):
        rules = make_rule(1, body="gid:1;", metadata="priority low") + "\n"
        rs, _ = apply(['set_gid: "-5"'], filter_string='"sid 1"', rules=rules)
        assert "gid:0;" in self.raw(rs, 1)

    def test_set_keyword_added_when_missing(self, apply):
        rules = make_rule(1, metadata="priority low") + "\n"
        rs, _ = apply(["set_priority: 2"], filter_string='"sid 1"', rules=rules)
        assert self.raw(rs, 1).endswith("sid:1; rev:1; priority:2;)")

    def test_relative_on_missing_keyword_warns_and_skips(self, apply, caplog):
        rules = make_rule(1, metadata="priority low") + "\n"
        rs, _ = apply(['set_priority: "+1"'], filter_string='"sid 1"', rules=rules)
        assert "priority" not in self.raw(rs, 1).split("(", 1)[1].replace("priority low", "")
        assert "keyword 'priority' not found in SID 1" in caplog.text

    def test_set_rev(self, apply):
        rs, _ = apply(["set_rev: 7"], filter_string='"sid 1"')
        assert "rev:7;" in self.raw(rs, 1)

    def test_set_rev_relative(self, apply):
        rs, _ = apply(['set_rev: "+1"'], filter_string='"sid 1"')
        assert "rev:2;" in self.raw(rs, 1)

    def test_set_sid_changes_raw_rule_only(self, apply):
        rs, _ = apply(["set_sid: 8675309"], filter_string='"sid 1"')
        assert "sid:8675309;" in self.raw(rs, 1)
        assert 1 in rs.metadata_dict

    def test_set_gid_added(self, apply):
        rs, _ = apply(["set_gid: 0"], filter_string='"sid 1"')
        assert self.raw(rs, 1).endswith(" gid:0;)")

    def test_set_msg_is_quoted(self, apply):
        rs, _ = apply(['set_msg: "New MSG"'], filter_string='"sid 1"')
        assert 'msg:"New MSG";' in self.raw(rs, 1)
        assert "Malware CnC Beacon" not in self.raw(rs, 1)

    def test_set_classtype_replaces(self, apply):
        rs, _ = apply(['set_classtype: "command-and-control"'], filter_string='"sid 1"')
        assert "classtype:command-and-control;" in self.raw(rs, 1)
        assert "trojan-activity" not in self.raw(rs, 1)

    def test_set_classtype_added(self, apply):
        rs, _ = apply(['set_classtype: "bad-unknown"'], filter_string='"sid 5"')
        assert self.raw(rs, 5).endswith(" classtype:bad-unknown;)")

    def test_set_reference(self, apply):
        rs, _ = apply(['set_reference: "url,example.com"'], filter_string='"sid 1"')
        assert self.raw(rs, 1).endswith(" reference:url,example.com;)")

    def test_set_reference_replaces_existing(self, apply):
        rs, _ = apply(['set_reference: "url,example.com"'], filter_string='"sid 2"')
        assert "reference:url,example.com;" in self.raw(rs, 2)
        assert "reference:cve,2017-0144;" not in self.raw(rs, 2)

    @pytest.mark.parametrize("value", ["src_ip", "dest_ip"])
    def test_set_target_valid(self, apply, value):
        rs, _ = apply(['set_target: "{}"'.format(value)], filter_string='"sid 1"')
        assert self.raw(rs, 1).endswith(" target:{};)".format(value))

    def test_set_target_invalid_raises(self, apply):
        with pytest.raises(AristotleException, match="Invalid value 'both' for keyword 'target'"):
            apply(['set_target: "both"'], filter_string='"sid 1"')

    def test_set_threshold(self, apply):
        rs, _ = apply(['set_threshold: "type limit, count 1, track by_src, seconds 120"'], filter_string='"sid 1"')
        assert " threshold:type limit, count 1, track by_src, seconds 120;)" in self.raw(rs, 1)

    def test_set_flow_replaces(self, apply):
        rs, _ = apply(['set_flow: "established,to_client"'], filter_string='"sid 1"')
        assert "flow:established,to_client;" in self.raw(rs, 1)
        assert "to_server" not in self.raw(rs, 1)

    @pytest.mark.parametrize("value", ['a"b', "a\\\\b", "a;b"])
    def test_string_values_with_dangerous_characters_raise(self, apply, value):
        with pytest.raises(AristotleException, match="not supported in value"):
            apply(["set_msg: '{}'".format(value)], filter_string='"sid 1"')

    @pytest.mark.parametrize("action", ["set_priority: 0", "set_priority: abc", 'set_priority: "+abc"',
                                        "set_sid: 0", "set_rev: 0"])
    def test_invalid_int_values_raise(self, apply, action):
        with pytest.raises(AristotleException, match="Invalid value"):
            apply([action], filter_string='"sid 1"')

    def test_unsupported_keyword_is_error_and_skipped(self, apply, caplog):
        rs, _ = apply(['set_content: "x"', "disable"], filter_string='"sid 1"')
        assert "Setting keyword 'content' not supported" in caplog.text
        assert rs.metadata_dict[1]['disabled'] is True

    def test_set_actions_only_affect_matching_sids(self, apply):
        rs, _ = apply(["set_priority: 4"], filter_string='"sid 1"')
        assert "priority:2;" in self.raw(rs, 2)


class TestSetArbitraryIntegerMetadata:
    def md(self, rs, sid, key="risk_score"):
        return rs.metadata_dict[sid]['metadata'].get(key)

    def test_absolute_value(self, apply):
        rs, _ = apply(["set_risk_score: 42"], filter_string='"sid 1"')
        assert self.md(rs, 1) == ['42']
        assert rs.keys_dict['risk_score']['42'] == [1]
        assert 1 not in rs.keys_dict['risk_score']['90']

    def test_single_character_value(self, apply):
        # Regression: a one-character value such as 5 was rejected as invalid
        rs, _ = apply(["set_risk_score: 5"], filter_string='"sid 1"')
        assert self.md(rs, 1) == ['5']

    def test_zero_value(self, apply):
        rs, _ = apply(["set_risk_score: 0"], filter_string='"sid 1"')
        assert self.md(rs, 1) == ['0']

    def test_relative_increase(self, apply):
        rs, _ = apply(['set_risk_score: "+5"'], filter_string='"sid 1"')
        assert self.md(rs, 1) == ['95']

    def test_relative_decrease(self, apply):
        rs, _ = apply(['set_risk_score: "-10"'], filter_string='"sid 1"')
        assert self.md(rs, 1) == ['80']

    def test_relative_with_default_when_missing(self, apply):
        rs, _ = apply(['set_risk_score: "+0,50"'], filter_string='"sid 2"')
        assert self.md(rs, 2) == ['50']

    def test_relative_with_default_when_present(self, apply):
        rs, _ = apply(['set_risk_score: "+0,50"'], filter_string='"sid 1"')
        assert self.md(rs, 1) == ['90']

    def test_relative_without_default_when_missing_warns(self, apply, caplog):
        rs, _ = apply(['set_risk_score: "+5"'], filter_string='"sid 2"')
        assert self.md(rs, 2) is None
        assert "metadata key 'risk_score' not found in SID 2" in caplog.text

    def test_arbitrary_key_name(self, apply):
        rs, _ = apply(['set_machine_level: "-50,100"'], filter_string='"sid 1"')
        assert self.md(rs, 1, "machine_level") == ['100']
        rs, _ = apply(['set_machine_level: 7'], filter_string='"sid 1"')
        assert self.md(rs, 1, "machine_level") == ['7']

    def test_sets_metadata_used_by_later_rules(self, apply):
        yaml_text = ("rules:\n"
                     "  - filter_string: '\"sid 2\"'\n    actions:\n      - set_risk_score: \"+0,50\"\n"
                     "  - filter_string: '\"risk_score >= 50\"'\n    actions:\n      - set_risk_score: \"+30\"\n")
        rs, matched = apply(None, yaml_text=yaml_text)
        assert self.md(rs, 2) == ['80']
        assert self.md(rs, 1) == ['120']
        assert self.md(rs, 6) == ['130']
        assert matched == {1, 2, 6}

    def test_non_integer_existing_value_is_error_and_skipped(self, apply, caplog):
        rules = make_rule(1, metadata="priority low, risk_score high") + "\n"
        rs, _ = apply(['set_risk_score: "+5"'], filter_string='"sid 1"', rules=rules)
        assert self.md(rs, 1) == ['high']
        assert "invalid existing metadata value 'high'" in caplog.text

    @pytest.mark.parametrize("action", ['set_risk_score: "+5,abc"', 'set_risk_score: "+abc"', 'set_risk_score: abc',
                                        'set_risk_score: "1.5"', 'set_risk_score: "+"'])
    def test_invalid_values_raise(self, apply, action):
        with pytest.raises(AristotleException):
            apply([action], filter_string='"sid 1"')


class TestYamlStructure:
    def test_missing_file_raises(self, small_rules_str, tmp_path):
        path = str(tmp_path / "nope.yaml")
        rs = Ruleset(small_rules_str, modify_metadata=True)
        with pytest.raises(AristotleException, match="file not found"):
            rs._pfmod_apply(path, rs.get_all_sids())

    def test_invalid_yaml_raises(self, apply):
        with pytest.raises(AristotleException, match="Unable to open PFMod YAML file"):
            apply(None, yaml_text="rules:\n  - name: [unclosed\n")

    def test_non_mapping_yaml_raises(self, apply):
        with pytest.raises(AristotleException, match="Unexpected YAML format"):
            apply(None, yaml_text="- just\n- a\n- list\n")

    def test_no_rules_or_include_raises(self, apply):
        with pytest.raises(AristotleException, match="No 'rules' directives"):
            apply(None, yaml_text="version: '1.0'\n")

    def test_empty_rules_is_ok(self, apply):
        rs, matched = apply(None, yaml_text="version: '1.0'\ninclude:\nrules:\n")
        assert matched == set()

    def test_missing_filter_string_raises(self, apply):
        with pytest.raises(AristotleException, match="No 'filter_string' defined for PFMod rule 'r1'"):
            apply(None, yaml_text="rules:\n  - name: r1\n    actions: [disable]\n")

    def test_missing_actions_raises(self, apply):
        with pytest.raises(AristotleException, match="No 'actions' defined for PFMod rule '<undefined>'"):
            apply(None, yaml_text="rules:\n  - filter_string: '\"sid 1\"'\n")

    def test_bad_filter_string_raises(self, apply):
        with pytest.raises(AristotleException, match="Unable to apply filter string"):
            apply(["disable"], filter_string='("sid 1"')

    def test_name_is_optional(self, apply):
        rs, matched = apply(None, yaml_text="rules:\n  - filter_string: '\"sid 1\"'\n    actions: [disable]\n")
        assert matched == {1}

    def test_version_and_yaml_directive_accepted(self, apply):
        rs, matched = apply(None, yaml_text="%YAML 1.1\n---\nversion: \"1.0\"\nrules:\n  - filter_string: '\"sid 1\"'\n    actions: [disable]\n")
        assert matched == {1}


class TestInclude:
    def test_relative_include(self, small_rules_str, write_yaml):
        write_yaml("rules:\n  - filter_string: '\"sid 1\"'\n    actions: [disable]\n", name="sub.yaml")
        main = write_yaml("include:\n  - sub.yaml\n", name="main.yaml")
        rs = Ruleset(small_rules_str, modify_metadata=True)
        assert rs._pfmod_apply(main, rs.get_all_sids()) == {1}
        assert rs.metadata_dict[1]['disabled'] is True

    def test_relative_include_in_subdirectory(self, small_rules_str, write_yaml, tmp_path):
        (tmp_path / "sub").mkdir()
        write_yaml("rules:\n  - filter_string: '\"sid 2\"'\n    actions: [disable]\n", name=os.path.join("sub", "inner.yaml"))
        main = write_yaml("include:\n  - sub/inner.yaml\n", name="main.yaml")
        rs = Ruleset(small_rules_str, modify_metadata=True)
        assert rs._pfmod_apply(main, rs.get_all_sids()) == {2}

    def test_absolute_include(self, small_rules_str, write_yaml, tmp_path):
        other = tmp_path / "elsewhere"
        other.mkdir()
        sub = other / "abs.yaml"
        sub.write_text("rules:\n  - filter_string: '\"sid 3\"'\n    actions: [disable]\n")
        main = write_yaml("include:\n  - {}\n".format(sub), name="main.yaml")
        rs = Ruleset(small_rules_str, modify_metadata=True)
        assert rs._pfmod_apply(main, rs.get_all_sids()) == {3}

    def test_includes_processed_before_own_rules_in_order(self, small_rules_str, write_yaml):
        write_yaml("rules:\n  - filter_string: '\"sid 1\"'\n    actions:\n      - add_metadata_exclusive: \"stage one\"\n", name="a.yaml")
        write_yaml("rules:\n  - filter_string: '\"sid 1\"'\n    actions:\n      - add_metadata_exclusive: \"stage two\"\n", name="b.yaml")
        main = write_yaml("include:\n  - a.yaml\n  - b.yaml\nrules:\n  - filter_string: '\"stage two\"'\n    actions:\n      - add_metadata_exclusive: \"stage three\"\n", name="main.yaml")
        rs = Ruleset(small_rules_str, modify_metadata=True)
        assert rs._pfmod_apply(main, rs.get_all_sids()) == {1}
        assert rs.metadata_dict[1]['metadata']['stage'] == ['three']

    def test_missing_include_raises(self, small_rules_str, write_yaml):
        main = write_yaml("include:\n  - missing.yaml\n", name="main.yaml")
        rs = Ruleset(small_rules_str, modify_metadata=True)
        with pytest.raises(AristotleException, match="file not found"):
            rs._pfmod_apply(main, rs.get_all_sids())


@pytest.mark.examples
class TestExamplePfmodFiles:
    @pytest.mark.parametrize("yaml_file", ["pfmod-example.yaml", "pfmod-example2.yaml"])
    def test_example_files_apply_cleanly(self, example_rules_path, examples_dir, yaml_file):
        path = os.path.join(examples_dir, yaml_file)
        rs = Ruleset(example_rules_path, metadata_filter='"priority <ALL>"', enhance=True, modify_metadata=True, pfmod_file=path)
        sids = rs.filter_ruleset()
        matched = rs._pfmod_apply(path, sids)
        assert isinstance(matched, set)
        assert matched <= set(sids)

    def test_pfmod_example2_sets_confidence_unknown(self, example_rules_path, examples_dir):
        path = os.path.join(examples_dir, "pfmod-example2.yaml")
        rs = Ruleset(example_rules_path, metadata_filter='"priority <ALL>"', enhance=True, modify_metadata=True, pfmod_file=path)
        sids = rs.filter_ruleset()
        matched = rs._pfmod_apply(path, sids)
        assert matched == set(sids)
        for s in sids:
            assert rs.metadata_dict[s]['metadata']['confidence'] == ['unknown']
