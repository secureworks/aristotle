"""Tests using dummy rules that mimic real-world ruleset syntax (see REALISTIC_RULES in conftest)."""
import logging

import pytest

from aristotle.aristotle import Ruleset

from .conftest import REALISTIC_RULES, REALISTIC_SIDS


@pytest.fixture
def rs(realistic_rules_file):
    return Ruleset(realistic_rules_file, enhance=True, normalize=True)


class TestLoading:
    def test_loads_without_warnings_or_errors(self, realistic_rules_file, caplog):
        with caplog.at_level(logging.WARNING, logger="aristotle"):
            rs = Ruleset(realistic_rules_file, enhance=True, normalize=True)
        assert set(rs.get_all_sids()) == REALISTIC_SIDS
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []

    def test_disabled_rule_detected(self, rs):
        assert rs.get_disabled_sids() == [9000004]

    def test_msg_extracted_with_parentheses(self, rs):
        assert rs.metadata_dict[9000005]['msg'] == "DUMMY P2P Search Request (search by name)"
        assert rs.metadata_dict[9000007]['msg'] == "DUMMY MALWARE Keylogger FTP Log Upload (Null obfuscated)"

    def test_escaped_semicolon_in_content_does_not_break_parsing(self, rs):
        md = rs.metadata_dict[9000003]['metadata']
        assert md['signature_severity'] == ['major']
        assert md['sid'] == ['9000003']
        md = rs.metadata_dict[9000004]['metadata']
        assert md['former_category'] == ['policy']
        assert md['confidence'] == ['low']

    def test_metadata_after_rev_is_parsed(self, rs):
        assert rs.metadata_dict[9000001]['metadata']['tag'] == ['blocklist']
        assert rs.metadata_dict[9000001]['metadata']['classtype'] == ['misc-attack']

    def test_underscore_values_preserved_when_not_dates(self, rs):
        assert rs.metadata_dict[9000003]['metadata']['mitre_tactic_name'] == ['command_and_control']
        assert rs.metadata_dict[9000010]['metadata']['affected_product'] == ['windows_xp_vista_7_8_10_server_32_64_bit']


class TestNormalization:
    def test_dates_normalized(self, rs):
        assert rs.metadata_dict[9000001]['metadata']['created_at'] == ['2010-12-30']
        assert rs.metadata_dict[9000001]['metadata']['updated_at'] == ['2026-09-16']
        for s in rs.metadata_dict:
            for v in rs.metadata_dict[s]['metadata']['created_at']:
                assert len(v) == 10 and v.count('-') == 2

    def test_cve_metadata_normalized_and_merged_with_reference(self, rs):
        assert rs.metadata_dict[9000002]['metadata']['cve'] == ['2009-4179']
        assert rs.keys_dict['cve']['2009-4179'] == [9000002]

    def test_mitre_ids_mapped_to_mitre_attack(self, rs):
        assert set(rs.metadata_dict[9000003]['metadata']['mitre_attack']) == {'ta0011', 't1071'}
        assert 'mitre_tactic_id' not in rs.keys_dict
        assert 'mitre_technique_id' not in rs.keys_dict
        assert set(rs.metadata_dict[9000007]['metadata']['mitre_attack']) == {'ta0010', 't1041'}

    def test_mitre_from_reference_url(self, rs):
        assert rs.metadata_dict[9000009]['metadata']['mitre_attack'] == ['t1071.004']
        assert rs.metadata_dict[9000010]['metadata']['mitre_attack'] == ['ta0002']


class TestEnhancement:
    @pytest.mark.parametrize("sid, expected", [
        (9000001, "inbound"),
        (9000002, "inbound"),
        (9000003, "any"),
        (9000004, "outbound"),
        (9000005, "outbound"),
        (9000006, "outbound-notexclusive"),
        (9000007, "outbound"),
        (9000008, "inbound"),
        (9000009, "outbound"),
        (9000010, "inbound"),
    ])
    def test_detection_direction(self, rs, sid, expected):
        assert rs.metadata_dict[sid]['metadata']['detection_direction'] == [expected]

    def test_protocols(self, rs):
        assert set(rs.metadata_dict[9000002]['metadata']['protocols']) == {'http'}
        assert set(rs.metadata_dict[9000003]['metadata']['protocols']) == {'dns'}
        assert set(rs.metadata_dict[9000008]['metadata']['protocols']) == {'tls'}
        assert set(rs.metadata_dict[9000009]['metadata']['protocols']) == {'tcp'}

    def test_flow_with_pcre_group_still_gets_direction(self, rs):
        assert set(rs.metadata_dict[9000002]['metadata']['flow']) == {'established', 'to_server'}

    def test_flow_from_client_normalized(self, rs):
        assert rs.metadata_dict[9000010]['metadata']['flow'] == ['to_server']

    def test_hostile_from_target(self, rs):
        assert rs.metadata_dict[9000010]['metadata']['hostile'] == ['src_ip']

    def test_cve_from_reference_only(self, rs):
        assert rs.metadata_dict[9000006]['metadata']['cve'] == ['2014-0160']
        assert rs.metadata_dict[9000010]['metadata']['cve'] == ['2018-12589']


class TestFiltering:
    def test_signature_severity_and_dates(self, rs):
        sids = set(rs.filter_ruleset('"signature_severity major" AND "updated_at >= 2020-01-01"'))
        assert sids == {9000001, 9000002, 9000003, 9000006, 9000007}

    def test_mitre_attack_filter(self, rs):
        assert set(rs.filter_ruleset('"mitre_attack ta0011"')) == {9000003}
        assert set(rs.filter_ruleset('"mitre_attack <ALL>"')) == {9000003, 9000007, 9000009, 9000010}

    def test_rule_regex_on_flowbits_setters(self, rs):
        assert set(rs.filter_ruleset('"rule_regex /[\\s\\x3B\\x28]flowbits\\s*\\x3A\\s*set/"')) == {9000001}

    def test_msg_regex_category(self, rs):
        assert set(rs.filter_ruleset('"msg_regex /^DUMMY (MALWARE|EXPLOIT) /"')) == {9000007, 9000010}

    def test_detection_direction_filter(self, rs):
        assert set(rs.filter_ruleset('"detection_direction inbound" AND "protocols http"')) == {9000002}

    def test_former_category_and_disabled(self, rs):
        assert set(rs.filter_ruleset('"former_category <ALL>"')) == {9000004, 9000008}
        assert set(rs.filter_ruleset('"former_category <ALL>" AND NOT "originally_disabled true"')) == {9000008}


class TestOutput:
    def test_unmodified_output_is_verbatim(self, realistic_rules_file, tmp_path):
        rs = Ruleset(realistic_rules_file, output_disabled_rules=True)
        out = tmp_path / "out.rules"
        rs.output_rules(rs.get_all_sids(), outfile=str(out))
        assert out.read_text().splitlines() == REALISTIC_RULES

    def test_modified_output_reloads_with_same_metadata(self, rs, tmp_path):
        out = tmp_path / "out.rules"
        rs.output_rules(rs.get_all_sids(), outfile=str(out), modify_metadata=True)
        # ignore_filename so 'out.rules' isn't added; the original filename survives via the written metadata
        rs2 = Ruleset(str(out), ignore_filename=True)
        assert set(rs2.get_all_sids()) == REALISTIC_SIDS - {9000004}
        for s in rs2.get_all_sids():
            expected = {k: sorted(v) for k, v in rs.metadata_dict[s]['metadata'].items()}
            actual = {k: sorted(v) for k, v in rs2.metadata_dict[s]['metadata'].items()}
            assert actual == expected
            assert actual['filename'] == ['dummy-threats.rules']
            # the rule body outside the metadata keyword is untouched
            assert rs2.metadata_dict[s]['raw_rule'].split("metadata:")[0] == \
                [r for r in REALISTIC_RULES if "sid:{};".format(s) in r][0].split("metadata:")[0]
