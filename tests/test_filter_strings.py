import logging
import os

import pytest

from aristotle.aristotle import AristotleException, Ruleset

from .conftest import SMALL_SIDS, make_rule


def f(rs, filter_string):
    """Apply a filter and return the matching SIDs as a set."""
    return set(rs.filter_ruleset(filter_string))


class TestBooleanLogic:
    def test_single_key_value(self, small_ruleset):
        assert f(small_ruleset, '"priority high"') == {1, 2, 6}

    def test_and(self, small_ruleset):
        assert f(small_ruleset, '"priority high" AND "protocols http"') == {1}

    def test_or(self, small_ruleset):
        assert f(small_ruleset, '"protocols smb" OR "protocols dns"') == {2, 5}

    def test_not(self, small_ruleset):
        assert f(small_ruleset, 'NOT "priority high"') == SMALL_SIDS - {1, 2, 6}

    def test_and_not(self, small_ruleset):
        assert f(small_ruleset, '"protocols tcp" AND NOT "priority high"') == {3, 4}

    def test_parentheses_and_precedence(self, small_ruleset):
        assert f(small_ruleset, '("priority high" OR "priority medium") AND "protocols http"') == {1, 7}
        # without parens AND binds tighter than OR
        assert f(small_ruleset, '"priority high" OR "priority medium" AND "protocols http"') == {1, 2, 6, 7}

    def test_lowercase_operators(self, small_ruleset):
        assert f(small_ruleset, '"priority high" and not "protocols http" or "protocols dns"') == {2, 5, 6}

    def test_whitespace_and_newlines_allowed(self, small_ruleset):
        fs = '\n  (\n\t"priority high"\n  AND\n    "protocols http"\n  )\n'
        assert f(small_ruleset, fs) == {1}

    def test_key_and_value_case_insensitive(self, small_ruleset):
        assert f(small_ruleset, '"PRIORITY High"') == {1, 2, 6}

    @pytest.mark.parametrize("token", ['"priority    high  "', '"  priority high"', '"\t priority high "', '"\n  priority high\n"'])
    def test_extra_whitespace_inside_token(self, small_ruleset, token):
        assert f(small_ruleset, token) == {1, 2, 6}

    def test_leading_whitespace_in_token_combined_with_operators(self, small_ruleset):
        assert f(small_ruleset, '(" priority high" AND "  protocols http") OR " sid 5"') == {1, 5}

    def test_same_token_used_twice(self, small_ruleset):
        assert f(small_ruleset, '"priority high" OR ("priority high" AND "protocols smb")') == {1, 2, 6}

    def test_expression_simplifying_to_false_returns_empty_list(self, small_ruleset):
        # Regression: boolean.py simplifies this to a constant and evaluate() returned None
        assert set(small_ruleset.filter_ruleset('"priority high" AND NOT "priority high"')) == set()

    def test_expression_simplifying_to_true_returns_all_sids(self, small_ruleset):
        assert f(small_ruleset, '"priority high" OR NOT "priority high"') == SMALL_SIDS

    def test_disabled_rules_match_but_stay_disabled(self, small_ruleset):
        assert f(small_ruleset, '"protocols smtp"') == {4}
        assert small_ruleset.metadata_dict[4]['disabled'] is True


class TestMultiValuedKeys:
    """A token matches a rule if ANY of the rule's values for that key satisfies it."""

    @pytest.fixture
    def rs(self):
        rules = make_rule(1, metadata="created_at 2018-01-01, created_at 2020-01-01, cve 2017-0001, cve 2021-0001, "
                                      "risk_score 10, risk_score 90, priority low, priority high") + "\n" + \
            make_rule(2, metadata="created_at 2019-06-01, cve 2019-0001, risk_score 50, priority medium") + "\n"
        return Ruleset(rules)

    def test_each_range_side_matches_via_different_values(self, rs):
        assert f(rs, '"created_at > 2019-01-01"') == {1, 2}
        assert f(rs, '"created_at < 2019-01-01"') == {1}
        assert f(rs, '"created_at > 2019-01-01" AND "created_at < 2019-01-01"') == {1}
        assert f(rs, '"cve >= 2020-0000"') == {1}
        assert f(rs, '"cve < 2018-0000"') == {1}
        assert f(rs, '"risk_score >= 90"') == {1}
        assert f(rs, '"risk_score < 20"') == {1}
        # each token is satisfied independently (10 < 60 and 90 > 20), so rule 1 matches too
        assert f(rs, '"risk_score > 20" AND "risk_score < 60"') == {1, 2}

    def test_negation_applies_to_the_whole_rule(self, rs):
        # NOT means "no value satisfies", i.e. the complement of the match set
        assert f(rs, 'NOT "created_at > 2019-01-01"') == set()
        assert f(rs, 'NOT "created_at < 2019-01-01"') == {2}
        assert f(rs, 'NOT "priority high"') == {2}

    def test_exact_values(self, rs):
        assert f(rs, '"priority low"') == {1}
        assert f(rs, '"priority high"') == {1}
        assert f(rs, '"priority low" AND "priority high"') == {1}
        assert f(rs, '"cve 2017-0001" OR "cve 2019-0001"') == {1, 2}

    def test_single_rule_counted_once(self, rs):
        result = rs.filter_ruleset('"priority <ALL>" OR "created_at > 2000-01-01" OR "risk_score > 0"')
        assert sorted(result) == [1, 2]


class TestResultContract:
    def test_no_duplicates_and_only_known_sids(self, small_ruleset):
        result = small_ruleset.filter_ruleset('"protocols <ALL>" OR "priority high" OR NOT "cve <ALL>"')
        assert len(result) == len(set(result))
        assert set(result) <= SMALL_SIDS

    def test_result_is_a_list(self, small_ruleset):
        assert isinstance(small_ruleset.filter_ruleset('"priority high"'), list)
        assert isinstance(small_ruleset.filter_ruleset('"priority nosuchvalue"'), list)

    def test_repeated_calls_are_stable_and_independent(self, small_ruleset):
        a = set(small_ruleset.filter_ruleset('"priority high" AND "protocols tcp"'))
        b = set(small_ruleset.filter_ruleset('NOT "priority high"'))
        c = set(small_ruleset.filter_ruleset('"priority high" AND "protocols tcp"'))
        assert a == c == {1, 2}
        assert b == SMALL_SIDS - {1, 2, 6}

    def test_filter_reflects_metadata_added_after_construction(self, small_ruleset):
        assert f(small_ruleset, '"verdict benign"') == set()
        small_ruleset.add_metadata(5, "verdict", "benign")
        small_ruleset.add_metadata(1, "protocols", "udp")
        assert f(small_ruleset, '"verdict benign"') == {5}
        assert f(small_ruleset, '"protocols udp"') == {1, 5}
        assert f(small_ruleset, 'NOT "verdict benign"') == SMALL_SIDS - {5}


class TestAllAndBareKey:
    @pytest.mark.parametrize("token", ['"malware <ALL>"', '"malware <all>"', '"malware <Any>"', '"malware <ANY>"'])
    def test_all_pseudo_value(self, small_ruleset, token):
        assert f(small_ruleset, token) == {1}

    def test_bare_key_matches_all_values(self, small_ruleset):
        assert f(small_ruleset, '"cve"') == {2, 6}
        assert f(small_ruleset, '"risk_score"') == {1, 5, 6}

    def test_not_all(self, small_ruleset):
        assert f(small_ruleset, 'NOT "cve <ALL>"') == SMALL_SIDS - {2, 6}

    def test_originally_disabled_pseudo_key(self, small_ruleset):
        assert f(small_ruleset, '"originally_disabled true"') == {4}
        assert f(small_ruleset, '"originally_disabled false"') == SMALL_SIDS - {4}

    def test_classtype_pseudo_key(self, small_ruleset):
        assert f(small_ruleset, '"classtype trojan-activity"') == {1}
        assert f(small_ruleset, '"classtype <ALL>"') == {1, 2, 3, 4, 6}

    def test_filename_pseudo_key(self, small_rules_file):
        rs = Ruleset(small_rules_file)
        assert f(rs, '"filename small.rules"') == SMALL_SIDS
        assert f(rs, '"filename other.rules"') == set()


class TestUnknownKeysAndValues:
    def test_unknown_key_returns_nothing_with_warning(self, small_ruleset, caplog):
        assert set(small_ruleset.filter_ruleset('"nosuchkey value"')) == set()
        assert "metadata key 'nosuchkey' not found in ruleset" in caplog.text

    def test_unknown_value_returns_nothing_with_warning(self, small_ruleset, caplog):
        assert set(small_ruleset.filter_ruleset('"priority nosuchvalue"')) == set()
        assert "metadata key-value pair 'priority nosuchvalue' not found in ruleset" in caplog.text

    def test_not_unknown_key_returns_all(self, small_ruleset):
        assert f(small_ruleset, 'NOT "nosuchkey value"') == SMALL_SIDS


class TestSid:
    def test_sid_exact(self, small_ruleset):
        assert f(small_ruleset, '"sid 3"') == {3}

    def test_sid_ranges(self, small_ruleset):
        assert f(small_ruleset, '"sid > 6"') == {7, 8}
        assert f(small_ruleset, '"sid >= 6"') == {6, 7, 8}
        assert f(small_ruleset, '"sid < 3"') == {1, 2}
        assert f(small_ruleset, '"sid <= 3"') == {1, 2, 3}
        assert f(small_ruleset, '"sid >= 3" AND "sid <= 5"') == {3, 4, 5}

    def test_sid_of_rule_without_metadata(self, small_ruleset):
        assert f(small_ruleset, '"sid 8"') == {8}


class TestDateRanges:
    def test_greater_than_is_exclusive(self, small_ruleset):
        assert f(small_ruleset, '"created_at > 2019-01-01"') == {5, 6, 7}

    def test_greater_than_or_equal_is_inclusive(self, small_ruleset):
        assert f(small_ruleset, '"created_at >= 2019-01-01"') == {3, 5, 6, 7}

    def test_less_than_is_exclusive(self, small_ruleset):
        assert f(small_ruleset, '"created_at < 2017-05-12"') == {4}

    def test_less_than_or_equal_is_inclusive(self, small_ruleset):
        assert f(small_ruleset, '"created_at <= 2017-05-12"') == {2, 4}

    def test_range_with_and(self, small_ruleset):
        assert f(small_ruleset, '"created_at >= 2018-01-01" AND "created_at <= 2019-12-31"') == {1, 3, 7}

    def test_no_space_between_operator_and_value(self, small_ruleset):
        assert f(small_ruleset, '"created_at >=2019-01-01"') == {3, 5, 6, 7}

    def test_updated_at_requires_parseable_values(self, small_ruleset):
        # sid 7 has 'updated_at 2020_01_15' which is not a parseable date unless normalized
        with pytest.raises(AristotleException, match="as datetime"):
            small_ruleset.filter_ruleset('"updated_at >= 2018-03-20"')

    def test_updated_at_with_normalize(self, small_rules_str):
        rs = Ruleset(small_rules_str, normalize=True)
        assert f(rs, '"updated_at >= 2018-03-20"') == {1, 7}
        assert f(rs, '"updated_at > 2018-03-20"') == {7}

    def test_exact_date_match(self, small_ruleset):
        assert f(small_ruleset, '"created_at 2020-02-29"') == {5}

    def test_unparseable_date_bound_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="as datetime"):
            small_ruleset.filter_ruleset('"created_at > not-a-date"')

    def test_unparseable_metadata_date_raises(self):
        rs = Ruleset('alert tcp any any -> any any (msg:"x"; metadata:created_at yesterday-ish; sid:1;)\n')
        with pytest.raises(AristotleException, match="as datetime"):
            rs.filter_ruleset('"created_at > 2000-01-01"')


class TestCveRanges:
    def test_exact(self, small_ruleset):
        assert f(small_ruleset, '"cve 2017-0144"') == {2}

    def test_greater_or_equal_full_cve(self, small_ruleset):
        assert f(small_ruleset, '"cve >= 2017-0144"') == {2, 6}
        assert f(small_ruleset, '"cve >= 2017-0145"') == {6}

    def test_greater_than_full_cve(self, small_ruleset):
        assert f(small_ruleset, '"cve > 2017-0144"') == {6}

    def test_less_than_full_cve(self, small_ruleset):
        assert f(small_ruleset, '"cve < 2021-44228"') == {2}
        assert f(small_ruleset, '"cve <= 2021-44228"') == {2, 6}

    def test_year_only_bounds(self, small_ruleset):
        assert f(small_ruleset, '"cve >= 2018"') == {6}
        assert f(small_ruleset, '"cve > 2017"') == {6}
        assert f(small_ruleset, '"cve < 2018"') == {2}
        assert f(small_ruleset, '"cve <= 2017"') == {2}
        assert f(small_ruleset, '"cve >= 2017-0000"') == {2, 6}

    def test_invalid_cve_bound_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="CVE"):
            small_ruleset.filter_ruleset('"cve >= abc-def"')


class TestCveCompare:
    @pytest.mark.parametrize("left, op, right, expected", [
        ("2018-100", ">", "2018-99", True),
        ("2018-99", ">", "2018-100", False),
        ("2018-100", ">", "2018-100", False),
        ("2018-100", ">=", "2018-100", True),
        ("2018-100", "<", "2018-100", False),
        ("2018-100", "<=", "2018-100", True),
        ("2019-1", ">", "2018-99999", True),
        ("2017-99999", "<", "2018-1", True),
        ("2018-5", ">=", "2018", True),
        ("2018-5", ">", "2018", False),
        ("2019-1", ">", "2018", True),
        ("2018-5", "<", "2018", False),
        ("2018-5", "<=", "2018", True),
        ("2017-5", "<", "2018", True),
        ("2018-5", "=", "2018-5", False),  # unsupported operator returns False
    ])
    def test_table(self, small_ruleset, left, op, right, expected):
        assert small_ruleset.cve_compare(left, right, op) is expected

    def test_non_numeric_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="Unable to do CVE comparison"):
            small_ruleset.cve_compare("abc", "2018-1", ">")


class TestFloatRanges:
    def test_cvss_v3_base(self, small_ruleset):
        assert f(small_ruleset, '"cvss_v3_base >= 8.1"') == {1, 6}
        assert f(small_ruleset, '"cvss_v3_base > 8.1"') == {6}
        assert f(small_ruleset, '"cvss_v3_base < 10"') == {1}
        assert f(small_ruleset, '"cvss_v3_base <= 10"') == {1, 6}

    def test_cvss_v2_base(self, small_ruleset):
        assert f(small_ruleset, '"cvss_v2_base > 9"') == {2}

    def test_risk_score(self, small_ruleset):
        assert f(small_ruleset, '"risk_score >= 90"') == {1, 6}
        assert f(small_ruleset, '"risk_score < 50"') == {5}
        assert f(small_ruleset, '"risk_score > 10" AND "risk_score < 100"') == {1}

    def test_exact_float_value_as_string(self, small_ruleset):
        assert f(small_ruleset, '"risk_score 90"') == {1}

    def test_non_numeric_bound_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="as float"):
            small_ruleset.filter_ruleset('"risk_score > high"')

    def test_non_numeric_metadata_raises(self):
        rs = Ruleset('alert tcp any any -> any any (msg:"x"; metadata:risk_score high; sid:1;)\n')
        with pytest.raises(AristotleException, match="as float"):
            rs.filter_ruleset('"risk_score > 5"')

    def test_operator_without_value_raises(self, small_ruleset):
        with pytest.raises(AristotleException):
            small_ruleset.filter_ruleset('"risk_score >"')

    def test_range_operator_on_non_range_key_is_literal(self, small_ruleset, caplog):
        # '>' is only special for range keys; for other keys it is part of the value
        assert set(small_ruleset.filter_ruleset('"priority > high"')) == set()
        assert "not found in ruleset" in caplog.text


class TestRegex:
    def test_msg_regex_case_sensitive(self, small_ruleset):
        assert f(small_ruleset, '"msg_regex /Phishing/"') == {3}
        assert f(small_ruleset, '"msg_regex /phishing/"') == set()

    def test_msg_regex_case_insensitive(self, small_ruleset):
        assert f(small_ruleset, '"msg_regex /phishing/i"') == {3}

    def test_msg_regex_anchors_and_groups(self, small_ruleset):
        assert f(small_ruleset, '"msg_regex /^Acme\\x20-\\x20(SMB|DNS)/"') == {2, 5}
        assert f(small_ruleset, '"msg_regex /INFORMATIONAL$/"') == {4}

    def test_msg_regex_value_case_preserved_while_key_lowercased(self, small_ruleset):
        assert f(small_ruleset, '"MSG_REGEX /Phishing/"') == {3}

    def test_rule_regex(self, small_ruleset):
        assert f(small_ruleset, '"rule_regex /^alert\\s+ip\\s+/"') == {6}
        assert f(small_ruleset, '"rule_regex /flowbits/"') == set()
        assert f(small_ruleset, '"rule_regex /priority\\s*:\\s*[12]\\s*;/"') == {1, 2, 6, 7}

    def test_rule_regex_case_insensitive(self, small_ruleset):
        assert f(small_ruleset, '"rule_regex /TARGET:DEST_IP/i"') == {2}

    def test_regex_ending_with_escaped_slash(self, small_ruleset):
        # Regression: strip('/') also removed the escaped trailing slash from the pattern
        assert f(small_ruleset, '"rule_regex /T1190\\//"') == {6}
        assert f(small_ruleset, '"rule_regex /t1190\\//i"') == {6}

    def test_regex_combined_with_metadata(self, small_ruleset):
        assert f(small_ruleset, '"msg_regex /Acme/" AND NOT "protocols tcp"') == {5, 6, 7, 8}

    @pytest.mark.parametrize("value", ["Phishing", "/Phishing", "Phishing/", "/Phishing/x", "'Phishing'"])
    def test_bad_regex_format_raises(self, small_ruleset, value):
        with pytest.raises(AristotleException, match="Pattern must start with '/'"):
            small_ruleset.filter_ruleset('"msg_regex {}"'.format(value))

    def test_invalid_regex_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="Unable to compile RegEx pattern"):
            small_ruleset.filter_ruleset('"msg_regex /(unclosed/"')

    def test_pattern_ending_in_i_without_flag(self, small_ruleset):
        # a pattern ending in the letter 'i' must not be misread as the /i flag
        assert f(small_ruleset, '"msg_regex /SNI/"') == {3}
        assert f(small_ruleset, '"msg_regex /sni/"') == set()


class TestFilterStringErrors:
    def test_no_tokens_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="contains no tokens"):
            small_ruleset.filter_ruleset("priority high")

    def test_unbalanced_parentheses_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="Problem processing metadata_filter"):
            small_ruleset.filter_ruleset('("priority high" AND "protocols http"')

    def test_missing_operator_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="Problem processing metadata_filter"):
            small_ruleset.filter_ruleset('"priority high" "protocols http"')

    def test_no_filter_set_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="No metadata_filter set"):
            small_ruleset.filter_ruleset()

    def test_empty_filter_raises(self, small_ruleset):
        with pytest.raises(AristotleException):
            small_ruleset.filter_ruleset("")


class TestFilterSources:
    def test_filter_via_constructor(self, small_rules_str):
        rs = Ruleset(small_rules_str, metadata_filter='"priority high"')
        assert rs.metadata_filter == '"priority high"'
        assert set(rs.filter_ruleset()) == {1, 2, 6}

    def test_set_metadata_filter_string(self, small_ruleset):
        small_ruleset.set_metadata_filter('"protocols dns"')
        assert set(small_ruleset.filter_ruleset()) == {5}

    def test_argument_overrides_stored_filter(self, small_ruleset):
        small_ruleset.set_metadata_filter('"protocols dns"')
        assert set(small_ruleset.filter_ruleset('"priority high"')) == {1, 2, 6}
        # stored filter unchanged
        assert set(small_ruleset.filter_ruleset()) == {5}

    def test_filter_file_with_comments_and_blank_lines(self, small_ruleset, tmp_path):
        p = tmp_path / "x.filter"
        p.write_text("# leading comment\n\n   # indented comment\n(\n  \"priority high\"\n  # inline-ish comment line\n  AND \"protocols http\"\n)\n\n")
        small_ruleset.set_metadata_filter(str(p))
        assert set(small_ruleset.filter_ruleset()) == {1}
        assert small_ruleset.enable_all_rules is False

    def test_filter_file_enable_all_rules_directive(self, small_rules_str, tmp_path):
        p = tmp_path / "x.filter"
        p.write_text("# enable everything\n<enable-all-rules>\n\"protocols smtp\"\n")
        rs = Ruleset(small_rules_str, metadata_filter=str(p))
        assert rs.enable_all_rules is True
        assert rs.get_disabled_sids() == []
        assert set(rs.filter_ruleset()) == {4}
        assert rs.metadata_dict[4]['disabled'] is False
        assert rs.metadata_dict[4]['originally_disabled'] is True

    def test_enable_all_rules_directive_is_case_insensitive(self, small_rules_str, tmp_path):
        p = tmp_path / "x.filter"
        p.write_text("<ENABLE-ALL-RULES>\n\"protocols smtp\"\n")
        rs = Ruleset(small_rules_str, metadata_filter=str(p))
        assert rs.enable_all_rules is True
        assert rs.metadata_filter == '"protocols smtp"\n'

    def test_enable_all_rules_directive_with_leading_whitespace(self, small_rules_str, tmp_path):
        # Regression: leading whitespace caused the tail of the directive to be appended to the filter
        p = tmp_path / "x.filter"
        p.write_text("   <enable-all-rules>\n\"protocols smtp\"\n")
        rs = Ruleset(small_rules_str, metadata_filter=str(p))
        assert rs.enable_all_rules is True
        assert rs.metadata_filter == '"protocols smtp"\n'
        assert set(rs.filter_ruleset()) == {4}

    def test_enable_all_rules_directive_with_filter_on_same_line(self, small_rules_str, tmp_path):
        p = tmp_path / "x.filter"
        p.write_text('<enable-all-rules> "protocols smtp"\n')
        rs = Ruleset(small_rules_str, metadata_filter=str(p))
        assert rs.enable_all_rules is True
        assert set(rs.filter_ruleset()) == {4}

    def test_non_file_path_is_treated_as_literal_filter(self, small_ruleset, tmp_path):
        small_ruleset.set_metadata_filter(str(tmp_path))  # a directory, so not loaded as a file
        assert small_ruleset.metadata_filter == str(tmp_path)
        with pytest.raises(AristotleException, match="contains no tokens"):
            small_ruleset.filter_ruleset()


class TestGetSids:
    def test_get_sids_direct(self, small_ruleset):
        assert set(small_ruleset.get_sids("priority high")) == {1, 2, 6}
        assert set(small_ruleset.get_sids("priority high", negate=True)) == SMALL_SIDS - {1, 2, 6}

    def test_get_sids_returns_unique(self, small_ruleset):
        # protocols <all> touches multiple values per sid; result must be deduplicated
        result = small_ruleset.get_sids("protocols <all>")
        assert len(result) == len(set(result))
        assert set(result) == SMALL_SIDS - {8}


@pytest.mark.examples
class TestExampleFilters:
    """Regression values for the example filter files against examples/example.rules."""

    @pytest.mark.parametrize("filter_file, expected_total, expected_enabled, enable_all", [
        ("example1.filter", 2529, 2503, False),
        ("example2.filter", 1854, 1833, False),
        ("example3.filter", 326, 315, False),
        ("example4.filter", 1302, 1285, False),
        ("example5.filter", 1433, 1433, True),
    ])
    def test_example_filter_counts(self, example_rules_path, examples_dir, filter_file, expected_total, expected_enabled, enable_all):
        rs = Ruleset(example_rules_path, metadata_filter=os.path.join(examples_dir, filter_file))
        assert rs.enable_all_rules is enable_all
        sids = rs.filter_ruleset()
        assert len(sids) == expected_total
        assert len([s for s in sids if not rs.metadata_dict[s]['disabled']]) == expected_enabled

    def test_readme_example_filter(self, example_ruleset):
        fs = ('(("priority high" AND "malware <ALL>") AND "created_at >= 2018-01-01") '
              'AND NOT ("protocols smtp" OR "protocols pop" OR "protocols imap") OR "sid 80181444"')
        sids = set(example_ruleset.filter_ruleset(fs))
        assert 80181444 in sids
        for s in sids - {80181444}:
            md = example_ruleset.metadata_dict[s]['metadata']
            assert 'high' in md['priority']
            assert 'malware' in md
            assert not ({'smtp', 'pop', 'imap'} & set(md['protocols']))
            assert min(md['created_at']) >= '2018-01-01'

    def test_example1_filter_semantics(self, example_ruleset, examples_dir, small_rules_str):
        # load the filter file through a throwaway Ruleset so the shared fixture isn't mutated
        filter_string = Ruleset(small_rules_str, metadata_filter=os.path.join(examples_dir, "example1.filter")).metadata_filter
        sids = example_ruleset.filter_ruleset(filter_string)
        assert len(sids) == 2529
        for s in sids:
            md = example_ruleset.metadata_dict[s]['metadata']
            assert ('2018-17994' in md.get('cve', [])) or \
                ('high' in md['priority'] and ({'http', 'tls'} & set(md['protocols'])))

    def test_sid_filter_on_example_ruleset(self, example_ruleset):
        assert set(example_ruleset.filter_ruleset('"sid 80181444"')) == {80181444}

    def test_cve_and_date_filters_consistent(self, example_ruleset):
        newer = set(example_ruleset.filter_ruleset('"cve >= 2018-0000"'))
        older = set(example_ruleset.filter_ruleset('"cve < 2018-0000"'))
        all_cve = set(example_ruleset.filter_ruleset('"cve <ALL>"'))
        assert newer | older == all_cve
        assert not (newer & older)


class TestScopedFilter:
    """``filter_ruleset(..., sids=...)`` restricts evaluation to the given SIDs."""

    def test_scope_limits_results(self, small_ruleset):
        assert set(small_ruleset.filter_ruleset('"priority high"', sids=[1, 3, 6])) == {1, 6}

    def test_empty_scope_gives_empty_result(self, small_ruleset):
        assert small_ruleset.filter_ruleset('"priority <ALL>"', sids=[]) == []

    def test_negation_is_relative_to_scope(self, small_ruleset):
        assert set(small_ruleset.filter_ruleset('NOT "priority high"', sids=[1, 3, 5])) == {3, 5}
        assert set(small_ruleset.filter_ruleset('NOT "nosuchkey x"', sids=[2, 4])) == {2, 4}

    def test_regex_and_range_terms_respect_scope(self, small_ruleset):
        assert set(small_ruleset.filter_ruleset('"msg_regex /Acme/"', sids=[2, 7])) == {2, 7}
        assert set(small_ruleset.filter_ruleset('"created_at >= 2019-01-01"', sids=[1, 3, 5])) == {3, 5}
        assert set(small_ruleset.filter_ruleset('"risk_score > 50" OR "cve >= 2020-0000"', sids=[1, 5])) == {1}

    def test_scope_matches_intersecting_afterwards(self, small_ruleset):
        fs = '("priority high" OR "msg_regex /DNS/") AND NOT "protocols smb" AND "created_at > 2017-01-01"'
        scope = [1, 2, 5, 8]
        assert set(small_ruleset.filter_ruleset(fs, sids=scope)) == set(small_ruleset.filter_ruleset(fs)) & set(scope)

    def test_repeated_regex_filter_gives_same_result(self, small_ruleset):
        first = set(small_ruleset.filter_ruleset('"rule_regex /priority:1;/"'))
        assert first == {1, 6}
        assert set(small_ruleset.filter_ruleset('"rule_regex /priority:1;/"', sids=[6, 7])) == {6}
        assert set(small_ruleset.filter_ruleset('"rule_regex /priority:1;/"')) == first
