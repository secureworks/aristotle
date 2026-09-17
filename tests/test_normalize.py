import pytest

from aristotle.aristotle import Ruleset

from .conftest import make_rule


class TestNormalizeBetter:
    @pytest.fixture
    def rs(self, small_ruleset):
        return small_ruleset

    @pytest.mark.parametrize("key, value, expected", [
        ("created_at", "2018_03_19", "2018-03-19"),
        ("created_at", "2018-03-19", "2018-03-19"),
        ("updated_at", "2019/12/31", "2019-12-31"),
        ("updated-at", "March 19, 2018", "2018-03-19"),
        ("reviewed_at", "20200229", "2020-02-29"),
        ("created_at", "2021-07-04T12:34:56Z", "2021-07-04"),
    ])
    def test_dates_normalized(self, rs, key, value, expected):
        assert rs.normalize_better(key, value) == [[key, expected]]

    def test_unparseable_date_left_unchanged_with_warning(self, rs, caplog):
        assert rs.normalize_better("created_at", "not a date", sid=7) == [["created_at", "not a date"]]
        assert "Unable to parse metadata 'created_at' key with value 'not a date' as date for sid 7" in caplog.text

    @pytest.mark.parametrize("value, expected", [
        ("2021-27561", ["2021-27561"]),
        ("2021_27561", ["2021-27561"]),
        ("cve_2021_27561_cve_2021_27562", ["2021-27561", "2021-27562"]),
        ("cve-2017-0144", ["2017-0144"]),
        ("2018-0000", ["2018-0000"]),
        ("1999-1234", ["1999-1234"]),
    ])
    def test_cve_normalized(self, rs, value, expected):
        assert rs.normalize_better("cve", value) == [["cve", v] for v in expected]

    def test_unparseable_cve_dropped_with_warning(self, rs, caplog):
        assert rs.normalize_better("cve", "unknown", sid=3) == []
        assert "Unable to parse metadata 'cve' key with value 'unknown' for sid 3" in caplog.text

    @pytest.mark.parametrize("key", ["mitre_technique_id", "mitre_tactic_id"])
    def test_mitre_keys_mapped_to_mitre_attack(self, rs, key):
        assert rs.normalize_better(key, "t1190") == [["mitre_attack", "t1190"]]

    def test_other_keys_pass_through(self, rs):
        assert rs.normalize_better("priority", "high") == [["priority", "high"]]
        assert rs.normalize_better("format", "2018_03_19") == [["format", "2018_03_19"]]


class TestNormalizeOption:
    def test_default_does_not_normalize(self, small_ruleset):
        assert small_ruleset.metadata_dict[7]['metadata']['updated_at'] == ['2020_01_15']
        assert small_ruleset.metadata_dict[6]['metadata']['mitre_technique_id'] == ['t1190']
        assert 'mitre_attack' not in small_ruleset.keys_dict

    def test_normalize_dates_and_mitre_in_ruleset(self, small_rules_str):
        rs = Ruleset(small_rules_str, normalize=True)
        assert rs.metadata_dict[7]['metadata']['updated_at'] == ['2020-01-15']
        assert rs.keys_dict['updated_at']['2020-01-15'] == [7]
        assert rs.metadata_dict[6]['metadata']['mitre_attack'] == ['t1190']
        assert 'mitre_technique_id' not in rs.metadata_dict[6]['metadata']
        assert 'mitre_technique_id' not in rs.keys_dict

    def test_normalized_dates_usable_in_range_filters(self, small_rules_str):
        rs = Ruleset(small_rules_str, normalize=True)
        assert rs.filter_ruleset('"updated_at >= 2020-01-01"') == [7]

    def test_normalize_multi_cve_value(self):
        rs = Ruleset(make_rule(1, metadata="cve cve_2021_27561_cve_2021_27562, priority low") + "\n", normalize=True)
        assert set(rs.metadata_dict[1]['metadata']['cve']) == {'2021-27561', '2021-27562'}
        assert set(rs.filter_ruleset('"cve 2021-27562"')) == {1}

    def test_normalize_keeps_sid_internally(self, small_rules_str):
        rs = Ruleset(small_rules_str, normalize=True)
        assert rs.metadata_dict[1]['metadata']['sid'] == ['1']
        assert rs.filter_ruleset('"sid 1"') == [1]


@pytest.mark.examples
class TestNormalizeExampleRuleset:
    def test_example_ruleset_normalizes_cleanly(self, example_rules_path):
        rs = Ruleset(example_rules_path, normalize=True)
        for s in rs.metadata_dict:
            md = rs.metadata_dict[s]['metadata']
            for v in md['created_at'] + md['updated_at']:
                assert len(v) == 10 and v[4] == '-' and v[7] == '-'
            for v in md.get('cve', []):
                assert v[4] == '-' and v[:4].isdigit()
