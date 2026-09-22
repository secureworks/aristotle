import pytest

from aristotle.aristotle import AristotleException


class TestAddMetadata:
    def test_adds_to_both_structures(self, small_ruleset):
        small_ruleset.add_metadata(5, "verdict", "benign")
        assert small_ruleset.metadata_dict[5]['metadata']['verdict'] == ['benign']
        assert small_ruleset.keys_dict['verdict'] == {'benign': [5]}

    def test_adds_sid_to_existing_key_value(self, small_ruleset):
        small_ruleset.add_metadata(5, "confidence", "high")
        assert small_ruleset.metadata_dict[5]['metadata']['confidence'] == ['high']
        assert small_ruleset.keys_dict['confidence']['high'] == [3, 5]

    def test_lowercases_and_strips(self, small_ruleset):
        small_ruleset.add_metadata(5, "  Verdict ", " BENIGN ")
        assert small_ruleset.metadata_dict[5]['metadata']['verdict'] == ['benign']
        assert small_ruleset.keys_dict['verdict'] == {'benign': [5]}

    def test_appends_additional_value_for_existing_key(self, small_ruleset):
        small_ruleset.add_metadata(1, "protocols", "udp")
        assert set(small_ruleset.metadata_dict[1]['metadata']['protocols']) == {'http', 'tcp', 'udp'}
        assert small_ruleset.keys_dict['protocols']['udp'] == [5, 1]

    def test_no_duplicate_on_repeat(self, small_ruleset):
        small_ruleset.add_metadata(1, "protocols", "http")
        small_ruleset.add_metadata(1, "protocols", "http")
        assert small_ruleset.metadata_dict[1]['metadata']['protocols'].count('http') == 1
        assert small_ruleset.keys_dict['protocols']['http'].count(1) == 1

    def test_invalid_sid_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="sid is invalid"):
            small_ruleset.add_metadata(999, "k", "v")


class TestDeleteMetadata:
    def test_delete_key_removes_all_values(self, small_ruleset):
        small_ruleset.delete_metadata(1, "protocols")
        assert 'protocols' not in small_ruleset.metadata_dict[1]['metadata']
        assert 1 not in small_ruleset.keys_dict['protocols']['http']
        assert 1 not in small_ruleset.keys_dict['protocols']['tcp']
        # other rules untouched
        assert 7 in small_ruleset.keys_dict['protocols']['http']

    def test_delete_specific_value(self, small_ruleset):
        small_ruleset.delete_metadata(1, "protocols", "tcp")
        assert small_ruleset.metadata_dict[1]['metadata']['protocols'] == ['http']
        assert 1 not in small_ruleset.keys_dict['protocols']['tcp']
        assert 1 in small_ruleset.keys_dict['protocols']['http']

    def test_delete_is_case_insensitive(self, small_ruleset):
        small_ruleset.delete_metadata(1, "PROTOCOLS", " TCP ")
        assert small_ruleset.metadata_dict[1]['metadata']['protocols'] == ['http']

    def test_delete_unknown_key_is_noop(self, small_ruleset):
        before = dict(small_ruleset.metadata_dict[1]['metadata'])
        small_ruleset.delete_metadata(1, "nosuchkey")
        small_ruleset.delete_metadata(1, "nosuchkey", "value")
        small_ruleset.delete_metadata(1, "protocols", "nosuchvalue")
        assert small_ruleset.metadata_dict[1]['metadata'] == before

    def test_invalid_sid_raises(self, small_ruleset):
        with pytest.raises(AristotleException, match="sid is invalid"):
            small_ruleset.delete_metadata(999, "k")

    def test_filters_reflect_deletion(self, small_ruleset):
        assert 1 in small_ruleset.filter_ruleset('"priority high"')
        small_ruleset.delete_metadata(1, "priority")
        assert 1 not in small_ruleset.filter_ruleset('"priority high"')
        assert 1 in small_ruleset.filter_ruleset('NOT "priority <ALL>"')


class TestSidAccessors:
    def test_all_enabled_disabled_partition(self, small_ruleset):
        all_sids = set(small_ruleset.get_all_sids())
        enabled = set(small_ruleset.get_enabled_sids())
        disabled = set(small_ruleset.get_disabled_sids())
        assert enabled | disabled == all_sids
        assert not (enabled & disabled)

    def test_reflects_runtime_disable(self, small_ruleset):
        small_ruleset.metadata_dict[1]['disabled'] = True
        assert 1 in small_ruleset.get_disabled_sids()
        assert 1 not in small_ruleset.get_enabled_sids()
