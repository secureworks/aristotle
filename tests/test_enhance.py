import pytest

from aristotle.aristotle import AristotleException, Ruleset

from .conftest import make_rule


class TestReduceIpval:
    @pytest.fixture
    def rs(self, small_ruleset):
        return small_ruleset

    @pytest.mark.parametrize("ipval, expected", [
        ("any", "any"),
        ("$HOME_NET", "$HOME_NET"),
        ("$EXTERNAL_NET", "$EXTERNAL_NET"),
        ("!$HOME_NET", "$EXTERNAL_NET"),
        ("!$EXTERNAL_NET", "$HOME_NET"),
        ("$HTTP_SERVERS", "$HOME_NET"),
        ("$DNS_SERVERS", "$HOME_NET"),
        ("$SQL_SERVERS", "$HOME_NET"),
        ("$RFC1918", "$EXTERNAL_NET"),
        ("$AIM_SERVERS", "$EXTERNAL_NET"),
        ("$CUSTOM_NET", "$HOME_NET"),
        ("!$CUSTOM_NET", "$EXTERNAL_NET"),
        ("[$HOME_NET,$DNS_SERVERS]", "$HOME_NET"),
        ("[$EXTERNAL_NET,$RFC1918]", "$EXTERNAL_NET"),
        ("[any,$HOME_NET]", "any"),
        ("![$HOME_NET]", "$EXTERNAL_NET"),
        ("![$EXTERNAL_NET]", "$HOME_NET"),
        ("[10.0.0.0/8]", "$HOME_NET"),
        ("[192.168.0.0/16,172.16.0.0/12]", "$HOME_NET"),
        ("192.168.0.0/16", "$HOME_NET"),
        ("192.168.0.0/24", "$EXTERNAL_NET"),
        ("127.0.0.0/8", "$HOME_NET"),
        ("![10.0.0.0/8]", "$EXTERNAL_NET"),
        ("[1.2.3.4,5.6.7.8]", "$EXTERNAL_NET"),
        ("[1.2.3.0/24, 5.6.7.0/24]", "$EXTERNAL_NET"),
        ("![1.2.3.4]", "$EXTERNAL_NET"),
        ("8.8.8.8", "$EXTERNAL_NET"),
        ("[$HOME_NET,!10.0.0.0/8]", "$HOME_NET"),
        ("[1.2.3.4,$EXTERNAL_NET]", "$EXTERNAL_NET"),
        ("[1.2.3.4,$HOME_NET]", "$HOME_NET"),
    ])
    def test_reduction(self, rs, ipval, expected):
        assert rs.reduce_ipval(ipval) == expected

    def test_unclassified_variable_is_undetermined_not_fatal(self, rs, caplog):
        # Regression: this raised and aborted the whole ruleset load
        assert rs.reduce_ipval("$FOO_SERVERS") == "UNDETERMINED"
        assert "Unclassified variable found" in caplog.text

    def test_double_nested_list_is_undetermined_not_fatal(self, rs, caplog):
        assert rs.reduce_ipval("[$HOME_NET,![10.0.0.0/8]]") == "UNDETERMINED"
        assert "Double nested ipval found" in caplog.text

    def test_too_short_value_is_undetermined_not_fatal(self, rs, caplog):
        assert rs.reduce_ipval("!") == "UNDETERMINED"
        assert "Bad IPVAR found" in caplog.text

    def test_result_cached(self, rs):
        from aristotle import aristotle as mod
        rs.reduce_ipval("[9.9.9.9,8.8.8.8]")
        assert mod.ipval_cache["[9.9.9.9,8.8.8.8]"] == "$EXTERNAL_NET"


class TestDetectionDirection:
    @pytest.mark.parametrize("src, direction, dst, expected", [
        ("$EXTERNAL_NET", "->", "$HOME_NET", "inbound"),
        ("any", "->", "$HOME_NET", "inbound-notexclusive"),
        ("$HOME_NET", "->", "$EXTERNAL_NET", "outbound"),
        ("$EXTERNAL_NET", "->", "$EXTERNAL_NET", "outbound"),
        ("$HOME_NET", "->", "any", "outbound-notexclusive"),
        ("$HOME_NET", "->", "$HOME_NET", "internal"),
        ("any", "->", "any", "any"),
        ("$HOME_NET", "<>", "$EXTERNAL_NET", "both"),
        ("any", "<>", "any", "both"),
        ("$FOO_SERVERS", "->", "$HOME_NET", "unknown"),
        ("$HOME_NET", "->", "[$EXTERNAL_NET,![1.2.3.4]]", "unknown"),
        ("[10.0.0.0/8,192.168.0.0/16]", "->", "[1.2.3.4,5.6.7.8]", "outbound"),
        ("192.168.0.0/16", "->", "$EXTERNAL_NET", "outbound"),
        ("!$HOME_NET", "->", "$HTTP_SERVERS", "inbound"),
        ("any", "->", "$EXTERNAL_NET", "outbound"),
        ("$EXTERNAL_NET", "->", "any", "inbound"),
    ])
    def test_direction(self, src, direction, dst, expected):
        rs = Ruleset(make_rule(1, src=src, direction=direction, dst=dst) + "\n", enhance=True)
        assert rs.metadata_dict[1]['metadata']['detection_direction'] == [expected]
        assert rs.keys_dict['detection_direction'][expected] == {1}

    def test_no_detection_direction_without_enhance(self, small_ruleset):
        assert 'detection_direction' not in small_ruleset.keys_dict


class TestEnhanceMetadata:
    @pytest.fixture
    def rs(self, small_rules_str):
        return Ruleset(small_rules_str, enhance=True)

    def test_cve_extracted_from_msg_and_reference(self, rs):
        assert rs.metadata_dict[2]['metadata']['cve'] == ['2017-0144']
        assert rs.keys_dict['cve']['2017-0144'] == {2}

    def test_cve_extracted_from_reference_keyword(self):
        # Regression: 'reference:cve,YYYY-NNNN' (the standard form) was not recognized
        rule = make_rule(1, body="reference:cve,2014-0160; reference:CVE, 2021-44228; reference:url,example.com;", metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert set(rs.metadata_dict[1]['metadata']['cve']) == {'2014-0160', '2021-44228'}

    def test_cve_extracted_when_only_in_rule_text(self):
        rule = make_rule(1, msg="Exploit CVE-2019-0708 (BlueKeep) and cve-2020-0601", metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert set(rs.metadata_dict[1]['metadata']['cve']) == {'2019-0708', '2020-0601'}

    def test_mitre_attack_extracted_from_reference_url(self, rs):
        assert rs.metadata_dict[6]['metadata']['mitre_attack'] == ['t1190']

    @pytest.mark.parametrize("url, expected", [
        ("attack.mitre.org/techniques/T1059/001", "t1059.001"),
        ("attack.mitre.org/techniques/T1059/001/", "t1059.001"),
        ("attack.mitre.org/tactics/TA0011/", "ta0011"),
        ("attack.mitre.org/groups/G0016", "g0016"),
        ("https://attack.mitre.org/techniques/T1071/001/", "t1071.001"),
        ("example.com/techniques/T1071", None),
        ("attack.mitre.org/software/S0154", "s0154"),
        ("attack.mitre.org/campaigns/C0001", "c0001"),
        ("attack.mitre.org/datasources/DS0029", "ds0029"),
    ])
    def test_mitre_url_forms(self, url, expected):
        rule = make_rule(1, body="reference:url,{};".format(url), metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        if expected is None:
            assert 'mitre_attack' not in rs.metadata_dict[1]['metadata']
        else:
            assert rs.metadata_dict[1]['metadata']['mitre_attack'] == [expected]

    def test_target_keyword_becomes_hostile(self, rs):
        assert rs.metadata_dict[2]['metadata']['hostile'] == ['src_ip']

    def test_target_src_ip_becomes_hostile_dest_ip(self):
        rs = Ruleset(make_rule(1, body="target:src_ip;", metadata="priority low") + "\n", enhance=True)
        assert rs.metadata_dict[1]['metadata']['hostile'] == ['dest_ip']

    def test_invalid_target_value_raises(self):
        with pytest.raises(AristotleException, match="invalid value"):
            Ruleset(make_rule(1, body="target:both;", metadata="priority low") + "\n", enhance=True)

    def test_header_protocol_added(self, rs):
        assert 'smb' in rs.metadata_dict[2]['metadata']['protocols']
        assert 'tcp' in rs.metadata_dict[2]['metadata']['protocols']
        assert rs.metadata_dict[8]['metadata']['protocols'] == ['tcp']
        assert 'ip' in rs.metadata_dict[6]['metadata']['protocols']

    def test_protocol_inferred_from_keywords(self, rs):
        assert 'tls' in rs.metadata_dict[3]['metadata']['protocols']  # tls.sni
        assert 'dns' in rs.metadata_dict[5]['metadata']['protocols']  # dns.query
        assert 'http' in rs.metadata_dict[7]['metadata']['protocols']  # http.uri

    @pytest.mark.parametrize("keyword, expected_proto", [
        ("http_uri", "http"),
        ("http.host", "http"),
        ("ja3.hash", "tls"),
        ("ja3_hash", "tls"),
        ("dns_query", "dns"),
        ("ssh.proto", "ssh"),
        ("cip_service", "enip"),
        ("ftpdata_command", "ftp"),
        ("krb5_cname", "kerberos"),
        ("http2.header", "http2"),
        ("snmp.community", "snmp"),
        ("mqtt.type", "mqtt"),
        ("dnp3_func", "dnp3"),
        ("sip.method", "sip"),
        ("rfb.name", "rfb"),
        ("enip_command", "enip"),
    ])
    def test_keyword_protocol_mapping(self, keyword, expected_proto):
        rule = make_rule(1, proto="tcp", body="{}; content:\"x\";".format(keyword), metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert expected_proto in rs.metadata_dict[1]['metadata']['protocols']

    def test_app_layer_protocol_keyword(self):
        rule = make_rule(1, body="app-layer-protocol:ssh;", metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert set(rs.metadata_dict[1]['metadata']['protocols']) == {'tcp', 'ssh'}

    @pytest.mark.parametrize("value", ["!http", "failed"])
    def test_app_layer_protocol_negated_or_failed_ignored(self, value):
        rule = make_rule(1, body="app-layer-protocol:{};".format(value), metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert rs.metadata_dict[1]['metadata']['protocols'] == ['tcp']

    def test_flow_added_and_normalized(self, rs):
        assert set(rs.metadata_dict[1]['metadata']['flow']) == {'established', 'to_server'}
        assert rs.keys_dict['flow']['to_server']

    @pytest.mark.parametrize("flow, expected", [
        ("established,from_server", {'established', 'to_client'}),
        ("from_client, established", {'established', 'to_server'}),
        ("to_client,established,only_stream", {'to_client', 'established', 'only_stream'}),
        ("ESTABLISHED,TO_SERVER", {'established', 'to_server'}),
    ])
    def test_flow_normalization(self, flow, expected):
        rule = make_rule(1, body="flow:{};".format(flow), metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert set(rs.metadata_dict[1]['metadata']['flow']) == expected

    def test_flow_direction_inferred_from_request_keyword(self, rs):
        # sid 7 has flow:established (no direction) but uses http.uri
        assert set(rs.metadata_dict[7]['metadata']['flow']) == {'established', 'to_server'}

    def test_flow_direction_inferred_from_response_keyword(self):
        rule = make_rule(1, body="flow:established; http.stat_code; content:\"200\";", metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert set(rs.metadata_dict[1]['metadata']['flow']) == {'established', 'to_client'}

    def test_keywords_after_pcre_with_parentheses_still_seen(self):
        # Regression: the rule body regex stopped at the first ')' so keywords after a
        # pcre containing a group were never examined for protocol/flow inference.
        rule = make_rule(1, proto="tcp", body='flow:established; pcre:"/^(a|b)$/Ri"; http.stat_code; content:"200";',
                         metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert set(rs.metadata_dict[1]['metadata']['flow']) == {'established', 'to_client'}
        assert 'http' in rs.metadata_dict[1]['metadata']['protocols']

    def test_flow_direction_not_inferred_without_hints(self):
        rule = make_rule(1, body="flow:established; content:\"x\";", metadata="priority low")
        rs = Ruleset(rule + "\n", enhance=True)
        assert rs.metadata_dict[1]['metadata']['flow'] == ['established']

    def test_no_flow_keyword(self, rs):
        assert 'flow' not in rs.metadata_dict[6]['metadata']

    def test_rule_not_matching_rule_regex_raises(self):
        # sid_re accepts this at parse time but the header is not a valid rule header for enhancement
        with pytest.raises(AristotleException, match="Invalid rule"):
            Ruleset('bogus tcp any any -> any any (msg:"x"; metadata:priority low; sid:1;)\n', enhance=True)

    def test_enhance_does_not_duplicate_existing_metadata(self, rs):
        assert rs.metadata_dict[1]['metadata']['protocols'].count('http') == 1
        assert 1 in rs.keys_dict['protocols']['http']


@pytest.mark.examples
class TestEnhanceExampleRuleset:
    def test_every_rule_gets_detection_direction_and_protocols(self, example_rules_path):
        rs = Ruleset(example_rules_path, enhance=True)
        valid = {"inbound", "inbound-notexclusive", "outbound", "outbound-notexclusive", "internal", "any", "both", "unknown"}
        for s in rs.metadata_dict:
            md = rs.metadata_dict[s]['metadata']
            assert len(md['detection_direction']) == 1
            assert md['detection_direction'][0] in valid
            assert 'protocols' in md
