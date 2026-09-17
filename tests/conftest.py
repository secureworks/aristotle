import logging
import os
import re

import pytest

from aristotle.aristotle import Ruleset

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(REPO_ROOT, "examples")
EXAMPLE_RULES = os.path.join(EXAMPLES_DIR, "example.rules")


def make_rule(sid, msg="Acme - Test Rule", metadata="priority low", action="alert", proto="tcp",
              src="$EXTERNAL_NET", sport="any", direction="->", dst="$HOME_NET", dport="any",
              body="", classtype=None, disabled=False):
    """Build a syntactically valid Suricata rule string.

    ``body`` is inserted verbatim after msg (must end with ';' if non-empty).
    ``metadata=None`` omits the metadata keyword entirely.
    """
    parts = ['msg:"{}";'.format(msg)]
    if body:
        parts.append(body)
    if classtype:
        parts.append("classtype:{};".format(classtype))
    if metadata is not None:
        parts.append("metadata:{};".format(metadata))
    parts.append("sid:{}; rev:1;".format(sid))
    rule = "{} {} {} {} {} {} {} ({})".format(action, proto, src, sport, direction, dst, dport, " ".join(parts))
    if disabled:
        rule = "#" + rule
    return rule


# A small, hand-crafted ruleset whose SIDs and metadata are known so filter
# results can be asserted exactly.
SMALL_RULES = [
    make_rule(1, msg="Acme - Malware CnC Beacon", proto="http", src="$HOME_NET", dst="$EXTERNAL_NET",
              body="flow:established,to_server; priority:1;", classtype="trojan-activity",
              metadata="priority high, malware post-infection, protocols http, protocols tcp, "
                       "created_at 2018-03-19, updated_at 2018-03-20, attack_target http-client, "
                       "cvss_v3_base 8.1, risk_score 90"),
    make_rule(2, msg="Acme - SMB Exploit Attempt CVE-2017-0144", dport="445",
              body="flow:established,to_server; reference:cve,2017-0144; target:dest_ip; priority:2;",
              classtype="attempted-admin",
              metadata="priority high, protocols smb, protocols tcp, created_at 2017-05-12, "
                       "cve 2017-0144, cvss_v2_base 9.3, attack_target smb-server"),
    make_rule(3, msg="Acme - Phishing Landing Page TLS SNI", proto="tls", src="$HOME_NET", dst="$EXTERNAL_NET", dport="443",
              body="flow:established,to_server; tls.sni; content:\"phish\"; priority:3;",
              classtype="social-engineering",
              metadata="priority medium, protocols tls, protocols tcp, created_at 2019-01-01, "
                       "attack_target http-client, confidence high"),
    make_rule(4, msg="Acme - Spam Campaign INFORMATIONAL", proto="smtp", dport="25", disabled=True,
              body="flow:established,to_server; priority:4;", classtype="misc-activity",
              metadata="priority low, protocols smtp, protocols tcp, created_at 2016-11-30, "
                       "signature_severity informational"),
    make_rule(5, msg="Acme - DNS Query Suspicious Domain", proto="dns", src="any", dst="any",
              body="dns.query; content:\"evil\"; priority:3;",
              metadata="priority low, protocols dns, protocols udp, created_at 2020-02-29, risk_score 10"),
    make_rule(6, msg="Acme - 3CORESec Bad IP", proto="ip",
              body="reference:url,attack.mitre.org/techniques/T1190/; priority:1;", classtype="attempted-recon",
              metadata="priority high, protocols ip, created_at 2021-07-04, cve 2021-44228, "
                       "cvss_v3_base 10.0, risk_score 100, mitre_technique_id T1190"),
    make_rule(7, msg="Acme - Both Directions", proto="http", src="$HOME_NET", dst="$EXTERNAL_NET", direction="<>",
              body="flow:established; http.uri; content:\"/both\"; priority:2;",
              metadata="priority medium, protocols http, created_at 2019-12-31, updated_at 2020_01_15"),
    make_rule(8, msg="Acme - Internal SSH", src="$HOME_NET", dst="$HOME_NET", dport="22",
              body="flow:to_server; priority:3;", metadata=None),
]
SMALL_RULES_STR = "\n".join(SMALL_RULES) + "\n"
SMALL_SIDS = {1, 2, 3, 4, 5, 6, 7, 8}


def pytest_addoption(parser):
    parser.addoption("--run-slow", action="store_true", default=False, help="run tests marked 'slow' (benchmarks)")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-slow"):
        return
    skip = pytest.mark.skip(reason="needs --run-slow")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text):
    """Remove ANSI color codes (present when the tests run attached to a TTY)."""
    return ANSI_RE.sub("", text)


@pytest.fixture(autouse=True)
def _aristotle_logger_isolation():
    """Make the 'aristotle' logger capturable by caplog and undo any handler/level changes main() makes."""
    logger = logging.getLogger("aristotle")
    saved_handlers = list(logger.handlers)
    saved_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.propagate = True
    yield
    logger.handlers = saved_handlers
    logger.setLevel(saved_level)


# Dummy rules written to mimic syntax seen in real-world (e.g. Emerging Threats)
# rulesets: IP/port lists, hex content, escaped ';' and ':' inside content, pcre
# with groups and flags, threshold/flowbits/byte_test, metadata placed after rev,
# underscore dates, MITRE ids, etc.  None of these are real rules.
REALISTIC_RULES = [
    'alert ip [203.0.113.0/24,198.51.100.0/24,192.0.2.0/24] any -> $HOME_NET any (msg:"DUMMY DROP Blocklisted Source group 1"; reference:url,example.com/block.txt; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; flowbits:set,DUMMY.Evil; sid:9000001; rev:12; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag Blocklist, signature_severity Major, created_at 2010_12_30, updated_at 2026_09_16;)',
    'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"DUMMY WEB_SERVER Example CGI Overflow Attempt"; flow:established,to_server; http.method; content:"GET"; nocase; http.uri; content:"/cgi-bin/example.exe"; nocase; fast_pattern; content:"verbose="; nocase; distance:0; pcre:"/^(1|on|true)/Ri"; http.accept_lang; isdataat:100,relative; reference:cve,2009-4179; classtype:web-application-attack; sid:9000002; rev:10; metadata:created_at 2010_07_30, cve CVE_2009_4179, deployment Perimeter, signature_severity Major, updated_at 2024_01_01;)',
    'alert dns any any -> any any (msg:"DUMMY CURRENT_EVENTS DNS Beacon TXT Record"; content:"|00 01 00 01|"; offset:4; depth:4; content:"|0a|_dummykey"; distance:3; within:11; content:"|00 00 10 00 01|v=DUMMY1\\; p="; fast_pattern; reference:url,example.com/countermeasures; classtype:trojan-activity; sid:9000003; rev:2; metadata:attack_target Client_Endpoint, created_at 2020_12_08, deployment Perimeter, signature_severity Major, updated_at 2020_12_08, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol;)',
    '#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"DUMMY DELETED Legacy Coupon Printer UA"; flow:established,to_server; content:"|0d 0a|User-Agent\\: Mozilla/4.0 (compatible\\; DummyApp\\; Windows 95)|0d 0a|"; nocase; reference:url,example.com/legacy; classtype:policy-violation; sid:9000004; rev:2; metadata:created_at 2010_07_30, confidence Low, signature_severity Unknown, updated_at 2010_07_30, former_category POLICY;)',
    'alert udp $HOME_NET [!3389,1024:65535] -> $EXTERNAL_NET [!3389,1024:65535] (msg:"DUMMY P2P Search Request (search by name)"; dsize:>5; content:"|e3 98|"; depth:2; content:"|01|"; within:3; reference:url,example.com/p2p; classtype:policy-violation; sid:9000005; rev:4; metadata:created_at 2010_07_30, updated_at 2019_09_27, signature_severity Minor;)',
    'alert tcp $HOME_NET [!$HTTP_PORTS,!445,!22] -> any any (msg:"DUMMY RETIRED Malformed Heartbeat Response"; flow:established,to_client; flowbits:isset,DUMMY.MalformedHB; content:"|18 03|"; depth:2; byte_test:1,<,4,2; byte_test:2,>,200,3; threshold:type limit,track by_src,count 1,seconds 120; reference:cve,2014-0160; classtype:bad-unknown; sid:9000006; rev:9; metadata:created_at 2014_04_09, updated_at 2022_05_03, signature_severity Major, deployment Perimeter;)',
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 1024: (msg:"DUMMY MALWARE Keylogger FTP Log Upload (Null obfuscated)"; flow:established,to_server; content:"C|00|o|00|n|00|g|00|r|00|a|00|t|00|s|00|"; depth:32; classtype:trojan-activity; sid:9000007; rev:3; metadata:attack_target Client_Endpoint, created_at 2011_03_15, deployment Perimeter, confidence High, signature_severity Major, malware_family Keylogger, updated_at 2020_08_11, mitre_tactic_id TA0010, mitre_technique_id T1041;)',
    'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"DUMMY JA3 Hash - Suspected Malware Family"; ja3.hash; content:"deadbeefdeadbeefdeadbeefdeadbeef"; reference:url,example.com/ja3; classtype:unknown; sid:9000008; rev:2; metadata:created_at 2019_09_10, former_category JA3, confidence Low, signature_severity Unknown, updated_at 2019_10_29;)',
    'alert tcp [$HOME_NET,!$DNS_SERVERS] any -> $EXTERNAL_NET 53 (msg:"DUMMY HUNTING Non-DNS-server DNS over TCP"; flow:established,to_server; content:"|00 01|"; offset:4; depth:2; reference:url,attack.mitre.org/techniques/T1071/004/; classtype:bad-unknown; sid:9000009; rev:1; metadata:created_at 2023_02_14, updated_at 2023_02_14, signature_severity Informational, performance_impact Low, tls_state plaintext;)',
    'drop tcp $EXTERNAL_NET any -> $HOME_NET [445,139] (msg:"DUMMY EXPLOIT SMB Insecure Library Loading - ASCII"; flow:from_client; content:"SMB"; offset:4; depth:5; byte_test:1,!&,0x80,7,relative; content:"dummyframework|2E|dll"; nocase; distance:0; fast_pattern; reference:cve,2018-12589; reference:url,attack.mitre.org/tactics/TA0002/; classtype:attempted-user; target:dest_ip; sid:9000010; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2018_08_02, deployment Perimeter, signature_severity Major, updated_at 2019_10_29;)',
]
REALISTIC_RULES_STR = "\n".join(REALISTIC_RULES) + "\n"
REALISTIC_SIDS = set(range(9000001, 9000011))


@pytest.fixture
def small_rules_str():
    return SMALL_RULES_STR


@pytest.fixture
def small_ruleset():
    return Ruleset(SMALL_RULES_STR)


@pytest.fixture
def realistic_rules_str():
    return REALISTIC_RULES_STR


@pytest.fixture
def realistic_rules_file(tmp_path):
    p = tmp_path / "dummy-threats.rules"
    p.write_text(REALISTIC_RULES_STR)
    return str(p)


@pytest.fixture
def small_rules_file(tmp_path):
    p = tmp_path / "small.rules"
    p.write_text(SMALL_RULES_STR)
    return str(p)


@pytest.fixture
def examples_dir():
    return EXAMPLES_DIR


@pytest.fixture
def example_rules_path():
    return EXAMPLE_RULES


@pytest.fixture(scope="session")
def example_ruleset():
    """Session-wide, read-only Ruleset built from examples/example.rules.

    Tests must not mutate this object (use ``Ruleset(example_rules_path)`` instead).
    """
    return Ruleset(EXAMPLE_RULES)


@pytest.fixture
def write_yaml(tmp_path):
    """Return a helper that writes YAML text to a file in tmp_path and returns its path."""
    def _write(text, name="pfmod.yaml"):
        p = tmp_path / name
        p.write_text(text)
        return str(p)
    return _write
