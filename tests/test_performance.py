"""Benchmarks; skipped unless ``pytest --run-slow`` is given.  Run with ``-s`` to see the timings.

Ceilings are deliberately generous so the tests act as a tripwire for gross regressions;
compare the printed numbers before and after performance work.
"""
import random
import time

import pytest

from aristotle.aristotle import Ruleset

from .conftest import make_rule

RULE_COUNT = 20000

FILTERS = {
    "simple kv": '"priority high"',
    "and/or/not": '("priority high" OR "priority medium") AND "protocols http" AND NOT ("protocols smtp" OR "protocols pop")',
    "date range": '"created_at >= 2018-01-01" AND "created_at <= 2020-12-31"',
    "float range": '"risk_score > 40" AND "cvss_v3_base >= 7.0"',
    "cve range": '"cve >= 2019-0000"',
    "msg regex": '"msg_regex /^Acme - (Malware|Exploit) .* (Beacon|Attempt)$/i"',
    "rule regex": '"rule_regex /flow\\s*:\\s*established,to_server/"',
    "mixed": '(("priority high" AND "malware <ALL>") AND "created_at >= 2018-01-01") AND NOT ("protocols smtp" OR "protocols pop" OR "protocols imap") OR "sid 500"',
}


def synthetic_ruleset(count, seed=42):
    rng = random.Random(seed)
    priorities = ['high', 'medium', 'low', 'info']
    protocols = [['http', 'tcp'], ['tls', 'tcp'], ['smtp', 'tcp'], ['dns', 'udp'], ['pop', 'tcp'], ['imap', 'tcp'], ['tcp']]
    kinds = ['Malware', 'Exploit', 'Phishing', 'Policy']
    lines = []
    for sid in range(1, count + 1):
        proto = rng.choice(protocols)
        year = rng.randint(2014, 2024)
        md = ["priority {}".format(rng.choice(priorities)),
              "created_at {}-{:02d}-{:02d}".format(year, rng.randint(1, 12), rng.randint(1, 28)),
              "updated_at {}-{:02d}-{:02d}".format(year, rng.randint(1, 12), rng.randint(1, 28)),
              "risk_score {}".format(rng.randint(0, 100)),
              "attack_target {}".format(rng.choice(['http-client', 'http-server', 'client', 'server']))]
        md += ["protocols {}".format(p) for p in proto]
        if rng.random() < 0.4:
            md.append("malware {}".format(rng.choice(['post-infection', 'pre-infection', 'download-attempt'])))
        if rng.random() < 0.3:
            md.append("cve {}-{}".format(rng.randint(2010, 2024), rng.randint(1000, 99999)))
            md.append("cvss_v3_base {:.1f}".format(rng.uniform(1, 10)))
        msg = "Acme - {} {} {}".format(rng.choice(kinds), rng.choice(['CnC', 'Landing', 'Download', 'Generic']),
                                       rng.choice(['Beacon', 'Attempt', 'Detected', 'Observed']))
        lines.append(make_rule(sid, msg=msg, proto=proto[0], src=rng.choice(['$HOME_NET', '$EXTERNAL_NET', 'any']),
                               dst=rng.choice(['$HOME_NET', '$EXTERNAL_NET', 'any']),
                               body="flow:established,{}; content:\"x{}\"; priority:{};".format(
                                   rng.choice(['to_server', 'to_client']), sid, rng.randint(1, 4)),
                               classtype=rng.choice(['trojan-activity', 'attempted-admin', 'policy-violation']),
                               metadata=", ".join(md), disabled=rng.random() < 0.2))
    return "\n".join(lines) + "\n"


@pytest.mark.slow
class TestBenchmarks:
    @pytest.fixture(scope="class")
    def loaded(self):
        rules = synthetic_ruleset(RULE_COUNT)
        t = time.time()
        rs = Ruleset(rules, enhance=True, normalize=True)
        load_seconds = time.time() - t
        print("\nload+enhance+normalize {} rules: {:.2f}s".format(RULE_COUNT, load_seconds))
        return rs, load_seconds

    def test_load_time(self, loaded):
        rs, load_seconds = loaded
        assert len(rs.get_all_sids()) == RULE_COUNT
        assert load_seconds < 120

    @pytest.mark.parametrize("name", sorted(FILTERS))
    def test_filter_time(self, loaded, name):
        rs, _ = loaded
        t = time.time()
        result = rs.filter_ruleset(FILTERS[name])
        seconds = time.time() - t
        print("\nfilter '{}': {:.3f}s ({} matches)".format(name, seconds, len(result)))
        assert seconds < 30

    def test_repeated_filters(self, loaded):
        rs, _ = loaded
        t = time.time()
        for _ in range(20):
            rs.filter_ruleset(FILTERS["and/or/not"])
        seconds = time.time() - t
        print("\n20x 'and/or/not' filter: {:.3f}s".format(seconds))
        assert seconds < 60
