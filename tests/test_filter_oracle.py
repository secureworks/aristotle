"""Differential tests: compare filter_ruleset() against a naive reference evaluator on generated expressions.

The reference evaluator applies each token directly to a rule's metadata (any value of a key may
satisfy a token), so these tests pin the *semantics* of filtering independently of how the engine
indexes or evaluates expressions.  Expressions are generated from a fixed seed so runs are repeatable.
"""
import random
import re

import pytest
from dateutil.parser import parse as dateparse

from aristotle.aristotle import Ruleset

from .conftest import REALISTIC_RULES_STR, SMALL_RULES_STR

RANGE_KEYS = ['sid', 'cve', 'cvss_v2_base', 'cvss_v2_temporal', 'cvss_v3_base', 'cvss_v3_temporal',
              'created_at', 'updated_at', 'risk_score']
OPS = ['>', '>=', '<', '<=']


def _cmp(op, left, right):
    return {'>': left > right, '>=': left >= right, '<': left < right, '<=': left <= right}[op]


def _cve_tuple(v):
    year, seq = v.split('-', 1)
    return (int(year), int(seq))


class Generator:
    """Generates (filter_string, predicate) pairs where predicate(rule_entry) is the reference result."""

    def __init__(self, rs, seed):
        self.rs = rs
        self.rng = random.Random(seed)
        self.keys = sorted(k for k in rs.keys_dict if rs.keys_dict[k] and k != 'sid')
        self.msgs = [rs.metadata_dict[s]['msg'] for s in rs.metadata_dict if rs.metadata_dict[s]['msg']]
        self.sids = sorted(rs.metadata_dict)

    def _values(self, key):
        return sorted(v for v in self.rs.keys_dict[key] if self.rs.keys_dict[key][v])

    def _quote(self, key, value, regex=False):
        # keys/values are case-insensitive; exercise that randomly (never for regex patterns)
        if not regex and self.rng.random() < 0.3:
            key = key.upper()
            value = value.upper()
        pad = self.rng.choice(["", " ", "  ", "\n  "])
        return '"{}{} {}{}"'.format(pad, key, value, pad)

    def leaf(self):
        kind = self.rng.choice(['kv', 'kv', 'kv', 'all', 'bare', 'unknown', 'sid', 'range', 'range', 'msg_regex', 'rule_regex'])
        if kind == 'kv':
            key = self.rng.choice(self.keys)
            value = self.rng.choice(self._values(key))
            return self._quote(key, value), lambda e, k=key, v=value: v in e['metadata'].get(k, [])
        if kind == 'all':
            key = self.rng.choice(self.keys)
            token = self._quote(key, self.rng.choice(['<ALL>', '<all>', '<Any>']))
            return token, lambda e, k=key: k in e['metadata']
        if kind == 'bare':
            key = self.rng.choice(self.keys)
            return '"{}"'.format(key), lambda e, k=key: k in e['metadata']
        if kind == 'unknown':
            if self.rng.random() < 0.5:
                return '"no_such_key whatever"', lambda e: False
            key = self.rng.choice(self.keys)
            return self._quote(key, 'no-such-value-xyz'), lambda e: False
        if kind == 'sid':
            sid = self.rng.choice(self.sids)
            return '"sid {}"'.format(sid), lambda e, s=str(sid): s in e['metadata']['sid']
        if kind == 'range':
            return self.range_leaf()
        if kind == 'msg_regex':
            word = self.rng.choice(re.findall(r"[A-Za-z]{3,}", self.rng.choice(self.msgs)))
            flag = self.rng.choice(['', 'i'])
            pattern = self.rng.choice([word, word.lower(), "^" + word, word + "$", "(" + word + "|zzz)"])
            flags = re.I if flag else 0
            token = '"msg_regex /{}/{}"'.format(pattern, flag)
            return token, lambda e, p=pattern, fl=flags: re.search(p, e['msg'], flags=fl) is not None
        # rule_regex
        pattern = self.rng.choice([r"flow\s*:\s*established", r"^alert\s+http", r"^drop\s", r"\$HOME_NET\s+any\s+->",
                                   r"priority\s*:\s*[12]\s*;", r"reference\s*:\s*cve", r"content:\x22[a-z]+\x22;"])
        flag = self.rng.choice(['', 'i'])
        flags = re.I if flag else 0
        return '"rule_regex /{}/{}"'.format(pattern, flag), lambda e, p=pattern, fl=flags: re.search(p, e['raw_rule'], flags=fl) is not None

    def range_leaf(self):
        candidates = [k for k in RANGE_KEYS if k in self.rs.keys_dict and self._values(k)]
        key = self.rng.choice(candidates)
        values = self._values(key)
        op = self.rng.choice(OPS)
        if key in ('created_at', 'updated_at'):
            bound = self.rng.choice(values)
            token = self._quote(key, "{} {}".format(op, bound))
            b = dateparse(bound)
            return token, lambda e, k=key, o=op, b=b: any(_cmp(o, dateparse(v), b) for v in e['metadata'].get(k, []))
        if key == 'cve':
            bound = self.rng.choice(values)
            token = self._quote(key, "{}{}{}".format(op, self.rng.choice(['', ' ']), bound))
            b = _cve_tuple(bound)
            return token, lambda e, k=key, o=op, b=b: any(_cmp(o, _cve_tuple(v), b) for v in e['metadata'].get(k, []))
        # numeric keys (sid, cvss_*, risk_score)
        bound = self.rng.choice(values)
        if self.rng.random() < 0.3:
            bound = str(float(bound) + self.rng.choice([-0.5, 0.5, 1]))
        token = self._quote(key, "{} {}".format(op, bound))
        b = float(bound)
        return token, lambda e, k=key, o=op, b=b: any(_cmp(o, float(v), b) for v in e['metadata'].get(k, []))

    def expression(self, depth=0):
        if depth >= 3 or self.rng.random() < 0.35:
            token, pred = self.leaf()
            if self.rng.random() < 0.25:
                return "NOT " + token, lambda e, p=pred: not p(e)
            return token, pred
        n = self.rng.choice([2, 2, 3])
        parts = [self.expression(depth + 1) for _ in range(n)]
        op = self.rng.choice(['AND', 'OR', 'and', 'or'])
        sep = self.rng.choice([" ", "\n", "  "])
        text = "({})".format("{}{}{}".format(sep, op, sep).join(p[0] for p in parts))
        preds = [p[1] for p in parts]
        if op.upper() == 'AND':
            combined = lambda e, ps=preds: all(p(e) for p in ps)
        else:
            combined = lambda e, ps=preds: any(p(e) for p in ps)
        if self.rng.random() < 0.2:
            return "NOT " + text, lambda e, c=combined: not c(e)
        return text, combined


def check(rs, generator, count):
    failures = []
    for _ in range(count):
        text, pred = generator.expression()
        expected = {s for s in rs.metadata_dict if pred(rs.metadata_dict[s])}
        result = rs.filter_ruleset(text)
        if len(result) != len(set(result)) or set(result) != expected:
            failures.append((text, sorted(expected - set(result)), sorted(set(result) - expected)))
    assert failures == [], "mismatches (filter, missing, extra):\n" + "\n".join(repr(f) for f in failures)


class TestOracleSmallRulesets:
    @pytest.mark.parametrize("seed", range(5))
    def test_small_and_realistic(self, seed):
        rs = Ruleset(SMALL_RULES_STR + REALISTIC_RULES_STR, enhance=True, normalize=True)
        check(rs, Generator(rs, seed), 60)

    def test_known_tricky_expressions(self):
        rs = Ruleset(SMALL_RULES_STR + REALISTIC_RULES_STR, enhance=True, normalize=True)
        all_sids = set(rs.metadata_dict)
        cases = {
            'NOT NOT "priority high"': {s for s in all_sids if 'high' in rs.metadata_dict[s]['metadata'].get('priority', [])},
            '"priority high" OR NOT "priority high"': all_sids,
            'NOT ("priority high" OR "priority low")': {s for s in all_sids if not ({'high', 'low'} & set(rs.metadata_dict[s]['metadata'].get('priority', [])))},
            'NOT "no_such_key x" AND NOT "priority no-such"': all_sids,
            '"sid <ALL>"': all_sids,
            '"originally_disabled <ALL>"': all_sids,
            '"protocols tcp" AND "protocols tcp" AND "protocols tcp"': {s for s in all_sids if 'tcp' in rs.metadata_dict[s]['metadata'].get('protocols', [])},
        }
        for text, expected in cases.items():
            assert set(rs.filter_ruleset(text)) == expected, text


@pytest.mark.examples
class TestOracleExampleRuleset:
    @pytest.mark.parametrize("seed", range(3))
    def test_example_rules(self, example_rules_path, seed):
        rs = Ruleset(example_rules_path, normalize=True)
        check(rs, Generator(rs, 100 + seed), 12)
