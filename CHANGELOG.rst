*******************
Aristotle Changelog
*******************

1.0.1 (2019-10-16)
##################

Initial public release.

Special thanks: SuriCon 2019

1.0.2 (2019-10-21)
##################

Documentation reorganization

1.0.3 (2021-02-24)
##################

Minor cleanup
Made it so module could be invoked via command line, e.g.:

.. code:: bash

    python3 -m aristotle -r examples/example.rules --stats

2.0.0 (2023-09-20)
##################

Features added:

  - Metadata Normalization
  - Metadata Enhancement
  - Post Filter Modification
  - Regular expression based filtering
  - Sundry tweaks and updates

See documentation for details.

Special thanks: Uber

2.1.0 (2024-11-01)
##################

Features added:

  - Add support for PFMod 'copy_key' action

Bug Fixes:

  - The enabling of modify_metadata automatically if unset when a PFMod file is given wasn't being honored when running as a script.
  - Empty PFMod YAML entries were not always being handled properly.

2.1.1 (2026-07-20)
##################

Bug Fixes:

  - A filter string token consisting of just a metadata key with no value (e.g. ``"priority"``, meaning "match all values") raised an ``UnboundLocalError`` instead of matching as documented.
  - Range comparisons (``>=``/``<=``) against float-valued metadata keys (``cvss_v2_base``, ``cvss_v2_temporal``, ``cvss_v3_base``, ``cvss_v3_temporal``, ``risk_score``) could silently return incorrect results due to an integer-only bound adjustment.
  - Internal error handling in ``Ruleset.__init__()`` and ``parse_rules()`` called ``traceback.print_exc()`` incorrectly, which masked the real underlying error with an unrelated ``TypeError``.
  - ``msg_regex``/``rule_regex`` filter values that didn't conform to the documented ``/pattern/`` or ``/pattern/i`` format were silently accepted instead of being rejected, which could also cause valid patterns ending in the letter "i" to be misinterpreted as using the case-insensitive flag.

2.1.2 (2026-09-17)
##################

Added:

  - Test suite (``pytest``) covering rule parsing, filter strings, normalization, enhancement, PFMod, output/statistics, and the command line interface.  Run with ``pip install -r requirements-dev.txt && pytest``.

Bug Fixes:

  - A ``<enable-all-rules>`` directive with leading whitespace in a filter file corrupted the filter string.
  - Filter strings that reduce to a constant (e.g. ``"x" AND NOT "x"``) returned ``None`` instead of a list of SIDs.
  - ``msg_regex``, ``rule_regex``, and PFMod ``regex_sub`` patterns ending in an escaped slash (``\/``) failed to compile because all leading/trailing slashes were stripped. ``regex_sub`` values are now also validated against the documented ``/pattern/replacement/[i]`` format.
  - With ``enhance`` enabled, a rule using an unrecognized IP variable (e.g. ``$FOO_SERVERS``) or a nested IP list aborted the entire ruleset load instead of yielding ``detection_direction unknown`` as documented.
  - Keywords following a ``pcre`` containing parentheses were ignored during metadata enhancement (protocol and flow direction inference).
  - MITRE ATT&CK tactic URLs (``attack.mitre.org/tactics/TA...``) were not extracted during enhancement.
  - CVEs given via the standard ``reference:cve,YYYY-NNNN`` keyword were not extracted during enhancement.
  - Unsupported/invalid PFMod actions (e.g. an unknown action name, an unsupported ``set_<keyword>``, a ``regex_sub`` problem, or a non-integer existing value for ``set_<arbitrary_integer_metadata>``) aborted processing instead of being reported and skipped as the code intended.
  - When an enabled rule replaced an earlier disabled duplicate (same SID), the replaced rule's metadata remained in the filter index, so filters could match the new rule on the old rule's metadata.
  - PFMod ``set_<arbitrary_integer_metadata>`` rejected single-character values such as ``set_risk_score: 5``.
  - A PFMod action with an empty/null YAML value crashed with ``AttributeError`` instead of reporting a clean error.
  - ``print_ruleset_summary()`` (``--summary``) looped forever if a rule's ``msg`` could not be extracted.
  - ``examples/pfmod-example.yaml`` contained a ``rule_regex`` pattern missing its closing ``/``.
  - Leading whitespace inside a quoted filter string token (e.g. ``"  priority high"``) caused the token to be ignored.
  - The RFC 1918 block ``192.168.0.0/16`` was listed as ``192.168.0.0/24`` when reducing IP values for ``detection_direction``.

2.2.0 (2026-09-18)
##################

Bug Fixes:

  - When a PFMod action changed a rule's text (``set_msg``, ``set_classtype``, or a ``regex_sub`` affecting either), the ``filter_string`` of subsequent PFMod rules still matched the original ``msg`` (via ``msg_regex``) and ``classtype`` values, contrary to the documented top-to-bottom ordering behavior.  Both are now updated along with the rule text, and the ``classtype`` change is reflected in the ``metadata`` keyword on output when ``modify_metadata`` is enabled.

Performance:

  - The internal key-value-pair index (``Ruleset.keys_dict``) now maps each value to a ``set`` of SIDs instead of a ``list``.  Adding a metadata key-value pair previously scanned the existing SID list for that pair, which made ruleset loading quadratic in the number of rules sharing a value; loading a 70,000 rule ruleset with ``enhance`` and ``normalize`` dropped from about 150 seconds to under 40.  Code that reads ``keys_dict`` directly and expects lists (e.g. indexing or ``.count()``) will need to be updated.
  - Filter evaluation only considers a candidate set of SIDs: PFMod rules are evaluated against just the SIDs passed to PFMod (``filter_ruleset()`` and ``get_sids()`` gained an optional ``sids``/``candidates`` parameter), and the terms of an ``AND`` are evaluated cheapest first so ``msg_regex``/``rule_regex`` terms are only applied to the rules that survived the other terms.
  - ``msg_regex`` and ``rule_regex`` results are remembered per rule and reused by later filter strings (e.g. the same regex term repeated across PFMod rules); a rule's cached results are discarded whenever its text is modified, so later PFMod rules still see the changes made by earlier ones.
  - Range comparisons (``created_at``, ``cve``, ``risk_score``, etc.) are done once per distinct metadata value instead of once per rule; a ``created_at`` range filter over a 123,000 rule ruleset dropped from 12 seconds to 0.25.
  - Ruleset loading: metadata enhancement checks keyword names for a protocol prefix in one pass instead of one pass per known protocol; normalization parses dates already in ``YYYY-MM-DD`` form without going through ``dateutil``; and a redundant per-key-value-pair de-duplication loop was removed from rule parsing (``add_metadata()`` already prevents duplicate values, and metadata values now keep the order in which they were encountered rather than an arbitrary one).  Loading the Emerging Threats ruleset (70,000 rules) with ``enhance`` and ``normalize`` now takes under 10 seconds; it took about 150 before this release.
