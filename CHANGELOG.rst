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
