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
