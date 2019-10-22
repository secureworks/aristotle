=========
Aristotle
=========

Aristotle is a simple Python program that allows for the filtering of
Suricata and Snort rulesets based on interpreted key-value pairs present
in the metadata keyword within each rule. It can be run as a standalone
script or utilized as a library.

Documentation
=============

`<https://aristotle-py.readthedocs.io/>`__

Application Overview
====================

Aristotle takes in a ruleset and can provide statistics on the included
metadata keys. If a filter string is provided, it will also be applied
against the ruleset and the filtered ruleset outputted.

Aristotle is compatible with Python 2.7 and Python 3.x.

+------------------------------------------------------------------------------------+
| In order for Aristotle to be useful, it must be provided a ruleset that            |
| has rules with the metadata keyword populated with appropriate key-value           |
| pairs. Aristotle assumes that the provided ruleset conforms to the                 |
| `BETTER Schema <https://better-schema.readthedocs.io/>`__.                         |
+------------------------------------------------------------------------------------+

Setup
=====

Install dependencies:

``pip install -r requirements.txt``

Or if using as a library:

``pip install aristotle``

And refer to `Aristotle as a Library <https://aristotle-py.readthedocs.io/en/latest/library.html>`__.

Usage
=====

.. code:: text

  usage: aristotle.py [-h] -r RULES [-f METADATA_FILTER] [--summary]
                      [-o OUTFILE] [-s [STATS [STATS ...]]] [-i] [-q] [-d]

  optional arguments:
    -h, --help            show this help message and exit
    -r RULES, --rules RULES, --ruleset RULES
                          path to rules file or string containing the ruleset
                          (default: None)
    -f METADATA_FILTER, --filter METADATA_FILTER
                          Boolean filter string or path to a file containing it
                          (default: None)
    --summary             output a summary of the filtered ruleset to stdout; if
                          an output file is given, the full, filtered ruleset
                          will still be written to it. (default: False)
    -o OUTFILE, --output OUTFILE
                          output file to write filtered ruleset to (default:
                          <stdout>)
    -s [STATS [STATS ...]], --stats [STATS [STATS ...]]
                          display ruleset statistics about specified key(s). If
                          no key(s) supplied, then summary statistics for all
                          keys will be displayed. (default: None)
    -i, --include-disabled
                          include (effectively enable) disabled rules when
                          applying the filter (default: False)
    -q, --quiet, --suppress_warnings
                          quiet; suppress warning logging (default: False)
    -d, --debug           turn on debug logging (default: False)

License
=======

Aristotle is licensed under the `Apache License, Version 2.0 <https://github.com/secureworks/aristotle/blob/master/LICENSE>`__.

Authors
=======

-  David Wharton
