=========
Aristotle
=========

Aristotle is a simple Python program that allows for the filtering and modifying of
Suricata and Snort rulesets based on interpreted key-value pairs present
in the metadata keyword within each rule. It can be run as a standalone
script or utilized as a module.

.. image:: docs/_static/aristotle.png

Documentation
=============

`<https://aristotle-py.readthedocs.io/>`__

Application Overview
====================

Aristotle takes in a ruleset and can provide statistics on the included
metadata keys. If a filter string is provided, it will also be applied
against the ruleset and the filtered ruleset outputted.

Aristotle also offers the ability to intelligently process rules to extract, enrich, and add
metadata to them.  After initial filtering, rules can additionally
undergo "Post Filter Modification" which can modify them
based on user-defined criteria, to help ensure the resulting
rules in the ruleset are enabled, configured, and optimized for the target environment.

Aristotle is compatible with Python 2.7 and Python 3.x.

+------------------------------------------------------------------------------------+
| In order for Aristotle to be most useful, it should be provided a ruleset that     |
| has rules with the metadata keyword populated with appropriate key-value           |
| pairs. Aristotle assumes that the provided ruleset conforms to the                 |
| `BETTER Schema <https://better-schema.readthedocs.io/>`__.                         |
+------------------------------------------------------------------------------------+

Setup
=====

Install dependencies:

``pip install -r requirements.txt``

Or if using as a module:

``pip install aristotle``

And refer to `Aristotle as a Module <https://aristotle-py.readthedocs.io/en/latest/module.html>`__.

Usage
=====

.. code:: console

    usage: aristotle.py [-h] -r RULES [-f METADATA_FILTER]
                        [--summary [DISPLAY_MAX]] [-o OUTFILE]
                        [-s [STATS [STATS ...]]] [-i] [-c] [-n] [-e] [-t] [-g]
                        [-m] [-p PFMOD_FILE] [-q] [-d]

    Filter Suricata and Snort rulesets based on metadata keyword values.

    optional arguments:
      -h, --help            show this help message and exit
      -r RULES, --rules RULES, --ruleset RULES
                            path to a rules file, a directory containing '.rules'
                            file(s), or string containing the ruleset
      -f METADATA_FILTER, --filter METADATA_FILTER
                            Boolean filter string or path to a file containing it
      --summary [DISPLAY_MAX]
                            output a summary of the filtered ruleset to stdout,
                            limited to DISPLAY_MAX number of lines (or 16 if no
                            value given); if the option to output to a file is
                            set, the full, filtered ruleset will still be written.
      -o OUTFILE, --output OUTFILE
                            output file to write filtered ruleset to
      -s [STATS [STATS ...]], --stats [STATS [STATS ...]]
                            display ruleset statistics about specified key(s). If
                            no key(s) supplied, then summary statistics for all
                            keys will be displayed.
      -i, --enable-all-rules, --enable-all, --include-disabled
                            enable all valid rules, including those
                            disabled/commented out in the given rules file(s),
                            when applying the filter
      -c, --output-disabled-rules
                            include disabled rules in the output as commented out
                            lines.
      -n, --normalize, --better, --iso8601
                            try to convert date and cve related metadata values to
                            conform to the BETTER schema for filtering and
                            statistics. Dates are normalized to the format YYYY-
                            MM-DD and CVEs to YYYY-<num>. Also, 'sid' is removed
                            from the metadata.
      -e, --enhance         enhance metadata by adding additional key-value pairs
                            based on the rules.
      -t, --ignore-classtype, --ignore-classtype-keyword
                            don't incorporate the 'classtype' keyword and value
                            from the rule into the metadata structure for
                            filtering and reporting.
      -g, --ignore-filename
                            don't incorporate the 'filename' keyword (filename of
                            the rules file) into the metadata structure for
                            filtering and reporting.
      -m, --modify-metadata
                            modify the rule metadata keyword value on output to
                            contain the internally tracked and normalized metadata
                            data.
      -p PFMOD_FILE, --pfmod PFMOD_FILE, --pfmod-file PFMOD_FILE
                            YAML file of directives to apply actions on post-
                            filtered rules based on filter strings.
      -q, --quiet, --suppress_warnings
                            quiet; suppress warning logging
      -d, --debug           turn on debug logging

    A filter string defines the desired outcome based on Boolean logic, and uses
    the metadata key-value pairs as values in a (concrete) Boolean algebra.
    The key-value pair specifications must be surrounded by double quotes.
    Example:

    python3 aristotle/aristotle.py -r examples/example.rules --summary -n
    -f '(("priority high" AND "malware <ALL>") AND "created_at >= 2018-01-01")
    AND NOT ("protocols smtp" OR "protocols pop" OR "protocols imap") OR "sid 80181444"'

License
=======

Aristotle is licensed under the `Apache License, Version 2.0 <https://github.com/secureworks/aristotle/blob/master/LICENSE>`__.

Authors
=======

-  David Wharton
