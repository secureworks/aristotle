=========
Aristotle
=========

Aristotle is a simple Python program that allows for the filtering of
Suricata and Snort rulesets based on interpreted key-value pairs present
in the metadata keyword within each rule. It can be run as a standalone
script or utilized as a library.

.. contents::
   :depth: 5

Application Overview
====================

Aristotle takes in a ruleset and can provide statistics on the included
metadata keys. If a filter string is provided, it will also be applied
against the ruleset and the filtered ruleset outputted.

.. note::
    Aristotle does *not* modify the contents of rules. It simply
    includes or excludes rules based on the given Boolean filter string.

Aristotle is compatible with Python 2.7 and Python 3.x.

Background
==========

Suricata and Snort support the ``metadata`` keyword that allows for
non-functional (in terms of detection), arbitrary information to be
included in a rule. By defining key-value pairs and including them in
the metadata keyword, ruleset providers can embed rich teleological and
taxonomic information. This information can be used to filter a ruleset
– essentially enabling and disabling rules in a ruleset based on the
metadata key-value pairs.  Aristotle allows for the easy leveraging of
the metadata key-value pairs to "slice-and-dice" Suricata and Snort
rulesets that implement metadata key-value pairs.

Metadata Key-Value Pairs
========================

.. important:: In order for Aristotle to be useful, it must be provided a ruleset that
    has rules with the metadata keyword populated with appropriate key-value
    pairs. Aristotle assumes that the provided ruleset conforms to the
    :doc:`BETTER Schema <BETTER>`.

Setup
=====

Install dependencies:

``pip install -r requirements.txt``

Or if using as a library:

``pip install aristotle``

And refer to :ref:`Aristotle as a Library`

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

Example Files
-------------

The ``examples`` directory has ``.filter`` files that show examples of Boolean
filter strings.

Also in the ``examples`` directory is an ``example.rules`` file that has a dummy
Suricata ruleset that implements the :doc:`BETTER Schema <BETTER>`.  While the example
ruleset is syntactically correct, *it is not a real ruleset*
intended to be used by a Suricata sensor.
It is provided to assist in demonstrating the functionality of
Aristotle and to provide examples of rules with ``metadata`` keywords that
conform to the :doc:`BETTER Schema <BETTER>`.

Example Usage
-------------

.. note::
    ``aristotle.py`` in the root of the repository is a symlink
    to ``aristotle/aristotle.py``.  If the evironment in use does
    not recognize symlinks, adjust the paths accordingly.

Show high level statistics on all the keys in the ``example.rules`` file:

.. code-block:: bash

    python aristotle.py -r examples/example.rules -s

Show statistics on the ``protocols`` key in the ``example.rules`` file:

.. code-block:: bash

    python aristotle.py -r examples/example.rules -s protocols

Apply the Boolean filter defined in the ``example1.filter`` file against the
rules in the ``example.rules`` file and output summary results to stdout:

.. code-block:: bash

    python aristotle.py -r examples/example.rules -f examples/example1.filter --summary

Apply the Boolean filter defined in the ``example1.filter`` file against the
rules in the ``example.rules`` file and output the results to the file ``newrules.rules``:

.. code-block:: bash

    python aristotle.py -r examples/example.rules -f examples/example1.filter -o newrules.rules

Apply the Boolean filter defined specified on the command line against the
rules in the ``example.rules`` file and output the results to the file ``newrules.rules``:

.. code-block:: bash

    python aristotle.py -r examples/example.rules -f '"malware <ALL>" AND ("attack_target http-server" or "attack_target tls-server")' -o newrules.rules

.. important:: Because Aristotle requires key-value pairs (values) in the filter string
    to be enclosed in double quotes, a filter string specified on the command line must
    be enclosed in single quotes.

Statistics
----------

The statistics command line option allows a user to to easily see what
metadata key-value pairs the ruleset contains to assist in building a
filter string.

If no key names are passed, summary info on all present keys is
displayed:

.. code:: text

  $ python aristotle.py -r examples/example.rules -s

         Aristotle       
   Ruleset Metadata Tool 

  All Rules: Total: 6799; Enabled: 4977; Disabled: 1822

    attack_target (Total: 6028; Enabled: 4554; Disabled: 1474)
    malware (Total: 3467; Enabled: 3330; Disabled: 137)
    cve (Total: 1570; Enabled: 887; Disabled: 683)
    hostile (Total: 5962; Enabled: 4403; Disabled: 1559)
    created_at (Total: 6799; Enabled: 4977; Disabled: 1822)
    capec_id (Total: 2669; Enabled: 1191; Disabled: 1478)
    updated_at (Total: 6799; Enabled: 4977; Disabled: 1822)
    cwe_id (Total: 5199; Enabled: 4332; Disabled: 867)
    priority (Total: 6799; Enabled: 4977; Disabled: 1822)
    cvss_v3_base (Total: 271; Enabled: 259; Disabled: 12)
    infected (Total: 2679; Enabled: 2520; Disabled: 159)
    sid (Total: 6799; Enabled: 4977; Disabled: 1822)
    cvss_v2_base (Total: 1130; Enabled: 829; Disabled: 301)
    rule_source (Total: 6799; Enabled: 4977; Disabled: 1822)
    cvss_v3_temporal (Total: 271; Enabled: 259; Disabled: 12)
    filename (Total: 6799; Enabled: 4977; Disabled: 1822)
    cvss_v2_temporal (Total: 1130; Enabled: 829; Disabled: 301)
    protocols (Total: 6799; Enabled: 4977; Disabled: 1822)

If one or more key names are passed, summary info is displayed for those
keys:

.. code:: text

  $ python aristotle.py -r examples/example.rules -s malware protocols

         Aristotle       
   Ruleset Metadata Tool 

  All Rules: Total: 6799; Enabled: 4977; Disabled: 1822

  malware (Total: 3467; Enabled: 3330; Disabled: 137)
      download-attempt (Total: 178; Enabled: 171; Disabled: 7)
      malware (Total: 135; Enabled: 117; Disabled: 18)
      post-infection (Total: 2647; Enabled: 2589; Disabled: 58)
      pre-infection (Total: 507; Enabled: 453; Disabled: 54)

  protocols (Total: 6799; Enabled: 4977; Disabled: 1822)
      smtp (Total: 143; Enabled: 82; Disabled: 61)
      pop (Total: 64; Enabled: 45; Disabled: 19)
      rpc (Total: 16; Enabled: 4; Disabled: 12)
      dnp3 (Total: 5; Enabled: 0; Disabled: 5)
      vnc (Total: 1; Enabled: 0; Disabled: 1)
      ftp (Total: 130; Enabled: 65; Disabled: 65)
      sip (Total: 5; Enabled: 3; Disabled: 2)
      iccp (Total: 4; Enabled: 0; Disabled: 4)
      dns (Total: 20; Enabled: 6; Disabled: 14)
      ldap (Total: 1; Enabled: 1; Disabled: 0)
      irc (Total: 21; Enabled: 19; Disabled: 2)
      nntp (Total: 4; Enabled: 0; Disabled: 4)
      smb (Total: 60; Enabled: 42; Disabled: 18)
      http (Total: 5447; Enabled: 4199; Disabled: 1248)
      telnet (Total: 9; Enabled: 3; Disabled: 6)
      dcerpc (Total: 1; Enabled: 1; Disabled: 0)
      tcp (Total: 6788; Enabled: 4976; Disabled: 1812)
      imap (Total: 55; Enabled: 25; Disabled: 30)
      tls (Total: 145; Enabled: 128; Disabled: 17)
      modbus (Total: 7; Enabled: 0; Disabled: 7)
      tftp (Total: 1; Enabled: 0; Disabled: 1)
      ssh (Total: 9; Enabled: 4; Disabled: 5)

Boolean Filter Strings
======================

A filter string defines the desired outcome based on Boolean logic, and
uses the metadata key-value pairs as values in a (concrete)
`Boolean algebra <https://en.wikipedia.org/wiki/Boolean_algebra>`__:

-  The Boolean operators ``AND``, ``OR``, and ``NOT`` are allowed.
-  Grouping should be done with parentheses.
-  **The key-value pair specifications must be surrounded by double
   quotes** (ASCII 0x22).
-  **To match all values of a key**, use the pseudo-value "<ALL>" (not case
   sensitive), e.g. ``"malware <ALL>"``.
-  **To match a specific SID**, use the "sid" key, e.g. "sid 80181444", even
   though it may not be present in the ``metadata`` value.

   -  A (pseudo) key of "sid" with the value of the rule's ``sid`` keyword
      is added to the internal key-value pair data structure(s).
   -  If the ruleset ``metadata`` actually contains a "sid" key, it will be used
      instead of the value from the rule's ``sid`` keyword although if the values
      differ, a warning will be raised.
   -  Note that per the :doc:`BETTER Schema <BETTER>`, a
      "sid" metadata key is not recommended but if present, it must have a
      value that matches the ``sid`` keyword value of the rule.

-  Extraneous whitespace, including newlines, *is* allowed in the filter
   string.

The following keys support the ``>``, ``<``, ``>=``, and ``<=`` operators
in the filter string to specify, respectively, "greater than", "less than",
"greater than or equal to", and "less than or equal to"; they must come
between the key and value, and after the space that separates the key
and value:

-  ``sid``
-  ``cve``
-  ``cvss_v2_base``
-  ``cvss_v2_temporal``
-  ``cvss_v3_base``
-  ``cvss_v3_temporal``
-  ``created_at``
-  ``updated_at``

Example Filter Strings
----------------------

Match all high priority malware related rules:

``"priority high" AND "malware <ALL>"``

Match all high priority malware related rules that were created in 2018
or later:

``("priority high" AND "malware <ALL>") AND "created_at > 2018-01-01"``

Match all high and medium rules that are designed to protect a
webserver:

``("priority high" OR "priority medium") AND ("attack_target http-server"
OR "attack_target tls-server")``

Match all high priority rules that were created in 2019 or involve a
vulnerability (based on CVE number) from 2018 or later:

``"priority high" AND (("created_at >= 2019-01-01" AND "created_at <=
2019-12-31") OR "cve >= 2018-0000")``

See more in the ``examples`` directory.

Aristotle as a Library
======================

Aristotle can be imported and used like a normal library:

``import aristotle``

For logging and/or output, attach to the logger named ``aristotle`` and
add desired Handler(s), e.g.:

.. code:: python

  logger = logging.getLogger("aristotle")
  logger.addHandler(logging.StreamHandler())

To use, create a ``Ruleset`` object and pass it a string containing the
ruleset or a filename of a ruleset, along with a filter string.
Then call  the ``Ruleset`` object's ``filter_ruleset()`` function
to get a list of SIDs matching the filter string.

Example:

.. code-block:: python

    import aristotle

    a = aristotle.Ruleset("examples/example.rules")
    a.set_metadata_filter("examples/example1.filter")
    sids = a.filter_ruleset()


``Ruleset`` class and functions:

.. autoclass:: aristotle.Ruleset
   :members: get_stats, set_metadata_filter, filter_ruleset, output_rules, get_all_sids, print_header, get_stats, print_stats, print_ruleset_summary

License
=======

Aristotle is licensed under the `Apache License, Version 2.0 <https://github.com/secureworks/aristotle/blob/master/LICENSE>`__.

Authors
=======

-  David Wharton
