=========
Aristotle
=========

Aristotle is a simple Python program that allows for the filtering of
Suricata and Snort rulesets based on interpreted key-value pairs present
in the metadata keyword within each rule. It can be run as a standalone
script or utilized as a library.

.. contents::
   :depth: 3

Application Overview
====================

Aristotle takes in a ruleset and can provide statistics on the included
metadata keys. If a filter string is provided, it will also be applied
against the ruleset and the filtered ruleset outputted.

Background
==========

Suricata and Snort support the ``metadata`` keyword that allows for
non-functional (in terms of detection), arbitrary information to be
included in a rule. By defining key-value pairs and including them in
the metadata keyword, ruleset providers can embed rich teleological and
taxonomic information. This information can be used to filter a ruleset
– essentially enabling and disabling rules in a ruleset based on the
metadata key-value pairs. Aristotle allows for the easy leveraging of
the metadata key-value pairs to "slice-and-dice" Suricata and Snort
rulesets that implement metadata key-value pairs.

Metadata Key-Value Pairs
========================

In order for Aristotle to be useful, it must be provided a ruleset that
has rules with the metadata keyword populated with appropriate key-value
pairs. Aristotle assumes that the provided ruleset conforms to the
`BETTER Schema <https://github.com/secureworks/BETTER/>`__.

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
                          output file (default: <stdout>)
    -s [STATS [STATS ...]], --stats [STATS [STATS ...]]
                          display ruleset statistics about specified key(s)
                          (default: None)
    -i, --include-disabled
                          include disabled rules when applying the filter
                          (default: False)
    -q, --quiet, --suppress_warnings
                         quiet; suppress warning messages (default: False)
    -d, --debug           turn on debug output (default: False)

Example Files
-------------

The examples directory has .filter files that show examples of Boolean
filter strings.

Also in the ``examples`` directory is an ``example.rules`` file that has a dummy
ruleset that implements the `BETTER
Schema <https://github.com/secureworks/BETTER/>`__. *This is not a real
ruleset*. It is provided to assist in demonstrating the functionality of
Aristotle.

Example Usage
-------------

``python aristotle.py -r examples/example.rules -s``

``python aristotle.py -r examples/example.rules -s protocols``

``python aristotle.py -r examples/example.rules -f examples/example1.filter --summary``

``python aristotle.py -r examples/example.rules -f examples/example1.filter -o newrules.rules``

``python aristotle.py -r examples/example.rules -f '"malware <ALL>" AND ("attack_target http-server" or "attack_target tls-server")' -o newrules.rules``

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

If one of more key names are passed, summary info is displayed for those
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

-  The Boolean operators AND, OR, and NOT are allowed.
-  Grouping should be done with parentheses.
-  **The key-value pair specifications must be surrounded by double
   quotes (ASCII 0x22).**
-  To match all values of a key, use the pseudo-value "<ALL>" (not case
   sensitive), e.g. ``"malware <ALL>"``.
-  Extraneous whitespace, including newlines, is allowed in the filter
   string.

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

Aristotle as a Library
======================

Aristotle can be imported and used like a normal library:

``import aristotle``

For logging and/or output, attach to the logger named "aristotle" and
add desired Handler(s), e.g.:

.. code:: python

  logger = logging.getLogger("aristotle")
  logger.addHandler(logging.StreamHandler())

To use, create a Ruleset object and pass it a string containing the
ruleset or a filename of a ruleset:

\ *class Ruleset*\ (*self*, *rules*, *metadata\_filter=None*,
*include\_disabled\_rules=False*)

+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Parameters:   | **rules** (*string, required*) – a string containing a ruleset or a filename of a ruleset file                                                                                                                                    |
|               |                                                                                                                                                                                                                                   |
|               | **metadata\_filter** (*string, optional*) – A string that defines the desired outcome based on Boolean logic, and uses the metadata key-value pairs as values in the Boolean algebra. Defaults to None (can be provided later).   |
|               |                                                                                                                                                                                                                                   |
|               | **include\_disabled\_rules** (*boolean*) – effectively enable all commented out rules when dealing with the ruleset, defaults to *False*                                                                                          |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Raises:       | *AristotleException*                                                                                                                                                                                                              |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Statistics on the ruleset can be returned (if desired):

\ *get\_stats*\ (**self**, **key**, **keyonly=False**)

+----------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| Parameters:    | **key** (*string, required*) – key to print stats for                                                                                         |
|                |                                                                                                                                               |
|                | **keyonly** (*boolean, optional*) – only print stats for the key itself and not stats for all possible key-value pairs, defaults to *False*   |
+----------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| Returns:       | string contaning stats, suitable for printing to stdout                                                                                       |
+----------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| Return type:   | string                                                                                                                                        |
+----------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| Raises:        | *AristotleException*                                                                                                                          |
+----------------+-----------------------------------------------------------------------------------------------------------------------------------------------+

If no value to the ``metadata_filter`` parameter is passed to the
constructor, then at some
point before filtering happens, a filter must be provided, either
in the call to ``filter_ruleset()`` or the ``Ruleset`` object parameter
set, e.g.:

``myruleset.metatdata_filter = '<filter here>'``

To filter the ruleset using the ``metadata_filter``, call
filter\_ruleset(); if a filter has
not been defined, it can be passed when calling this function.

\ *filter\_ruleset*\ (**self**, **metadata\_filter=None**)

+----------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Parameters:    | **metadata\_filter** (*string, optional*) – A string that defines the desired outcome based on Boolean logic, and uses the metadata key-value pairs as values in the Boolean algebra. Defaults to *self.metadata\_filter*.   |
+----------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Returns:       | list of matching SIDs                                                                                                                                                                                                        |
+----------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Return type:   | list                                                                                                                                                                                                                         |
+----------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Raises:        | *AristotleException*                                                                                                                                                                                                         |
+----------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

To output the ruleset, call ``output_rules()``:

\ *output\_rules*\ (*self*, *sid\_list*, *outfile=None*)

+----------------+-----------------------------------------------------------------------------------------------------------------+
| Parameters:    | **sid\_list** (*list, required*) – list of SIDs of the rules to output                                          |
|                |                                                                                                                 |
|                | **outfile** (*string or None, optional*) – filename to output to; if None, output to stdout; defaults to None   |
+----------------+-----------------------------------------------------------------------------------------------------------------+
| Returns:       | None                                                                                                            |
+----------------+-----------------------------------------------------------------------------------------------------------------+
| Return type:   | NoneType                                                                                                        |
+----------------+-----------------------------------------------------------------------------------------------------------------+
| Raises:        | *AristotleException*                                                                                            |
+----------------+-----------------------------------------------------------------------------------------------------------------+

See the code/docstrings for more details on these and other functions.

License
=======

Aristotle is licensed under the Apache License, Version 2.0. See
`LICENSE <LICENSE>`__.

Authors
=======

-  David Wharton
