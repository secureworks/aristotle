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
Suricata ruleset that implements the `BETTER Schema <https://better-schema.readthedocs.io/>`__.
While the example
ruleset is syntactically correct, *it is not a real ruleset*
intended to be used by a Suricata sensor.
It is provided to assist in demonstrating the functionality of
Aristotle and to provide examples of rules with ``metadata`` keywords that
conform to the `BETTER Schema <https://better-schema.readthedocs.io/>`__.

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

