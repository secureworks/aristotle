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

.. code-block:: console

    python aristotle.py -r examples/example.rules -s

Show statistics on the ``protocols`` key in the ``example.rules`` file:

.. code-block:: console

    python aristotle.py -r examples/example.rules -s protocols

Apply the Boolean filter defined in the ``example1.filter`` file against the
rules in the ``example.rules`` file and output summary results to stdout:

.. code-block:: console

    python aristotle.py -r examples/example.rules -f examples/example1.filter --summary

Apply the Boolean filter defined in the ``example1.filter`` file against the
rules in the ``example.rules`` file and output the results to the file ``newrules.rules``:

.. code-block:: console

    python aristotle.py -r examples/example.rules -f examples/example1.filter -o newrules.rules

Apply the Boolean filter defined specified on the command line against the
rules in the ``example.rules`` file and output the results to the file ``newrules.rules``:

.. code-block:: console

    python aristotle.py -r examples/example.rules -f '"malware <ALL>" AND ("attack_target http-server" or "attack_target tls-server")' -o newrules.rules

Consume the rules defined in the ``examples/example.rules``, `Normalize`_ the metadata,
apply the Boolean filter defined in the ``example1.filter`` file against the
rules in the ``example.rules`` file, and output the results -- `with updated metadata` -- to
the file ``newrules.rules``:

.. code-block:: console

    python aristotle.py -r examples/example.rules -f examples/example1.filter -o newrules.rules --normalize --modify-metadata

.. important:: Because Aristotle requires key-value pairs (values) in the filter string
    to be enclosed in double quotes, a filter string specified on the command line must
    be enclosed in single quotes.

Statistics
----------

The statistics command line option allows a user to to easily see what
metadata key-value pairs the ruleset contains to assist in building a
filter string.

.. note::
    If a filter string is provided, or other options to manipulate the metadata (e.g.
    :ref:`Normalize`, :ref:`Modify Metadata`) are set, along with a request for
    statistics, then the filter and/or other manipulations are performed first,
    and the statistics outputted apply to the filtered/modified ruleset.

If no key names are passed, summary info on all present keys is
displayed:

.. code:: console

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

.. code:: console

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

Classtype
---------

Suricata and Snort support the ``classtype`` keyword and many rulesets choose to utilize this rule keyword
instead of putting the ``classtype`` key-value pair into the metadata.  Therefore, by default, Aristotle
will take the ``classtype`` value from the rule keyword and add a ``classtype`` metadata key and value into the
(internal data structures representing the) metadata so that it can be used for filtering and statistics generation.
If multiple ``classtype`` keywords are used in a rule, only the first one seen (from left-to-right) will be
incorporated.  The ``classtype`` keyword can be used in a rule and defined in the metadata without issue; only
the unique values will be considered.
This default behavior can be changed with a command line switch or in
the :ref:`Ruleset class constructor <target Ruleset class>`.

Filename
--------

If a rule was loaded from a file, Aristotle will add the ``filename`` key-value pair so that it can be
used for filtering and statistics generation.  The value will be the filename the rule was read from.
This default behavior can be changed with a command line switch or in
the :ref:`Ruleset class constructor <target Ruleset class>`.

Disabled Rules
--------------
Internally, an ``originally_disabled`` key and boolean value (``true`` or ``false``, case insensitive) is added to
the metadata of each rule.  If a rule from a rule file is a valid rule but commented out, the ``originally_disabled``
value will be ``true``, otherwise it will be ``false``.  The ``originally_disabled`` metadata can be used for filtering,
including `Post Filter Modification`_.  For more details see the :doc:`Disabled Rules <disabled_rules>` doc.

.. _target Normalize Metadata:

Normalize
---------

The normalize command line option (also supported in
the :ref:`Ruleset class constructor <target Ruleset class>` will do the following
to the internal data structure used to store metadata and filter against:

  - ``cve`` value normalized to ``YYYY-<num>``. If multiple CVEs are represented in the
    value and strung together with a ``_`` (e.g. ``cve_2021_27561_cve_2021_27562`` [`sic`])
    then all identified CVEs will be included.
  - Values from non-BETTER schema keys ``mitre_technique_id`` and ``mitre_tactic_id`` will be
    put into the standards compliant ``mitre_attack`` key.
  - date key values -- determined by any key names that end with ``_at`` or ``-at`` -- will
    be attempted to be normalized to ``YYYY-MM-DD``.  A failure to parse or normalize
    the value will result in a warning message and the value being unchanged.

If the :ref:`Modify Metadata`
option is also set then the normalized values, rather than the originals, will be
included in the output, and the ``sid`` key will be removed from the metadata.

.. _target Enhance Metadata:

Enhance
--------

The enhance command line option (also supported in
the :ref:`Ruleset class constructor <target Ruleset class>` will analyze the rule(s) and attempt
to update the metadata on each.

  - ``flow`` key with values normalized to be ``to_server`` or ``to_client``.
  - ``protocols`` key and applicable values, per the `BETTER Schema <https://better-schema.readthedocs.io/en/latest/schema.html#defined-keys>`__.
  - ``cve`` key and applicable values, per the `BETTER Schema <https://better-schema.readthedocs.io/en/latest/schema.html#defined-keys>`__.
    The value(s) are based on data extracted from the raw rule, e.g. ``msg`` field, ``reference`` keyword, etc.
  - ``mitre_attack`` key and applicable values, per the `BETTER Schema <https://better-schema.readthedocs.io/en/latest/schema.html#defined-keys>`__.
    The value(s) are based on data extracted from the rule's ``reference`` keyword.
  - ``hostile`` key and applicable values (``dest_ip`` or ``src_ip``, per the `BETTER Schema <https://better-schema.readthedocs.io/en/latest/schema.html#defined-keys>`__.
    The values are the inverse of values taken from the ``target`` keyword.
  - ``classtype``\* key and applicable values, per the `BETTER Schema <https://better-schema.readthedocs.io/en/latest/schema.html#defined-keys>`__.
    See the :ref:`Classtype` section.
  - ``filename``\* key and applicable values, per the `BETTER Schema <https://better-schema.readthedocs.io/en/latest/schema.html#defined-keys>`__.
    The value will be the filename the rule came from, if the rule was loaded from a file.  See the :ref:`Filename` section.
  - ``originally_disabled`` key and boolean value gets added on each rule internally, and can be used for filtering, but only is included in the output
    if "enhance" is enabled (along with `Modify Metadata`_).  See also the `Disabled Rules`_ section.
  - ``detection_direction`` keyword (see below).

\* Key added by default unless explicitly disabled.

Detection Direction
...................

The ``detection_direction`` metadata key attempts to normalize the directionality of traffic the rule
detects on. To do this, the source and destination (IP/IPVAR) sections of the rule are reduced down to "$HOME_NET",
"$EXTERNAL_NET", "any", or "UNDETERMINED" and used to set the ``detection_direction`` value as follows:

=============================  ==============================
detection_direction value      reduced condition
=============================  ==============================
inbound                        ``$EXTERNAL_NET -> $HOME_NET``
inbound-notexclusive           ``any -> $HOME_NET``
outbound                       ``$HOME_NET -> $EXTERNAL_NET``
outbound-notexclusive          ``$HOME_NET -> any``
internal                       ``$HOME_NET -> $HOME_NET``
any                            ``any -> any``
both                           direction in rule is ``<>``
=============================  ==============================

Modify Metadata
---------------

.. note::
    No metadata is altered on output unless the Modify Metdata option is set!

The command line and the :ref:`Ruleset class constructor <target Ruleset class>` offer
the option to update the metadata keyword value on output.  If this option is not set,
Aristotle does not modify rules, it just enable or disables them based on the given
filter.  However, if the `modify metadata` option is set, then the value of the ``metadata``
keyword will be replaced with a string sourced form the internal data structure that
Aristotle uses to track, parse, and filter metadata. Practically, the metadata will
be updated accordingly:

  - ``sid`` key and value added to metadata (unless the `Normalize`_ option is set).
  - ``classtype`` key and value added to metadata, if the ``classtype`` keyword is present in the rule and the option to ignore classtype is not set.
  - ``filename`` key and value added to metadata, if the rule(s) came from a file and the option to ignore filename is not set.
  - if the `Normalize`_ option is set, any changes done by that will be included.
  - if the `Enhance`_ options is set, any changes done by that will be included.

Additionally, the order of the key-value pairs in the metadata will be sorted by
key and then value.

.. important:: To enable efficient boolean logic application and because metadata is considered
    by Aristotle to be case insensitive per the `BETTER Schema <https://better-schema.readthedocs.io/en/latest/schema.html#details>`__,
    metadata key-value pairs are represented internally as lowercase.  Therefore, if :ref:`Modify Metadata` is
    enabled, the outputted metadata key-value pairs will be all lowercase.

Post Filter Modification
------------------------

See :doc:`Post Filter Modification <post_filter_mod>`.
