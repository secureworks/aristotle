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
   -  Note that per the `BETTER Schema <https://better-schema.readthedocs.io/>`__, a
      "sid" metadata key is not recommended but if present, it must have a
      value that matches the ``sid`` keyword value of the rule.

-  **To do a regular expression pattern based match against the rules' "msg" field**,
   use the pseudo key ``msg_regex``.  See the :ref:`Matching on the msg Field` section
   below for more details.
-  **To do a regular expression pattern based match against the raw rule**,
   use the pseudo key ``rule_regex``.  See the :ref:`Matching on the raw rule` section
   below for more details.
-  Extraneous whitespace, including newlines, *is* allowed in the filter
   string.
-  If a file containing a Boolean filter string is supplied:

   - Lines beginning with '#' are considered comments and are ignored.
   - A line starting with the string ``<enable-all-rules>`` results in
     enabling all rules, including disabled ones, before applying
     the Boolean filter.

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

Matching on the msg Field
-------------------------
A filter string supports the filtering of rules based on a regular expression
pattern applied against the rules' ``msg`` filed.  To specify such a filter, use
the (pseudo) key ``msg_regex`` with the pattern as the value. Details:

  - Patterns must be contained between ``/`` characters.
  - A trailing ``i`` after the pattern makes the match case insensitive,
    e.g. ``"msg_regex /(Not\x20|In)sensitive/i"``.
  - Patterns are passed to the Python ``re.search()`` function *as raw strings*
    and support whatever the ``re`` library of the running version of
    Python supports.

.. note::
    Python's ``re.search`` function looks for the given pattern anywhere in
    the target string.  To anchor on the beginning or end of the ``msg`` field, use
    the ``^`` (beginning) and/or ``$`` (end) special characters as usual.

Examples:

=============================================  =========================================================
Filter string key-value pair                   Functional Python equivalent
=============================================  =========================================================
``"msg_regex /^ET\x20MALWARE\x20/"``           ``re.search(r"^ET\x20MALWARE\x20", <msg>, flags=0)``
``"msg_regex /\x20(Malware|Trojan)/i"``        ``re.search(r"\x20(Malware|Trojan)", <msg>, flags=re.I)``
=============================================  =========================================================

Matching on the raw rule
------------------------
A filter string supports the filtering of rules based on a regular expression
pattern applied against the full raw rule..  To specify such a filter, use
the (pseudo) key ``rule_regex`` with the pattern as the value. This behaves
the same way and follows the same rules as the ``msg_regex`` pseudo keyword
(except for the data it matches against).  See the :ref:`Matching on the msg Field` section.


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

Match all rules with the RegEx pattern ``^ET\x20MALWARE\x20.*(Ransomware|CnC|C2)``
(case sensitive) or ``\x20(Malware|Trojan)`` (case insensitive) in the msg field:

``"msg_regex /^ET\x20MALWARE\x20.*(Ransomware|CnC|C2)/" OR "msg_regex
/\x20(Malware|Trojan)/i"``

See more in the ``examples`` directory.

