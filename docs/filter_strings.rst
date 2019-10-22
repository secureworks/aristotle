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

