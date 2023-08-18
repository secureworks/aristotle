Post Filter Modification ("PFMod")
==================================

Overview
--------

Aristotle offers the option to further filter *and modify* the ruleset,
after the initial filter string and metadata enhancements (if so enabled)
are applied.  This is known as "Post Filter Modification", a.k.a. "PFMod".

PFMod allows for the identification of rules based on :doc:`Filter Strings <filter_strings>`, and
then particular "actions" taken on those rules.  :ref:`PFMod Actions` include the
ability to add/delete metadata, enable/disable rules, set ``priority``, and do a regular expression
based "find and replace" on the full rule.

..  important::
    Only rules that match the initial filter string phase are passed to PFMod
    for consideration.

PFMod YAML Format
-----------------

.. note::
    Keep in mind, this is a YAML file and entries must conform to the YAML specification.

PFMod rules (not to be confused with Suricata or Snort rules) are defined in
YAML format in a file that is passed to Aristotle. For examples, see the :ref:`Example PFMod YAML Files`
section.  Some notes about the
PFMod rule definition:

-  The ``version`` key is optional and can be used (in the future) to distinguish among different
   PFMod format versions.  However, at this point there is only one version -- 1.0.
-  The ``include`` key can be given a list of (other) PFMod rules files to include. Files are
   processed in the order they appear, with files in the ``include`` list being processed
   before any ``rules`` directives in a file (basically depth-first search).  If an absolute path is not given, the location
   of the referenced file will assume to be relative to the file in which it is referenced.
-  Under the ``rules`` key is a list of (PFMod) rules each with its applicable data:

   -  ``name`` - optional but useful for a description of the rule, and used in error output.
   -  ``filter_string`` - the :doc:`Filter String <filter_strings>` to use against the (initially filtered)
      ruleset whose results will be the object of the rule's actions.
   -  ``actions`` - a list of actions to perform on the rules that matched the filter string
      in the rule.

.. warning::
     Using the ``include`` key to include files can create a cyclic situation if included files
     include themselves or subsequent files include previous files.  Currently, no checking is
     done to ensure the "includes" chain is a directed acyclic graph, so for now that responsibility
     falls on the user.

.. warning:: PFMod requires that the "modify" (``-m``) option be set and it will be automatically
     enabled, if not already enabled, if a PFMod file is provided.

PFMod Actions
*************

Supported ``actions`` are:

-  ``disable`` - disable the rule.  This is a standalone string in the list.
-  ``enable`` - enable the rule.  This is a standalone string in the list.  Note that for "disabled" rules to make it
   to PFMod for consideration, they must first match in the initial filter string matching phase.
-  ``add_metadata`` - key-value pair where the value is the metadata key-value pair to add (e.g. ``protocols http``).
   Note that if there is already metadata using the given key, it is not overwritten (unless the values are the
   same too in which case nothing is added since it already exists).
-  ``add_metadata_exclusive`` - key-value pair where the value is the metadata key-value pair to add (e.g. ``priority high``).
   If the given key already exists, overwrite it with the new value.
-  ``delete_metadata`` - if a key-value pair is given (e.g. ``former_category malware``) remove the key-value pair
   from the rule.  If just a key name is given (e.g. ``former_category``), remove all metadata using the given key,
   regardless of the value.
-  ``regex_sub`` -- Perform a RegEx find and replace on the rule based on the given value. Details:

    -  Values follow the format ``/regex-to-find/replacement_string/i``
    -  A trailing ``i`` after the pattern makes the match case insensitive,
       e.g. ``"regex_sub /(Not\x20|In)sensitive/quite\20/i"``.
    -  Patterns are passed to the Python ``re.sub()`` function *as raw strings*
       and support whatever the ``re`` library of the running version of Python supports.
    -  For ``regex_sub`` values, it is recommended that they be *single quoted*.  Double
       quoted strings in YAML will interpret the backslash character as a control character
       which will cause issues in non-trivial regular expressions if not encoded.

-  ``set_<keyword>`` -- set the *<keyword>* in the IDS rule string to have the given value.  If the rule does not contain
   the given keyword, add it and set the value to the given value. Little to no validation checking is done so it
   is up to the PFMod rule author to ensure that the proper syntax is used for the keyword value(s).
   Supported keywords and examples:

    ================  =============  ===================================================================
    IDS Rule Keyword  PFMod Action   Example
    ================  =============  ===================================================================
    priority          set_priority   ``set_priority: 4``
    sid               set_sid        ``set_sid: 8675309``
    gid               set_gid        ``set_gid: 0``
    rev               set_rev        ``set_rev: 2``
    msg               set_msg        ``set_msg: "New MSG"``
    classtype         set_classtype  ``set_classtype: "command-and-control"``
    reference         set_reference  ``set_reference: "url,examle.com"``
    target*           set_target     ``set_target: "dest_ip"``
    threshold         set_threshold  ``set_threshold: "type limit, count 1, track by_src, seconds 120"``
    flow              set_flow       ``set_flow: "established,to_server"``
    ================  =============  ===================================================================

`*` Suricata only keyword

.. note::
    PFMod ``rules`` and ``actions`` are applied in the order they are processed -- from top to bottom of the file. This
    means that, depending on how the rules and actions are written, subsequent rules and actions can affect changes
    made by previous rules and actions.  Remember too that the files included with the ``include`` key are processed
    before any ``rules`` directives, resulting in a depth-first search type of behavior.

Example PFMod YAML Files
------------------------

Example file using ``include`` to load multiple PFMod files:

.. code-block:: yaml

    %YAML 1.1
    ---

    # Created By George P. Burdell 2023-03-02
    # Main includes file

    version: "1.0"
    includes:
      - "pfmod-inbound.yaml"
      - "pfmod-outbound.yaml"
      - "pfmod-malware.yaml"


Example file with ``rules`` specified.  Note: you can have a PFMod file with ``include`` and ``rules``; the former
will be processed and then the latter.

.. code-block:: yaml

    %YAML 1.1
    ---

    # Created By George P. Burdell 2023-03-02
    # For DMZ perimiter

    version: "1.0"
    rules:
      - name: ip-rules-inbound
        filter_string: >-
          (
            "filename ip-blocklist.rules" OR "msg_regex /\x203CORESec\x20/i"
            OR "rule_regex /^(pass|drop|reject|alert|sdrop|log|rejectsrc|rejectdst|rejectboth)\s+ip\s+/"
          ) AND (
            "detection_direction inbound"
          )
        actions:
          - add_metadata_exclusive: "risk_score 10"
          - set_priority: 2
          - set_target: "dest_ip"

      - name: ip-rules-outbound
        filter_string: >-
          (
            "detection_direction outbound"
            AND "rule_regex /^(pass|drop|reject|alert|sdrop|log|rejectsrc|rejectdst|rejectboth)\s+ip\s+/"
            AND "signature_severity major"
          )
        actions:
          - add_metadata_exclusive: "risk_score 51"
          - add_metadata: "soc_response_color brown"
          - set_priority: 3
      - name: drop-inbound-dns-requests
        filter_string: >-
          (
            "detection_direction inbound"
          ) AND (
            "protocols dns"
            AND "rule_regex /dns[\x2E\x5F]query\x3B/"
          )
        actions:
          - regex_sub: '/^alert\x20/drop /'
          - add_metadata: "custom_action drop"
          - set_target: "dest_ip"
      - name: disable-informational-and-audit
        filter_string: >-
          "signature_severity informational" OR "signature_severity audit"
          OR "msg_regex /INFORMATIONAL/i" OR "rule_regex /[\s\x3B\x28]priority\s*\x3A\s*5\s*\x3B"
        actions:
          - disable
      - name: enable-disabled-critical
        filter_string: >-
          "signature_severity critical"
          AND NOT "performance_impact significant"
          AND "originally_disabled true"
        actions:
          - enable
          - set_priority: 3
          - add_metadata_exclusive: "risk_score 67"
          - add_metadata: "soc_response_color pink"
