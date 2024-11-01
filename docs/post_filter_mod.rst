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
     done to ensure the "include" chain is a directed acyclic graph, so for now that responsibility
     falls on the user.

.. warning:: PFMod requires that the "modify" (``-m``) option be set and it will be automatically
     enabled, if not already enabled, if a PFMod file is provided.

PFMod Actions
*************

Supported ``actions`` are:

-  ``disable`` - disable the rule.  This is a standalone string in the list.
-  ``enable`` - enable the rule.  This is a standalone string in the list.  Note that for "disabled" rules to make it
   to PFMod for consideration, they must first match in the initial filter string matching phase.
-  ``copy_key`` - copy the value from one metadata key to a new one. Format: ``<src_key> <dst_key>``, e.g.
   ``risk_score risk_score_original``.  If the destination key already exists, it will *not* be overwritten.
-  ``add_metadata`` - YAML key-value pair where the (YAML) value is the metadata key-value pair to add (e.g. ``protocols http``).
   Note that if there is already metadata using the given key, it is not overwritten unless the value is the
   same too in which case nothing is added since it already exists.
-  ``add_metadata_exclusive`` - YAML key-value pair where the (YAML) value is the metadata key-value pair to add (e.g. ``priority high``).
   If the given metadata key already exists, overwrite it with the new value.
-  ``delete_metadata`` - if a metadata key-value pair is given (e.g. ``former_category malware``) remove the key-value pair.
   from the rule.  If just a metadata key name is given (e.g. ``former_category``), remove all metadata using the given key,
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
   For integer keywords (``priority``, ``rev``, ``gid``, and ``sid``), relative values can be used by preceding the
   integer value with a '+' or '-'. (Note that the YAML value should be quoted in this case so that it is treated as
   a string; if it is specified as an integer, the leading '+' will not be preserved when consuming the YAML.)  For
   example, the action ``set_priority "-1"`` will cause the existing priority value in the rule to be decreased by
   1; the action ``set_priority "+2"`` will cause the existing priority value to be increased by 2.  If a given keyword
   (e.g. ``priority``, ``rev``, etc.) does not already exist in the rule, no changes will be made and a warning message will
   be given.  If a relative modification causes a value to drop below what the engine allows (e.g. a negative ``priority``
   value), then the value will be set to the minimum allowed (e.g. ``priority: 1``).
   Supported keywords and examples:

    ================  =============  ===================================================================
    IDS Rule Keyword  PFMod Action   Example
    ================  =============  ===================================================================
    priority          set_priority   ``set_priority: 4``
    priority          set_priority   ``set_priority: "+1"``
    priority          set_priority   ``set_priority: "-1"``
    sid               set_sid        ``set_sid: 8675309``
    gid               set_gid        ``set_gid: 0``
    rev               set_rev        ``set_rev: 2``
    msg               set_msg        ``set_msg: "New MSG"``
    classtype         set_classtype  ``set_classtype: "command-and-control"``
    reference         set_reference  ``set_reference: "url,example.com"``
    target*           set_target     ``set_target: "dest_ip"``
    threshold         set_threshold  ``set_threshold: "type limit, count 1, track by_src, seconds 120"``
    flow              set_flow       ``set_flow: "established,to_server"``
    ================  =============  ===================================================================

-  ``set_<arbitrary_integer_metadata>`` -- similar to ``add_metadata_exclusive``, allows for the setting or changing of an arbitrary
   integer-based metadata key value, but also supports relative values along with default values.

    Format:
     .. code-block:: yaml

         set_<arbitrary_integer_metadata>: "[-+]<value>[,<default>]"


    Notes:
     - The *<arbitrary_integer_metadata>* string corresponds to the metadata key name and must contain at least one underscore ('_') character.
     - The metadata key being referenced should have a value corresponding to an integer.
     - A preceding '+' or '-' to the given *<value>* will cause the existing metadata value in the rule to be increased or decreased by the given
       *<value>*, respectively.  If the metadata key does not exist, then the value will be set to the given *<default>* value, if provided, otherwise
       no change will be made.

    Examples:
      ============================  =====================================================================================================================================================================
      Example                       Description
      ============================  =====================================================================================================================================================================
      ``set_risk_score: 42``        Set the "risk_score" metadata key to value 42.  Functionally the same as ``add_metadata_exclusive: "risk_score 42"``.
      ``set_risk_score: "-10,50"``  Decrease the existing "risk_score" metadata key value by 10; if there is no "risk_score" metadata key name, add it and set it to the default value of 50.
      ``set_risk_score: "+10"``     If there is an existing "risk_score" metadata key value, increase it by 10; otherwise do nothing.
      ``set_machine_level: "-50"``  If there is an existing "machine_level" metadata key value, decrease it by 50; otherwise do nothing. (The key name can be arbitrary as long as it has an underscore.)
      ============================  =====================================================================================================================================================================

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
    include:
      - "pfmod-inbound.yaml"
      - "pfmod-outbound.yaml"
      - "pfmod-malware.yaml"
      - "pfmod-phishing.yaml"


Example file with ``rules`` specified.  Note: you can have a PFMod file with ``include`` and ``rules``; the former
will be processed and then the latter.

.. code-block:: yaml

  YAML 1.1
  ---

  # Created By George P. Burdell 2023-03-14
  # Handle Phishing Rules

  version: "1.0"
  rules:
    - name: confidence-unknown
      # set all rules without a 'confidence' metadata key to "confidence unknown"; populate for SIEM
      filter_string: >-
        NOT "confidence <ANY>"
      actions:
        - add_metadata: "confidence unknown"
    - name: default-risk-score-50
      # set all phishing related rules with out a risk_score metadata to 50
      filter_string: >-
        "filename phishing.rules" OR "msg_regex /phish/i"
      actions:
        - set_risk_score: "+0,50"
    - name: phish-high-confidence
      # add 5 to risk_score for phishing related rules with "confidence high"
      filter_string: >-
        ("filename phishing.rules" OR "msg_regex /phish/i")
        AND "confidence high"
      actions:
        - set_risk_score: "+5"
    - name: phish-low-confidence
      # subtract 10 to risk_score for phishing related rules with "confidence low"
      filter_string: >-
        ("filename phishing.rules" OR "msg_regex /phish/i")
        AND "confidence low"
      actions:
        - set_risk_score: "-10"
    - name: phish-high-critical
      # add 30 to risk_score for critical/high phishing related rules
      filter_string: >-
        ("severity critical" OR "priority high")
        AND ("filename phishing.rules" OR "msg_regex /phish/i")
      actions:
        - set_risk_score: "+30"
        - set_priority: 1
        - add_metadata_exclusive: "priority high"
    - name: phish-internal-landing-page
      # add 50 to risk_score for detection of internal landing page or
      # phishing panel being hosted; set rules to drop.
      filter_string: >-
        ("filename phishing.rules" OR "msg_regex /phish/i")
        AND (("detection_direction outbound" OR "detection_direction outbound-notexclusive")
             AND "protocols http" AND "flow to_client"
            )
      actions:
        - set_risk_score: "+50"
        - set_priority: 1
        - add_metadata_exclusive: "priority high"
        - regex_sub: '/^alert\x20/drop /'  # set to drop
    - name: phish-major
      # add 15 to risk_score for "severity major"  phishing related rules
      filter_string: >-
        ("severity major")
        AND ("filename phishing.rules" OR "msg_regex /phish/i")
      actions:
        - set_risk_score: "+15"
    - name: phish-malware-classtype
      # increase risk_score metadata by 15 for certain classtype values'
      filter_string: >-
        ("classtype trojan-activity" OR "classtype command-and-control" OR "classtype targeted-activity")
        AND ("filename phishing.rules" OR "msg_regex /phish/i")
      actions:
        - set_risk_score: "+15"
    - name: phish-disable-low
      # disable phishing rules marked as audit, info, or research
      filter_string: >-
        ("filename phishing.rules" OR "msg_regex /phish/i")
        AND (
             "signature_severity informational" OR "signature_severity audit" OR "msg_regex /INFORMATIONAL/i"
             OR "rule_regex /[\s\x3B\x28]priority\s*\x3A\s*[45]\s*\x3B/" OR "priority research" OR "priority low"
            )
        AND NOT "rule_regex /[\s\x3B\x28]flowbits\s*\x3A\s*set/"  # don't disable flowbits setters
      actions:
        - set_risk_score: "-25" # in case a subsequent rule (re)enables this, the risk score will be accurate.
        - disable
