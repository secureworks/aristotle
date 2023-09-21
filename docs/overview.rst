Application Overview
====================

Aristotle takes in a ruleset and can provide statistics on the included
metadata keys. If a filter string is provided, it will also be applied
against the ruleset and the filtered ruleset outputted.

By default, Aristotle does *not* modify the contents of rules; it
simply includes or excludes rules based on the given Boolean filter string.
But Aristotle is much more powerful than that.  It can also :ref:`enhance <target Enhance Metadata>`
and :ref:`normalize <target Normalize Metadata>` metadata for use in filtering and even output.
Rules can be further modified using the :doc:`Post Filter Modification <post_filter_mod>` option and directives.

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

To help address the lack of rich, comprehensive metadata lacking in most
rulesets -- even commercial ones from established and respected vendors -- Aristotle
offers the ability to intelligently process rules to extract, enrich, and add
metadata to rules.  Rules can also undergo :doc:`Post Filter Modification <post_filter_mod>`
to modify rules based on user-defined criteria to help ensure the resulting
rules in the ruleset are enabled, configured, and optimized for the target environment.

Metadata Key-Value Pairs
========================

.. important:: In order for Aristotle to be most useful, it must be provided a ruleset that
    has rules with the metadata keyword populated with appropriate key-value
    pairs. Aristotle assumes that the provided ruleset conforms to the
    `BETTER Schema <https://better-schema.readthedocs.io/>`__.

