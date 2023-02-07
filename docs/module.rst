Aristotle as a Module
=====================

If the module is installed, Aristotle can be invoked from the command
line and run like a script, e.g.:

``python3 -m aristotle -r examples/example.rules --stats``

Of course, Aristotle can be imported and used like a normal module:

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

.. _target Ruleset class:

.. autoclass:: aristotle.Ruleset
   :members: get_stats, set_metadata_filter, filter_ruleset, output_rules, get_all_sids, print_header, print_stats, print_ruleset_summary

