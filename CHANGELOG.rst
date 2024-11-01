*******************
Aristotle Changelog
*******************

1.0.1 (2019-10-16)
##################

Initial public release.

Special thanks: SuriCon 2019

1.0.2 (2019-10-21)
##################

Documentation reorganization

1.0.3 (2021-02-24)
##################

Minor cleanup
Made it so module could be invoked via command line, e.g.:

.. code:: bash

    python3 -m aristotle -r examples/example.rules --stats

2.0.0 (2023-09-20)
##################

Features added:

  - Metadata Normalization
  - Metadata Enhancement
  - Post Filter Modification
  - Regular expression based filtering
  - Sundry tweaks and updates

See documentation for details.

Special thanks: Uber

2.1.0 (2024-11-01)
##################

Features added:

  - Add support for PFMod 'copy_key' action

Bug Fixes:

  - The enabling of modify_metadata automatically if unset when a PFMod file is given wasn't being honored when running as a script.
  - Empty PFMod YAML entries were not always being handled properly.
