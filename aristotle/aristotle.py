#!/usr/bin/env python
"""Aristotle

Command line tool and library for filtering Suricata
and Snort rulesets based on metadata keyword values.
"""
# Copyright 2019 Secureworks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import boolean
import datetime
from dateutil.parser import parse as dateparse
import hashlib
import logging
import os
import re
import sys

class AristotleException(Exception):
    pass

# if used as library, attach to "aristotle",
# e.g. logger = logging.getLogger("aristotle")
aristotle_logger = logging.getLogger("aristotle")

# If no logging configured then Python >= version 3.2 will log level WARNING
# to logging.lastResort (default sys.stderr);  With Python < 3.2, will
# generate an error so adding NullHander in that case (logs will go nowhere).
# If this program is run from command line, a  logging.StreamHandler()
# handler is added. But if using as library, be sure to add a hander (and
# formatter if desired) to logger "aristotle", e.g.:
#     logger = logging.getLogger("aristotle")
#     logger.addHandler(logging.StreamHandler())
# Ref: https://docs.python.org/3/howto/logging.html#what-happens-if-no-configuration-is-provided
if (sys.version_info < (3, 2)):
    aristotle_logger.addHandler(logging.NullHandler())

disabled_rule_re = re.compile(r"^\x23(?:pass|drop|reject|alert|sdrop|log)\x20.*[\x28\x3B]\s*sid\s*\x3A\s*\d+\s*\x3B")
sid_re = re.compile(r"[\x28\x3B]\s*sid\s*\x3A\s*(?P<SID>\d+)\s*\x3B")
metadata_keyword_re = re.compile(r"[\x28\x3B]\s*metadata\s*\x3A\s*(?P<METADATA>[^\x3B]+)\x3B")
rule_msg_re = re.compile(r"[\s\x3B\x28]msg\s*\x3A\s*\x22(?P<MSG>[^\x22]+?)\x22\s*\x3B")

if os.isatty(0) and sys.stdout.isatty():
    # ANSI colors; see https://en.wikipedia.org/wiki/ANSI_escape_code
    RESET = "\x1b[0m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    BROWN = "\x1b[38;5;137m"
    BOLD = "\x1b[1m"
    INVERSE = "\x1b[7m"
    ORANGE = "\x1b[38;5;202m"
    REDISH = "\x1b[38;5;160m"
    YELLOW = "\x1b[38;5;178m"
    BLUE = "\x1b[38;5;33m"
    UNDERLINE = "\x1b[4m"
else:
    # ANSI colors not supported
    RESET = ""
    RED = ""
    GREEN = ""
    BROWN = ""
    BOLD = ""
    INVERSE = ""
    ORANGE = ""
    REDISH = ""
    YELLOW = ""
    BLUE = ""
    UNDERLINE = ""

def print_error(msg, fatal=True):
    """Error reporting and logging to "aristotle" logger.

    :param msg: error message
    :type msg: string, required
    :param fatal: also log to logging.critical and raise an Exception (or exit if running as a stand-alone script), defaults to `True`.
    :type fatal: boolean, optional
    :raises: `AristotleException`
    """
    aristotle_logger.error(INVERSE + RED + "ERROR:" + RESET + RED + " {}".format(msg) + RESET)
    if fatal:
        aristotle_logger.critical(RED + "Cannot continue" + RESET)
        if __name__== "__main__":
            sys.exit(1)
        else:
            raise AristotleException(msg)

def print_debug(msg):
    """logging.debug output to "aristotle" logger."""
    aristotle_logger.debug(INVERSE + BLUE + "DEBUG:" + RESET + BLUE + " {}".format(msg) + RESET)

def print_warning(msg):
    """logging.warning output to "aristotle" logger."""
    aristotle_logger.warning(INVERSE + YELLOW + "WARNING:" + RESET + YELLOW + " {}".format(msg) + RESET)

class Ruleset():
    """Class for ruleset data structures, filter string, and ruleset operations.

    :param rules: a string containing a ruleset or a filename of a ruleset file
    :type rules: string, required
    :param metadata_filter: A string or a filename of a file that defines the
        desired outcome based on
        Boolean logic, and uses the metadata key-value pairs as values in the
        Boolean algebra. Defaults to None (can be set later with ``set_metadata_filter()``).
    :type metadata_filter: string, optional
    :param include_disabled_rules: effectively enable all commented out rules when dealing with the ruleset, defaults to `False`
    :type include_disabled_rules: boolean
    :param summary_max: the maximum number of rules to print when outputting summary/truncated filtered ruleset, defaults to `16`.
    :type summary_max: int, optional
    :raises: `AristotleException`
    """
    def __init__(self, rules, metadata_filter=None, include_disabled_rules=False, summary_max=16):
        """Constructor."""

        # dict keys are sids
        self.metadata_dict = {}
        # dict keys are keys from metadata key-value pairs
        self.keys_dict = {'sid': {}}
        # dict keys are hash of key-value pairs from passed in filter string/file
        self.metadata_map = {}

        try:
            if os.path.isfile(rules):
                with open(rules, 'r') as fh:
                    self.rules = fh.read()
            else:
                if len(rules) < 256 and "metadata" not in rules:
                    # probably a mis-typed filename
                    print_error("'{}' is not a valid file and does not appear to be a string containing valid rule(s)".format(rules), fatal=True)
                self.rules = rules
        except Exception as e:
            print_error("Unable to process rules '{}':\n{}".format(rules, e), fatal=True)

        self.include_disabled_rules = include_disabled_rules

        if not metadata_filter:
            self.metadata_filter = None
            print_debug("No metadata_filter given to Ruleset() constructor")
        else:
            self.set_metadata_filter(metadata_filter)

        try:
            self.summary_max = int(summary_max)
        except Exception as e:
            print_error("Unable to process 'summary_max' value '{}' passed to Ruleset constructor:\n{}".format(summary_max, e))
        self.parse_rules()

    def set_metadata_filter(self, metadata_filter):
        """Sets the metadata filter to use.

        :param metadata_filter: A string or a filename of a file that defines the
            desired outcome based on
            Boolean logic, and uses the metadata key-value pairs as values in the
            Boolean algebra.
        :type metadata_filter: string, required
        :raises: `AristotleException`
        """
        try:
            if os.path.isfile(metadata_filter):
                print_debug("Loading metadata_filter file '{}'.".format(metadata_filter))
                self.metadata_filter = ""
                with open(metadata_filter, 'r') as fh:
                    for line in fh:
                        # check for "<enable-all-rules>" directive that enables all rules
                        if line.lstrip().lower().startswith("<enable-all-rules>"):
                            print_debug("Enabling all rules.")
                            self.include_disabled_rules = True
                            line = line[len("<enable-all-rules>"):].lstrip()
                        # strip out comments and ignore blank lines
                        if line.strip().startswith('#') or len(line.strip()) == 0:
                            continue
                        self.metadata_filter += line
            else:
                self.metadata_filter = metadata_filter
        except Exception as e:
            print_error("Unable to process metadata_filter '{}':\n{}".format(metadata_filter, e), fatal=True)


    def parse_rules(self):
        """Parses the ruleset and builds necessary data structures."""
        try:
            for lineno, line in enumerate(self.rules.splitlines()):
             # ignore comments and blank lines
                is_disabled_rule = False
                if len(line.strip()) == 0:
                    continue
                if line.lstrip().startswith('#'):
                    if disabled_rule_re.match(line):
                        is_disabled_rule = True
                    else:
                        # valid comment (not disabled rule)
                        print_debug("Skipping comment: {}".format(line))
                        continue

                # extract sid
                matchobj = sid_re.search(line)
                if not matchobj:
                    print_error("Invalid rule on line {}:\n{}".format(lineno, line), fatal=True)
                sid = int(matchobj.group("SID"))

                # extract metadata keyword value
                metadata_str = ""
                matchobj = metadata_keyword_re.search(line)
                if matchobj:
                    metadata_str = matchobj.group("METADATA")
                else:
                    print_warning("No 'metatdata' keyword found in sid {}".format(sid))
                if (lineno % 1000 == 0):
                    print_debug("metadata_str for sid {}:\n{}".format(sid, metadata_str))

                # build dict
                self.metadata_dict[sid] = {'metadata': {},
                                      'disabled': False,
                                      'default-disabled': False,
                                      'raw_rule': line
                                     }
                if is_disabled_rule:
                    self.metadata_dict[sid]['disabled'] = True
                    self.metadata_dict[sid]['default-disabled'] = True

                if len(metadata_str) > 0:
                    for kvpair in metadata_str.split(','):
                        # key-value pairs are case insensitive; make everything lower case
                        # also remove extra spaces before, after, and between key and value
                        kvsplit = [e.strip() for e in kvpair.lower().strip().split(' ', 1)]
                        if len(kvsplit) < 2:
                            # just a single word in metadata. warn and skip
                            print_warning("Single word metadata value found, ignoring '{}' in sid {}".format(kvpair, sid))
                            continue
                        k, v = kvsplit
                        if k == "sid" and int(v) != sid:
                            # this is in violation of the BETTER schema, throw warning
                            print_warning("line {}: 'sid' metadata key value '{}' does not match rule sid '{}'. This may lead to unexpected results".format(lineno, v, sid))
                        # populate metadata_dict
                        if k not in self.metadata_dict[sid]['metadata'].keys():
                            self.metadata_dict[sid]['metadata'][k] = []
                        self.metadata_dict[sid]['metadata'][k].append(v)
                        # populate keys_dict
                        if k not in self.keys_dict.keys():
                            self.keys_dict[k] = {}
                        if v not in self.keys_dict[k].keys():
                            self.keys_dict[k][v] = []
                        self.keys_dict[k][v].append(sid)
                # add sid as pseudo metadata key unless it already exist
                if 'sid' not in self.metadata_dict[sid]['metadata'].keys():
                    # keys and values are strings; variable "sid" is int so must
                    # be cast as str when used the same way other keys and values are used.
                    self.metadata_dict[sid]['metadata']['sid'] = [str(sid)]
                    self.keys_dict['sid'][str(sid)] = [sid]

        except Exception as e:
            print_error("Problem loading rules: {}".format(e), fatal=True)

    def cve_compare(self, left_val, right_val, cmp_operator):
        """Compare CVE values given comparison operator.

        May have unexpected results if CVE values (left_val, right_val) not formatted as CVE numbers.
        Returns boolean.
        """
        try:
            if '-' not in left_val:
                lyear = int(left_val)
                if cmp_operator[0] == '<':
                    if len(cmp_operator) > 1 and cmp_operator[1] == '=':
                        lseq = float('-inf')
                    else:
                        lseq = float('inf')
                else:
                    if len(cmp_operator) > 1 and cmp_operator[1] == '=':
                        lseq = float('inf')
                    else:
                        lseq = float('-inf')
            else:
                lyear, lseq = [int(v) for v in left_val.split('-', 1)]
            if '-' not in right_val:
                ryear = int(right_val)
                if cmp_operator[0] == '<':
                    if len(cmp_operator) > 1 and cmp_operator[1] == '=':
                        rseq = float('inf')
                    else:
                        rseq = float('-inf')
                else:
                    if len(cmp_operator) > 1 and cmp_operator[1] == '=':
                        rseq = float('-inf')
                    else:
                        rseq = float('inf')
            else:
                ryear, rseq = [int(v) for v in right_val.split('-', 1)]
            if len(cmp_operator) > 1 and cmp_operator[1] == '=':
                if cmp_operator[0] == '<':
                    rseq += 1
                else:
                    lseq += 1
            if cmp_operator[0] == '<':
                if lyear == ryear:
                    return lseq < rseq
                else:
                    return lyear < ryear
            if cmp_operator[0] == '>':
                if lyear == ryear:
                    return lseq > rseq
                else:
                    return lyear > ryear
            return False
        except Exception as e:
            print_error("Unable to do CVE comparison '{} {} {}':\n{}".format(left_val, cmp_operator, right_val, e), fatal=True)

    def get_all_sids(self):
        """Returns a list of all enabled SIDs.

        .. note::
            If ``self.include_disabled_rules`` is True, then
            all SIDs are returned.

        :returns: list of all enabled SIDs.
        :rtype: list
        """
        return [s for s in self.metadata_dict.keys() if (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]

    def get_sids(self, kvpair, negate=False):
        """Get a list of all SIDs for passed in key-value pair.

        :param kvpair: key-value pair
        :type kvpair: string, required
        :param negate: returns the inverse of the result (i.e. all SIDs not matching the ``kvpair``), defaults to `False`
        :type negate: boolean, optional
        :returns: list of matching SIDs
        :rtype: list
        :raises: `AristotleException`
        """
        k, v = [e.strip() for e in kvpair.split(' ', 1)]
        retarray = []
        # these keys support '>', '<', '>=', and '<='
        rangekeys = ['sid',
                     'cve',
                     'cvss_v2_base',
                     'cvss_v2_temporal',
                     'cvss_v3_base',
                     'cvss_v3_temporal',
                     'created_at',
                     'updated_at']
        if k in rangekeys and (v.startswith('<') or v.startswith('>')) and v not in ["<all>", "<any>"]:
            if len(v) < 2:
                print_error("Invalid value '{}' for key '{}'.".format(v, k), fatal=True)
            if k == "cve":
                # handle cve ranges; format is YYYY-<sequence_number>
                try:
                    offset = 1
                    if v[1] == '=':
                        offset += 1
                    cmp_operator = v[:offset]
                    cve_val = v[offset:].strip()
                    print_debug("cmp_operator: {}, cve_val: {}".format(cmp_operator, cve_val))
                    retarray = [s for s in [s2 for s2 in self.metadata_dict.keys() if k in self.metadata_dict[s2]["metadata"].keys()] \
                                  for val in self.metadata_dict[s]["metadata"][k] \
                                    if self.cve_compare(left_val=val, right_val=cve_val, cmp_operator=cmp_operator) and \
                                    (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
                except Exception as e:
                    print_error("Unable to process key '{}' value '{}' (as CVE number):\n{}".format(k, v, e), fatal=True)
            elif k in ["created_at", "updated_at"]:
                # parse/treat as datetime objects
                try:
                    lbound = datetime.datetime.min
                    ubound = datetime.datetime.max
                    offset = 1
                    if v.startswith('<'):
                        if v[offset] == '=':
                            offset += 1
                        ubound = dateparse(v[offset:].strip())
                        ubound += datetime.timedelta(microseconds=(offset - 1))
                    else: # v.startswith('>'):
                        if v[offset] == '=':
                            offset += 1
                        lbound = dateparse(v[offset:].strip())
                        lbound -= datetime.timedelta(microseconds=(offset - 1))
                    print_debug("lbound: {}\nubound: {}".format(lbound, ubound))
                    retarray = [s for s in [s2 for s2 in self.metadata_dict.keys() if k in self.metadata_dict[s2]["metadata"].keys()] \
                                  for val in self.metadata_dict[s]["metadata"][k] \
                                    if (dateparse(val) < ubound and dateparse(val) > lbound) and \
                                    (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
                except Exception as e:
                    print_error("Unable to process '{}' value '{}' (as datetime):\n{}".format(k, v, e), fatal=True)
            else:
                # handle everything else as a float
                try:
                    lbound = float('-inf')
                    ubound = float('inf')
                    offset = 1
                    if v.startswith('<'):
                        if v[offset] == '=':
                            offset += 1
                        ubound = float(v[offset:].strip())
                        ubound += (float(offset) - 1.0)
                    else: # v.startswith('>'):
                        if v[offset] == '=':
                            offset += 1
                        lbound = float(v[offset:].strip())
                        lbound -= (float(offset) - 1.0)
                    print_debug("lbound: {}\nubound: {}".format(lbound, ubound))
                    retarray = [s for s in [s2 for s2 in self.metadata_dict.keys() if k in self.metadata_dict[s2]["metadata"].keys()] \
                                  for val in self.metadata_dict[s]["metadata"][k] \
                                    if (float(val) < float(ubound) and float(val) > float(lbound)) and \
                                    (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
                except Exception as e:
                    print_error("Unable to process '{}' value '{}' (as float):\n{}".format(k, v, e), fatal=True)
        else:
            if k not in self.keys_dict.keys():
                print_warning("metadata key '{}' not found in ruleset".format(k))
            else:
                # special keyword '<all>' means all values for that key
                if v in ["<all>", "<any>"]:
                    retarray = [s for val in self.keys_dict[k].keys() for s in self.keys_dict[k][val] if (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
                elif v not in self.keys_dict[k]:
                    print_warning("metadata key-value pair '{}' not found in ruleset".format(kvpair))
                    # retarray should stil be empty but in case not:
                    retarray = []
                else:
                    retarray = [s for s in self.keys_dict[k][v] if (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
        if negate:
            # if key or value not found, this will be all rules
            retarray = list(frozenset(self.get_all_sids()) - frozenset(retarray))
        return list(set(retarray))

    def evaluate(self, myobj):
        """Recursive evaluation function that deals with BooleanAlgebra elements from boolean.py."""
        if myobj.isliteral:
            if isinstance(myobj, boolean.boolean.NOT):
                return self.get_sids(self.metadata_map[myobj.args[0].obj], negate=True)
            else:
                return self.get_sids(self.metadata_map[myobj.obj])
        elif isinstance(myobj, boolean.boolean.OR):
            retlist = []
            for i in range(0, len(myobj.args)):
                retlist = list(set(retlist + self.evaluate(myobj.args[i])))
            return retlist
        elif isinstance(myobj, boolean.boolean.AND):
            retlist = list(frozenset(self.evaluate(myobj.args[0])))
            for i in range(1, len(myobj.args)):
                retlist = list(frozenset(retlist).intersection(self.evaluate(myobj.args[i])))
            return retlist
        # not reached
        return None

    def filter_ruleset(self, metadata_filter=None):
        """Applies boolean filter against the ruleset and returns list of matching SIDs.

        :param metadata_filter: A string that defines the desired outcome based on
            Boolean logic, and uses the metadata key-value pairs as values in the
            Boolean algebra. Defaults to ``self.metadata_filter`` which must be set
            if this parameter is not set.
        :type metadata_filter: string, optional
        :returns: list of matching SIDs
        :rtype: list
        :raises: `AristotleException`
        """
        if not metadata_filter:
            metadata_filter = self.metadata_filter
        if metadata_filter is None:
            print_error("No metadata_filter set or passed to filter_ruleset()", fatal=True)
        metadata_filter_original = metadata_filter
        # the boolean.py library uses tokenize which isn't designed to
        # handle multi-word tokens (and doesn't support quoting). So
        # just replace and map to single word. This way we can still
        # leverage boolean.py to do simplifying and building of the tree.
        mytokens = re.findall(r'\x22[a-zA-Z0-9_]+[^\x22]+\x22', metadata_filter, re.DOTALL)
        if not mytokens or len(mytokens) == 0:
            # nothing to filter on so exit
            print_error("metadata_filter string contains no tokens", fatal=True)
        for t in mytokens:
            # key-value pairs are case insensitive; make everything lower case
            tstrip = t.strip('"').lower()
            # also remove extra spaces before, after, and between key and value
            tstrip = ' '.join([e.strip() for e in tstrip.strip().split(' ', 1)])
            print_debug(tstrip)
            if len(tstrip.split(' ')) == 1:
                # if just key provided (no value), match on all values
                tstrip = "{} <all>".format(tstrip)
            # if token begins with digit, the tokenizer doesn't like it
            hashstr = "D" + hashlib.md5(tstrip.encode()).hexdigest()
            # add to mapp dict
            self.metadata_map[hashstr] = tstrip
            # replace in filter str
            metadata_filter = metadata_filter.replace(t, hashstr)

        print_debug("{}".format(metadata_filter_original))
        print_debug("\t{}".format(metadata_filter))
        try:
            algebra = boolean.BooleanAlgebra()
            mytree = algebra.parse(metadata_filter).literalize().simplify()
            return self.evaluate(mytree)
        except Exception as e:
            print_error("Problem processing metadata_filter string:\n\n{}\n\nError:\n{}".format(metadata_filter_original, e), fatal=True)

    def print_header(self):
        """Prints vanity header and global stats."""
        total = len(self.metadata_dict)
        enabled = len([sid for sid in self.metadata_dict.keys() \
                    if not self.metadata_dict[sid]['disabled']])
        disabled = total - enabled
        print("\n" + INVERSE + BROWN + "       Aristotle       " + \
              RESET + BROWN + \
              "\n Ruleset Metadata Tool " + RESET + "\n")
        print(UNDERLINE + BOLD + GREEN + "All Rules:" + \
              RESET + GREEN + \
              " Total: {}; Enabled: {}; Disabled: {}".format(total, enabled, disabled) + \
              RESET + "\n")

    def get_stats(self, key, keyonly=False):
        """Returns string of statistics (total, enabled, disabled) for specified key and its values.

        :param key: key to print statistics for
        :type key: string, required
        :param keyonly: only print stats for the key itself and not stats for all possible key-value pairs, defaults to `False`
        :type keyonly: boolean, optional
        :returns: string contaning stats, suitable for printing to stdout
        :rtype: string
        :raises: `AristotleException`
        """
        retstr = ""
        if key not in self.keys_dict.keys():
            print_warning("key '{}' not found".format(key))
            return
        total = len([sid for sid in self.metadata_dict.keys() \
                     if key in self.metadata_dict[sid]['metadata'].keys()])
        enabled = len([sid for sid in self.metadata_dict.keys() \
                     if key in self.metadata_dict[sid]['metadata'].keys() \
                     and not self.metadata_dict[sid]['disabled']])
        disabled = total - enabled
        retstr += "{} (Total: {}; Enabled: {}; Disabled: {})\n".format(REDISH + UNDERLINE + BOLD + key + RESET, total, enabled, disabled)

        if not keyonly:
            for value in self.keys_dict[key].keys():
                total = len(self.keys_dict[key][value])
                enabled = len([sid for sid in self.keys_dict[key][value] if not self.metadata_dict[sid]['disabled']])
                disabled = total - enabled
                retstr += "\t{} (Total: {}; Enabled: {}; Disabled: {})\n".format(ORANGE + value + RESET, total, enabled, disabled)
            retstr += "\n"
        return retstr

    def print_stats(self, key, keyonly=False):
        """Print statistics (total, enabled, disabled) for specified key and its values.

        :param key: key to print statistics for
        :type key: string, required
        :param keyonly: only print stats for the key itself and not stats for all possible key-value pairs, defaults to `False`
        :type keyonly: boolean, optional
        """
        stats_str = self.get_stats(key=key, keyonly=keyonly)
        if stats_str[-1] == '\n':
            stats_str = stats_str[:-1]
        print("{}".format(stats_str))

    def print_ruleset_summary(self, sids):
        """Prints summary/truncated filtered ruleset to stdout.

        :param sids: list of SIDs.
        :type sids: list, required
        :raises: `AristotleException`
        """
        print_debug("print_ruleset_summary() called")
        print("")
        i = 0
        while i < len(sids):
            if i < self.summary_max:
                matchobj = rule_msg_re.search(self.metadata_dict[sids[i]]['raw_rule'])
                if not matchobj:
                    print_warning("Unable to extract rule msg from '{}'.".format(self.metadata_dict[sids[i]]['raw_rule']))
                    continue
                msg = matchobj.group("MSG")
                print("{} [sid:{}]".format(msg, sids[i]))
            else:
                break
            i += 1
        print("\n" + BLUE + "Showing {} of {} rules".format(i, len(sids)) + RESET + "\n")

    def output_rules(self, sid_list, outfile=None):
        """Output rules, given a list of SIDs.

        :param sid_list: list of SIDs of the rules to output
        :type sid_list: list, required
        :param outfile: filename to output to; if None, output to stdout; defaults to `None`
        :type outfile: string or None, optional
        :returns: None
        :rtype: NoneType
        :raises: `AristotleException`
        """
        # TODO: handle order because of/based on flowbits? Ideally IDS engine should handle...
        #       see https://redmine.openinfosecfoundation.org/issues/1399
        if outfile is None:
            for s in sid_list:
                print("{}".format(self.metadata_dict[s]['raw_rule']))
        else:
            try:
                with open(outfile, "w") as fh:
                    for s in sid_list:
                        fh.write("{}\n".format(self.metadata_dict[s]['raw_rule']))
            except Exception as e:
                print_error("Problem writing to file '{}':\n{}".format(outfile, e), fatal=True)
            print(GREEN + "Wrote {} rules to file, '{}'".format(len(sid_list), outfile) + RESET + "\n")

def get_parser():
    """return parser for command line args"""
    try:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="Filter Suricata and Snort rulesets based on metadata keyword values.",
            epilog="""A filter string defines the desired outcome based on Boolean logic, and uses
the metadata key-value pairs as values in a (concrete) Boolean algebra.
The key-value pair specifications must be surrounded by double quotes.
Example:

python3 aristotle.py -r examples/example.rules --summary -f '(("priority high"
AND "malware <ALL>") AND "created_at > 2018-01-01") AND NOT ("protocols smtp"
AND "protocols pop" AND "protocols imap") OR "sid 80181444"'

"""
            )
        parser.add_argument("-r", "--rules", "--ruleset",
                            action="store",
                            dest="rules",
                            required=True,
                            help="path to rules file or string containing the ruleset")
        parser.add_argument("-f", "--filter",
                            action="store",
                            dest="metadata_filter",
                            required=False,
                            default = None,
                            help="Boolean filter string or path to a file containing it")
        parser.add_argument("--summary",
                            action="store_true",
                            dest="summary_ruleset",
                            required=False,
                            default = False,
                            help="output a summary of the filtered ruleset to stdout; \
                                  if an output file is given, the full, filtered ruleset \
                                  will still be written to it.")
        parser.add_argument("-o", "--output",
                            action="store",
                            dest="outfile",
                            required=False,
                            default="<stdout>",
                            help="output file to write filtered ruleset to")
        parser.add_argument("-s", "--stats",
                            nargs='*',
                            action="store",
                            dest="stats",
                            required=False,
                            default=None,
                            help="display ruleset statistics about specified key(s). \
                                  If no key(s) supplied, then summary statistics for \
                                  all keys will be displayed.")
        parser.add_argument("-i", "--include-disabled",
                            action="store_true",
                            dest="include_disabled_rules",
                            required=False,
                            default=False,
                            help="include (effectively enable) disabled rules when applying the filter")
        parser.add_argument("-q", "--quiet", "--suppress_warnings",
                            action="store_true",
                            dest="suppress_warnings",
                            default=False,
                            required=False,
                            help="quiet; suppress warning logging")
        parser.add_argument("-d", "--debug",
                            action="store_true",
                            dest="debug",
                            default=False,
                            required=False,
                            help="turn on debug logging")
        return parser
    except Exception as e:
        print_error("Problem parsing command line args: {}".format(e), fatal=True)


def main():
    """Main method, called if run as script."""
    global aristotle_logger

    # program is run not as library so add logging to console
    aristotle_logger.addHandler(logging.StreamHandler())

    # get command line args
    try:
        parser = get_parser()
        args = parser.parse_args()
    except Exception as e:
        print_error("Problem parsing command line args: {}".format(e), fatal=True)



    if args.debug:
        aristotle_logger.setLevel(logging.DEBUG)
    elif args.suppress_warnings:
        aristotle_logger.setLevel(logging.ERROR)
    else:
        aristotle_logger.setLevel(logging.INFO)

    if args.stats is None and args.metadata_filter is None:
        print_error("'metadata_filter' or 'stats' option required. Neither provided.", fatal=True)

    if args.stats is not None:
        keys = []
        keyonly = False
        rs = Ruleset(rules=args.rules)
        rs.print_header()
        if len(args.stats) > 0:
            # print stats for specified key(s)
            keys = args.stats
        else:
            # print stats for ALL keys
            keys = rs.keys_dict.keys()
            keyonly = True

        for key in keys:
            rs.print_stats(key=key, keyonly=keyonly)

        print("")
        sys.exit(0)

    # create object
    rs = Ruleset(rules=args.rules, metadata_filter=args.metadata_filter,
                 include_disabled_rules=args.include_disabled_rules)

    filtered_sids = rs.filter_ruleset()

    print_debug("filtered_sids: {}".format(filtered_sids))

    if args.outfile == "<stdout>":
        if args.summary_ruleset:
            rs.print_ruleset_summary(filtered_sids)
        else:
            rs.output_rules(sid_list=filtered_sids, outfile=None)
    else:
        if args.summary_ruleset:
            rs.print_ruleset_summary(filtered_sids)
        rs.output_rules(sid_list=filtered_sids, outfile=args.outfile)

if __name__== "__main__":
    main()

