#!/usr/bin/env python
"""
Aristotle CLI - command line tool for slicing-and-dicing
Suricata and Snort rulesets based on metadata keyword values.
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

#
# TODO: stats
#       flowbits?
#       use objects; make importable/lib
#       command line option to enable disabled rules when evaluating?

import argparse
import boolean
import datetime
from dateutil.parser import parse as dateparse
import hashlib
import logging
import os
import re
import sys

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
    aristotle_logger.error(INVERSE + RED + "ERROR:" + RESET + RED + " %s" % msg + RESET)
    if fatal:
        aristotle_logger.critical(RED + "Cannot continue" + RESET)
        sys.exit(1)

def print_debug(msg):
    aristotle_logger.debug(INVERSE + BLUE + "DEBUG:" + RESET + BLUE + " %s" % msg + RESET)

def print_warning(msg):
    aristotle_logger.warning(INVERSE + YELLOW + "WARNING:" + RESET + YELLOW + " %s" % msg + RESET)

class Ruleset():
    # TODO: use a Rule class instead of dicts?
    # dict keys are sids
    metadata_dict = {}
    # dict keys are keys from metadata key-value pairs
    keys_dict = {'sid': {}}
    # dict keys are hash of key-value pairs from passed in filter string/file
    metadata_map = {}

    def __init__(self, rules, filter="", outfile=None, include_disabled_rules=False):
        try:
            if os.path.isfile(rules):
                with open(rules, 'r') as fh:
                    self.rules = fh.read()
            else:
                self.rules = rules
        except Exception as e:
            print_error("Unable to process rules '%s':\n%s" % (rules, e), fatal=True)

        try:
            if os.path.isfile(filter):
                with open(filter, 'r') as fh:
                    self.filter = fh.read()
            else:
                self.filter = filter
        except Exception as e:
            print_error("Unable to process filter '%s':\n%s" % (filter, e), fatal=True)

        self.outfile = outfile
        self.include_disabled_rules = include_disabled_rules

        self.parse_rules()

    def parse_rules(self):
        lineno = 1
        try:
            for line in self.rules.splitlines():
             # ignore comments and blank lines
                is_disabled_rule = False
                if len(line.strip()) == 0:
                    lineno += 1
                    continue
                if line.lstrip().startswith('#'):
                    if disabled_rule_re.match(line):
                        is_disabled_rule = True
                    else:
                        # valid comment (not disabled rule)
                        print_debug("Skipping comment: %s" % line)
                        lineno += 1
                        continue

                # extract sid
                matchobj = sid_re.search(line)
                if not matchobj:
                    print_error("Invalid rule on line %d:\n%s" % (lineno, line), fatal=True)
                sid = int(matchobj.group("SID"))

                # extract metadata keyword value
                metadata_str = ""
                matchobj = metadata_keyword_re.search(line)
                if matchobj:
                    metadata_str = matchobj.group("METADATA")
                if (lineno % 1000 == 0):
                    print_debug("metadata_str for sid %d:\n%s" % (sid, metadata_str))

                # build dict
                self.metadata_dict[sid] = {'metadata': {},
                                      'disabled': False,
                                      'default-disabled': False
                                     }
                if is_disabled_rule:
                    self.metadata_dict[sid]['disabled'] = True
                    self.metadata_dict[sid]['default-disabled'] = True

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
                        # this is in violation of the schema, should we error and die?
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
                    self.metadata_dict[sid]['metadata']['sid'] = [sid]
                    self.keys_dict['sid'][sid] = [sid]
                lineno += 1
            print_debug("metadata_dict:\n%s" % self.metadata_dict)
            print_debug("keys_dict:\n%s" % self.keys_dict)

        except Exception as e:
            print_error("Problem loading rules: %s" % (e), fatal=True)

    def get_all_sids(self):
        return [s for s in self.metadata_dict.keys() if (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]

    def get_sids(self, kvpair, negate=False):
        k, v = kvpair.split(' ', 1)
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
        if k in rangekeys and (v.startswith('<') or v.startswith('>')) and v != "<all>":

            if k == "cve":
                # TODO: handle cve; format is YYYY-<sequence_number>
                pass
            elif k in ["created_at", "updated_at"]:
                # parse/treat as datetime objects
                try:
                    lbound = datetime.datetime.min
                    ubound = datetime.datetime.max
                    offset = 1
                    if v.startswith('<'):
                        if v[offset] == '=':
                            offset += 1
                        ubound = dateparse(v[offset:])
                        ubound += datetime.timedelta(days=(offset - 1))
                    else: # v.startswith('>'):
                        if v[offset] == '=':
                            offset += 1
                        lbound = dateparse(v[offset:])
                        lbound -= datetime.timedelta(days=(offset - 1))
                    print_debug("lbound: {}\nubound: {}".format(lbound, ubound))
                    retarray = [s for s in self.metadata_dict.keys() \
                                  for val in self.metadata_dict[s]["metadata"][k]
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
                        ubound = float(v[offset:])
                        ubound += (float(offset) - 1.0)
                    else: # v.startswith('>'):
                        if v[offset] == '=':
                            offset += 1
                        lbound = float(v[offset:])
                        lbound -= (float(offset) - 1.0)
                    print_debug("lbound: {}\nubound: {}".format(lbound, ubound))
                    retarray = [s for s in self.metadata_dict.keys() \
                                  for val in self.metadata_dict[s]["metadata"][k]
                                    if (float(val) < float(ubound) and float(val) > float(lbound)) and \
                                    (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
                except Exception as e:
                    print_error("Unable to process '{}' value '{}' (as float):\n{}".format(k, v, e), fatal=True)
        else:
            if k not in self.keys_dict.keys():
                print_warning("metadata key '{}' not found in ruleset".format(k))
            else:
                # special keyword '<all>' means all values for that key
                if v == "<all>":
                    retarray = [s for val in self.keys_dict[k].keys() for s in self.keys_dict[k][val] if (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
                elif v not in self.keys_dict[k]:
                    print_warning("metadata key-value pair '{}' not found in ruleset".format(kvpair))
                else:
                    retarray = [s for s in self.keys_dict[k][v] if (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]
        if negate:
            # if key or value not found, this will be all rules
            retarray = list(frozenset(self.get_all_sids()) - frozenset(retarray))
        return retarray

    def evaluate(self, myobj):
        if myobj.isliteral:
            #TODO: deal with "sid nnnn"
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

    # process boolean string
    def filter_ruleset(self, filter=None):
        if not filter:
            filter = self.filter
        # the boolean.py library uses tokenize which isn't designed to
        # handle multi-word tokens (and doesn't support quoting). So
        # just replace and map to single word. This way we can still
        # leverage boolean.py to do simplifying and building of the tree.
        mytokens = re.findall(r'\x22[a-zA-Z0-9_]+[^\x22]+\x22', filter, re.DOTALL)
        if not mytokens or len(mytokens) == 0:
            # nothing to filter on so exit
            print_error("filter string contains no tokens", fatal=True)
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
            filter = filter.replace(t, hashstr)

        print_debug(filter)
        try:
            algebra = boolean.BooleanAlgebra()
            mytree = algebra.parse(filter).literalize().simplify()
            return self.evaluate(mytree)

        except Exception as e:
            print_error("Problem processing filter string:\n\n%s\n\nError:\n%s" % (filter, e), fatal=True)

    def print_header(self):
        """ prints vanity header and global stats """
        total = len(self.metadata_dict)
        enabled = len([sid for sid in self.metadata_dict.keys() \
                    if not self.metadata_dict[sid]['disabled']])
        disabled = total - enabled
        print("\n" + INVERSE + BROWN + "       Aristotle       " + \
              RESET + BROWN + \
              "\n Ruleset Metadata Tool " + RESET + "\n")
        print(UNDERLINE + BOLD + GREEN + "All Rules:" + \
              RESET + GREEN + \
              " Total: %d; Enabled: %d; Disabled: %d" % (total, enabled, disabled) + \
              RESET + "\n")

    def print_stats(self, key, keyonly=False):
        """ prints stats (total, enabled, disabled) for specified
            key and values.
        """
        if key not in self.keys_dict.keys():
            print_warning("key '%s' not found" % key)
            return
        total = len([sid for sid in self.metadata_dict.keys() \
                     if key in self.metadata_dict[sid]['metadata'].keys()])
        enabled = len([sid for sid in self.metadata_dict.keys() \
                     if key in self.metadata_dict[sid]['metadata'].keys() \
                     and not self.metadata_dict[sid]['disabled']])
        disabled = total - enabled
        print("%s (Total: %d; Enabled: %d; Disabled: %d)" % (REDISH + UNDERLINE + BOLD + key + RESET, total, enabled, disabled))

        if not keyonly:
            for value in self.keys_dict[key].keys():
                total = len(self.keys_dict[key][value])
                enabled = len([sid for sid in self.keys_dict[key][value] if not self.metadata_dict[sid]['disabled']])
                disabled = total - enabled
                print("\t%s (Total: %d; Enabled: %d; Disabled: %d)" % (ORANGE + value + RESET, total, enabled, disabled))
            print("")

def main():
    global aristotle_logger

    # program is run not as library so add logging to console
    aristotle_logger.addHandler(logging.StreamHandler())

    # process command line args
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--rules", "--ruleset",
                            action="store",
                            dest="rules",
                            required=True,
                            help="path to rules file")
        parser.add_argument("-f", "--filter",
                            action="store",
                            dest="filter",
                            required=False,
                            default = None,
                            help="boolean filter string or file containing it")
        parser.add_argument("-o", "--output",
                            action="store",
                            dest="outfile",
                            required=False,
                            default="<stdout>",
                            help="output file")
        parser.add_argument("-s", "--stats",
                            nargs='*',
                            action="store",
                            dest="stats",
                            required=False,
                            default=None,
                            help="display ruleset statistics about specified key(s)")
        parser.add_argument("-i", "--include-disabled",
                            action="store",
                            dest="include_disabled_rules",
                            required=False,
                            default=False,
                            help="include disabled rules when applying the filter")
        parser.add_argument("-q", "--quiet", "--suppress_warnings",
                            action="store_true",
                            dest="suppress_warnings",
                            default=False,
                            required=False,
                            help="quiet; suppress warning messages")
        parser.add_argument("-d", "--debug",
                            action="store_true",
                            dest="debug",
                            default=False,
                            required=False,
                            help="turn on debug output")
        args = parser.parse_args()
    except Exception as e:
        print_error("Problem parsing command line args: %s" % (e), fatal=True)


    if args.debug:
        aristotle_logger.setLevel(logging.DEBUG)
    elif args.suppress_warnings:
        aristotle_logger.setLevel(logging.ERROR)
    else:
        aristotle_logger.setLevel(logging.INFO)

    if args.stats is None and args.filter is None:
        print_error("'filter' or 'stats' option required. Neither is defined.", fatal=True)

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
    rs = Ruleset(rules=args.rules, filter=args.filter,
                 outfile=args.outfile,
                 include_disabled_rules=args.include_disabled_rules)


    results = rs.filter_ruleset()

    # for now, just print list of matching sids
    print(results)
    print("Total: %d" % len(results))

if __name__== "__main__":
    main()

