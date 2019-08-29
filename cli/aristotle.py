#!/usr/bin/env python
"""
Aristotle CLI - command line tool for slicing-and-dicing
Suricata and Snort rulesets based on metadata keyword values.
"""
# Copyright 2019 Secureworks
#
# Licensed under (TBD)
#
# TODO: stats
#       flowbits?
#       use objects; make importable/lib
#       command line option to enable disabled rules when evaluating?
#       log file?

import argparse
import boolean
import hashlib
import os
import re
import sys

DEBUG = False

disabled_rule_re = re.compile(r"^\x23(?:pass|drop|reject|alert|sdrop|log)\x20.*[\x28\x3B]\s*sid\s*\x3A\s*\d+\s*\x3B")
sid_re = re.compile(r"[\x28\x3B]\s*sid\s*\x3A\s*(?P<SID>\d+)\s*\x3B")
metadata_keyword_re = re.compile(r"[\x28\x3B]\s*metadata\s*\x3A\s*(?P<METADATA>[^\x3B]+)\x3B")

def print_error(msg, fatal=True):
    print("ERROR: %s" % msg)
    if fatal:
        print("Cannot continue")
        sys.exit(1)

def print_debug(msg):
    if msg and DEBUG:
        print("DEBUG: %s" % msg)

def print_warning(msg):
    if not suppress_warnings and msg:
        print("WARNING: %s" % msg)

class Ruleset():
    global DEBUG

    metadata_dict = {}
    keys_dict = {}
    metadata_map = {}

    def __init__(self, rules, filter, outfile=None, debug=False, suppress_warnings=False, include_disabled_rules=False):
        DEBUG = debug
        # TODO: add try/catch here? we are going to fatal error out either way
        if os.path.isfile(rules):
            with open(rules, 'r') as fh:
                self.rules = fh.read()
        else:
            self.rules = rules

        if os.path.isfile(filter):
            with open(filter, 'r') as fh:
                self.filter = fh.read()
        else:
            self.filter = filter

        self.outfile = outfile
        self.suppress_warnings = suppress_warnings
        self.outfile = outfile
        self.include_disabled_rules = include_disabled_rules

        self.parse_rules()

    def parse_rules(self):
        lineno = 1
        try:
            for line in self.rules.splitlines():
             # ignore comments and blank lines
                if len(line.strip()) == 0:
                    continue
                if line.lstrip().startswith('#'):
                    if not disabled_rule_re.match(line):
                        # valid comment (not disabled rule)
                        print_debug("Skipping comment: %s" % line)
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
                if (DEBUG and (lineno % 1000 == 0)):
                    print_debug("metadata_str for sid %d:\n%s" % (sid, metadata_str))

                # build dict
                self.metadata_dict[sid] = {'metadata': {},
                                      'disabled': False,
                                      'default-disabled': False
                                     }
                if line.startswith('#'):
                    self.metadata_dict[sid]['disabled'] = True
                    self.metadata_dict[sid]['default-disabled'] = True

                for kvpair in metadata_str.split(','):
                    kvsplit = kvpair.strip().split(' ', 1)
                    if len(kvsplit) < 2:
                        # just a single word in metadata; warning? skip?
                        print_warning("Single word metatdata value found: %s" % kvsplit)
                        continue
                    k, v = kvsplit
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

                lineno += 1
            #print_debug("metadata_dict:\n%s" % metadata_dict)
            #print_debug("keys_dict:\n%s" % keys_dict)

        except Exception as e:
            print_error("Problem loading rules: %s" % (e), fatal=True)

    def get_all_sids(self):
        return [s for s in self.metadata_dict.keys() if (not self.metadata_dict[s]['disabled'] or self.include_disabled_rules)]

    def get_sids(self, kvpair, negate=False):
        # TODO: handle key ALL situation
        # TODO: support date ranges for created_at and updated_at
        k, v = kvpair.split(' ', 1)
        retarray = []
        if k not in self.keys_dict.keys():
            print_warning("metadata key '%s' not found in ruleset" % k)
        else:
            if v not in self.keys_dict[k]:
                print_warning("metadata key-value pair '%s' not found in ruleset" % kvpair)
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
        # handle multiline tokens (and doesn't support quoting). So
        # just replace and map to single word. This way we can still
        # leverage boolean.py to do simplifying building the tree.
        mytokens = re.findall(r'\x22[a-zA-Z0-9_]+\s[^\x22]+\x22', filter, re.DOTALL)
        if not mytokens or len(mytokens) == 0:
            # nothing to filter on ... why go on living?
            print_error("filter string contains no tokens", fatal=True)
        for t in mytokens:
            tstrip = t.strip('"')
            print_debug(tstrip)
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

def main():
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

    # create object
    rs = Ruleset(rules=args.rules, filter=args.filter,
                 outfile=args.outfile, debug=args.debug,
                 suppress_warnings=args.suppress_warnings,
                 include_disabled_rules=args.include_disabled_rules)


    results = rs.filter_ruleset()

    print(results)
    print("Total: %d" % len(results))

if __name__== "__main__":
    main()

