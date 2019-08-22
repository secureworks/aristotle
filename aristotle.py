#!/usr/bin/env python3
"""
Aristotle CLI - command line tool for slicing-and-dicing
Suricata and Snort rulesets based on metadata keyword values.
"""
# Copyright 2019 Secureworks
#
# Licensed under (TBD)

import argparse
import os
import re
import sys

DEBUG = True

def print_error(msg, fatal=False):
    print("ERROR: %s" % msg)
    if fatal:
        print("Cannot continue")
        sys.exit(1)

def print_debug(msg):
    if msg and DEBUG:
        print("DEBUG: %s" % msg)

def print_warning(msg):
    if msg:
        print("WARNING: %s" % msg)

parser = argparse.ArgumentParser()

parser.add_argument("-r", "--rules", "--ruleset",
                    action="store",
                    dest="ruleset_file",
                    required=True,
                    help="path to rules file")

args = parser.parse_args()

if not os.path.isfile(args.ruleset_file):
    print_error("Provided ruleset file does not exist: '%s'" % args.ruleset_file, fatal=True)

metadata_dict = {}

disabled_rule_re = re.compile(r"^\x23(?:pass|drop|reject|alert|sdrop|log)\x20.*[\x28\s\x3B]sid\s*\x3A\s*\d+\s*\x3B")
sid_re = re.compile(r"[\x28\s\x3B]sid\s*\x3A\s*(?P<SID>\d+)\s*\x3B")
metadata_keyword_re = re.compile(r"[\x28\s\x3B]metadata\s*\x3A\s*(?P<METADATA>[^\x3B]+)\x3B")

try:
    with open(args.ruleset_file, 'r') as ruleset_fh:
        lineno = 1
        for line in ruleset_fh:
            # ignore comments and blank lines
            if len(line.strip()) == 0:
                continue
            if line.lstrip().startswith('#'):
                if not disabled_rule_re.match(line):
                    # valid comment (not disabled rule)
                    print_debug("Skipping comment")
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
            if (lineno % 1000) == 0:
                print_debug("%s" % metadata_str)

            # build dict
            metadata_dict[sid] = {'metadata': {},
                                  'disabled': False,
                                  'default-disabled': False
                                 }
            if line.startswith('#'):
                metadata_dict[sid]['disabled'] = True
                metadata_dict[sid]['default-disabled'] = True

            for kvpair in metadata_str.split(','):
                kvsplit = kvpair.strip().split(' ', 1)
                if len(kvsplit) < 2:
                    # just a single word in metadata; skip?
                    continue
                k, v = kvpair.strip().split(' ', 1)
                if k not in metadata_dict[sid]['metadata'].keys():
                    metadata_dict[sid]['metadata'][k] = []
                metadata_dict[sid]['metadata'][k].append(v)

            if (lineno % 1000) == 0:
                print_debug("%s" % metadata_dict)

            lineno += 1

except Exception as e:
    print_error("Problem reading ruleset file '%s':\n%s" % (args.ruleset_file, e), fatal=True)
