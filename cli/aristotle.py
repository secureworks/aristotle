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

DEBUG = True

global ruleset_file, filter_string, output_file, filter_file

suppress_warnings = False

metadata_dict = {}
keys_dict = {}
metadata_map = {}

disabled_rule_re = re.compile(r"^\x23(?:pass|drop|reject|alert|sdrop|log)\x20.*[\x28\s\x3B]sid\s*\x3A\s*\d+\s*\x3B")
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

parser = argparse.ArgumentParser()

parser.add_argument("-r", "--rules", "--ruleset",
                    action="store",
                    dest="ruleset_file",
                    required=True,
                    help="path to rules file")
parser.add_argument("-f", "--filter",
                    action="store",
                    dest="filter_string",
                    required=False,
                    default = None,
                    help="boolean filter string")
parser.add_argument("-o", "--output",
                    action="store",
                    dest="output_file",
                    required=False,
                    default="<stdout>",
                    help="output file")
parser.add_argument("-c", "--config",
                    action="store",
                    dest="filter_file",
                    required=False,
                    default = None,
                    help="config file containing boolean filter string")
parser.add_argument("-q", "--quiet",
                    action="store_true",
                    dest="quiet",
                    default=False,
                    required=False,
                    help="quiet; suppress warning messages")
parser.add_argument("-d", "--debug",
                    action="store_true",
                    dest="debug",
                    default=False,
                    required=False,
                    help="turn on debug output")
# TODO: log file?


args = parser.parse_args()

if args.debug:
    DEBUG = True

if args.quiet:
    suppress_warnings = True

if not os.path.isfile(args.ruleset_file):
    print_error("Provided ruleset file does not exist: '%s'" % args.ruleset_file, fatal=True)

if args.output_file != "<stdout>" and os.path.isfile(args.output_file):
    print("Warning: output file '%s' already exits.  Overwrite? [y/N]  " % args.output_file)
    # TODO: prompt for input
    sys.exit(0)

if not args.filter_file:
    if not args.filter_string:
        print_error("Provided config filter file does not exist: '%s'" % args.filter_file, fatal=True)
    filter_string = args.filter_string
else:
    if not os.path.isfile(args.filter_file):
        print_error("Provided config filter file does not exist: '%s'" % args.filter_file, fatal=True)
    with open(args.filter_file, 'r') as fh:
        filter_string = fh.read()

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
                    # just a single word in metadata; warning? skip?
                    print_warning("Single word metatdata value found: %s" % kvsplit)
                    continue
                k, v = kvsplit
                # populate metadata_dict
                if k not in metadata_dict[sid]['metadata'].keys():
                    metadata_dict[sid]['metadata'][k] = []
                metadata_dict[sid]['metadata'][k].append(v)
                # populate keys_dict
                # TODO: don't include disabled rules?
                if k not in keys_dict.keys():
                    keys_dict[k] = {}
                if v not in keys_dict[k].keys():
                    keys_dict[k][v] = []
                keys_dict[k][v].append(sid)

            lineno += 1
        #print_debug("metadata_dict:\n%s" % metadata_dict)
        #print_debug("keys_dict:\n%s" % keys_dict)

except Exception as e:
    print_error("Problem reading ruleset file '%s':\n%s" % (args.ruleset_file, e), fatal=True)

def get_all_enabled_swids():
    return [s for s in metadata_dict.keys() if not metadata_dict[s]['disabled']]

def get_swids(kvpair, negate=False):
    # TODO: handle key ALL situation
    # TODO: support date ranges for created_at and updated_at
    # TODO: support inclusion of default-disabled rules
    k, v = kvpair.split(' ', 1)
    retarray = []
    if k not in keys_dict.keys():
        print_warning("metadata key '%s' not found in ruleset" % k)
    else:
        if v not in keys_dict[k]:
            print_warning("metadata key-value pair '%s' not found in ruleset" % kvpair)
        else:
            retarray = [s for s in keys_dict[k][v] if not metadata_dict[s]['disabled']]
    if negate:
        # if key or value not found, this will be all rules
        retarray = list(frozenset(get_all_enabled_swids()) - frozenset(retarray))
    return retarray

def evaluate(myobj):
    if myobj.isliteral:
        #TODO: deal with "sid nnnn"
        if isinstance(myobj, boolean.boolean.NOT):
            return get_swids(metadata_map[myobj.args[0].obj], negate=True)
        else:
            return get_swids(metadata_map[myobj.obj])
    elif isinstance(myobj, boolean.boolean.OR):
        retlist = []
        for i in range(0, len(myobj.args)):
            retlist = list(set(retlist + evaluate(myobj.args[i])))
        return retlist
    elif isinstance(myobj, boolean.boolean.AND):
        retlist = list(frozenset(evaluate(myobj.args[0])))
        for i in range(1, len(myobj.args)):
            retlist = list(frozenset(retlist).intersection(evaluate(myobj.args[i])))
        return retlist

# process boolean string
def filter_ruleset(filter=None):
    if not filter:
        filter = filter_string
    # the boolean.py library uses tokenize which isn't designed to
    # handle multiline tokens (and doesn't support quoting). So
    # just replace and map to single word and let boolean.py
    # handle building the tree.
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
        metadata_map[hashstr] = tstrip
        # replace in filter str
        filter = filter.replace(t, hashstr)

    print_debug(filter)
    try:
        algebra = boolean.BooleanAlgebra()
        mytree = algebra.parse(filter).literalize().simplify()
        return evaluate(mytree)

    except Exception as e:
        print_error("Problem processing filter string:\n\n%s\n\nError:\n%s" % (filter, e), fatal=True)

results = filter_ruleset()

print(results)
print("Total: %d" % len(results))
