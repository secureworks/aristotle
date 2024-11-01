#!/usr/bin/env python
"""
Aristotle

Command line tool and library for filtering and
manipulating Suricata and Snort rulesets based
on metadata keyword values.
"""
# Copyright 2019 Secureworks, Inc.
# Copyright 2023 Uber Technologies, Inc.
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
import glob
import hashlib
import logging
import os
import re
import sys
import traceback
import yaml


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

rule_re = re.compile(
    r"^(?P<HEADER>(?P<ACTION>pass|drop|reject|alert|sdrop|log|rejectsrc|rejectdst|rejectboth)\s+"
    r"(?P<PROTO>[^\s]+)\s+(?P<SRCIP>[^\s]+)\s+(?P<SRCPORT>[^\s]+)\s+(?P<DIRECTION>[\x2D\x3C]\x3E)\s+(?P<DSTIP>[^\s]+)\s+(?P<DSTPORT>[^\s]+))\s+"
    r"\x28(?P<BODY>[^\x29]+)"
)
# Note: TODO? could have a generic re for keyword with a placeholder for the name; conflate with one in _pfmod_apply()
disabled_rule_re = re.compile(r"^\x23\s*(?:pass|drop|reject|alert|sdrop|log|rejectsrc|rejectdst|rejectboth)\x20.*[\x28\x3B]\s*sid\s*\x3A\s*\d+\s*\x3B.*\x29$")
sid_re = re.compile(r"[\x28\x3B]\s*sid\s*\x3A\s*(?P<SID>\d+)\s*\x3B")
metadata_keyword_re = re.compile(r"(?P<PRE>[\x28\x3B]\s*metadata\s*\x3A\s*)(?P<METADATA>[^\x3B]+)\x3B")
classtype_keyword_re = re.compile(r"(?P<PRE>[\x28\x3B]\s*classtype\s*\x3A\s*)(?P<CLASSTYPE>[^\x3B]+)\x3B")
flow_re = re.compile(r"[\s\x3B\x28]flow\s*\x3A\s*(?P<FLOW>[^\x3B]+?)\x3B")
app_layer_protocol_re = re.compile(r"[\s\x3B\x28]app-layer-protocol\s*\x3A\s*(?P<ALPROTO>[^\x3B]+?)\x3B")
target_keyword_re = re.compile(r"[\x28\x3B]\s*target\s*\x3A\s*(?P<TARGET>[^\x3B]+)\x3B")
rule_msg_re = re.compile(r"[\s\x3B\x28]msg\s*\x3A\s*\x22(?P<MSG>[^\x22]+?)\x22\s*\x3B")
cve_re = re.compile(r"(?:19|20)\d{2}\x2D(?:0\d{3}|[1-9]\d{3,})")
cve_re_broad = re.compile(r"\bcve\x2D\d{4}\x2D\d+\b", flags=re.I)
mitre_attack_url_re = re.compile(r"attack\x2Emitre\x2Eorg\x2F(?:techniques|datasources|groups|software|campaigns)\x2F(?:TA|DS|[TGSC])\d+(?:\x2F\d+)?")
eol_re = re.compile(r"\x29\s*$")

ipval_cache = {}

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
    :type fatal: bool, optional
    :raises: `AristotleException`
    """
    aristotle_logger.error(INVERSE + RED + "ERROR:" + RESET + RED + " {}".format(msg) + RESET)
    if fatal:
        aristotle_logger.critical(RED + "Cannot continue" + RESET)
        if __name__ == "__main__":
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
    :param enable_all_rules: enable all valid rules, including those disabled/commented out in the given rules file(s), when applying the filter; defaults to `False`
    :type enable_all_rules: bool, optional
    :param summary_max: the maximum number of rules to print when outputting summary/truncated filtered ruleset, defaults to `16`.
    :type summary_max: int, optional
    :param output_disabled_rules: include disabled rules in the output as commented out lines, defaults to `False`
    :type output_disabled_rules: bool, optional
    :param ignore_classtype_keyword: don't incorporate the 'classtype' keyword and value into the
        metadata structure for filtering and reporting
    :type ignore_classtype_keyword: bool, optional
    :param ignore_filename: don't incorporate the filename of the rules file into the metadata structure for filtering and reporting
    :type ignore_filename: bool, optional
    :param normalize: try to convert and normalize date and CVE related metadata values into the schema defined by BETTER.
        Dates are normalized to the format YYYY-MM-DD and CVEs to YYYY-<num>.  Also, 'sid' is removed from the metadata. Defaults to `False`
    :type normalize: bool, optional
    :param enhance: enhance metadata by adding additional key-value pairs based on the rules, defaults to `False`
    :type enhance: bool, optional
    :param modify_metadata: modify the rule metadata keyword value on output to contain the internally tracked and normalized metadata data, defaults to `False`
    :type modify_metadata: bool, optional
    :param pfmod_file: A filename of a YAML file of directives to apply actions on post-filtered rules based on filter strings.
    :type pfmod_file: string, optional
    :raises: `AristotleException`
    """
    def __init__(self, rules, metadata_filter=None, enable_all_rules=False, summary_max=16, output_disabled_rules=False, ignore_classtype_keyword=False,
                 ignore_filename=False, normalize=False, enhance=False, modify_metadata=False, pfmod_file=None):
        """Constructor."""
        # dict keys are sids
        self.metadata_dict = {}
        # dict keys are keys from metadata key-value pairs
        self.keys_dict = {'sid': {}}
        # dict keys are hash of key-value pairs from passed in filter string/file
        self.metadata_map = {}

        self.enable_all_rules = enable_all_rules
        self.output_disabled_rules = output_disabled_rules
        self.ignore_classtype_keyword = ignore_classtype_keyword
        self.ignore_filename = ignore_filename
        self.normalize = normalize
        self.enhance = enhance
        self.modify_metadata = modify_metadata
        self.pfmod_file = pfmod_file
        if pfmod_file and not modify_metadata:
            print_warning("'pfmod_file' specified but 'modify_metadata' not enabled.  Enabling 'modify_metadata'....")
            self.modify_metadata = True
        if not metadata_filter:
            self.metadata_filter = None
            print_debug("No metadata_filter given to Ruleset() constructor")
        else:
            self.set_metadata_filter(metadata_filter)

        try:
            self.summary_max = int(summary_max)
        except Exception as e:
            print_error("Unable to process 'summary_max' value '{}' passed to Ruleset constructor:\n{}".format(summary_max, e))

        # deal with rules file(s)
        try:
            if os.path.isfile(rules):
                with open(rules, 'r') as fh:
                    self.parse_rules(rules=fh.read(), filename=os.path.basename(rules))
            elif os.path.isdir(rules):
                # process all files ending with ".rules"; sort (alphabetically) and process in order
                rules_files = sorted(glob.glob(os.path.join(rules, "*.rules")))
                if len(rules_files) == 0:
                    print_error("No '.rules' files found in directory '{}'.".format(rules), fatal=True)
                for file in rules_files:
                    if os.path.isfile(file):
                        with open(file, 'r') as fh:
                            self.parse_rules(rules=fh.read(), filename=os.path.basename(file))
                    else:
                        print_debug("File '{}' not a file! Skipping.".format(file))
            else:
                if len(rules) < 256 and "metadata" not in rules:
                    # probably a mis-typed filename
                    print_error("'{}' is not a valid file or directory, and does not appear to be a string containing valid rule(s)".format(rules), fatal=True)
                self.parse_rules(rules)

            if self.enhance:
                self._enhance_metadata()
            print_debug("Total cache size: {}".format(len(ipval_cache.keys())))
        except Exception as e:
            traceback.print_exc(e)
            print_error("Unable to process rules '{}':\n{}".format(rules, e), fatal=True)

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
                            self.enable_all_rules = True
                            line = line[len("<enable-all-rules>"):].lstrip()
                        # strip out comments and ignore blank lines
                        if line.strip().startswith('#') or len(line.strip()) == 0:
                            continue
                        self.metadata_filter += line
            else:
                self.metadata_filter = metadata_filter
        except Exception as e:
            print_error("Unable to process metadata_filter '{}':\n{}".format(metadata_filter, e), fatal=True)

    def reduce_ipval(self, ipval):
        """ Take an "IP" value (raw IP, list, ipvar) and reduce it to one of the following:
                - any
                - $HOME_NET
                - $EXTERNAL_NET
                - UNDETERMINED

            Assumptions:
                - ipval doesn't contain any nested lists
                    - (could recurse on nested lists but once we start reducing, we loose accuraccy pretty fast.)
                    - (most 3rd party rulesets should rarely, if ever, need to include rules that require nested IPs/ranges.)

            :param ipval: IP part of a rule, e.g. $HOME_NET, 10.0.0.0/8, [192.168.1.0/24,192.168.2.0/24], etc.
            :type ipval: string, required
            :returns: 'any', '$HOME_NET', '$EXTERNAL_NET', or 'UNDETERMINED'
            :rtype: string
        """
        global ipval_cache
        unknown = "UNDETERMINED"
        return_values = ["any", "$HOME_NET", "$EXTERNAL_NET", "UNDETERMINED"]
        if ipval in return_values:
            return ipval
        if len(ipval) < 2:
            print_error("Bad IPVAR found: {}".format(ipval))
            return unknown
        # check cache. Testing shows using a cache doesn't speed things up....
        cached_val = ipval_cache.get(ipval)
        if cached_val:
            return ipval_cache[ipval]
        original_val = ipval
        negated = False
        if ipval[0] == '!':
            negated = True
            ipval = ipval[1:]
        if ipval[0] == '[':
            ipval = ipval[1:-1]
        brackets = [c for c in ipval if c == '[']
        if len(brackets) > 0:
            print_error("Double nested ipval found: {}.  Cannot reduce".format(original_val))
            return unknown
        ipval_list = [v.strip() for v in ipval.split(',')]
        reduced_ipval = self._reduce_ipval_helper(ipval_list, global_negate=negated)
        # print_debug(" Original: {}\nProcessed: {}\n  Reduced: {}\n".format(original_val, ipval, reduced_ipval))
        ipval_cache[original_val] = reduced_ipval
        return reduced_ipval

    def _reduce_ipval_helper(self, vals, global_negate=False):
        """ Take in list of IPVAR values and reduce to 'any', '$HOME_NET",
            '$EXTERNAL_NET", or 'UNKNOWN'.
            Assumption: no overlap in HOME_NET and EXTERNAL_NET vars.

            :param vals: list of IPVAR values
            :type vals: list, required
            :param global_negate: invert response
            :type global_negate: bool, optional
        """
        home_net_vars = ["$HOME_NET", "$DNS_SERVERS", "$HTTP_SERVERS", "$SMTP_SERVERS", "$SQL_SERVERS",
                         "$TELNET_SERVERS", "$FTP_SERVERS", "$DNP3_CLIENT", "$DNP3_SERVER", "$ICCP_CLIENT",
                         "$ICCP_SERVER", "$ENIP_CLIENT", "$ENIP_SERVER", "$MODBUS_CLIENT", "$MODBUS_SERVER"]
        external_net_vars = ["$EXTERNAL_NET", "$RFC1918", "$GOTOMYPC", "$AIM_SERVERS"]
        # add CG-NAT (100.64.0.0/10)?
        known_localnet_ips = ["10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12", "127.0.0.0/8", "255.255.255.255"]
        unknown = "UNDETERMINED"
        rfc1918_found = False
        if 'any' in vals:
            return 'any'
        for v in vals:
            negated = global_negate
            if v[0] == '!':
                negated = not global_negate
                v = v[1:]
            # Assume variable ending in "_SERVERS" is HOME_NET unless already listed as in EXTERNAL_NET
            if v not in external_net_vars and v not in home_net_vars and v.endswith("_NET"):
                home_net_vars.append(v)
            if not negated:
                if v in home_net_vars:
                    return "$HOME_NET"
                if v in external_net_vars:
                    return "$EXTERNAL_NET"
            else:
                if v in home_net_vars:
                    return "$EXTERNAL_NET"
                if v in external_net_vars:
                    return "$HOME_NET"
            if v.startswith('$'):
                print_error("Unclassified variable found in _reduce_ipval_helper(): '{}'".format(v))
                return unknown
            # this *should* be an IP or CIDR block
            if v in known_localnet_ips and not negated:
                rfc1918_found = True
        # at this point we *should* be left with a list of IPs.  Assume these are EXTERNAL_NET,
        # even if negated, unless explicit RFC1918 has been seen.
        if rfc1918_found:
            return "$HOME_NET"
        else:
            return "$EXTERNAL_NET"
        # never reached
        return unknown

    def _enhance_metadata(self):
        """ Enhance metadata on all the rules by adding additional key-value pairs based on the rule.
            Specifically:
                - 'flow' key-value pair
                - 'detection direction' key-value pair
                - CVE values found in rule (typically msg or references)
                - MITRE ATT&CK found in rule (typically extracted from references)
        """
        for sid in self.metadata_dict.keys():
            rule = self.metadata_dict[sid]['raw_rule']

            rule_match_obj = rule_re.match(rule)
            if not rule_match_obj:
                print_error("Invalid rule: '{}'".format(rule), fatal=True)

            # find CVE references (often in msg or reference) and add as metadata
            cves = cve_re_broad.findall(rule)
            if cves:
                for cve in cves:
                    self.add_metadata(sid, "cve", cve[4:])

            # find MITRE ATT&CK URL references, extract the values, and add as metadata
            mitres = mitre_attack_url_re.findall(rule)
            if mitres:
                for mitre in mitres:
                    val = mitre.split('/', 2)[-1].replace('/', '.')
                    self.add_metadata(sid, "mitre_attack", val)

            # find 'target' keyword and convert to 'hostile' BETTER key-value
            target_match_obj = target_keyword_re.search(rule)
            if target_match_obj:
                target = target_match_obj.group("TARGET")
                if target == "src_ip":
                    self.add_metadata(sid, "hostile", "dest_ip")
                elif target == "dest_ip":
                    self.add_metadata(sid, "hostile", "src_ip")
                else:
                    # shouldn't happen b/c Suricata will error on the rule on load
                    print_error("Keyword 'target' found in rule but with invalid value '{}'.".format(target))

            # get rule direction arrow ("->" or "<>")
            direction_arrow = rule_match_obj.group("DIRECTION")

            # get set of keywords (and modifiers, technically)
            keywords = rule_match_obj.group("BODY")
            keywords = list(set([k.split(':')[0].strip() for k in keywords.split(';') if len(k.strip()) > 1]))

            # get/add protocols
            proto = rule_match_obj.group("PROTO").lower().strip()
            self.add_metadata(sid, 'protocols', proto)
            match_obj = app_layer_protocol_re.search(rule)
            if match_obj:
                proto = match_obj.group("ALPROTO").lower().strip()
                if not proto.startswith('!') and proto != "failed":
                    self.add_metadata(sid, "protocols", proto)
            # check keywords known to be associated with particular protocols
            known_protocols = ['http', 'dns', 'tls', 'ssh', 'snmp', 'sip', 'rfb', 'mqtt', 'http2',
                               'ja3', 'dnp3', 'cip', 'enip', 'ftpdata', 'krb5', ]
            for app_proto in known_protocols:
                htest = [k for k in keywords if k.startswith("{}_".format(app_proto)) or k.startswith("{}.".format(app_proto))]
                if len(htest) > 0:
                    if app_proto == "ja3":
                        app_proto = "tls"
                    elif app_proto == "cip":
                        app_proto = "enip"
                    elif app_proto == "ftpdata":
                        app_proto = "ftp"
                    elif app_proto == "krb5":
                        app_proto = "kerberos"
                    self.add_metadata(sid, 'protocols', app_proto)

            # get flow
            match_obj = flow_re.search(rule)
            if match_obj:
                # normalize so direction is "to_client" or "to_server"
                flow_str = match_obj.group("FLOW").lower().replace("from_server", "to_client").replace("from_client", "to_server")
                flows = [f.strip() for f in flow_str.split(',')]
                direction_found = False
                for v in flows:
                    self.add_metadata(sid, 'flow', v)
                    if v.startswith("to_"):
                        direction_found = True
                if not direction_found:
                    # check keywords that force direction (request or response)
                    # This hits the most common ones; further checking could be done
                    # e.g. mqtt keywords.
                    request_keywords = ["http.uri", "http_uri", "http.uri.raw", "http_raw_uri",
                                        "http.method", "http_method", "http.request_line",
                                        "http_request_line", "http.request_body", "http_client_body",
                                        "http.user_agent", "http_user_agent", "http.host", "http_host",
                                        "http.host.raw", "http_raw_host", "http.accept", "http_accept",
                                        "http.accept_lang", "http_accept_lang", "http.accept_enc",
                                        "http_accept_enc", "http.referer", "http_referer", "http.connection",
                                        "http_connection", "dns.query", "dns_query", "ssh.hassh.string",
                                        "ja3.hash", "ja3.string", "ftpdata_command", "krb5_cname",
                                        "sip.method", "sip.uri", "sip.request_line"]
                    response_keywords = ["http.stat_msg", "http_stat_msg", "http.stat_code", "http_stat_code",
                                         "http.response_line", "http_response_line", "http.response_body",
                                         "http_server_body", "http.server", "http.location", "ssh.hassh.server",
                                         "ssh.hassh.server.string", "ja3s.hash", "ja3s.string", "krb5_sname",
                                         "sip.stat_code", "sip.stat_msg", "sip.response_line"]
                    matches = [k for k in keywords if k in request_keywords]
                    if len(matches) > 0:
                        self.add_metadata(sid, 'flow', 'to_server')
                    else:
                        matches = [k for k in keywords if k in response_keywords]
                        if len(matches) > 0:
                            self.add_metadata(sid, 'flow', 'to_client')
                        else:
                            print_debug("Flow direction could not be determined from 'flow' keyword for sid '{}'.".format(sid))
            else:
                print_debug("No 'flow' keyword found for SID '{}'.".format(sid))

            # calculate direction
            sip_val = rule_match_obj.group("SRCIP")
            dip_val = rule_match_obj.group("DSTIP")
            sip_reduced = self.reduce_ipval(sip_val)
            dip_reduced = self.reduce_ipval(dip_val)

            # print_debug("{}\n{}\n".format(sip_val, sip_reduced))
            # print_debug("{}\n{}\n".format(dip_val, dip_reduced))

            # self.metadata_dict[sid]['sip_reduced'] = sip_reduced
            # self.metadata_dict[sid]['dip_reduced'] = dip_reduced

            # calculate detection direction; possible values:
            # inbound, inbound-notexclusive, outbound, outbound-notexclusive,
            # internal, any, both, unknown
            if direction_arrow == "<>":
                detection_direction = "both"
            elif sip_reduced == "any" and dip_reduced == "$HOME_NET":
                detection_direction = "inbound-notexclusive"
            elif sip_reduced == "$HOME_NET" and dip_reduced == "$EXTERNAL_NET":
                detection_direction = "outbound"
            elif sip_reduced == "$HOME_NET" and dip_reduced == "any":
                detection_direction = "outbound-notexclusive"
            elif sip_reduced == "$HOME_NET" and dip_reduced == "$HOME_NET":
                detection_direction = "internal"
            # $EXTERNAL_NET -> $EXTERNAL_NET only going to be seen in spoofed traffic (not TCP); set it to OUTBOUND
            elif dip_reduced == "$EXTERNAL_NET":
                detection_direction = "outbound"
            elif sip_reduced == "$EXTERNAL_NET":
                detection_direction = "inbound"
            elif sip_reduced == "any" and dip_reduced == "any":
                detection_direction = "any"
            else:
                detection_direction = "unknown"
            self.add_metadata(sid, 'detection_direction', detection_direction)
        # TODO: remove duplicates?
        return

    def normalize_better(self, k, v, sid=None):
        """ Try to convert date, MITRE ATT&CK, and cve related metadata values to conform to the
            BETTER schema for filtering and statistics. Currently applies to keys
            'cve', 'mitre_tactic_id', 'mitre_technique_id' and those ending with '_at' or "-at".

            :param k: key name of a metadata key-value pair
            :type k: string, required
            :param v: value of a metadata key-value pair
            :type v: string, required
            :param sid: SID related to the passed in key-value pair. Used only for enriching logging.
            :type sid: int, optional

            :returns: list of all key/value pairs to add to metadata structure
            :rtype: list
        """
        retlist = []
        if k.endswith("_at") or k.endswith("-at"):
            # treat as possible date
            try:
                v = dateparse(v.replace('_', '-'))
                v = v.strftime("%Y-%m-%d")
            except Exception as e:
                print_warning("Unable to parse metadata '{}' key with value '{}' as date{}: {}".format(k, v, " for sid {}".format(sid) if sid is not None else "", e))
            retlist.append([k, v])
        elif k == "cve":
            # ET ruleset will in some cases string together multiple CVEs in one
            # string, e.g. "cve_2021_27561_cve_2021_27562" so deal with that and
            # the other underscore nonsense.
            cves = cve_re.findall(v.replace('_', '-'))
            if len(cves) == 0:
                print_warning("Unable to parse metadata '{}' key with value '{}'{}".format(k, v, " for sid {}".format(sid) if sid is not None else ""))
            for cve in cves:
                retlist.append([k, cve])
        elif k in ['mitre_technique_id', 'mitre_tactic_id']:
            # pull values out of 'mitre_tactic_id' and 'mitre_technique_id' metadata and
            # put into BETTER 'mitre_attack' key
            retlist.append(["mitre_attack", v])
        else:
            retlist.append([k, v])
        return retlist

    def add_metadata(self, sid, key, value):
        """ Update self.metadata_dict and self.keys_dict data structures for the
            given sid, adding the passed in key and value.

            :param sid: sid to update
            :type sid: int, required
            :param key: key to add or update
            :type key: string, required
            :param value: value corresponding to given key
            :type value: string, required
        """
        # key-value pairs are case insensitive; make everything lower case (needed for accurate matching
        # in filters) and strip leading and trailing whitespace.
        key = key.lower().strip()
        value = value.lower().strip()
        if sid not in self.metadata_dict.keys():
            print_error("add_metadata() called for sid '{}' but sid is invalid (does not exist).".format(sid))
            return
        # populate metadata_dict
        if key not in self.metadata_dict[sid]['metadata'].keys():
            self.metadata_dict[sid]['metadata'][key] = []
        if value not in self.metadata_dict[sid]['metadata'][key]:
            self.metadata_dict[sid]['metadata'][key].append(value)
        # populate keys_dict
        if key not in self.keys_dict.keys():
            self.keys_dict[key] = {}
        if value not in self.keys_dict[key].keys():
            self.keys_dict[key][value] = []
        if sid not in self.keys_dict[key][value]:
            self.keys_dict[key][value].append(sid)

    def delete_metadata(self, sid, key, value=None):
        """ Update self.metadata_dict and self.keys_dict data structures for the
            given sid, deleting the passed in key and value.  If value is not
            provided (or None), delete all references involving the given key.

            :param sid: sid to update
            :type sid: int, required
            :param key: key to add or update
            :type key: string, required
            :param value: value corresponding to given key
            :type value: string, optional
        """
        key = key.lower().strip()
        if value:
            value = value.lower().strip()
        if sid not in self.metadata_dict.keys():
            print_error("delete_metadata() called for sid '{}' but sid is invalid (does not exist).".format(sid))
            return
        if value is None:
            if key in self.metadata_dict[sid]['metadata'].keys():
                del self.metadata_dict[sid]['metadata'][key]
            else:
                print_debug("key '{}' not found in sid '{}', cannot delete.".format(key, sid))
            if key in self.keys_dict.keys():
                for value in self.keys_dict[key].keys():
                    if sid in self.keys_dict[key][value]:
                        self.keys_dict[key][value].remove(sid)
        else:
            if key in self.metadata_dict[sid]['metadata'].keys():
                if value in self.metadata_dict[sid]['metadata'][key]:
                    self.metadata_dict[sid]['metadata'][key].remove(value)
            if key in self.keys_dict.keys():
                if value in self.keys_dict[key].keys():
                    if sid in self.keys_dict[key][value]:
                        self.keys_dict[key][value].remove(sid)

    def parse_rules(self, rules, filename=None):
        """Parses the given rules and builds/updates necessary data structures.

        :param rules: rules (one per line) to parse and build/update the necessary data structures
        :type rules: string, required
        :param filename: if the passed in rules came from a file, the filename of that file
        :type filename: string, optional
        """
        try:
            for lineno, line in enumerate(rules.splitlines()):
                # ignore comments and blank lines
                is_disabled_rule = False
                if len(line.strip()) == 0:
                    continue
                if line.lstrip().startswith('#'):
                    if disabled_rule_re.match(line.strip()):
                        is_disabled_rule = True
                        line = line.lstrip()[1:].strip()
                    else:
                        # valid comment (not disabled rule)
                        print_debug("Skipping comment: {}".format(line))
                        continue

                # extract sid
                matchobj = sid_re.search(line)
                if not matchobj:
                    print_error("Invalid rule on line {}:\n{}".format(lineno, line), fatal=True)
                sid = int(matchobj.group("SID"))

                # extract classtype. This only grabs the first one; some engines support multiple
                # 'classtype' keywords in rules but it practice it is rarely, if ever, done.
                classtype = None
                matchobj = classtype_keyword_re.search(line)
                if matchobj:
                    classtype = matchobj.group("CLASSTYPE")
                else:
                    print_debug("No 'classtype' keyword found in sid {}".format(sid))

                # extract metadata keyword value
                metadata_str = ""
                matchobj = metadata_keyword_re.search(line)
                if matchobj:
                    metadata_str = matchobj.group("METADATA")
                else:
                    print_warning("No 'metatdata' keyword found in sid {}".format(sid))
                if (lineno % 1000 == 0):
                    print_debug("metadata_str for sid {}:\n{}".format(sid, metadata_str))

                # extract 'msg' field
                matchobj = rule_msg_re.search(line)
                if not matchobj:
                    print_warning("Unable to extract rule msg from SID '{}'.".format(sid))
                    msg = ""
                else:
                    msg = matchobj.group("MSG")

                # build dict
                if sid in self.metadata_dict.keys():
                    # include the first encountered enabled rule; if they are all disabled, include the first encountered.
                    print_warning("Duplicate sid '{}' found{}".format(sid, "!" if not filename else " in file '{}'!".format(filename)))
                    if is_disabled_rule:
                        print_warning("Ignoring disabled rule with duplicate sid: {}".format(line))
                        continue
                    if self.metadata_dict[sid]['disabled']:
                        print_warning("Ignoring disabled rule with duplicate sid: {}".format(self.metadata_dict[sid]['raw_rule']))
                    else:
                        print_warning("Ignoring rule with duplicate sid: {}".format(line))
                        continue

                self.metadata_dict[sid] = {'metadata': {},
                                           'msg': msg,
                                           'disabled': False if self.enable_all_rules else is_disabled_rule,
                                           'originally_disabled': is_disabled_rule,
                                           'raw_rule': line
                                           }

                metadata_pairs = []

                if len(metadata_str) > 0:
                    metadata_pairs.extend(metadata_str.split(','))

                if classtype and not self.ignore_classtype_keyword:
                    # add classtype from keyword as pseudo metadata key
                    metadata_pairs.append("classtype {}".format(classtype))

                if filename and not self.ignore_filename:
                    metadata_pairs.append("filename {}".format(filename))

                for kvpair in metadata_pairs:
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
                    # normalize_better() returns a list b/c in rare cases it will produce more than one key/value pair.
                    # Because of that, make everything a(nother) list, even though most of the time it will be
                    # a one element list
                    if self.normalize:
                        kvs = self.normalize_better(k, v, sid)
                    else:
                        kvs = [kvsplit]
                    for current_kvp in kvs:
                        k, v = current_kvp
                        self.add_metadata(sid, k, v)
                    for k in self.metadata_dict[sid]['metadata'].keys():
                        # remove duplicate values for the same key
                        self.metadata_dict[sid]['metadata'][k] = list(set(self.metadata_dict[sid]['metadata'][k]))

                # add sid as pseudo metadata key unless it already exists
                if 'sid' not in self.metadata_dict[sid]['metadata'].keys():
                    # keys and values are strings; variable "sid" is int so must
                    # be cast as str when used the same way other keys and values are used.
                    self.metadata_dict[sid]['metadata']['sid'] = [str(sid)]
                    self.keys_dict['sid'][str(sid)] = [sid]

                # add 'originally_disabled' as pseudo metadata key so it can be filtered on
                if 'originally_disabled' in self.metadata_dict[sid]['metadata'].keys():
                    print_warning("Metadata key 'originally_disabled' found in SID {}. "
                                  "This is an internal metadata key used by Aristotle. "
                                  "The value '{}' found in the rule will be ignored.".format(sid, self.metadata_dict[sid]['metadata']['originally_disabled']))
                    self.delete_metadata(sid, 'originally_disabled')
                self.add_metadata(sid, 'originally_disabled', str(self.metadata_dict[sid]['originally_disabled']))

        except Exception as e:
            traceback.print_exc(e)
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
        """Returns a list of all SIDs, enabled and disabled.

        :returns: list of all enabled SIDs, enabled and disabled.
        :rtype: list
        """
        return [s for s in self.metadata_dict.keys()]

    def get_enabled_sids(self):
        """Returns a list of all enabled SIDs.

        :returns: list of all enabled SIDs.
        :rtype: list
        """
        return [s for s in self.metadata_dict.keys() if not self.metadata_dict[s]['disabled']]

    def get_disabled_sids(self):
        """Returns a list of all disabled SIDs.

        :returns: list of all disabled SIDs.
        :rtype: list
        """
        return [s for s in self.metadata_dict.keys() if self.metadata_dict[s]['disabled']]

    def get_sids(self, kvpair, negate=False):
        """Get a list of all SIDs for passed in key-value pair.

        :param kvpair: key-value pair
        :type kvpair: string, required
        :param negate: returns the inverse of the result (i.e. all SIDs not matching the ``kvpair``), defaults to `False`
        :type negate: bool, optional
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
                     'updated_at',
                     'risk_score']
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
                    retarray = [s for s in [s2 for s2 in self.metadata_dict.keys() if k in self.metadata_dict[s2]["metadata"].keys()]
                                for val in self.metadata_dict[s]["metadata"][k]
                                if self.cve_compare(left_val=val, right_val=cve_val, cmp_operator=cmp_operator)]
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
                    else:  # v.startswith('>'):
                        if v[offset] == '=':
                            offset += 1
                        lbound = dateparse(v[offset:].strip())
                        lbound -= datetime.timedelta(microseconds=(offset - 1))
                    print_debug("lbound: {}\nubound: {}".format(lbound, ubound))
                    retarray = [s for s in [s2 for s2 in self.metadata_dict.keys() if k in self.metadata_dict[s2]["metadata"].keys()]
                                for val in self.metadata_dict[s]["metadata"][k]
                                if (dateparse(val) < ubound and dateparse(val) > lbound)]
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
                    else:  # v.startswith('>'):
                        if v[offset] == '=':
                            offset += 1
                        lbound = float(v[offset:].strip())
                        lbound -= (float(offset) - 1.0)
                    print_debug("lbound: {}\nubound: {}".format(lbound, ubound))
                    retarray = [s for s in [s2 for s2 in self.metadata_dict.keys() if k in self.metadata_dict[s2]["metadata"].keys()]
                                for val in self.metadata_dict[s]["metadata"][k]
                                if (float(val) < float(ubound) and float(val) > float(lbound))]
                except Exception as e:
                    print_error("Unable to process '{}' value '{}' (as float):\n{}".format(k, v, e), fatal=True)
        elif k in ["msg_regex", "rule_regex"]:
            # apply regex pattern to rule msg field
            if not (v.startswith('/') or v.endswith('.') or v.endswith("/i")):
                print_error("Bad {} pattern '{}' in filter string. Pattern must start with '/' and end with '/' or '/i'.".format(k, v), fatal=True)
            re_flag = 0
            re_v = v
            if v.endswith('i'):
                re_flag = re.I
                re_v = v[:-1]
            re_v = re_v.strip('/')
            try:
                pattern_re = re.compile(r"{}".format(re_v), flags=re_flag)
            except Exception as e:
                print_error("Unable to compile RegEx pattern '{}': {}".format(v, e), fatal=True)
            try:
                if k == "msg_regex":
                    retarray = [s for s in self.metadata_dict.keys() if pattern_re.search(self.metadata_dict[s]['msg'])]
                else:
                    # match against raw rule
                    retarray = [s for s in self.metadata_dict.keys() if pattern_re.search(self.metadata_dict[s]['raw_rule'])]
            except Exception as e:
                print_error("Problem matching RegEx pattern '{}': {}".format(v, e), fatal=True)
        else:
            if k not in self.keys_dict.keys():
                print_warning("metadata key '{}' not found in ruleset".format(k))
            else:
                # special keyword '<all>' means all values for that key
                if v in ["<all>", "<any>"]:
                    retarray = [s for val in self.keys_dict[k].keys() for s in self.keys_dict[k][val]]
                elif v not in self.keys_dict[k]:
                    print_warning("metadata key-value pair '{}' not found in ruleset".format(kvpair))
                    # retarray should stil be empty but in case not:
                    retarray = []
                else:
                    retarray = [s for s in self.keys_dict[k][v]]
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
            # key-value pairs are case insensitive; make everything lower case unless key is "msg_regex" or "rule_regex"
            tsplit = [e.strip() for e in t.strip('"').strip().split(' ', 1)]
            tsplit[0] = tsplit[0].lower()
            if len(tsplit) == 2:
                if not tsplit[0] in ["msg_regex", "rule_regex"]:
                    tsplit[1] = tsplit[1].lower()
                tstrip = ' '.join(tsplit)
            else:
                # if just key provided (no value), match on all values
                tstrip = "{} <all>".format(tstrip)
            print_debug(tstrip)
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

    def _pfmod_apply(self, pfmod_file, sids):
        """ Applies the directives in the pfmod YAML file to passed in SIDs

        :param pfmod_file: filename of FPMod file
        :type pfmod_file: string, required
        :param sids: list of sids to scope to
        :type sids: list, required
        :returns: list of matching SIDs
        :rtype: list
        """
        # see docs
        valid_actions_str = ["disable", "enable"]
        valid_actions_dict = ["add_metadata",
                              "add_metadata_exclusive",
                              "delete_metadata",
                              "regex_sub",
                              "copy_key",
                              # set_<keyword> actions not listed here (see below)
                              ]
        # valid_actions = valid_actions_str + valid_actions_dict

        # Supported rule keywords (and defined type) that can be updated by PFMod, e.g. using "set_priority"
        valid_set_keywords = {'sid': {'type': 'int', 'default': 5000000},
                              'gid': {'type': 'int', 'default': 1},
                              'rev': {'type': 'int', 'default': 2},
                              'priority': {'type': 'int', 'default': 3},
                              'msg': {'type': 'str', 'default': None},
                              'reference': {'type': 'str_noquote', 'default': None},
                              'classtype': {'type': 'str_noquote', 'default': None},
                              'target': {'type': 'str_noquote', 'default': None},
                              'threshold': {'type': 'str_noquote', 'default': None},
                              'flow': {'type': 'str_noquote', 'default': None}
                              }
        keyword_re_template = r"(?P<PRE>[\x28\x3B]\s*{}\s*\x3A\s*)(?P<VALUE>[^\x3B]+)\x3B"
        matched_sids_all = set()

        print_debug("pfmod_apply() called")

        try:
            if not os.path.isfile(pfmod_file):
                print_error("Problem processing PFMod file '{}': file not found.".format(pfmod_file), fatal=True)
            with open(pfmod_file, 'r') as fh:
                pfmod_rules = yaml.safe_load(fh)
        except Exception as e:
            print_error("Unable to open PFMod YAML file '{}': {}".format(pfmod_file, e), fatal=True)
        if not type(pfmod_rules) == dict:
            print_error("Unexpected YAML format in file '{}'. Cannot continue.".format(pfmod_file), fatal=True)

        if "include" in pfmod_rules.keys() and pfmod_rules['include'] is not None:
            # Note: allowing for include directives creates a directed graph but checking is not done
            # to ensure it is acyclic.  We could check to ensure this is a DAG but for now, it's the
            # responsibility of the user.
            for f in pfmod_rules['include']:
                if not os.path.isabs(f):
                    f = os.path.join(os.path.dirname(pfmod_file), f)
                matched_sids_all.update(self._pfmod_apply(f, sids))
        elif "rules" not in pfmod_rules.keys():
            print_error("No 'rules' directives defined in file '{}'.".format(pfmod_file), fatal=True)
        if "version" in pfmod_rules.keys() and pfmod_rules['version'] is not None:
            print_debug("Processing PFMod rules file '{}', version {}.".format(os.path.basename(pfmod_file), pfmod_rules['version']))
        if "rules" in pfmod_rules.keys() and pfmod_rules['rules'] is not None:
            for rule in pfmod_rules['rules']:
                rule_name = "<undefined>"
                if "name" in rule.keys():
                    rule_name = rule['name']
                    print_debug("Processing PFMod rule '{}'".format(rule_name))
                for k in ["filter_string", "actions"]:
                    if k not in rule.keys():
                        print_error("No '{}' defined for PFMod rule '{}'".format(k, rule_name), fatal=True)
                # print_debug("Filter String: {}".format(rule['filter_string']))
                try:
                    matched_sids = self.filter_ruleset(rule['filter_string'])
                except Exception as e:
                    print_error("Unable to apply filter string '{}' in PFMod rule named '{}': {}.".format(rule['filter_string'], rule_name, e), fatal=True)
                # print_debug("matched_sids: {}\npassed sids: {}".format(matched_sids, sids))
                matched_sids = list(set(sids) & set(matched_sids))
                matched_sids_all.update(matched_sids)
                # print_debug("Matched sids: {}".format(matched_sids))
                print_debug("Rule:\n\t{}\n\tModified: {}".format(rule_name, len(matched_sids)))
                for sid in matched_sids:
                    for action in rule['actions']:
                        if type(action) == str:
                            if action not in valid_actions_str:
                                print_error("Invalid action '{}' in PFMod rule named '{}'. Supported str actions are: {}.".format(action, rule_name, valid_actions_str))
                                continue
                            if action == 'disable':
                                self.metadata_dict[sid]['disabled'] = True
                            elif action == 'enable':
                                self.metadata_dict[sid]['disabled'] = False
                            else:
                                print_error("Action not implemented: '{}'.".format(action))
                                continue
                        elif type(action) == dict:
                            for action_key in action.keys():
                                action_key = action_key.strip()
                                if action_key not in valid_actions_dict and not action_key.startswith("set_"):
                                    print_error("Invalid action found: '{}' in PFMod rule named '{}'. Supported dict actions are: '{}'.".format(action, rule_name, valid_actions_dict))
                                    continue
                                if len(str(action[action_key]).strip()) == 0:
                                    print_error("No value for action '{}'.".format(action_key), fatal=True)

                                if action_key == "copy_key":
                                    a = [k.strip().lower() for k in action[action_key].split(' ') if len(k.strip()) > 0]
                                    if len(a) != 2:
                                        print_error("Invalid value for action '{}' in PFMod rule '{}'. "
                                                    "Expected 2 arguments but received {}".format(action_key, rule_name, len(a)))
                                    else:
                                        key = a[0]
                                        new_key = a[1]
                                        if key == new_key:
                                            print_error("Invalid action found: '{}' in PFMod rule named '{}'. Old and new keyword names are both '{}'. "
                                                        " You are doing it wrong.".format(action_key, rule_name, key))
                                            continue
                                        # check if key exists
                                        if key not in self.metadata_dict[sid]['metadata'].keys():
                                            print_warning("PFMod rule named '{}': metadata key '{}' not found in SID {}. "
                                                          "Unable to perform action '{}'.".format(rule_name, key, sid, action_key))
                                            continue
                                        # check if new key exists and leave it alone if it does
                                        if new_key in self.metadata_dict[sid]['metadata'].keys():
                                            print_warning("PFMod rule named '{}': destination metadata key '{}' already exists.  "
                                                          "Not overwriting with action '{}'.".format(rule_name, new_key, action_key))
                                            continue
                                        # copy key to new key
                                        for v in self.metadata_dict[sid]['metadata'][key]:
                                            self.add_metadata(sid, new_key, v)

                                elif action_key.startswith("set_") and len(action_key.split('_')) > 2:
                                    # set arbitrary integer-based metadata key if key name has an underscore in it; support relative values and default value.
                                    key = action_key.split('_', 1)[1]
                                    print_debug("PFMod: setting '{}' metadata key on SID {} ...".format(key, sid))
                                    key_value = str(action[action_key]).strip()
                                    if len(key_value) > 1:
                                        if key_value[0] in ['+', '-']:
                                            key_value_orig = key_value
                                            r = [x.strip() for x in key_value.split(',')]
                                            default_value = None
                                            if len(r) > 1:
                                                # default given
                                                default_value = r[1]
                                                try:
                                                    default_value = int(default_value)
                                                except Exception as e:
                                                    print_error("PFMod rule named '{}', action '{}': invalid default value '{}' (must be an integer).\n{}".format(
                                                        rule_name, action_key, default_value, e), fatal=True)
                                            try:
                                                key_value = int(r[0])
                                            except Exception as e:
                                                print_error("PFMod rule named '{}', action '{}': invalid default '{}' (must be an integer).\n{}".format(
                                                    rule_name, action_key, key_value, e), fatal=True)
                                            # get existing value
                                            if key in self.metadata_dict[sid]['metadata'].keys() and len(self.metadata_dict[sid]['metadata'][key]) > 0:
                                                # grab the first value (if there are multiple entries)
                                                existing_value = self.metadata_dict[sid]['metadata'][key][0]
                                                try:
                                                    existing_value = int(existing_value)
                                                except Exception as e:
                                                    print_error("PFMod rule named '{}', action '{}': invalid exiting metadata value '{}' for key '{}' in SID '{}' (must be an integer).  "
                                                                "Skipping.  Error:\n{}".format(rule_name, action_key, existing_value, key, sid, e))
                                                    continue
                                                key_value = existing_value + key_value
                                            else:
                                                if default_value is not None:
                                                    # use default
                                                    print_debug("PFMod rule named '{}': metadata key '{}' not found in SID {}. "
                                                                "Using default value '{}'.".format(rule_name, key, sid, default_value))
                                                    key_value = default_value
                                                else:
                                                    print_warning("PFMod rule named '{}': metadata key '{}' not found in SID {}. "
                                                                  "Unable to add relative value '{}'.".format(rule_name, key, sid, key_value_orig))
                                                    continue
                                        try:
                                            key_value = int(key_value)
                                        except Exception as e:
                                            print_error("PFMod rule named '{}', action '{}': invalid value '{}' (must be an integer).\n{}".format(rule_name, action_key, key_value, e), fatal=True)
                                        # effectivly make this "add_metadata_exclusive"
                                        self.delete_metadata(sid, key)
                                        self.add_metadata(sid, key, str(key_value))
                                    else:
                                        print_error("PFMod rule named '{}': Invalid value for action '{}'.".format(rule_name, action_key), fatal=True)

                                elif action_key == "delete_metadata":
                                    a = [k.strip().lower() for k in action[action_key].split(' ', 1) if len(k.strip()) > 0]
                                    if len(a) < 2:
                                        key = a[0]
                                        print_debug("Deleting all metadata for key '{}'.".format(key))
                                        self.delete_metadata(sid, key)
                                    else:
                                        key = a[0]
                                        value = a[1]
                                        print_debug("Deleting all metadata with key-value pair '{} {}'.".format(key, value))
                                        self.delete_metadata(sid, key, value)

                                elif action_key.startswith("add_metadata"):
                                    a = [k.strip().lower() for k in action[action_key].split(' ', 1) if len(k.strip()) > 0]
                                    if len(a) != 2:
                                        print_error("Invalid value for action '{}' in PFMod rule '{}'.".format(action_key, rule_name))
                                    else:
                                        key = a[0]
                                        value = a[1]
                                        if action_key.endswith("exclusive"):
                                            self.delete_metadata(sid, key)
                                        self.add_metadata(sid, key, value)

                                elif action_key.startswith("set_"):
                                    keyword = action_key.split('_')[1]
                                    if keyword not in valid_set_keywords.keys():
                                        print_error("Invalid PFMod action '{}'.  Setting keyword '{}' not supported.".format(action_key, keyword))
                                        continue
                                    print_debug("PFMod: setting '{}' keyword on SID {} ...".format(keyword, sid))
                                    keyword_value = str(action[action_key]).strip()
                                    if valid_set_keywords[keyword]['type'] == 'int':
                                        # 'int' keywords support leading '+' or '-' which will adjust the existing value of that keyword
                                        # up (for '+') or down (for '-'). YAML must quote value with leading '+' or it will be treated as
                                        # integer and the '+' won't be kept to be parsed here.
                                        if len(keyword_value) > 1 and keyword_value[0] in ['+', '-']:
                                            keyword_value_orig = keyword_value
                                            try:
                                                keyword_value = int(keyword_value)
                                                # extract value
                                                keyword_re = re.compile(keyword_re_template.format(keyword))
                                                matchobj = keyword_re.search(self.metadata_dict[sid]['raw_rule'])
                                                if not matchobj:
                                                    print_warning("PFMod rule named '{}': keyword '{}' not found in SID {}. "
                                                                  "Unable to add relative value '{}'.".format(rule_name, keyword, sid, keyword_value_orig))
                                                    continue
                                                else:
                                                    rule_value = int(matchobj.group("VALUE"))
                                                    keyword_value = rule_value + keyword_value
                                                    if (keyword in ["sid", "priority", "rev"] and keyword_value <= 0) or (keyword in ["gid"] and keyword_value < 0):
                                                        keyword_value = 1
                                                        if keyword in ["gid"]:
                                                            keyword_value = 0
                                                        print_warning("PFMod rule named '{}': keyword '{}' relative adjustment of value by {} results in a value below what is allowed for SID {};"
                                                                      " setting to minimum value of '{}'.".format(rule_name, keyword, keyword_value_orig, sid, keyword_value))
                                            except Exception as e:
                                                print_error("Invalid value '{}' for keyword '{}' in PFMod rule named '{}': {}".format(keyword_value_orig, keyword, rule_name, e), fatal=True)
                                        # validate as int
                                        try:
                                            keyword_value = int(keyword_value)
                                            if keyword in ["sid", "priority", "rev"] and keyword_value <= 0:
                                                # note: 'priority' on Suricata should be 1-255
                                                raise ValueError()
                                            # can add other validation checks here as necessary but ultimately, the responsibility for proper syntax
                                            # falls on the PFMod rule author.
                                        except Exception as e:
                                            print_error("Invalid value '{}' for keyword '{}' in PFMod rule named '{}': {}".format(keyword_value, keyword, rule_name, e), fatal=True)
                                    else:
                                        # validate as string
                                        badchars = ['"', '\\', ';']
                                        try:
                                            for c in badchars:
                                                # Rough filter and cursory rule injection prevention.
                                                # Technically these chars could be included in some contexts when properly escaped.
                                                if c in keyword_value:
                                                    raise ValueError("Character '{}' not supported in value for PFMod action '{}'.".format(c, action_key))
                                            if (keyword == "target" and keyword_value not in ['src_ip', 'dest_ip']):
                                                raise ValueError()
                                            # can add other validation checks here as necessary but ultimately, the responsibility for proper syntax
                                            # falls on the PFMod rule author.
                                            if valid_set_keywords[keyword]['type'] == "str":
                                                # keyword value needs to be double quoted in the rule string
                                                keyword_value = '"{}"'.format(keyword_value)
                                        except Exception as e:
                                            print_error("Invalid value '{}' for keyword '{}' in PFMod rule named '{}': {}".format(keyword_value, keyword, rule_name, e), fatal=True)
                                    # update rule
                                    keyword_re = re.compile(keyword_re_template.format(keyword))
                                    if keyword_re.search(self.metadata_dict[sid]['raw_rule']):
                                        print_debug("PFMod: Overwriting keyword '{}' with value '{}' for SID {}.".format(keyword, keyword_value, sid))
                                        self.metadata_dict[sid]['raw_rule'] = keyword_re.sub(r'\g<PRE>' + str(keyword_value) + ';', self.metadata_dict[sid]['raw_rule'])
                                    else:
                                        # given keyword not in original rule; add one.
                                        print_debug("PFMod: Adding keyword '{}' with value '{}' for SID {}.".format(keyword, keyword_value, sid))
                                        keyword_string = " {}:{};)".format(keyword, keyword_value)
                                        self.metadata_dict[sid]['raw_rule'] = eol_re.sub(keyword_string, self.metadata_dict[sid]['raw_rule'])

                                elif action_key == "regex_sub":
                                    v = action[action_key]
                                    re_flag = 0
                                    re_v = v
                                    if v.endswith('i'):
                                        re_flag = re.I
                                        re_v = v[:-1]
                                    try:
                                        search_string, replace_string = re_v.strip().strip('/').split('/', 1)
                                        pattern_re = re.compile(r"{}".format(search_string), flags=re_flag)
                                        self.metadata_dict[sid]['raw_rule'] = pattern_re.sub(r'{}'.format(replace_string), self.metadata_dict[sid]['raw_rule'])
                                    except Exception as e:
                                        print_error("Problem processing '{}' value '{}' in PFMod rule named '{}': {}".format(action_key, v, rule_name, e))
                                        continue

                                else:
                                    # not reached
                                    print_error("Invalid action found: '{}' in PFMod rule named '{}'. Supported dict actions are: '{}'.".format(action, rule_name, valid_actions_dict), fatal=True)
                                # print_debug("Handled '{}' Action: '{}'. Value: '{}'".format(action_key, action, action[action_key]))
                        else:
                            print_error("Invalid action data type '{}' in PFMod rule named '{}'.".format(type(action), rule_name))
                            continue
        return matched_sids_all

    def print_header(self, sids=None):
        """ Prints vanity header and stats.

        :param sids: list of SIDs to consider. If not provided, global list is used.
        :type sids: list, optional
        """
        if sids is None:
            sids = list(self.metadata_dict.keys())
        total = len(sids)
        enabled = len([sid for sid in sids
                       if not self.metadata_dict[sid]['disabled']])
        disabled = total - enabled
        print("\n" + INVERSE + BROWN + "       Aristotle       "
              + RESET + BROWN
              + "\n Ruleset Metadata Tool " + RESET + "\n")
        print(UNDERLINE + BOLD + GREEN + "All Rules:"
              + RESET + GREEN
              + " Total: {}; Enabled: {}; Disabled: {}".format(total, enabled, disabled)
              + RESET + "\n")

    def get_stats(self, key, keyonly=False, sids=None, include_empty_substat=False):
        """Returns string of statistics (total, enabled, disabled) for specified key and its values.

        :param key: key to print statistics for
        :type key: string, required
        :param keyonly: only print stats for the key itself and not stats for all possible key-value pairs, defaults to `False`
        :type keyonly: bool, optional
        :param sids: list of SIDs to consider. If not provided, global list is used.
        :type sids: list, optional
        :param include_empty_substat: includes cases where substat (key-value pair) has zero results
        :parap include_empty_substat: bool, optional
        :returns: string contaning stats, suitable for printing to stdout
        :rtype: string
        :raises: `AristotleException`
        """
        retstr = ""
        sids_orig = sids
        if sids is None:
            sids = list(self.metadata_dict.keys())
        if key not in self.keys_dict.keys():
            print_warning("key '{}' not found".format(key))
            return
        total = len([sid for sid in sids
                     if key in self.metadata_dict[sid]['metadata'].keys()])
        enabled = len([sid for sid in sids
                       if key in self.metadata_dict[sid]['metadata'].keys()
                       and not self.metadata_dict[sid]['disabled']])
        disabled = total - enabled
        retstr += "{} (Total: {}; Enabled: {}; Disabled: {})\n".format(REDISH + UNDERLINE + BOLD + key + RESET, total, enabled, disabled)

        if not keyonly:
            for value in self.keys_dict[key].keys():
                # use if/else to speed things up when filter not in use
                if sids_orig is None:
                    total = len(self.keys_dict[key][value])
                    enabled = len([sid for sid in self.keys_dict[key][value] if not self.metadata_dict[sid]['disabled']])
                else:
                    total = len([s for s in sids if s in self.keys_dict[key][value]])
                    enabled = len([sid for sid in self.keys_dict[key][value] if sid in sids and not self.metadata_dict[sid]['disabled']])
                disabled = total - enabled
                if include_empty_substat or total > 0:
                    retstr += "\t{} (Total: {}; Enabled: {}; Disabled: {})\n".format(ORANGE + value + RESET, total, enabled, disabled)
            retstr += "\n"
        return retstr

    def print_stats(self, key, keyonly=False, sids=None):
        """Print statistics (total, enabled, disabled) for specified key and its values.

        :param key: key to print statistics for.
        :type key: string, required
        :param keyonly: only print stats for the key itself and not stats for all possible key-value pairs, defaults to `False`.
        :type keyonly: bool, optional
        :param sids: list of SIDs to scope stats to. If None, global list will be used downstream.
        :type sids: list, optional
        """
        stats_str = self.get_stats(key=key, keyonly=keyonly, sids=sids)
        if stats_str:
            if stats_str[-1] == '\n':
                stats_str = stats_str[:-1]
            print("{}".format(stats_str))
            return True
        else:
            print_warning("No statistics to print.")
            return False

    def print_ruleset_summary(self, sids, pfmod_sids=None):
        """Prints summary/truncated filtered ruleset to stdout.

        :param sids: list of SIDs.
        :type sids: list, required
        :param pfmod_sids: list of SID modified by PFMod.
        :type sids: list, optional
        :raises: `AristotleException`
        """
        print_debug("print_ruleset_summary() called")
        print("")
        # ignore disabled rules when printing summary
        enabled_sids = [s for s in sids if not self.metadata_dict[s]['disabled']]
        i = 0
        while i < len(enabled_sids):
            if i < self.summary_max:
                matchobj = rule_msg_re.search(self.metadata_dict[enabled_sids[i]]['raw_rule'])
                if not matchobj:
                    print_warning("Unable to extract rule msg from '{}'.".format(self.metadata_dict[enabled_sids[i]]['raw_rule']))
                    continue
                msg = matchobj.group("MSG")
                print("{} [sid:{}]".format(msg, enabled_sids[i]))
            else:
                break
            i += 1
        print("\n" + BLUE + "Showing {} of {} enabled rules{}".format(
            i,
            len(enabled_sids),
            " ({} rules total, including disabled)".format(len(sids)) if len(sids) != len(enabled_sids) else '') + RESET)
        if pfmod_sids is not None and len(sids) > 0:
            pfmod_ratio = float(float(len(pfmod_sids)) / float(len(sids)))
            print(BLUE + "SIDs modifed by PFMod: {} of {} ({:.1%})".format(len(pfmod_sids), len(sids), pfmod_ratio) + RESET)
            print_debug("SIDs NOT modified by PFMod: {}".format(list(set(sids) - set(pfmod_sids))))
        print("")

    def output_rules(self, sid_list, outfile=None, modify_metadata=None):
        """Output rules, given a list of SIDs.

        :param sid_list: list of SIDs of the rules to output
        :type sid_list: list, required
        :param outfile: filename to output to; if None, output to stdout; defaults to `None`
        :type outfile: string or None, optional
        :param modify_metadata: modify the rule metadata keyword value on output to contain the internally tracked and normalized metadata data.
        :type modify_metadata: bool, optional
        :returns: None
        :rtype: NoneType
        :raises: `AristotleException`
        """
        # TODO: handle order because of/based on flowbits? Ideally IDS engine should handle...
        #       see https://redmine.openinfosecfoundation.org/issues/1399
        if not self.output_disabled_rules:
            sid_list = [s for s in sid_list if not self.metadata_dict[s]['disabled']]
        else:
            # 'output_disabled_rules' set so all non-matching and disabled rules get printed as disabled rules
            # Set all non-matching rules to 'disabled' and set sid_list to be all rules
            for s in list(set(self.get_all_sids()) - set(sid_list)):
                self.metadata_dict[s]['disabled'] = True
            sid_list = self.get_all_sids()
        if modify_metadata is None:
            modify_metadata = self.modify_metadata
        if modify_metadata:
            # Note: this updates/overwrites the self.metadata_dict[<sid>]['raw_rule'] value
            # so if your code expects that to be unchanged after calling output_rules(),
            # that won't be the case.
            print_debug("Modifying metadata...")
            for s in sid_list:
                metadata_string = ""
                # Sort before building; this way the ruleset hash won't change on every run.
                # Before Python 3.6, insertion order in dicts isn't necessarily preserved.
                # Could use an OrderedDict but doing this instead.
                for key in sorted(self.metadata_dict[s]['metadata'].keys()):
                    if key == "sid" and self.normalize:
                        # if normalize set, don't include 'sid' in metadata on output per BETTER recommendation
                        continue
                    if key == "originally_disabled" and not self.enhance:
                        # if the 'enhance' option is not enabled, don't include 'originally_disabled' key
                        continue
                    for val in sorted(self.metadata_dict[s]['metadata'][key]):
                        metadata_string += "{} {}, ".format(key, val)
                if len(metadata_string) > 0:
                    metadata_string = metadata_string[:-2] + ';'
                    if metadata_keyword_re.search(self.metadata_dict[s]['raw_rule']):
                        self.metadata_dict[s]['raw_rule'] = metadata_keyword_re.sub(r'\g<PRE>' + metadata_string, self.metadata_dict[s]['raw_rule'])
                    else:
                        # no 'metadata' keyword in original rule; add one.
                        metadata_string = " metadata:{})".format(metadata_string)
                        self.metadata_dict[s]['raw_rule'] = eol_re.sub(metadata_string, self.metadata_dict[s]['raw_rule'])
                else:
                    print_warning("No metadata found for SID {}.".format(s))
        if outfile is None:
            for s in sid_list:
                if not self.metadata_dict[s]['disabled'] or self.output_disabled_rules:
                    print("{}{}".format('#' if self.metadata_dict[s]['disabled'] else '', self.metadata_dict[s]['raw_rule']))
        else:
            try:
                with open(outfile, "w") as fh:
                    enabled_count = 0
                    disabled_count = 0
                    for s in sid_list:
                        if not self.metadata_dict[s]['disabled'] or self.output_disabled_rules:
                            if not self.metadata_dict[s]['disabled']:
                                fh.write("{}\n".format(self.metadata_dict[s]['raw_rule']))
                                enabled_count += 1
                            else:
                                fh.write("#{}\n".format(self.metadata_dict[s]['raw_rule']))
                                disabled_count += 1
            except Exception as e:
                print_error("Problem writing to file '{}':\n{}".format(outfile, e), fatal=True)
            print(GREEN + "Wrote {} rules {}to file, '{}'".format(
                (enabled_count + disabled_count),
                "({} enabled, {} disabled) ".format(enabled_count, disabled_count) if self.output_disabled_rules else '',
                outfile) + RESET + "\n")


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

python3 aristotle/aristotle.py -r examples/example.rules --summary -n
-f '(("priority high" AND "malware <ALL>") AND "created_at >= 2018-01-01")
AND NOT ("protocols smtp" OR "protocols pop" OR "protocols imap") OR "sid 80181444"'
""" + "\r\n"
        )
        parser.add_argument("-r", "--rules", "--ruleset",
                            action="store",
                            dest="rules",
                            required=True,
                            help="path to a rules file, a directory containing '.rules' file(s), or string containing the ruleset")
        parser.add_argument("-f", "--filter",
                            action="store",
                            dest="metadata_filter",
                            required=False,
                            default=None,
                            help="Boolean filter string or path to a file containing it")
        parser.add_argument("--summary",
                            action="store",
                            dest="display_max",
                            required=False,
                            type=int,
                            nargs='?',
                            default=-1,
                            help="output a summary of the filtered ruleset to stdout, limited \
                                  to DISPLAY_MAX number of lines (or 16 if no value given); \
                                  if the option to output to a file is set, the full, filtered ruleset \
                                  will still be written.")
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
        parser.add_argument("-i", "--enable-all-rules", "--enable-all", "--include-disabled",
                            action="store_true",
                            dest="enable_all_rules",
                            required=False,
                            default=False,
                            help="enable all valid rules, including those disabled/commented out in the given rules file(s), when applying the filter")
        parser.add_argument("-c", "--output-disabled-rules",
                            action="store_true",
                            dest="output_disabled_rules",
                            required=False,
                            default=False,
                            help="include disabled rules in the output as commented out lines.")
        parser.add_argument("-n", "--normalize", "--better", "--iso8601",
                            action="store_true",
                            dest="normalize",
                            required=False,
                            default=False,
                            help="try to convert date, MITRE ATT&CK, and cve related metadata values to conform to the \
                                  BETTER schema for filtering and statistics.  Dates are normalized to the \
                                  format YYYY-MM-DD and CVEs to YYYY-<num>.  Also, 'sid' is removed from the metadata.")
        parser.add_argument("-e", "--enhance",
                            action="store_true",
                            dest="enhance",
                            required=False,
                            default=False,
                            help="enhance metadata by adding additional key-value pairs based on the rules.")
        parser.add_argument("-t", "--ignore-classtype", "--ignore-classtype-keyword",
                            action="store_true",
                            dest="ignore_classtype_keyword",
                            required=False,
                            default=False,
                            help="don't incorporate the 'classtype' keyword and value from the rule into the metadata structure for filtering and reporting.")
        parser.add_argument("-g", "--ignore-filename",
                            action="store_true",
                            dest="ignore_filename",
                            required=False,
                            default=False,
                            help="don't incorporate the 'filename' keyword (filename of the rules file) into the metadata structure for filtering and reporting.")
        parser.add_argument("-m", "--modify-metadata",
                            action="store_true",
                            dest="modify_metadata",
                            required=False,
                            default=False,
                            help="modify the rule metadata keyword value on output to contain the internally tracked and normalized metadata data.")
        parser.add_argument("-p", "--pfmod", "--pfmod-file",
                            action="store",
                            dest="pfmod_file",
                            required=False,
                            default=None,
                            help="YAML file of directives to apply actions on post-filtered rules based on filter strings.")
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
    print_summary = False

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

    if args.display_max is None:
        # option set but not max given; defaults to 16
        args.display_max = 16
        print_summary = True
    elif args.display_max == -1:
        # option not set
        print_summary = False
    else:
        print_summary = True

    # create object
    rs = Ruleset(rules=args.rules, metadata_filter=args.metadata_filter,
                 enable_all_rules=args.enable_all_rules,
                 summary_max=args.display_max,
                 output_disabled_rules=args.output_disabled_rules,
                 ignore_classtype_keyword=args.ignore_classtype_keyword,
                 ignore_filename=args.ignore_filename,
                 normalize=args.normalize,
                 enhance=args.enhance,
                 modify_metadata=args.modify_metadata,
                 pfmod_file=args.pfmod_file)

    if args.stats is None or rs.metadata_filter is not None:
        filtered_sids = rs.filter_ruleset()
    else:
        filtered_sids = [s for s in rs.metadata_dict.keys()]
    # print_debug("filtered_sids: {}".format(filtered_sids))

    pfmod_sids = None
    if rs.pfmod_file:
        pfmod_sids = rs._pfmod_apply(rs.pfmod_file, filtered_sids)
        # print_debug("pfmod_sids: {}".format(pfmod_sids))

    # if stats requested, print out stats on filtered/modified ruleset
    if args.stats is not None:
        keys = []
        keyonly = False
        rs.print_header(sids=filtered_sids)
        if len(args.stats) > 0:
            # print stats for specified key(s)
            keys = args.stats
        else:
            # print stats for ALL keys
            keys = rs.keys_dict.keys()
            keyonly = True

        for key in keys:
            rs.print_stats(key=key, keyonly=keyonly, sids=None if rs.metadata_filter is None else filtered_sids)
        print("")
        sys.exit(0)

    if args.outfile == "<stdout>":
        if print_summary:
            rs.print_ruleset_summary(filtered_sids, pfmod_sids)
        else:
            rs.output_rules(sid_list=filtered_sids, outfile=None)
    else:
        if print_summary:
            rs.print_ruleset_summary(filtered_sids, pfmod_sids)
        rs.output_rules(sid_list=filtered_sids, outfile=args.outfile)


if __name__ == "__main__":
    main()
