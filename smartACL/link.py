#!/usr/bin/env python

# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import sys
import os
import argparse
from linkdef import *
import link_cisco
import link_juniper
import link_pol
import link_fortigate
import tools
import glob


def link(sourceIP, destIP, files, opts):
    """
    Main execution of Link
    :param sourceIP: Source IP
    :param destIP: Destination IP
    :param files: list of files to check 
    :param opts: dictionary with extra parameters
    :return: List of files with TRUE/FALSE if there is a HIT or not
    """
    if sourceIP == '0.0.0.0' and destIP == '0.0.0.0':
        return 'ERROR: Please, at least Source IP or Destination IP can not be 0.0.0.0'
    if type(files) is not list or len(files) < 1:
        return 'ERROR: No files specified.'

    # Initial values for opts
    list_k =     ['sport', 'dport','proto', 'acltype', 'showallmatches', 'showdenyall', 'hideallowall', 'matchanyport', 'summarized', 'capircadef', 'nooutput', 'ignore-line', 'debug']
    list_v_def = ['0',      # sport
                  '0',      # dport
                  'ip',     # proto
                  '',       # acltype
                  False,    # showallmatches
                  False,    # showdenyall
                  True,     # hideallowall
                  True,     # matchanyport
                  False,    # summarized
                  '',       # capircadef
                  False,    # nooutput
                  '',       # ignore-line
                  False]    # debug
    for i,v in enumerate(list_k):
        if v not in opts:
            opts[v] = list_v_def[i]

    ignore_lines = opts['ignore-line']
    if ignore_lines != '':
        ignore_lines = ignore_lines.split(',')
    sport = opts['sport']
    dport = opts['dport']
    if '-' in dport:
        if int(dport.split('-')[0]) > int(dport.split('-')[1]):
            dport = dport.split('-')[1] + '-' + dport.split('-')[0]
    if '-' in sport:
        if int(sport.split('-')[0]) > int(sport.split('-')[1]):
            sport = sport.split('-')[1] + '-' + sport.split('-')[0]

    files_found = {}
    parsed = False

    for sIP in sourceIP.split(','):
        for dIP in destIP.split(','):
            print '############ CHECKING FLOW ############'
            print sIP, '->', dIP, 'Dest Port: ', dport, 'Source Port: ', sport, 'Protocol:', opts['proto']
            print '############## ACL CHECK ##############'
            for filename in files:
                policy = FWPolicy('', filename, opts['debug'])
                if opts['acltype'] != '':
                    type_ext = opts['acltype']
                else:
                    type_ext = filename.split('.')[len(filename.split('.')) - 1]
                if type_ext == 'acl' or type_ext == 'ncl' or type_ext == 'fcl':
                    parsed = link_cisco.acl_parser(filename, policy, remarkasname=False, DEBUG=opts['debug'])
                elif type_ext == 'jcl':
                    parsed = link_juniper.jcl_parser(filename, policy, opts['debug'])
                elif type_ext == 'pol':
                    if opts['capircadef'] == '':
                        print 'Can\'t parse POL file without a valid Capirca Definitions Directory. Ignoring file:', filename
                        continue
                    parsed = link_pol.pol_parser(filename, opts['capircadef'], policy, opts['debug'])
                elif type_ext == 'ftg':
                    parsed = link_fortigate.for_parser(filename, policy, DEBUG=opts['debug'])
                else:
                    print 'Can\'t detect ACL type. Ignoring file:', filename
                    continue # if the file extension is not known next one
                    # TODO: Link should detect ff it's a file and can't detect is is ACL/JCL, etc. it should through an error

                if parsed:
                    if not opts['summarized']:
                        sys.stdout.write('Processing file: {0:<64}'.format(filename))
                    if opts['debug']: policy.print_policy()

                    # Ignoring lines
                    if len(ignore_lines) > 0:
                        num_rule = policy.get_rules_number()
                        while num_rule > 0:
                            rule = policy.get_rule(num_rule)
                            if not rule[0].startswith('^'):  # Disabled rules
                                if rule[0] in ignore_lines:
                                    policy.remove_rule(num_rule)
                            num_rule -= 1

                    rules_found = policy.link(sIP, dIP, dport, sport, opts['proto'], rules_exclude=[], show_deny=opts['showdenyall'], hide_allow_all=opts['hideallowall'], showallmatches=opts['showallmatches'], anyport=opts['matchanyport'])
                    if len(rules_found) > 0:
                        rules_names = []
                        for i in rules_found:
                            rules_names.append(policy.get_rule(i))
                        if filename not in files_found:
                            files_found[filename] = []
                        files_found[filename] = rules_names

                        if not opts['summarized']:
                            for i in rules_found:
                                if rules_found.index(i) > 0:
                                    sys.stdout.write('Processing file: {0:<64}'.format(filename))
                                print tools.color('B', 'red/black') + ' - HIT!!' + tools.color()
                                policy.print_rule(i, color=True)
                                print
                    else:
                        if not opts['summarized']:
                            print ' - no match'
                    del policy
                else:
                    print '[ERROR] Can\'t parse file:', filename

            if opts['summarized']:
                print 'Files processed:', len(files)
                print 'Files NOT matched', len(files) - len(files_found)
                if len(files_found) > 0:
                    print 'Files matched:'
                    for i in files_found:
                        print i
                else:
                    print 'NOT matched in any file'

    return files_found

"""
    MAIN
"""
if __name__ == '__main__':  # pragma: no cover
    parser = argparse.ArgumentParser()
    parser.add_argument('Source', help='Source IP/Network to check. Use 0.0.0.0 for ANY. You can specify more than one source separating them by "," (no spaces)')
    parser.add_argument('Destination', help='Destination IP/Network to check. Use 0.0.0.0 for ANY. You can specify more than one destination separating them by "," (no spaces)')
    parser.add_argument('File', help='File or Directory to check the IPs (you can use * )', nargs='*')
    parser.add_argument('--protocol', help='Value ip/tcp/udp/icmp. IP by default.', default='ip')
    parser.add_argument('--sport', help='Source port. It could be a range (use - to separate ports) (ANY by default).', default='0')
    parser.add_argument('--dport', help='Destination port. It could be a range (use - to separate ports) (ANY by default).', default='0')
    parser.add_argument('--match-any-range-port', dest='matchanyport', help='If a range is used for a port, then any match included in the range is shown', action='store_true')
    parser.add_argument('--showdenyall', help='Show matches with ANY ANY DENY', action='store_true')
    parser.add_argument('--hideallowall', help='Hide matches with ANY ANY PERMIT', action='store_true')
    parser.add_argument('--showallmatches', help='Show all matches instead of stopping with the first found', action='store_true')
    parser.add_argument('--acltype', help='Specifiy the ACL type: acl,ncl,jcl,pol,ftg')
    parser.add_argument('--summarized', help='Show only a summary for the flow/s requested', action='store_true')
    parser.add_argument('--capircadef', help='Capirca definitions directory', default='')
    parser.add_argument('--ignore-line', dest='ignore_term', help='Ignore the following lines (ACL remark for Cisco or Term name for Juniper)', default='')
    parser.add_argument('--nooutput', help='Hide any output (useful as module)', action='store_true')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--foo', help=argparse.SUPPRESS, action='store_true')  # no output at all, just for testing code
    args = parser.parse_args()
    
    if args.foo:
        null = open(os.devnull, 'w')
        sys.stdout = null

    opts = {}
    sIP = args.Source
    dIP = args.Destination
    files = ''

    for i in args.File:
        if '*' in i:
            # Windows platform
            files = glob.glob(args.File)
    if files == '':
        files = args.File

    opts['proto'] = args.protocol
    opts['dport'] = args.dport
    opts['sport'] = args.sport
    opts['matchanyport'] = False
    if args.matchanyport:
        opts['matchanyport'] = True
    opts['acltype'] = ''
    if args.acltype:
        if args.acltype == 'pol' and not args.capircadef:
            print 'ERROR: If you want to use POL (Capirca Policies) you need to specify Capirca Definitions Directory with --capircadef'
            sys.exit(-1)
        opts['acltype'] = args.acltype

    opts['showdenyall'] = args.showdenyall
    opts['hideallowall'] = args.hideallowall
    opts['showallmatches'] = args.showallmatches
    opts['summarized'] = args.summarized
    opts['capircadef'] = args.capircadef
    opts['ignore-line'] = args.ignore_term
    opts['nooutput'] = args.nooutput
    opts['debug'] = args.debug

    r = link(sIP, dIP, files, opts)
    if type(r) is not dict:
        print r
    print r
    sys.exit()




