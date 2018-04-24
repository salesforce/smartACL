#!/usr/bin/env python

# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import sys
from linkdef import *

def cidr_to_mask(cidr):
    return '.'.join([str((0xffffffff << (32 - int(cidr)) >> i) & 0xff)
                    for i in [24, 16, 8, 0]])


def acl_parser(filename, policy, remarkasname=False, DEBUG=False):
    """
    Parsing Cisco ACL
    :param filename: could be a file or if it's use as module a Python list with all the ACLs
    :param policy: policy object
    :param remarkasname: use remarks comments as rule names
    :param DEBUG: DEBUG flag
    :return: True
    """
    rule_name = ''

    if type(filename) is not list:
        f = open(filename, 'r')
    else:
        f = filename

    # Usually Cisco ACL is using wildcard, but it's possible to find a mask with prefix. It's not possible to have an ACL
    # with wildcard and without, so we need to find if there the ACL is using wildcard or not
    acl_wild = True
    for line in f:
        line = line.strip()
        if line.startswith('permit') or line.startswith('deny'):
            if '/' in line:
                acl_wild = False
                break
        # There are much better ways to check this, but this will work in a fast way
        line_s = line.split()
        if len(line_s) > 4:
            if line_s[3].startswith('0') and line_s[3] != '0.0.0.0':
                # We find one wildcard, we don't need to continue reading the rest of the file
                break
    if type(f) is not list:
        f.seek(0)
    for line in f:
        iPos = 0
        line = line.strip()
        if DEBUG:
            print '\n[DEBUG] Cisco ACL Parser:', line
        # Lines with a reference to any object using '{<name>}' are ignored
        if (line.startswith('permit') or line.startswith('deny')) and not 'established' in line and not '{' in line:
            sPortACL = '0'
            dPortACL = '0'
            aclsp = line.split()

            lPermit = aclsp[iPos] == 'permit'
            iPos += 1

            # Protocol
            protocolACL = aclsp[iPos]
            if protocolACL not in ['tcp', 'udp', 'icmp', 'igmp', 'pim', 'ip', 'ospf']:
                try:
                    int(protocolACL)
                    if protocolACL == '6':
                        protocolACL = 'tcp'
                    elif protocolACL == '17':
                        protocolACL = 'udp'
                    elif protocolACL == '1':
                        protocolACL = 'icmp'
                except ValueError:
                    if protocolACL == 'host':
                        protocolACL = 'ip'
                        iPos -= 1 # Exceptional case when the ACL is just "permit host X.X.X.X "
                    elif '.' in protocolACL:
                        protocolACL = 'ip'
                        iPos -= 1 # Exceptional case when the ACL is just "permit X.X.X.X W.W.W.W"
                    elif 'any' in protocolACL:
                        protocolACL = 'ip' # Exceptional case when ACL is just "deny any log"
                    else:
                        print '[ERROR] Error processing file: ', filename
                        print '[ERROR] Can\'t parse the line: ', line
                        print '[ERROR] Error with:', protocolACL
                        print 'Press Enter to continue...'
                        raw_input()
                        continue
            iPos += 1

            try:
                # Source/Mask
                if aclsp[iPos] == 'any':
                    sourceIPACL = 'any'
                    iPos += 1
                elif aclsp[iPos] == 'log':
                    sourceIPACL = 'any'
                    iPos += 1
                else:
                    if aclsp[iPos] == 'host':
                        if not acl_wild:
                            sourceIPACL = aclsp[iPos+1] + '/255.255.255.255'
                        else:
                            sourceIPACL = aclsp[iPos+1] + '/0.0.0.0'
                        iPos += 2
                    else:
                        if '/' in aclsp[iPos]:
                            sourceIPACL = aclsp[iPos].split('/')[0] + '/' + cidr_to_mask(aclsp[iPos].split('/')[1])
                            iPos += 1
                        else:
                            if len(aclsp)  == iPos + 1: # ACL only with permit IP
                                if not acl_wild:
                                    sourceIPACL = aclsp[iPos] + '/255.255.255.255'
                                else:
                                    sourceIPACL = aclsp[iPos] + '/0.0.0.0'
                            else:
                                sourceIPACL = aclsp[iPos] + '/' + aclsp[iPos + 1]
                            iPos += 2
                if sourceIPACL == 'any' and acl_wild:
                    sourceIPACL = '0.0.0.0/255.255.255.255'
                elif sourceIPACL == 'any' and not acl_wild:
                    sourceIPACL = '0.0.0.0/0.0.0.0'

                # It's possible than the ACL would be "permit host X.X.X.X"
                if len(aclsp) <= iPos:
                    if acl_wild:
                        destIPACL = '0.0.0.0/255.255.255.255'
                    else:
                        destIPACL = '0.0.0.0/0.0.0.0'
                else:
                    # Source Operator
                    if protocolACL == 'tcp' or protocolACL == 'udp':
                        if aclsp[iPos] == 'eq':
                            sPortACL = aclsp[iPos+1]
                            iPos += 2
                        elif aclsp[iPos] == 'neq' or aclsp[iPos] == 'lt' or aclsp[iPos] == 'gt':
                            if aclsp[iPos] == 'gt':
                                sPortACL = str(int(aclsp[iPos+1]) + 1) + '-65535'
                                iPos += 2
                            elif aclsp[iPos] == 'lt':
                                sPortACL = '0-' + str(int(aclsp[iPos+1]) - 1)
                                iPos += 2
                            elif aclsp[iPos] == 'neq':
                                sPortACL = '0-' + str(int(aclsp[iPos+1]) - 1) + ',' + str(int(aclsp[iPos+1]) + 1) + '-65535'
                                iPos += 2
                        elif aclsp[iPos] == 'range':
                            sPortACL = aclsp[iPos+1] + "-" + aclsp[iPos+2]
                            iPos += 3
                        if '-' in sPortACL:
                            # ftp-data has a '-' and now is late to change '-' as divisor for ranges
                            if 'ftp-data' in sPortACL:
                                sPortACL = sPortACL.replace('ftp-data', 'ftpdata')
                            t1 = sPortACL.split('-')[0]
                            t2 = sPortACL.split('-')[1]
                            if t1 in port_number:
                                t1 = port_number[t1]
                                sPortACL = t1 + '-' + t2
                            if t2 in port_number:
                                t2 = port_number[t2]
                                sPortACL = t1 + '-' + t2
                        else:
                            if sPortACL in port_number:
                                sPortACL = port_number[sPortACL]

                    # Destination/Mask
                    if aclsp[iPos] == 'any':
                        destIPACL = 'any'
                        iPos += 1
                    else:
                        if aclsp[iPos] == 'host':
                            if not acl_wild: # Checked while checking source
                                destIPACL = aclsp[iPos + 1] + '/255.255.255.255'
                            else:
                                destIPACL = aclsp[iPos+1] + '/0.0.0.0'
                            iPos += 2
                        else:
                            if '/' in aclsp[iPos]:
                                destIPACL = aclsp[iPos].split('/')[0] + '/' + cidr_to_mask(aclsp[iPos].split('/')[1])
                                iPos += 1
                            else:
                                destIPACL = aclsp[iPos] + '/' + aclsp[iPos + 1]
                                iPos += 2
                    if destIPACL == 'any' and acl_wild:
                        destIPACL = '0.0.0.0/255.255.255.255'
                    elif destIPACL == 'any' and not acl_wild:
                        destIPACL = '0.0.0.0/0.0.0.0'

                    # Dest Operator
                    if protocolACL == 'tcp' or protocolACL == 'udp':
                        if len(aclsp) > iPos:
                            if aclsp[iPos] == 'eq':
                                dPortACL = aclsp[iPos+1]
                                iPos += 2
                            elif aclsp[iPos] == 'neq' or aclsp[iPos] == 'lt' or aclsp[iPos] == 'gt':
                                if aclsp[iPos] == 'gt':
                                    dPortACL = str(int(aclsp[iPos + 1]) + 1) + '-65535'
                                    iPos += 2
                                elif aclsp[iPos] == 'lt':
                                    dPortACL = '0-' + str(int(aclsp[iPos + 1]) - 1)
                                    iPos += 2
                                elif aclsp[iPos] == 'neq':
                                    dPortACL = '0-' + str(int(aclsp[iPos + 1]) - 1) + ',' + str(int(aclsp[iPos + 1]) + 1) + '-65535'
                                    iPos += 2
                            elif aclsp[iPos] == 'range':
                                dPortACL = aclsp[iPos+1] + "-" + aclsp[iPos+2]
                                iPos += 3
                            if '-' in dPortACL:
                                if 'ftp-data' in dPortACL:
                                    dPortACL = dPortACL.replace('ftp-data', 'ftpdata')
                                t1 = dPortACL.split('-')[0]
                                t2 = dPortACL.split('-')[1]
                                if t1 in port_number:
                                    t1 = port_number[t1]
                                    dPortACL = t1 + '-' + t2
                                if t2 in port_number:
                                    t2 = port_number[t2]
                                    dPortACL = t1 + '-' + t2
                            else:
                                if dPortACL in port_number:
                                    dPortACL = port_number[dPortACL]
            except Exception, error_message:
                print '[ERROR] Error processing file: ', filename
                print '[ERROR] Can\'t parse the line: ', line
                print '[ERROR] ERROR MESSAGE:', error_message
                print 'Press Enter to continue...'
                raw_input()
                continue

            r = policy.new_rule(sourceIPACL,
                                destIPACL,
                                dPortACL,
                                sPortACL,
                                protocolACL,
                                lPermit,
                                acl_wild)

            if type(filename) is list or rule_name == '':
                policy.set_rule_name(r, line)
            else:
                policy.set_rule_name(r, rule_name)
        elif line.startswith('remark'):
            if DEBUG:
                print '\n[DEBUG]', line
            if remarkasname:
                rule_name = line
    if type(filename) is not list:
        f.close()
    return True
"""
    MAIN
"""

if __name__ == "__main__":
    d=False
    policy = FWPolicy(sys.argv[1],sys.argv[1], DEBUG=d)
    acl_parser(sys.argv[1], policy)
    policy.remove_shadowed_rules()
    policy.print_policy()

