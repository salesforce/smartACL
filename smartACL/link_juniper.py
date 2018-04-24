#!/usr/bin/env python

# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

from linkdef import *
import sys

def cidr_to_mask(cidr):
    return '.'.join([str((0xffffffff << (32 - int(cidr)) >> i) & 0xff)
                    for i in [24, 16, 8, 0]])

def parse_data_store(policy, rulenumber, attribute, data):
    if 'address' in attribute:
        if len(data.split(',')) >= 1:
            temp = data.split(',')
            for i in range(len(temp)):
                if ':' in temp[i]:
                    # IPv6
                    pass
                elif '/' in temp[i]:
                    tip = temp[i].split('/')
                    tip[1] = cidr_to_mask(tip[1])
                    temp[i] = tip[0] + '/' + tip[1]
                else:
                    temp[i] = temp[i] + '/255.255.255.255'
            tdata = ''
            for i in temp:
                tdata = tdata + ',' + i
            data = tdata[1:]

    if 'port' in attribute:
        if '[' in data:
            tdata = data.replace('[', '').replace(']', '').strip()
            tdata = tdata.split()
            data = ''
            for i in tdata:
                data = data + ',' + i
            data = data[1:]

    policy.set_rule_dyn_data(rulenumber, attribute, data)


def jcl_parser(filename, policy, DEBUG=False):
    """
    Parsing Juniper ACL
    :param filename: could be a file or if it's use as module a Python list with all the ACLs
    :param policy: policy object
    :param DEBUG: DEBUG flag
    :return: True
    """
    lfilter = False
    lterm = False
    lthen = False
    laction_set = False
    filterjcl = ''
    termjcl = ''
    value = ''
    rulenumber = 0
    jcl = ''
    oldline = ''
    data_section = ''

    # "pre-parsing" the file

    if type(filename) is not list:
        f = open(filename, 'r')
    else:
        f = filename

    for line in f:
        line = line.strip()
        if line == '{': # fixing some JCL with only '{' that belongs to the previous line
            oldline = oldline + ' ' + line

        if not oldline == '':
            if jcl == '':
                jcl = oldline
            else:
                jcl = jcl + '\n' + oldline

        oldline = line

    jcl = jcl + '\n' + oldline # Writing the last line

    for line in jcl.split('\n'):
        line = line.strip()
        if lfilter:
            if line.startswith('/*') or line.startswith('**') or line.startswith('*/') or line == '':
                continue

            if DEBUG:
                print '[DEBUG]', line

            firstw = line.split()[0]
            if ';' in firstw:
                firstw = firstw[:-1]

            if firstw in jclbanwords and \
               'fragment-offset 0' not in line: # Exception for fragment-offset 0 -> used in ICMP and only match for the first fragmented packet
                # Reset the value of the term and wait for the next one
                termjcl = '^' + policy.get_rule_name(rulenumber)
                policy.set_rule_name(rulenumber, termjcl)
                policy.set_empty_rule(rulenumber)
                lterm = False
                value = ''
                data_section = ''

            if '{' in line:
                # Checking last char is '{'
                if line[-1:] != '{':
                    print '[ERROR] "{" is not last character'
                    continue
                if line.startswith('filter'):
                    filterjcl = line.split('{')[0].strip()
                    policy.set_name(filterjcl)
                    value = ''
                    rulenumber = 0
                elif line.startswith('term'):
                    termjcl = line.split('{')[0].strip()
                    rulenumber = policy.new_empty_rule(False)
                    policy.set_rule_name(rulenumber, termjcl)
                    value = ''
                elif line.startswith('inactive'):
                        # If line term is inactive, still we added, but empty.
                        # We have to the same that the line starts with 'term'
                        termjcl = '^' + line.split('{')[0].strip()
                        rulenumber = policy.new_empty_rule(False)
                        policy.set_rule_name(rulenumber, termjcl)
                        # And we remove the rule
                        policy.set_empty_rule(rulenumber)
                        lterm = False
                        value = ''
                        data_section = ''
                elif line.startswith('then') and lterm:
                    lthen = True
                    laction_set = False
            elif '}' in line and lterm:
                if not data_section == '':
                    parse_data_store(policy, rulenumber,jcldict[data_section], value)
                if lthen and not laction_set: # Some rules could have a then section but not 'accept/discard', these lines can't be processed
                    policy.set_empty_rule(rulenumber)
                value = ''
                data_section = ''
                lthen = False
                laction_set = False

            if firstw in jclwords and lterm:
                if '{' in line:
                    data_section = firstw
                else:
                    # The value is directly there. There are not {}
                    data_section = firstw
                    # jlcdict contains a list of Juniper special words per section.
                    # A dictionary was created to map these values with FWRules attributes
                    parse_data_store(policy, rulenumber, jcldict[data_section], line.split(' ', 1)[1][:-1])
                    value = ''
                    data_section = ''
            elif not '{' in line and not '}' in line and lterm:
                if lthen:
                    if firstw == 'accept':
                        laction_set = True
                        policy.set_rule_action(rulenumber, True)
                    elif firstw == 'discard':
                        laction_set = True
                        policy.set_rule_action(rulenumber, False)
                else:
                    # Juniper allow to add "inactive" in any place of the rule, to have only part of it inactive
                    if value == '' and not line.startswith('inactive'):
                        value = line.split(';')[0]  # Removing ";"
                    elif not line.startswith('inactive'):
                        value = value + ',' + line.split(';')[0]

        if '{' in line and line.startswith('term'):
            lterm = True

        if '{' in line and line.startswith('family inet'):
            lfilter = True

    return True


"""
    MAIN
"""


if __name__ == "__main__":
    policy = FWPolicy('', sys.argv[1])
    jcl_parser(sys.argv[1], policy)
    policy.print_policy()

    print '-----------------'
    print 'SPLITTING POLICY'
    print '-----------------'

    policy.split_ips()
    policy.print_policy()
