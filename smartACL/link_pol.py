#!/usr/bin/env python

# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import sys
import os
import copy

from linkdef import *

def cidr_to_mask(cidr):
    return '.'.join([str((0xffffffff << (32 - int(cidr)) >> i) & 0xff)
                    for i in [24, 16, 8, 0]])


NETWORK_DEF = 'NETWORK.net'
SERVICE_DEF = 'SERVICES.svc'
TOKENS = {'source-address': [],
          'destination-address': [],
          'protocol': [],
          'source-port': [],
          'destination-port': [],
          'comment': '',
          'action': ''}
INVALID_TOKENS = ['source-prefix']


def pol_parser(filename, definition_dir, policy, DEBUG=False):
    """
    Parsing Capirca POL files
    :param filename: file with the policy
    :param definition_dir: NETWORK.net and SERVICES.svc directory
    :param policy: policy object
    :param DEBUG: DEBUG flag
    :return: True
    """

    def pol_parse_definitions(filename):
        definitions = {}
        inside = False
        f = open(filename, 'r')
        for line in f:
            line = line.strip()
            if line.startswith('#') or line == '':
                continue
            if '=' in line:
                inside = True
                line_split = line.split('=')
                top = line_split[0].strip()
                if line_split[1].strip() == '':
                    definitions[top] = []
                else:
                    t = line_split[1].strip()
                    if '#' in t:
                        t = t.split('#')[0].strip()
                    definitions[top] = [t]
            elif '=' not in line and inside:
                t = line
                if '#' in t:
                    t = t.split('#')[0].strip()
                definitions[top].append(t)
            else:
                print '[ERROR] Parsing policy file:', filename, 'line', line
                raw_input()

        return definitions

    def process_rule(rule, net_def, ser_def):

        def _get_ip(t, res):
            for i in t:
                if i in net_def:
                    i = net_def[i]
                    _get_ip(i, res)
                else:
                    res.append(i)

        rule['source-name'] = ','.join(rule['source-address'])
        rule['destination-name'] = ','.join(rule['destination-address'])

        # Source IP
        t = []
        _get_ip(rule['source-address'], t)
        t2 = []
        if t == []:
            t2 = ['0.0.0.0/0.0.0.0']
        else:
            for i in t:
                if '/' in i:
                    t2.append(i.split('/')[0] + '/' + cidr_to_mask(i.split('/')[1]))
                else:
                    t2.append(i + '/255.255.255.255')
        rule['source-address'] = ','.join(t2)

        # Destination IP
        t = []
        _get_ip(rule['destination-address'], t)
        t2 = []
        if t == []:
            t2 = ['0.0.0.0/0.0.0.0']
        else:
            for i in t:
                if '/' in i:
                    t2.append(i.split('/')[0] + '/' + cidr_to_mask(i.split('/')[1]))
                else:
                    t2.append(i + '/255.255.255.255')
        rule['destination-address'] = ','.join(t2)

        # Source Port
        t = []
        for i in rule['source-port']:
            if i in ser_def:
                for i2 in ser_def[i]:
                    t.append(i2.split('/')[0])
            else:
                print '[ERROR] Parsing policy file:', filename, 'line', line
                raw_input()
                continue
        if t == []:
            t = ['0']
        rule['source-port'] = ','.join(t)

        # Destination Port
        t = []
        for i in rule['destination-port']:
            if i in ser_def:
                for i2 in ser_def[i]:
                    t.append(i2.split('/')[0])
            else:
                print '[ERROR] Parsing policy file:', filename, 'line', line
                raw_input()
                continue
        if t == []:
            t = ['0']
        rule['destination-port'] = ','.join(t)


    ###### MAIN #####
    net_def = ''
    ser_def = ''
    for file in os.listdir(definition_dir):
        if file == NETWORK_DEF or file == filename.split('/')[-1] + '.' + NETWORK_DEF:
            net_def = pol_parse_definitions(definition_dir + '/' + file)
        elif file == SERVICE_DEF or file == filename.split('/')[-1]+ '.' + SERVICE_DEF:
            ser_def = pol_parse_definitions(definition_dir + '/' + file)

    if net_def == '' or ser_def == '':
        print '[ERROR] Network and/or Services definitions couldn\'t be loaded'
        raw_input()
        return False

    inside_term = False
    invalid_rule = False
    header = False
    f = open(filename, 'r')
    new_rule = copy.deepcopy(TOKENS)

    # Pre-parsing the file to "fix" small format issues:
    data_file = []
    for line in f:
        line = line.strip()
        if line.startswith('}'):
            if line.split('}')[1].strip() != '':
                data_file.append('}')
                line = line[1:]
        data_file.append(line)

    for line in data_file:
        line = line.strip()
        if DEBUG:
            print '\n[DEBUG] POL ACL Parser:', line
        if line.startswith('header'):
            header = True
            continue

        if header:
            if line.startswith('}'):
                header = False
            continue

        if line.startswith('#') or line == '':
            continue
        if line.startswith('term'):
            if inside_term:
                print '[ERROR] Parsing policy file:', file, 'line', line
                raw_input()
                continue
            inside_term = True
            rule_name = line.split('{')[0].split(' ')[1].strip()
            del new_rule
            new_rule = copy.deepcopy(TOKENS)
            continue
        elif line.startswith('}'):
            inside_term = False
            if DEBUG:
                print '\n[DEBUG] POL ACL Parser. NEW_RULE:', new_rule
            process_rule(new_rule, net_def, ser_def)
            if DEBUG:
                print '\n[DEBUG] POL ACL Parser. NEW_RULE PROCESSED:', new_rule

            if not invalid_rule:
                if len(new_rule['protocol']) == 0:
                    new_rule['protocol'] = ['ip']
                for i in new_rule['protocol']:
                    r = policy.new_rule(new_rule['source-address'], new_rule['destination-address'], new_rule['destination-port'], new_rule['source-port'], i, new_rule['action'] == 'accept', False, new_rule['source-name'], new_rule['destination-name'])
                    policy.set_rule_name(r, rule_name)
                    policy.set_rule_comment(r, new_rule['comment'])

            invalid_rule = False
            continue

        token = line.split('::')[0].strip()
        if token in INVALID_TOKENS:
            invalid_rule = True
        elif token in TOKENS:
            if token == 'comment' or token == 'action':
                new_rule[token] = line.split('::')[1].strip()
            else:
                v = line.split('::')[1].strip()
                for i in v.split(' '):
                    if i.strip() == '':
                        continue
                    new_rule[token].append(i)

    return True

if __name__ == "__main__":
    policy = FWPolicy(sys.argv[1], sys.argv[1])
    pol_parser(sys.argv[1], sys.argv[2], policy, True)
    policy.print_policy()
    policy.split_ips()
    print '\n\n\n\nPOLICY SPLIT!\n\n\n\n'
    policy.print_policy()

