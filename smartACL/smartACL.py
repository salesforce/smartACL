#!/usr/bin/env python

# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import sys
import os
import glob
import argparse
from copy import deepcopy

import link_cisco  # This import needs to be before linkdef
import link_juniper
import link_pol
import tools  # This import needs to be before linkdef

try:
    import third_party.ipaddress as ipaddress
except:
    raise ImportError("The ip address module is not installed, exiting...")

from linkdef import *


def smartCheck(policy_del, policy_add,
               list_rules_match_add=None,
               matched_rules_extended=None,
               subpolicy=False,
               print_add_matches=False,
               print_progress=False,
               DEBUG=False):
    """
    smartCheck will compare two policies trying to find if we can remove from the first policy rules that they are already included in the second one.

    :param policy_del: Rules that usually we want to check if we can delete
    :param policy_add: Rules that usually we want to check if they "cover" rules to be deleted
    :param list_rules_match_add: (OUTPUT Parameter) list of all rules matching the "del" rule. Usually this parameter is internal and it is only needed for non-contiguous wildcard and split networks
    :param matched_rules_extended: (OUTPUT Parameter) dictionary with rules can be removed and their matches
    :param subpolicy: True when checking a subpolicy created from a parent one. For example when a big network needs to be matched by split networks
    :param print_add_matches: Switch to see which rules match the one to be removed
    :param print_progress: Swith for a very verbose mode
    :param DEBUG: debug flag
    :return: List of rules matched
    """
    def _is_any(wild, ip):
        if wild:
            return ip == '0.0.0.0/255.255.255.255'
        else:
            return ip == '0.0.0.0/0.0.0.0'

    def _is_ip_equal(ip1, ip2):
        if ip1 == ip2:
            return True
        try:
            ipa1 = ipaddress.IPv4Network(unicode(ip1))
            ipa2 = ipaddress.IPv4Network(unicode(ip2))
        except:
            return False
        return ipa1 == ipa2

    tools.DEBUG(DEBUG, 'smartCheck', 'Entering smartCheck. subpolicy:', subpolicy)

    # Sentinel values
    if list_rules_match_add is None:
        list_rules_match_add = []

    if matched_rules_extended is None:
        matched_rules_extended = {}

    # It reduces complexity if policy_add is always split for non-cont
    if not subpolicy:
        policy_add.split_non_contiguous_wild()

    rules_to_remove = []
    rules_not_matched = []
    a = policy_del.get_rules_number()
    for x in range(1, a+1):
        if print_progress and not subpolicy:
            print 'Processing rule:', x, 'out of', a
        rule_found = False
        non_contigouos_found = False
        fake_any = False
        is_0_any = True

        ruled = policy_del.get_rule(x)
        tools.DEBUG(DEBUG, 'smartCheck', 'get_rule:', ruled)

        if ruled[0] in rules_not_matched:
            continue

        # Usually the last rule it's a DENY IP ANY ANY LOG, if this is the case, we skip it
        if x == a:
            if _is_any(ruled[7], ruled[1]) and _is_any(ruled[7], ruled[2]) and not ruled[6]:
                continue

        if ruled[0].startswith('^'):  # Especial rule, usually empty or inactive
            list_rules_match_add.append(ruled[0])
            rule_found = True

        # if DSMO rule was split and one of the networks didn't match. NOT continue
        if subpolicy:
            if ruled[0].startswith('split dsmo rule'):
                if ruled[0].split('}')[1] in rules_not_matched:
                    continue

        wildcard = ruled[7]
        # The wildcard 0.0.0.0 (host wildcard) is not working with ipaddress library as wildcard, only as netmask
        # the same happens with 255.255.255.255 so:
        # 0.0.0.0 wildcard -> 255.255.255.255 netmask
        # 255.255.255.255 wilcard -> 0.0.0.0 netmask
        if wildcard and (ruled[1] == '0.0.0.0/0.0.0.0' or ruled[2] == '0.0.0.0/0.0.0.0'):
            # Link use 0.0.0.0 usually as ANY. This is the specific case when the host 0.0.0.0/32 is being request to be checked
            is_0_any = False

        if not rule_found and (ruled[1] == '' or ruled[2] == ''):  # Empty rule
            continue

        sIP = ruled[1]
        if wildcard  and '/0.0.0.0' in sIP:
            sIP = sIP.split('/')[0] + '/255.255.255.255'
        elif wildcard and sIP == '0.0.0.0/255.255.255.255':
            sIP = sIP.split('/')[0] + '/0'
        else:
            if wildcard:
                non_contigouos_found = not tools.wild_is_contiguous(sIP.split('/')[1])

        dIP = ruled[2]
        if wildcard == True and '/0.0.0.0' in dIP:
            dIP = dIP.split('/')[0] + '/255.255.255.255'
        elif wildcard == True and dIP == '0.0.0.0/255.255.255.255':
            dIP = dIP.split('/')[0] + '/0'
        else:
            if wildcard:
                non_contigouos_found = non_contigouos_found or not tools.wild_is_contiguous(dIP.split('/')[1])


        dPort = ruled[3]
        sPort = ruled[4]
        proto = ruled[5]
        action = ruled[6]


        # If the rule that we are checking has non-cont wild, we need to split it and check again
        if non_contigouos_found:
            # If this is a subpolicy (policy_temp) and we find a non-cont, we can't continue checking
            # in subpolicies are not allowed non-cont
            if subpolicy:
                while len(list_rules_match_add) > 0:
                    list_rules_match_add.pop()
                return []
            policy_del_temp = FWPolicy('del-temp', 'temp', DEBUG)
            policy_del_temp.new_rule(ruled[1], ruled[2], ruled[3], ruled[4], ruled[5], ruled[6], ruled[7], '', '')
            policy_del_temp.split_non_contiguous_wild()
            tools.DEBUG(DEBUG, 'smartCheck', 'Non contiguous found. Splitting policy.', ruled)
            if policy_del_temp.check_if_any_non_contiguous():
                tools.DEBUG(DEBUG, 'smartCheck', 'Non contiguous found after policy splitting. Can not continue.', ruled)
                if subpolicy:
                    while len(list_rules_match_add) > 0:
                        list_rules_match_add.pop()
                    return []
                else:
                    if ruled[0] in rules_to_remove:
                        rules_to_remove.remove(ruled[0])
                    rules_not_matched.append(ruled[0])
                    while len(list_rules_match_add) > 0:
                        list_rules_match_add.pop()
            else:
                # When a rule is split, all the new rules will have the same name of the parent rule
                # While this is the expected behaviour, it creates a problem, because we need to match
                # the whole new temp policy, to know that the parent rule is fully covered
                # To do that, we need to rename the temp-policy with different names
                policy_temp_len = policy_del_temp.get_rules_number()
                for icont in range(1, policy_temp_len + 1):
                    policy_del_temp.set_rule_name(icont, 'split dsmo rule - ' + str(icont) + ' }' + ruled[0])

                tempPolicy_rules_matched = smartCheck(policy_del_temp, policy_add, list_rules_match_add, matched_rules_extended, subpolicy=True, print_add_matches=False, DEBUG=DEBUG)
                if len(tempPolicy_rules_matched) == policy_temp_len:
                    rule_found = True
                else:
                    rules_not_matched.append(ruled[0])
                    if ruled[0] in rules_to_remove:
                        rules_to_remove.remove(ruled[0])
        elif not rule_found:
            if dPort != '0' and sPort != '0':
                tools.DEBUG(DEBUG, 'smartCheck', 'request check flow:', sIP.split('/')[0], dIP.split('/')[0], dPort, sPort, proto)
                check1 = policy_add.link(sIP.split('/')[0], dIP.split('/')[0], dPort, sPort, proto, show_deny=True, hide_allow_all=False, strict_search=True, is_0_any=is_0_any)
                tools.DEBUG(DEBUG, 'smartCheck', 'requested check flow answer', check1)
            else:
                '''
                When dport or sport are 0, we want to check ALL ports, so ALL ports should be allowed. When LINK sees a 0
                in port (destination or source) is going to match with ANY rule that matches source/destination IPs, because 0 in port means ANY rule.
                In this case, we need something different, 0 it doesn't mean any, it means ALL. So, we have to perform a STRICT SEARCH:
                    - Check the first rule matched
                    - If we hit a DENY, clearly ALL ports are NOT allowed.
                    - If we hit any other rule, we need to verify if would need to catch any DENY that could hit (NO STRICT SEARCH)
                '''
                tools.DEBUG(DEBUG, 'smartCheck', 'dport or sport is 0. Checking ALL')
                tools.DEBUG(DEBUG, 'smartCheck', 'request check flow:', sIP.split('/')[0], dIP.split('/')[0], dPort, sPort, proto)
                check1 = policy_add.link(sIP.split('/')[0], dIP.split('/')[0], dPort, sPort, proto, show_deny=True, hide_allow_all=False, strict_search=True, is_0_any=is_0_any)
                tools.DEBUG(DEBUG, 'smartCheck', 'dport/sport != 0 first requested check flow answer', check1)
                if len(check1) > 0:
                    fake_any = False
                    '''
                    There is a candidate rule for ALL ports, now it's time to check if there is ANY DENY above that could affect
                    
                    DENY HUNT Example:
                    ACL1:
                    permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127

                    ACL2:
                    deny tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127 eq 22
                    permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127    

                    The line1 in ACL1 will match with line2 in ACL2. After that, we need to check if a DENY rule is matching also before the permit
                    '''
                    rule_matched = policy_add.get_rule(check1[0])

                    if rule_matched[6] or True: # Permit = TRUE
                        tools.DEBUG(DEBUG, 'smartCheck', 'request check flow (DENY HUNT):', sIP.split('/')[0], dIP.split('/')[0], dPort, sPort, proto)
                        check2 = policy_add.link(sIP.split('/')[0], dIP.split('/')[0], dPort, sPort, proto,  show_deny=True, hide_allow_all=False, strict_search=False, is_0_any=is_0_any)
                        tools.DEBUG(DEBUG, 'smartCheck', 'dport/sport != 0 second requested check flow answer (DENY HUNT)', check2)
                        if len(check2) > 0:
                            for i in check2:
                                rule_matched2 = policy_add.get_rule(i)
                                # If there was a match in the 'DENY HUNT' we need to be sure that:
                                # - if the original rule is an ACCEPT, the HUNT is for a DENY
                                # - if the original rule is a DENY, the HUNT is for an ACCEPT
                                if ((rule_matched[6] and not rule_matched2[6]) or
                                   (not rule_matched[6] and rule_matched2[6])):
                                    tools.DEBUG(DEBUG, 'smartCheck', 'Matched DENY. FAKE ANY')
                                    # We found a rule matching with a DENY ABOVE the ANY, so, the ANY is "fake"
                                    fake_any = True
                                    break

            matching_action = False
            if len(check1) > 0 and not fake_any:
                rule_matched = policy_add.get_rule(check1[0])
                matching_action = action == rule_matched[6]

            if matching_action:
                # Action
                if action != rule_matched[6]:
                    continue
                # Adding every matching
                t = rule_matched[0]
                if t not in list_rules_match_add:
                    list_rules_match_add.append(t)
                tools.DEBUG(DEBUG, 'smartCheck', 'Matching rule', check1, 'subpolicy', subpolicy, 'list_rules_match_add:', list_rules_match_add)

                # Check is the src/dst that we are looking for is exactly the same we found
                if not (_is_ip_equal(ruled[1], rule_matched[1]) and _is_ip_equal(ruled[2], rule_matched[2])):
                    # When smartCheck is called, all non-contiguous wildcards are split, so if at this point
                    # we found a match, either in the del_policy or in the add_policy, the rule can't be marked as
                    # rule match.
                    if wildcard:
                        if not _is_any(rule_matched[7], rule_matched[1]):
                            non_contigouos_found = not tools.wild_is_contiguous(rule_matched[1].split('/')[1])
                        if not _is_any(rule_matched[7], rule_matched[2]):
                            non_contigouos_found = non_contigouos_found or not tools.wild_is_contiguous(rule_matched[2].split('/')[1])
                        # If there is a non-cont wild in the matched rule, we need to go to the next rule, we can't do more
                        if non_contigouos_found:
                            t = rule_matched[0]
                            if t in list_rules_match_add:
                                list_rules_match_add.remove(t)
                            continue

                    tools.DEBUG(DEBUG, 'smartCheck', 'working with IPs', sIP, dIP, rule_matched[1], rule_matched[2])

                    n1s = ipaddress.IPv4Network(unicode(sIP))
                    n1d = ipaddress.IPv4Network(unicode(dIP))

                    if _is_any(rule_matched[7], rule_matched[1]):
                        n2s = ipaddress.IPv4Network(u'0.0.0.0/0')
                    else:
                        if '/0.0.0.0' in rule_matched[1]: # This will happen only with wildcard = True
                            # The wildcard 0.0.0.0 (host wildcard) is not working with ipaddress library
                            n2s = ipaddress.IPv4Network(unicode(rule_matched[1].split('/')[0] + '/255.255.255.255'))
                        else:
                            n2s = ipaddress.IPv4Network(unicode(rule_matched[1]))

                    if _is_any(rule_matched[7], rule_matched[2]):
                        n2d = ipaddress.IPv4Network(u'0.0.0.0/0')
                    else:
                        if '/0.0.0.0' in rule_matched[2]:
                            # The wildcard 0.0.0.0 (host wildcard) is not working with ipaddress library
                            n2d = ipaddress.IPv4Network(unicode(rule_matched[2].split('/')[0] + '/255.255.255.255'))
                        else:
                            n2d = ipaddress.IPv4Network(unicode(rule_matched[2]))

                    if n1s.compare_networks(n2s) < 0 and n1s != ipaddress.IPv4Network(u'0.0.0.0/0'):
                        new_sources = list(n1s.address_exclude(n2s))
                    else:
                        new_sources = [n1s]

                    if n1d.compare_networks(n2d) < 0 and n1d != ipaddress.IPv4Network(u'0.0.0.0/0'):
                        new_dest = list(n1d.address_exclude(n2d))
                    else:
                        new_dest = [n1d]

                    tools.DEBUG(DEBUG, 'smartCheck', 'working with IPs (2)', sIP, dIP, rule_matched[1], rule_matched[2], new_sources, new_dest)

                    if new_sources[0] != n1s or new_dest[0] != n1d:
                        tools.DEBUG(DEBUG, 'smartCheck', 'Creating new policy with smaller network')
                        tools.DEBUG(DEBUG, 'smartCheck', 'Sources:', new_sources, 'A:', new_sources[0], type(new_sources[0]), 'B:', n1s, type(n1s))
                        tools.DEBUG(DEBUG, 'smartCheck', 'Dest', new_dest)
                        policy_del_temp = FWPolicy('del-temp', 'temp', DEBUG)
                        for new_s in new_sources:
                            for new_d in new_dest:
                                irule_number = policy_del_temp.new_rule(str(new_s.with_hostmask) if wildcard else str(new_s.with_netmask),
                                                                        str(new_d.with_hostmask) if wildcard else str(new_d.with_netmask),
                                                                        ruled[3], ruled[4], ruled[5], ruled[6], ruled[7], '', '')
                                # Check comment for non-contiguous rule to understand the naming of the rules
                                policy_del_temp.set_rule_name(irule_number, 'split rule -' + str(irule_number))
                        # We are going to check a subpolicy, so from a rule partially matched, we create a subpolicy
                        # with all networks not mached. And start again, if in this case all of them are matched
                        # then the original rule can be removed
                        tempPolicy_rules_matched = smartCheck(policy_del_temp, policy_add, list_rules_match_add, matched_rules_extended, subpolicy=True, print_add_matches=False, DEBUG=DEBUG)
                        if len(tempPolicy_rules_matched) == policy_del_temp.get_rules_number():
                            rule_found = True
                        else:
                            tools.DEBUG(DEBUG, 'smartCheck', tempPolicy_rules_matched, '!=', policy_del_temp.get_rules_number(), 'Not all policy temp matched. Parent rule not mached.')
                            while len(list_rules_match_add) > 0:
                                list_rules_match_add.pop()
                            if ruled[0].startswith('split dsmo rule'):
                                rules_not_matched.append(ruled[0].split('}')[1])
                            else:
                                rules_not_matched.append(ruled[0])
                            if ruled[0] in rules_to_remove:
                                rules_to_remove.remove(ruled[0])
                    else:
                        # If there isn't any smaller network to check the whole rule is a match
                        rule_found = True
                else:
                    rule_found = True
            else: # if not matching_action
                tools.DEBUG(DEBUG, 'smartCheck', 'Not matching ACTION')
                if subpolicy:
                    tools.DEBUG(DEBUG, 'smartCheck', 'One rule not matched in subpolicy')
                    # list_rules_match_add can't be cleared with assigning an empty value because
                    # is a mutable object, so assigning an empty value will create a new object instead
                    # of removin the old one
                    while len(list_rules_match_add) > 0:
                        list_rules_match_add.pop()
                    return []
                # If we find a line that is not matched we need to be sure that line is not part of a bigger rule
                # for example a DSMO line
                while len(list_rules_match_add) > 0:
                    list_rules_match_add.pop()
                rules_not_matched.append(ruled[0])
                if ruled[0] in rules_to_remove:
                    rules_to_remove.remove(ruled[0])

        if rule_found and len(list_rules_match_add) > 0:
            if ruled[0] not in rules_to_remove:
                rules_to_remove.append(ruled[0])
            if not subpolicy:
                if print_add_matches:
                    print 'RULE MATCHED!'
                    print 'Rule to be removed:', ruled[0]
                    print 'Rules to be added: ', '\n\t\t    '.join(list_rules_match_add)
                    print '-------------------------------'
                matched_rules_extended[ruled[0]] = '\n'.join(list_rules_match_add)
                while len(list_rules_match_add) > 0:
                    list_rules_match_add.pop()

    return rules_to_remove


def smartLog(log_file, check_fakes=True, print_add_matches=False, print_removed_rules='flow', outprint=True, acldir='', verbose=False, ignore_acl_with_remark='', DEBUG=False):
    """
    Check a diff output file for Cisco ACL to check the removed ACL. This method will work only with Cisco ACL

    :param log_file: diff file
    :param check_fakes: Switch to check lines syntactically equal
    :param print_add_matches: Switch to see every rule matched
    :param print_removed_rules: Switch to see every rule removed
    :param outprint: If we want to print the output (so it can be use as module)
    :param verbose: Verbose switch
    :param ignore_acl_with_remark: ACLs containing this remark will be ignored
    :param DEBUG: Debug switch
    :return: List of lists with all data
    """
    num_adds_comments = 0
    num_del_comments = 0
    num_blank_lines_add = 0
    num_blank_lines_del = 0
    num_adds = 0
    num_dels = 0
    inumline = 0
    num_fake_del = 0
    num_non_impact_del = 0
    add_lines = {}
    del_lines = {}
    using_dir = False

    acl = log_file
    add_lines[acl] = []
    del_lines[acl] = []
    num_ignored_rules = 0
    matched_ignored_acl = []

    if DEBUG:
        tools.DEBUG(DEBUG, 'smartLog', 'Entering smartLog')

    if acldir is not None and acldir != '':
        using_dir = True

    with open(log_file) as file:
        for line in file:
            inumline += 1
            line_s = line.split()
            if line.startswith('Index'):
                # A new ACL begins, so we check if the previous one should be ignored
                acl = line_s[1]
                add_lines[acl] = []
                del_lines[acl] = []

            if using_dir:
                if not add_lines[acl]:
                    if acl in os.listdir(acldir):
                        add_lines[acl] = acldir + '/' + acl
                    else:
                        # ACL not found. Raise error.
                        print '[ERROR] Can\'t find the ACL:', acl, 'in directory', acldir
                        if __name__ == "__main__":
                            print 'Press Enter to continue...'
                            raw_input()
            elif line.startswith('+'):
                if not line.startswith('+++'):
                    num_adds += 1
                    if 'remark' in line_s or '+remark' in line_s:
                        if ignore_acl_with_remark != '' and ignore_acl_with_remark in line:
                            matched_ignored_acl.append([line.strip(), acl, inumline])
                        else:
                            num_adds_comments += 1
                    elif len(line_s) == 1:
                        num_blank_lines_add += 1
                    elif 'permit' in line:
                        add_lines[acl].append(line[1:].strip())

            if line.startswith('-'):
                if not line.startswith('---'):
                    num_dels += 1
                    if 'remark' in line_s or '-remark' in line_s:
                        if ignore_acl_with_remark != '' and ignore_acl_with_remark in line:
                            matched_ignored_acl.append([line.strip(), acl, inumline])
                        else:
                            num_del_comments += 1
                    elif len(line_s) == 1:
                        num_blank_lines_del += 1
                    elif 'permit' in line:
                        del_lines[acl].append(line[1:].strip())
    file.close()

    # If an ACL was marked as "ignored" we need to remove it
    if len(matched_ignored_acl) > 0:
        for i in matched_ignored_acl:
            if i[1] in del_lines:
                num_ignored_rules += len(del_lines[i[1]])
                del del_lines[i[1]]


    equal = False
    # Checking if there is any equal line (exact same line)
    if check_fakes and not using_dir:
        for acl, del_li in del_lines.iteritems():
            del_lines_acl = del_li[:]
            for lined in del_lines_acl:
                lined = lined.strip()
                for linea in add_lines[acl]:
                    linea = linea.strip()
                    if lined == linea:
                        equal = True
                        break
                if equal:
                    equal = False
                    num_fake_del += 1
                    del_lines[acl].remove(lined)
                    #add_lines[acl].remove(lined) We don't need to remove from the add

    for acl_name, acls in del_lines.iteritems():
        if len(del_lines[acl_name]) > 0:
            policy_del = FWPolicy('del', acl_name, DEBUG)
            link_cisco.acl_parser(acls, policy_del, DEBUG=DEBUG)
            policy_add = FWPolicy('add', acl_name, DEBUG)
            link_cisco.acl_parser(add_lines[acl_name], policy_add, DEBUG=DEBUG)
            rules_to_remove = smartCheck(policy_del, policy_add, print_add_matches=print_add_matches, print_progress=verbose, DEBUG=DEBUG)
            for i in rules_to_remove:
                num_non_impact_del += 1
                if DEBUG:
                    print '[DEBUG]', del_lines[acl_name]
                    print '[DEBUG][smartLog]Rules to remove:', i
                del_lines[acl_name].remove(i)

    num_dels_real = 0
    for i, v in del_lines.iteritems():
        num_dels_real += len(v)

    # --------------- Printing output ---------------
    if outprint:
        print "Number of lines to be added (+): ", num_adds
        print "-------------------------------------------"
        print "Number of remarks:", num_adds_comments
        print "Number of blank lines:", num_blank_lines_add
        print
        print
        print "Number of lines to be removed (-): ", num_dels
        print "-------------------------------------------------"

        if len(matched_ignored_acl) > 0:
            print
            print "THERE ARE IGNORED ACLS!!!!!"
            for i in matched_ignored_acl:
                print "ACL:", i[1], "REMARK:", i[0], " Diff file line:", i[2]
            print
            print "Total IGNORED REMOVED LINES inside ACLs:", num_ignored_rules
            print

        print "Number of lines reordered:", num_fake_del
        print "Number of lines shadowed:", num_non_impact_del
        print "Number of remarks removed:", num_del_comments
        print "Number of blank lines removed:", num_blank_lines_del
        print
        i = 0
        for acl, rule in del_lines.iteritems():
            i += len(rule)
        print "Number of FLOWS REALLY removed:", i


        if print_removed_rules == 'rack':
            for acl, rule in del_lines.iteritems():
                if len(rule) > 0:
                    print 'ACL:', acl
                    for i in rule:
                        print '- ' + i + (' ------ WIDE ACE REMOVED! ------' if 'any' in i else ' ')
        elif print_removed_rules == 'flow':
            # We need to change the list
            rule_list = {}
            for acl, rule in del_lines.iteritems():
                if len(rule) > 0:
                    for i in rule:
                        if i not in rule_list:
                            rule_list[i] = [acl]
                        else:
                            if acl not in rule_list[i]:
                                rule_list[i].append(acl)
            for rule, acl in rule_list.iteritems():
                # Usually wide opened rules that are removed (ANY -> IP, IP -> ANY) are "dangerous". They are shown the first ones
                print 'ACE:', rule, '------ WIDE ACE REMOVED! ------' if 'any' in rule else ' '
                for i in acl:
                    print '-', i
                print

    return [del_lines, [num_adds, num_adds_comments, num_blank_lines_add,
                        num_dels, num_fake_del, num_non_impact_del, num_del_comments, num_blank_lines_del,
                        matched_ignored_acl, num_ignored_rules]]



def smartShadow2(policy, print_add_matches=False, outprint=True, verbose=False, DEBUG=False):
    """
    Check if inside an ACL there are any rules shadowed
    :param policy: Policy or file to check
    :param print_add_matches: Switch to see all matches
    :param outprint: If we want to print the output (so it can be use as module)
    :param verbose: Verbose switch
    :param DEBUG: DEBUG switch
    :return: List with data for shadowed rules
    """

    def join_matched_rules(policy, rule_list):
        """
        Internal function to join Juniper split rules into the real term.
        :param policy: initial policy
        :param rule_list: list of rules that we want to check to join
        :return:
        """
        # Counting matched child rules
        full_rule = {}
        for i, j in rule_list.iteritems():
            if '{' in i:
                trule = i.split('{')
                if trule[0] + '{' + trule[1] in full_rule:
                    full_rule[trule[0] + '{' + trule[1]].append(trule[2])
                else:
                    full_rule[trule[0] + '{' + trule[1]] = [trule[2]]

        # Checking if total number of child rules is equal to number of child matches and if TRUE, then remove it
        for i, j in full_rule.iteritems():
            if len(j) == policy.get_number_split_rules(i):
                t_rules_matched = {}
                # for i2, j2 in rule_list.iteritems():
                # To avoid problems with testing we need to sort rule_list here (it's a dictionary so no order)
                for i2 in sorted(rule_list, key=rule_list.__getitem__):
                    j2 = rule_list[i2]
                    if i in i2:
                        if i.split('{')[0] in t_rules_matched:
                            t_rules_matched[i.split('{')[0]] = t_rules_matched[i.split('{')[0]] + '\n' + j2
                        else:
                            t_rules_matched[i.split('{')[0]] = j2
                    else:
                        t_rules_matched[i2] = j2
                rule_list = dict(t_rules_matched)
        return rule_list

    if policy.get_rules_number() == 0:
        return [0, {}, 0, {}]
    if DEBUG:
        tools.DEBUG(DEBUG, 'smartShadow', 'Inside smartShadow')
    add_lines = []
    del_lines = []
    rules_to_remove_list = []
    rules_matched = {}

    # Checking if there are any duplicated rule
    rules = policy.get_rules()
    rules_t = rules[:]
    for rule in rules:
        rule_data = rule.get_rule()
        rules_t.remove(rule)
        rule_data_t = None
        for rule_t in rules_t:
            if rule_t.compare(rule) > 0:
                rule_data_t = rule_t.get_rule()
                break
        if rule_data_t is None:
            add_lines.append(rule)
            del_lines.append(rule)
        else:
            rules_matched[rule_data[0]] = rule_data_t[0]
    if DEBUG:
        tools.DEBUG(DEBUG, 'smartShadow', 'Rules already matched', rules_matched)

    '''
    There are two different kind of shadow:
        - Two rules with the same action allowing the same flow, so the first will always take precedence over the second one
        - One rule with DENY and other rule BELOW allowing the same traffic (and exactly the same)
        
    The first type of shadowing is checked here
    '''
    total_rules = len(del_lines)
    if outprint:
        print 'Checking duplicated shadowing...'
        print 'Number of rules to process:', total_rules
    for inum, acl in enumerate(del_lines):
        policy_del = FWPolicy('del', policy, DEBUG)
        policy_del.set_all_rules([acl])
        #link_cisco.acl_parser([acl], policy_del, DEBUG)
        temp_add = add_lines[:]
        temp_add.remove(acl)

        # To avoid "double match" with a shadowed rule, the ones that they are already identified as shadowed shouldn't be included again.
        if len(rules_to_remove_list) > 0:
            for i in rules_to_remove_list:
                for i2 in temp_add:
                    data = i2.get_rule()
                    if data[0] == i:
                        temp_add.remove(i2)
                        break

        policy_add = FWPolicy('add', policy, DEBUG)
        policy_add.set_all_rules(temp_add)

        if DEBUG:
            tools.DEBUG(DEBUG, 'smartShadow', 'processing rule:', inum, ' ', acl.get_rule())
            tools.DEBUG(DEBUG, 'smartShadow', 'DEL POLICY')
            policy_del.print_policy()
            tools.DEBUG(DEBUG, 'smartShadow', 'ADD POLICY')
            policy_add.print_policy()
        if outprint:
            sys.stdout.write('\r Processing rule {} of {} '.format(inum + 1, total_rules))
        if verbose and outprint:
            print 'ACL: ', acl.get_rule()

        rules_to_remove = smartCheck(policy_del, policy_add, matched_rules_extended=rules_matched, print_add_matches=False, DEBUG=DEBUG)
        tools.DEBUG(DEBUG, 'smartShadow', 'rules_to_remove', rules_to_remove)
        if len(rules_to_remove) > 0:
            if verbose and outprint:
                print 'Rule shadowed:', rules_to_remove
            for i in rules_to_remove:
                rules_to_remove_list.append(i)
        del policy_del
        del policy_add

    '''
    Now we have to check the second type of shadowing 
    '''
    if outprint:
        print 'Checking DENY shadowing...'
    rules_matched2 = {}
    rules_to_remove_list2 = []
    temp_del = del_lines[:]
    for inum, acl in enumerate(del_lines):
        data_acl = acl.get_rule()
        if data_acl[6]: # Action: PERMIT
            temp_del.remove(acl)
            continue
        acl.set_action(True)  # We change the Action for the Check
        policy_del = FWPolicy('del', policy, DEBUG)
        policy_del.set_all_rules([acl])
        temp_add = temp_del[:]  # temp_add will have the rest of the rules below the DENY
        temp_add.remove(acl)

        # To avoid "double match" with a shadowed rule, the ones that they are already identified as shadowed shouldn't be included again.
        if len(rules_to_remove_list2) > 0:
            for i in rules_to_remove_list2:
                for i2 in temp_add:
                    data = i2.get_rule()
                    if data[0] == i:
                        temp_add.remove(i2)
                        break


        policy_add = FWPolicy('add', policy, DEBUG)
        policy_add.set_all_rules(temp_add)

        if DEBUG:
            tools.DEBUG(DEBUG, 'smartShadow', 'processing rule:', inum, ' ', acl.get_rule())
            tools.DEBUG(DEBUG, 'smartShadow', 'DEL POLICY')
            policy_del.print_policy()
            tools.DEBUG(DEBUG, 'smartShadow', 'ADD POLICY')
            policy_add.print_policy()
        if outprint:
            sys.stdout.write('\r Processing DENY rule {}'.format(inum + 1))
        if verbose and outprint:
            print 'ACL: ', acl.get_rule()
        # Important: we swap policy_add with policy_del in the call of smartCheck. We want to check the policy against
        # the deny rule, not in the other way around. So, it's like the "new" policy would be the DENY rule
        rules_to_remove2 = smartCheck(policy_add, policy_del, matched_rules_extended=rules_matched2, print_add_matches=False, DEBUG=DEBUG)

        if len(rules_to_remove2) > 0:
            if verbose and outprint:
                print 'Rule shadowed:', rules_to_remove2
            for i in rules_to_remove2:
                rules_to_remove_list2.append(i)
        tools.DEBUG(DEBUG, 'smartShadow', 'rules_to_remove2', rules_to_remove2)
        tools.DEBUG(DEBUG, 'smartShadow', 'rules_to_remove_list2', rules_to_remove_list2)
        del policy_del
        del policy_add

    '''
    After both checks where done, we have a list of matched rules than can be removed in rules_matched and rules_matched2. But, we need to review these lists to see
    if all "child-rules" of a rule were matched, so then, we only print the full rule. This is usually the case for JCL ACLs, where the lines
    were split to have only one source and only one destination.
    '''
    rules_matched = join_matched_rules(policy, rules_matched)
    rules_matched2 = join_matched_rules(policy, rules_matched2)

    tools.DEBUG(DEBUG, 'smartShadow', 'rules_matched', rules_matched)
    tools.DEBUG(DEBUG, 'smartShadow', 'rules_matched2', rules_matched2)


    if outprint:
        sys.stdout.flush()
        print
        print '----------- Summary -----------'
        print 'List of rules that can be removed (same permit or deny flow shadowed): (', len(rules_matched), ')'
        print
        for i, j in rules_matched.iteritems():
            if '{' in i:
                trule = i.split('{')
                tIPs = trule[3].replace("'", "").replace(' ', '')
                print '  Compound Rule:'
                print ' '*4, trule[0], 'Source IP:', tIPs.split('[')[1].split(',')[0], 'Destination IP:', tIPs.split(',')[1].split(']')[0]
                print '  Partially matched',
            else:
                print '  Rule:'
                print ' '*4, i
                print '  Fully matched',
            if '{' in j:
                trule = j.split('{')
                tIPs = trule[3].replace("'", "")
                print 'within compound rule:'
                print ' '*4, trule[0], 'Source IP:', tIPs.split('[')[1].split(',')[0], 'Destination IP:', tIPs.split(',')[1].split(']')[0]
                print '------'
            else:
                print 'with rule/s:'
                print '\n'.join([' '*5 + l for l in j.split('\n')])
                print '------'
        print
        print 'List of rules that can be removed (DENY shadowing): (', len(rules_matched2), ')'
        print
        for i, j in rules_matched2.iteritems():
            if '{' in i:
                trule = i.split('{')
                tIPs = trule[3].replace("'", "").replace(' ', '')
                print '  Compound Rule:'
                print ' '*4, trule[0], 'Source IP:', tIPs.split('[')[1].split(',')[0], 'Destination IP:', tIPs.split(',')[1].split(']')[0]
                print '  Partially matched',
            else:
                print '  Rule:'
                print ' '*4, i
                print '  Fully matched',
            if '{' in j:
                print 'within compound rule:'
                rule_lines = j.split('\n')
                for j2 in rule_lines:
                    trule = j2.split('{')
                    tIPs = trule[3].replace("'", "")
                    print ' '*4, trule[0], 'Source IP:', tIPs.split('[')[1].split(',')[0], 'Destination IP:', tIPs.split(',')[1].split(']')[0]
                print '------'
            else:
                print 'with rule/s:'
                print '\n'.join([' ' * 5 + l for l in j.split('\n')])
                print '------'
        print '-------------------'
    return [rules_matched, rules_matched2]


def smartCompare2(p_policy1, p_policy2, verbose=False, only_different=False, outprint=True, ignore_lines='', ignoredeny=False, ignoreshadowed=False, DEBUG=False):
    """
    Compare two ACLs to verify that they have the same flows

    :param p_policy1: First file to compare
    :param p_policy2: Second file to compare with
    :param verbose: Verbose switch
    :param only_different: Show only ACLs that they are different
    :param outprint: False to avoid any output
    :param DEBUG: DEBUG switch
    :return: List with all data from the ACLs comparison
    """

    if DEBUG:
        tools.DEBUG(DEBUG, 'smartCompare', 'Inside smartCompare')

    policy1 = deepcopy(p_policy1)
    policy2 = deepcopy(p_policy2)

    rules1 = list(policy1.get_rules())
    rules2 = list(policy2.get_rules())

    inumline_old = len(rules1)
    inumline_new = len(rules2)

    # Checking if we have a rules to ignore
    number_ignored_old = 0
    number_ignored_new = 0
    list_ignored_rules = []
    if ignore_lines != '' or ignoredeny:
        ignore_lines = ignore_lines.split(',')
        num_rule = policy1.get_rules_number()
        while num_rule > 0:
            rule = policy1.get_rule(num_rule)
            if not rule[0].startswith('^'): # Disabled rules
                if rule[0] in ignore_lines or (ignoredeny and not rule[6]):
                    tools.DEBUG(DEBUG, 'smartCompare', 'Removing ignore rule Policy1', rule[0])
                    policy1.remove_rule(num_rule)
                    number_ignored_old += 1
                    if rule[0] not in list_ignored_rules:
                        list_ignored_rules.append(rule[0])
            num_rule -= 1

        num_rule = policy2.get_rules_number()
        while num_rule > 0:
            rule = policy2.get_rule(num_rule)
            if not rule[0].startswith('^'): # Disabled rules
                if rule[0] in ignore_lines or (ignoredeny and not rule[6]):
                    tools.DEBUG(DEBUG, 'smartCompare', 'Removing ignore rule Policy2', rule[0])
                    policy2.remove_rule(num_rule)
                    number_ignored_new += 1
                    if rule[0] not in list_ignored_rules:
                        list_ignored_rules.append(rule[0])
            num_rule -= 1

    # We need to split any possible "multi IP" rule
    # smartCompare requires one IP per line
    policy1.split_ips()
    policy2.split_ips()

    # Checking if the last rule is the type DENY ANY ANY. If it is, we removed to avoid false positives
    last_deny_old = 0
    if policy1.last_deny():
        last_deny_old = 1
        policy1.remove_rule(policy1.get_rules_number())
    last_deny_new = 0
    if policy2.last_deny():
        last_deny_new = 1
        policy2.remove_rule(policy2.get_rules_number())

    if rules1[0] == '<empty>':
        rules_to_remove = []
    elif rules2[0] == '<empty>':
        rules_to_remove = []
    else:
        # We should check if every rule we want to compare is really allowed or not. If a rule is not already allowed in the "old" policy
        # Why do we need to check against the second policy?
        rules_shadowed = {}
        if ignoreshadowed:
            rules_shadowed = policy1.remove_shadowed_rules()

        rules_to_remove = smartCheck(policy1, policy2, print_progress=verbose, print_add_matches=verbose, DEBUG=DEBUG)
        tools.DEBUG(DEBUG, 'smartCompare', 'rules_to_remove', rules_to_remove)
        # Removing any duplicated rule
        rules_to_remove_t = []
        for i in rules_to_remove:
            if i not in rules_to_remove_t:
                rules_to_remove_t.append(i)
        if ignoreshadowed:
            '''
            For the shadowed rules we need to check if the rule that "shadowed" the one removed,
            it's included in the "rules_to_remove":
            - If it was included -> the one shadowed will be also included
            - If it was NOT included -> the one shadowed neither
            '''
            for r1, r2 in rules_shadowed.iteritems():
                if r2 in rules_to_remove and r1 not in rules_to_remove_t:
                    rules_to_remove_t.append(i)
        rules_to_remove = rules_to_remove_t[:]

    if outprint:
        if not only_different or (only_different and (inumline_old - len(rules_to_remove) > 0)):

            if ignoredeny:
                print '------------------------------------------------------------------'
                print 'YOU ARE IGNORING DENY RULES IN COMPARISON. RESULTS COULD BE WRONG!'
                print '------------------------------------------------------------------'
                print 'The following rules were ignored during the comparison:'
                for i in list_ignored_rules:
                    print i
            print '------ SmartCompare ------'
            print 'Number of rules in old policy (without remarks):', inumline_old
            print 'Number of rules in new policy (without remarks):', inumline_new
            if ignoreshadowed:
                print
                print 'Number of shadowed rules IGNORED in old policy:', len(rules_shadowed)
                print 'The following rules were ignored during the comparison:'
                for i in rules_shadowed:
                    print i

            iold = policy1.get_rules_number()
            last_rule_printed = ''
            output_to_print = []
            rules_fully_matched = []
            for i in xrange(1, iold+1):
                rule_old = policy1.get_rule(i)
                if rule_old[0] not in rules_to_remove and rule_old[0] != last_rule_printed:
                    if rule_old[0].split('{')[0] in rules_fully_matched:
                        rules_fully_matched.remove(rule_old[0].split('{')[0])
                    if '{' in rule_old[0]:
                        output_to_print.append('Compound rule: ' + rule_old[0].split('{')[0] + ' '*4 + 'Source IP: ' + rule_old[1] + '  Destination IP: ' + rule_old[2] + '  Source Port: ' + rule_old[4] + '  Destination Port: ' + rule_old[3])
                    else:
                        output_to_print.append(rule_old[0])
                    last_rule_printed = rule_old[0]
                else:
                    # If the rule was split ('{' in name) then we only need to add it once
                    # we checked with the 1 line of the split rule
                    if '{' in rule_old[0]:
                        if rule_old[0].split('{')[2] == '1':
                            rules_fully_matched.append(rule_old[0].split('{')[0])
                    else:
                        rules_fully_matched.append(rule_old[0].split('{')[0])
            print
            print 'Number of rules shadowed in the new policy:', len(rules_fully_matched) + (last_deny_old + number_ignored_old)
            print
            print 'Number of rules NOT fully matched in the new policy:', inumline_old - (len(rules_fully_matched) + (last_deny_old + number_ignored_old))
            print 'Rules not fully matched from OLD policy:'
            for i in output_to_print:
                print i

    return rules_to_remove



"""
    MAIN
"""
if __name__ == "__main__":

    def help_message(part=''):
        if part == 'smartlog':
            print 'usage: smartACL.py', '--smartlog', '--diff-file <DIFF_FILE>', '[-r]', '[-p]', '[-f]'
        elif part == 'smartshadow':
            print 'usage: smartACL.py', '--smartshadow', '--acl-old <ACL-FILE>'
        elif part == 'smartcompare':
            print 'usage: smartACL.py', '--smartcompare', '--acl-old <ACL-FILE>', '--acl-new <ACL-FILE>'
        else:
            print 'usage: smartACL.py', '[--smartcompare|--smartshadow|--smartlog]', '[--diff-file DIFF_FILE]', '[-h]', \
                  '[--diff-file Diff File]', '[--acl-old ACL_FILE1]', '[--acl-new ACL_FILE2]', '[-r]', '[-p]', '[-f]', '[-d]'

        print
        if part == '':
            print 'Mandatory arguments'
            print '--smartcompare       Execute smartCompare module'
            print '--smartshadow        Execute smartShadow module'
            print '--smartlog           Execute smartLog module'
            print
        print 'Optional arguments'
        if part == '' or part == 'smartlog':
            print '--diff-file                         Diff file'

        if part == '' or part == 'smartcompare':
            print '--acl-old                           Old ACL file or directory to compare'

        elif part == 'smartshadow':
            print '--acl-old                           ACL file'

        if part == '' or part == 'smartcompare':
            print '--acl-new                           New ACL file or directory to compare'
            print '-s, --show-only-different           When comparing directories will show an output only with different files'
            print '-il, --ignore-line                  Ignore the following lines (ACL remark for Cisco or Term name for Juniper)'
            print '-is, --ignore-shadowed              smartCompare will perform a BASIC rule shadowing lookup and discard any found rule for the comparison'
            print '--ignoredeny                        Ignore DENY rules. (DANGEROUS, CAN\'T SHOW FAKE RESULTS)'
            print '--capirca-dir                       Directory containing NETWORK.net and SERVICES.svc    '

        if part == '' or part == 'smartlog':
            if part == 'smartlog':
                print '-il, --ignore-line                  Ignore ACL with the following remark'
            print '-r, --print-removed-rules-by-file   Print all rules by file that they are really going to be removed'
            print '-p, --print-add-matches             Print ADD matches for DEL lines'
            print '-n, --no-check-fakes                NO check for twin rules (exactly the same - and + in the diff file)'
            print '-a, --acl-dir                       Directory with ALL ACLs to compare diff file'


        print '--remarkasname                      Will use "remarks" as name of the rule for Cisco ACLs'
        print '--acltype                           Specifiy the ACL type: acl,ncl,jcl'
        print '-v, --verbose                       Verbose output'
        print '-d, --debug'
        print '-h, --help                          This message'


    def run(dir1, dir2, op):
        for file1 in dir1:
            file_found = False

            if os.path.isdir(file1): continue
            if acltype != '':
                type_ext1 = acltype
                type_ext2 = acltype
            else:
                type_ext1 = file1.split('.')[len(file1.split('.')) - 1]
            if type_ext1 not in ['acl', 'ncl', 'fcl', 'jcl', 'pol']:
                print "Can't detect ACL type. Ignoring file:", file1
                continue  # if the file extension is not known next one

            if '/' in file1:
                file_name1 = file1.split('/')[len(file1.split('/')) - 1]
            else:
                file_name1 = file1
            if op != 'smartcompare':
                print '\nProcessing file: ', file1
                parsed = False
                policy1 = FWPolicy('', file1, debug)
                if type_ext1 in ['acl', 'ncl', 'fcl']:
                    parsed = link_cisco.acl_parser(file1, policy1, remarkasname=args.remarkasname, DEBUG=debug)
                elif type_ext1 == 'jcl':
                    parsed = link_juniper.jcl_parser(file1, policy1, debug)
                    if parsed:
                        policy1.split_ips()
                if parsed:
                    smartShadow2(policy1, print_add_matches=args.printadd, verbose=args.verbose, DEBUG=args.debug)
                else:
                    print "ERROR: Can't parse files. File:", file1
                break
            else:
                for file2 in dir2:
                    if os.path.isdir(file2): continue
                    if acltype == '':
                        type_ext2 = file2.split('.')[len(file2.split('.')) - 1]
                    if type_ext2 not in ['acl', 'ncl', 'fcl', 'jcl', 'pol']:
                        print "Can't detect ACL type. Ignoring file:", file2
                        continue  # if the file extension is not known next one

                    if '/' in file2:
                        file_name2 = file2.split('/')[len(file2.split('/')) - 1]
                    else:
                        file_name2 = file2

                    # If the directory is only one file, it doesn't make sense to match the names. We just use the file.
                    if file_name1 == file_name2 or len(dir2) == 1:
                        file_found = True
                        print '\nProcessing file: ', file1
                        parsed = False
                        policy1 = FWPolicy('', file1, debug)
                        if type_ext1 in ['acl', 'ncl', 'fcl']:
                            parsed = link_cisco.acl_parser(file1, policy1, remarkasname=args.remarkasname, DEBUG=debug)
                        elif type_ext1 == 'jcl':
                            parsed = link_juniper.jcl_parser(file1, policy1, debug)
                        elif type_ext1 == 'pol':
                            if args.capircadir is None:
                                print "Capirca Policies needs the parameter --capirca-dir"
                                continue
                            parsed = link_pol.pol_parser(file1, args.capircadir, policy1, debug)

                        policy2 = FWPolicy('', file2, debug)
                        if type_ext2 in ['acl', 'ncl', 'fcl']:
                            parsed = parsed and link_cisco.acl_parser(file2, policy2, remarkasname=args.remarkasname, DEBUG=debug)
                        elif type_ext2 == 'jcl':
                            parsed = parsed and link_juniper.jcl_parser(file2, policy2, debug)
                        elif type_ext2 == 'pol':
                            if args.capircadir is None:
                                print "Capirca Policies needs the parameter --capirca-dir"
                                continue
                            parsed = parsed and link_pol.pol_parser(file2, args.capircadir, policy2, debug)

                        if parsed:
                            smartCompare2(policy1, policy2, verbose=args.verbose, only_different=args.show_different, ignore_lines=args.ignore_term, ignoredeny=args.ignoredeny, ignoreshadowed=args.ignoreshadowed, DEBUG=args.debug)
                        else:
                            print "ERROR: Can't parse files. File1:", file1, "File2:", file2
                        break
                if not file_found:
                    if type(dir1) is list and len(dir1) > 1:
                        tdir1 = '/'.join(dir1[0].split('/')[0:-1])
                    else:
                        tdir1 = dir1
                    if type(dir2) is list and len(dir2) > 1:
                        tdir2 = '/'.join(dir2[0].split('/')[0:-1])
                    else:
                        tdir2 = dir2

                    tfile = file1

                    print 'FILE:', tfile, 'in directory:', tdir1, 'was NOT found in directory:', tdir2

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-sc', '--smartcompare', dest='smartcompare', action='store_true')
    parser.add_argument('-ss', '--smartshadow', dest='smartshadow', action='store_true')
    parser.add_argument('-sl', '--smartlog', dest='smartlog', action='store_true')
    parser.add_argument('--diff-file', dest='diff_file', metavar='Diff File', help='Diff file for smartLog')
    parser.add_argument('--acl-old', dest='acl_file1', help='Old ACL file (smartShadow only use this one)', nargs='+')
    parser.add_argument('--acl-new', dest='acl_file2', help='New ACL file', nargs='+')
    parser.add_argument('-s', '--show-only-different', dest='show_different', help='Show only different files', action='store_true')
    parser.add_argument('-il', '--ignore-line', dest='ignore_term', help='Ignore the following lines (ACL remark for Cisco or Term name for Juniper)', default='')
    parser.add_argument('-is', '--ignore-shadowed', dest='ignoreshadowed', help='smartCompare will perform a BASIC rule shadowing lookup and discard any found rule for the comparison', action='store_true')
    parser.add_argument('--ignore-deny', dest='ignoredeny', help='Ignore DENY rules. (DANGEROUS, CAN\'T SHOW FAKE RESULTS)', action='store_true')
    parser.add_argument('-r', '--print-removed-rules-by-file', dest='printdelrack', help='(smartLog) Print all rules by file that they are really going to be removed', action='store_true')
    parser.add_argument('-p', '--print-add-matches', dest='printadd', help='(smartShadow) Print ADD matches for DEL lines', action='store_true')
    parser.add_argument('-n', '--no-check-fakes', dest='chkfake', help='(smartShadow) NO check for twin rules (exactly the same - than +)', action='store_true')
    parser.add_argument('--remarkasname', help='Will use "remarks" as name of the rule for Cisco ACLs', action='store_true')
    parser.add_argument('--acltype', help='Specifiy the ACL type: acl,ncl,jcl')
    parser.add_argument('-a', '--acl-dir', dest='acldir', help='ACL Directory for smartLog')
    parser.add_argument('--capirca-dir', dest='capircadir', help='Capirca definitions directory')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true')
    parser.add_argument('-h', '--help', dest='help', action='store_true', help='Show this help message and exit.')
    args = parser.parse_args()

    ops = 'smartlog' if args.smartlog else 'smartcompare' if args.smartcompare else 'smartshadow' if args.smartshadow else ''

    if args.help or ops == '':
        help_message(ops)
        quit()

    acltype = ''
    if args.acltype:
        acltype = args.acltype

    debug = args.debug

    if ops == 'smartlog':
        if args.diff_file is None:
            print 'ERROR: With smartLog you need to specify a diff file. Please, use --diff-file'
            help_message(part='smartlog')
            quit()
        pr = 'flow'
        if args.printdelrack:
            pr = 'rack'
        smartLog(args.diff_file, check_fakes=not args.chkfake, print_add_matches=args.printadd, print_removed_rules=pr, acldir=args.acldir, verbose=args.verbose, ignore_acl_with_remark=args.ignore_term, DEBUG=args.debug)
    elif ops == 'smartshadow':
        if args.acl_file1 is None:
            print 'ERROR: With smartShadow you need to specify an ACL file using --acl-old'
            help_message(part='smartshadow')
            quit()
        run(args.acl_file1, None, ops)
    elif ops == 'smartcompare':
        if args.acl_file1 is None or args.acl_file2 is None:
            print 'ERROR: With smartCompare you need to specify two ACL files using --acl-old and --acl-new'
            help_message(part='smartcompare')
            quit()
        else:
            files1 = ''
            files2 = ''
            for i in args.acl_file1:
                if '*' in i:
                    files1 = glob.glob(i)
                else:
                    files1 = args.acl_file1
                break
            for i in args.acl_file2:
                if '*' in i:
                    files2 = glob.glob(i)
                else:
                    files2 = args.acl_file2
                break
            run(files1, files2, ops)


