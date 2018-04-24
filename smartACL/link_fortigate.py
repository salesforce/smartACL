#!/usr/bin/env python

# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import sys
from linkdef import *

try:
    import netaddr
except:
    try:
        import sys
        sys.path.insert(0, 'smartACL/third_party')
        sys.path.insert(0, 'third_party')
        import third_party.netaddr as netaddr
    except:
        raise ImportError("The netaddr module is not installed, exiting...")

###### ADDRESS OBJECTS

ADDRESS_OBJ = 'config firewall address'
# type iprange
# start-ip -> ip
# end-ip -> ip
#
# type ipmask
# subnet -> X.X.X.X Y.Y.Y.Y (net / mask)

MULTICAST_OBJ = 'config firewall multicast-address'
# type multicastrange
# start-ip -> ip
# end-ip -> ip

ADDRESS6_OBJ = 'config firewall address6'
# type ipprefix
# ip6 -> fdff:ffff::/120

ADDGRP_OBJ = 'config firewall addrgrp'
# member -> list separated by space of other objects

SERVICE_OBJ = 'config firewall service custom'
SERVICEGRP_OBJ ='config firewall service group'

IPPOOL_OBJ = 'config firewall ippool'

FIREWALL_VIP = 'config firewall vip'
# VIPs are SPECIAL Object -> Inside it's included protocol and PORT, we need to use this for the rule

FIREWALL_POLICY = 'config firewall policy'

addr_dict = {}
serv_dict = {}
ippool_dict = {}
fwvip_dict = {}


def get_ips(name):
    def expand_ips(start_ip, end_ip):
        list_ip = []
        ips = netaddr.cidr_merge(list(netaddr.iter_iprange(start_ip, end_ip)))
        for i in ips:
            ip = str(i.ip) + '/' + str(i.netmask)
            list_ip.append(ip)
        return list_ip

    ip_list = []

    if len(name.split()) > 1:
        for i in name.split():
            ip_t = ' '.join(get_ips(i)).strip()
            ip_list.append(ip_t)

    else:
        if name not in addr_dict and name not in fwvip_dict:
            print 'ERROR: Object:', name, 'found in policy but NOT found in objects.'
            return None

        if name in addr_dict:

            value = addr_dict[name]
            if 'member' in value:
                # It's an Address Group
                members = value['member'].split()
                for member in members:
                    if member not in addr_dict:
                        print 'ERROR: Object:', member,'referenced in Address Group object:', name, 'but not found.'
                        continue
                    ip_t = ' '.join(get_ips(member)).strip()
                    ip_list.append(ip_t)
            #
            # The original idea was to check:
            #   - first, if "member" was included, so the object should be a addrgrp
            #   - second, use "type" to identify the object, but unfortunately this is not possible because
            #   Fortigates allows to have different object with the same name, but from the Policy there is
            #   no information which object should be used first. We assume that it should be first Address
            #   type
            #
            #
            elif 'subnet' in value:
                ip_list = [value['subnet'].split()[0] + '/' + value['subnet'].split()[1]]
            elif 'multicastrange' in value or 'iprange' in value:
                ip_list = expand_ips(value['start-ip'], value['end-ip'])
            else:
                print 'ERROR: Object:', name, 'can not be identified'
        else:
            ip_list = [fwvip_dict[name]['extip']]

    return ip_list


def get_service(name):
    service_list = []
    if len(name.split()) > 1:
        for i in name.split():
            service_list = service_list + get_service(i)
    else:
        if name not in serv_dict:
            print 'ERROR: Object:', name, 'found in policy but NOT found in objects.'
            return None

        value = serv_dict[name]
        if 'member' in value:
            members = value['member'].split()
            for member in members:
                if member not in serv_dict:
                    print 'ERROR: Object:', member, 'referenced in Service Group object:', name, 'but not found.'
                    continue
                service_list = service_list +  get_service(member)
        else:
            if 'protocol' in value and value['protocol'] == 'ICMP':
                service_list.append('icmp')
            elif 'protocol' in value and value['protocol'] == 'IP':
                    service_list.append('ip')
            else:
                if 'tcp-portrange' in value:
                    for i in value['tcp-portrange'].split():
                        service_list.append(i + '/tcp')
                if 'udp-portrange' in value:
                    for i in value['udp-portrange'].split():
                        service_list.append(i + '/udp')

    return service_list


def for_parser(filename, policy, DEBUG=False):
    if type(filename) is not list:
        f = open(filename, 'r')
    else:
        f = filename

    config_addr = False
    config_serv = False
    config_ippool = False
    config_fwvip = False
    config_policy = False

    policy.set_name('Fortigate Policy')

    for line in f:
        line = line.strip()

        if DEBUG:
            print line

        if line in [ADDRESS_OBJ, MULTICAST_OBJ, ADDRESS6_OBJ, ADDGRP_OBJ]:
            config_addr = True
        elif line in [SERVICE_OBJ, SERVICEGRP_OBJ]:
            config_serv = True
        elif line in [IPPOOL_OBJ]:
            config_ippool = True
        elif line in [FIREWALL_VIP]:
            config_fwvip = True
        elif line in [FIREWALL_POLICY]:
            config_policy = True


        if line.startswith('end'):
            config_addr = False
            config_serv = False
            config_ippool = False
            config_fwvip = False
            config_policy = False

        in_config = config_addr or config_serv or config_ippool or config_fwvip

        if in_config and line.startswith('edit'):
            obj_name = line.split(' ')[1].strip('"')
            if config_addr:
                # Unforunately Fortigate allows duplicated object names
                if obj_name not in addr_dict:
                    addr_dict[obj_name] = {}
            elif config_serv:
                serv_dict[obj_name] = {}
            elif config_ippool:
                ippool_dict[obj_name] = {}
            elif config_fwvip:
                fwvip_dict[obj_name] = {}

        if in_config and line.startswith('set'):
            prop = line.split(' ')[1].strip('"')
            value = ' '.join(line.split(' ')[2:])
            value = value.replace('"', '').replace("'", '')
            if config_addr:
                addr_dict[obj_name][prop] = value
            elif config_serv:
                serv_dict[obj_name][prop] = value
            elif config_ippool:
                ippool_dict[obj_name][prop] = value
            elif config_fwvip:
                fwvip_dict[obj_name][prop] = value

        if config_policy:
            if line.startswith('edit'):
                rule_number = line.split(' ')[1]
                status = True
                source_neg = False
                dest_neg = False
                service_neg = False
                source_name = ''
                dest_name = ''
                source = ''
                dest = ''
                sport = ''
                dport = ''
                protocol = ''
                service = ''
                comments = ''
                rule_name = ''
            elif line.startswith('next'):
                # Create the rule
                if status:
                    source = ','.join(source)
                    dest = ','.join(dest)
                    comments = '(Rule: ' + rule_number + ') ' + comments

                    dport_udp = ''
                    dport_tcp = ''
                    # In Fortigate services with source port use ":" inside the port
                    # these "services" are processed creating one by one rule
                    t_source_tcp_port = []
                    t_source_udp_port = []

                    # Let's start with IP and ICMP rules
                    t_service = list(service)
                    for i in service:
                        if ':' in i:
                            if 'tcp' in i:
                                t_source_tcp_port.append(i)
                            else:
                                t_source_udp_port.append(i)

                            t_service.remove(i)
                            continue
                        if i == 'ip':
                            dport = '0'
                            sport = '0'
                            protocol = 'ip'
                            t_service.remove(i)
                        elif 'icmp' in i:
                            dport = '0'
                            sport = '0'
                            protocol = 'icmp'
                            t_service.remove(i)
                        else:
                            continue
                        rule = policy.new_rule(source,
                                               dest,
                                               dport,
                                               sport,
                                               protocol,
                                               action,
                                               wildcard=False,
                                               source_name=source_name,
                                               dest_name=dest_name,
                                               source_negated=source_neg,
                                               dest_negated=dest_neg)
                        policy.set_name(rule_name)
                        policy.set_rule_comment(rule, comments)

                    # Continue creating TCP and/or UDP rules
                    for i in t_service:
                        if 'udp' in i:
                            dport_udp = dport_udp + ',' + i.split('/')[0]
                            continue
                        elif 'tcp' in i:
                            dport_tcp = dport_tcp + ',' + i.split('/')[0]
                            continue
                    if dport_udp != '':
                        sport = ''
                        rule = policy.new_rule(source,
                                               dest,
                                               dport_udp[1:],
                                               sport,
                                               'udp',
                                               action,
                                               wildcard=False,
                                               source_name=source_name,
                                               dest_name=dest_name,
                                               source_negated=source_neg,
                                               dest_negated=dest_neg)
                        policy.set_name(rule_name)
                        policy.set_rule_comment(rule, comments)
                    if dport_tcp != '':
                        sport = ''
                        rule = policy.new_rule(source,
                                               dest,
                                               dport_tcp[1:],
                                               sport,
                                               'tcp',
                                               action,
                                               wildcard=False,
                                               source_name=source_name,
                                               dest_name=dest_name,
                                               source_negated=source_neg,
                                               dest_negated=dest_neg)
                        policy.set_name(rule_name)
                        policy.set_rule_comment(rule, comments)

                    # Finally rules with source port
                    for i in t_source_udp_port:
                        sport = i.split('/')[0].split(':')[1]
                        dport = i.split('/')[0].split(':')[0]
                        protocol = 'udp'
                        rule = policy.new_rule(source,
                                               dest,
                                               dport,
                                               sport,
                                               protocol,
                                               action,
                                               wildcard=False,
                                               source_name=source_name,
                                               dest_name=dest_name,
                                               source_negated=source_neg,
                                               dest_negated=dest_neg)
                        policy.set_name(rule_name)
                        policy.set_rule_comment(rule, comments)
                    for i in t_source_tcp_port:
                        sport = i.split('/')[0].split(':')[1]
                        dport = i.split('/')[0].split(':')[0]
                        protocol = 'tcp'
                        rule = policy.new_rule(source,
                                               dest,
                                               dport,
                                               sport,
                                               protocol,
                                               action,
                                               wildcard=False,
                                               source_name=source_name,
                                               dest_name=dest_name,
                                               source_negated=source_neg,
                                               dest_negated=dest_neg)
                        policy.set_name(rule_name)
                        policy.set_rule_comment(rule, comments)



            else:
                prop = line.split(' ')[1]
                value = ' '.join(line.split(' ')[2:])
                value = value.replace('"', '').replace("'", '')
                if prop == 'srcintf':
                    source_name = value
                elif prop == 'dstintf':
                    dest_name = value
                elif prop == 'srcaddr':
                    source = get_ips(value)
                elif prop == 'dstaddr':
                    dest = get_ips(value)
                elif prop == 'service':
                    service = get_service(value)
                elif prop == 'comments':
                    comments = value
                elif prop == 'label':
                    rule_name = value
                elif prop == 'action':
                    if 'accept' in value:
                        action = True
                    else:
                        action = False
                elif prop == 'status':
                    if 'enable' in value:
                        status = True
                    else:
                        status = False
                elif prop == 'srcaddr-negate':
                    source_neg = True
                elif prop == 'dstaddr-negate':
                    dest_neg = True
                elif prop == 'service-negate':
                    service_neg = True
                    print 'ERROR: Service-negate found. This is not supported by Link'
                    return None

    return True


if __name__ == "__main__":
    d=False
    policy = FWPolicy(sys.argv[1],sys.argv[1], DEBUG=d)
    for_parser(sys.argv[1], policy)
    policy.print_policy()



