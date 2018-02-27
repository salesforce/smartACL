# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

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

from tools import wild_is_contiguous
from tools import split_non_contiguous
from tools import color as tools_color
from tools import DEBUG as tools_debug
from tools import cidr_to_mask
from tools import mask_to_wild


# Ports Numbers
port_number = {'ftpdata': '20',  # In Cisco is ftp-data but '-' is used a separator for ranges
               'ftp': '21',
               'bootps': '67',
               'bootpc': '68',
               'http': '80',
               'ntp': '123',
               'ldap': '389',
               'https': '443'}

# Specific Juniper words to check ACL
jcldict = {'source-address': 'source_address',
           'destination-address': 'destination_address',
           'destination-port': 'destination_port',
           'source-port': 'source_port',
           'protocol': 'protocol'}

jclwords = ['source-address', 'destination-address', 'destination-port', 'source-port', 'protocol', 'action']

# Words 'banned' for any Juniper ACL. If the word is found the AC is ignored
jclbanwords = ['tcp-established', 'source-prefix-list', 'destination-prefix-list', 'next-header', 'fragment-offset']

colors = ['black', 'red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white']
styles = ['D', 'B', 'S', 'I', 'U', 'D2', 'D3', 'IN']


NONCONT_LIMIT = 256

class FWRule (object):
    DEBUG = False
    # Source/Destination address would allow the following formats (could be a list separated with ,:
    #   - X.X.X.X/Y.Y.Y.Y -> IP / net mask
    #   - X.X.X.X_Y.Y.Y.Y -> IP / Wildcard

    def __init__(self):
        self.rulenumber = 0                         # Rule number
        self.name = ''                              # Rule name
        self.source_address = ''                    # Source address (as it was read from the ACL)
        self.destination_address = ''               # Destination address (as it was read from the ACL)
        self.destination_port = ''                  # Destination port (can include operators)
        self.source_port = ''                       # Source port (can include operators)
        self.protocol = ''                          # Protocol
        self.permit = False                         # Permit (Accept)
        self.wildcard = False                       # If it's a rule with a valid wildcard (usually a Cisco ACL)
        self.source_name = ''                       # Name for source (useful in case of Pol files)
        self.dest_name = ''                         # Name for destination (useful in case of Pol files)
        self.comment = ''                           # Comment for the rule

    #################################
    # GET Methods                   #
    #################################

    def get_rule_action(self):
        return self.permit

    def get_rule(self):
        rule=[]
        rule.append(self.name)                  # 0
        rule.append(self.source_address)        # 1
        rule.append(self.destination_address)   # 2
        rule.append(self.destination_port)      # 3
        rule.append(self.source_port)           # 4
        rule.append(self.protocol)              # 5
        rule.append(self.permit)                # 6
        rule.append(self.wildcard)              # 7
        rule.append(self.source_name)           # 8
        rule.append(self.dest_name)             # 9
        rule.append(self.comment)               # 10
        return rule

    def get_rule_name(self):
        return self.name

    def get_rule_number(self):
        return self.rulenumber

    def get_contiguous(self):
        """
        Return the number of possible networks matching a non contiguous wildcard for source and destination
        Return 0 is Source and Destination has a contiguous wildcard

        :return: Integer (check description)
        """

        def __number_nets(wild):
            # The number of matches in a wildcard is defined by the number of 1
            x = 0
            wildS = wild.split('.')
            for octect in wildS:
                wildB = format(int(octect), 'b').zfill(8)
                x += wildB.count('1')

            return x

        net_number = 0
        if self.wildcard:
            if self.source_address != 'any' and self.source_address != '0.0.0.0/255.255.255.255':
                if not wild_is_contiguous(self.source_address.split('/')[1]):
                    net_number = __number_nets(self.source_address.split('/')[1])

            if self.destination_address != 'any' and self.destination_address != '0.0.0.0/255.255.255.255':
                if not wild_is_contiguous(self.destination_address.split('/')[1]):
                    if net_number == 0:
                        net_number = __number_nets(self.destination_address.split('/')[1])
                    else:
                        net_number = net_number * __number_nets(self.destination_address.split('/')[1])

        return net_number
    #################################
    # SET Methods                   #
    #################################

    def set_rule_data(self, sAddress='', dAddress='', dPort='', sPort='', protocol='', ACCEPT=False, wildcard=False, name='-1', rulenumber=-1, source_name='', dest_name=''):
        if rulenumber >= 0:
            self.rulenumber = rulenumber
        if name != '-1':
            self.name = name
        self.source_address = sAddress
        self.destination_address = dAddress
        self.destination_port = dPort
        self.source_port = sPort
        self.protocol = protocol
        self.permit = ACCEPT
        self.wildcard = wildcard
        self.source_name = source_name
        self.dest_name = dest_name


    def set_name(self, name):
        self.name = name

    def set_comment(self, comment):
        self.comment = comment

    def set_rulenumber(self, rulenumber):
        self.rulenumber = rulenumber

    def set_dyn_data(self, attribute, data):
        setattr(self, attribute, data)

    def set_action(self, accept):
        self.permit = accept

    def set_empty(self):
        self.set_rule_data(sAddress='',dAddress='',dPort='',sPort='',protocol='', ACCEPT=False, wildcard=False, source_name='' ,dest_name='')

    def set_debug(self):
        self.DEBUG = True

    def set_source(self, address):
        self.source_address = address

    def set_destination(self, address):
        self.destination_address = address

    #################################
    # Internal Methods               #
    #################################

    def _checkIPWild(self, net, wild, IP):
        """
        Check the IP is included in a network/wildcard

        :param net: network address to be checked
        :param wild: wildcard for the network
        :param IP: IP to discover if it's a match
        :return: TRUE/FALSE
        """
        if IP == '0.0.0.0':
            return True
        netS = net.split('.')
        ipS = IP.split('.')
        wildS = wild.split('.')
        iPos = 0
        for netOctect in netS:
            iPos += 1
            netB = format(int(netOctect), 'b').zfill(8)
            ipB = format(int(ipS[iPos - 1]), 'b').zfill(8)
            wildB = format(int(wildS[iPos - 1]), 'b').zfill(8)
            for x in xrange(8):
                if wildB[x] == '0':
                    xor = (int(netB[x]) ^ int(ipB[x]))
                    if xor:
                        break
            if xor:
                break
        return xor == 0

    def _checkNetWild(self, net, wild, net_check):
        """
        Check if net_check is included in a network/wildcard

        :param net: network address
        :param mask: mask address
        :param net_check: network to find if it's included.
        :return:
        """
        if '/' not in net_check:
            return False
        if net == '0.0.0.0':
            return True
        if not wild_is_contiguous(wild):
            net_list = split_non_contiguous(net, wild)
        else:
            net_list = [net + '/' + wild]

        if not wild_is_contiguous(net_check.split('/')[1]):
            net_check_list = split_non_contiguous(net_check.split('/')[0], net_check.split('/')[1])
        else:
            net_check_list = [net_check]
        '''
        Now we should have two lists without any non-contiguous IP included. Time to go through both of them
        checking that all networks to be "checked" are included
        '''
        net_checked = []
        for net1 in net_list:
            try:
                if net1.split('/')[1] == '0.0.0.0':
                    # When using wildcard 0.0.0.0 is 255.255.255.255, but Netaddr use the 0.0.0.0 ask mask for ALL, so this needs to be changed
                    net1 = net1.split('/')[0] + '/' + '255.255.255.255'
                net_object_ori = netaddr.IPNetwork(net1)
            except:
                return None
            if len(net_check_list) == 0:
                break
            net_check_temp = net_check_list[:]
            for net2 in net_check_temp:
                try:
                    net_object_des = netaddr.IPNetwork(net2)
                except:
                    return None
                if net2 in net_checked:
                    continue
                if net_object_des in net_object_ori:
                    net_checked.append(net2)
                    net_check_list.remove(net2)

        return len(net_check_list) == 0

    def _checkIPMask(self, net, mask, IP):
        """
        Check if the IP is included in a network/network mask

        :param net: network address to be checked
        :param mask: network mask for the network
        :param IP: IP to discover if it's a match
        :return: TRUE/FALSE
        """
        if IP == '0.0.0.0' or mask == '0.0.0.0':
            return True
        netS = net.split('.')
        ipS = IP.split('.')
        maskS = mask.split('.')
        iPos = 0
        eq = False
        for netOctect in netS:
            iPos += 1
            netB = format(int(netOctect), 'b').zfill(8)
            ipB = format(int(ipS[iPos - 1]), 'b').zfill(8)
            maskB = format(int(maskS[iPos - 1]), 'b').zfill(8)
            for x in xrange(8):
                if maskB[x] == '1':
                    eq = (int(netB[x]) == int(ipB[x]))
                    if not eq:
                        break
            if not eq:
                break
        return eq

    def _checkNetMask(self, net, mask, net_check):
        """
        Check if net_check is included in a network/mask

        :param net: network address
        :param mask: mask address
        :param net_check: network to find if it's included
        :return:
        """

        if net_check == '0.0.0.0/0':
            return False
        if net == '0.0.0.0' and mask == '0':
            return True
        try:
            net_object_ori = netaddr.IPNetwork(net + '/' + mask)
            net_object_dest = netaddr.IPNetwork(net_check)
        except:
            return False

        return net_object_dest in net_object_ori

    def _checkPort(self, DP, Port, anyport, strict_search):
        """
        Check if "Port" is matched or not for a Source or Destination port of the rule (DP switch)
        :param DP: TRUE -> Destination Port, FALSE -> Source Port
        :param Port: Port to check
        :param anyport: switch to know if with any port matched is enough (usually with a port range)
        :return: TRUE/FALSE
        """
        lport = False

        if DP:
            list_port = self.destination_port
        else:
            list_port = self.source_port

        if self.DEBUG:
            tools_debug(self.DEBUG, '_checkPort', DP, Port, list_port, anyport, strict_search)

        # Port with value 70000 means ANY
        if not strict_search and (Port == '0' or list_port == '0'):
            lport = True
        elif strict_search and (Port == '0' and list_port == '0'):
            lport = True
        else:
            for tport in list_port.split(','):
                if '-' in Port:
                    Port1 = Port.split('-')[0]
                    Port2 = Port.split('-')[1]
                    # We are checking a port range
                    if '-' not in tport:
                        if anyport:
                            lport = int(Port1) <= int(tport) <= int(Port2)
                            # If not anyport is checked, this won't match, so no "else".
                    else:
                        if anyport:
                            # dPort is bigger or dPort1 is inside the rule range or dPort2 is inside the rule range
                            lport = int(Port1) <= int(tport.split('-')[0]) and int(tport.split('-')[1]) <= int(Port2) or \
                                    int(tport.split('-')[0]) <= int(Port1) <= int(tport.split('-')[1]) or \
                                    int(tport.split('-')[0]) <= int(Port2) <= int(tport.split('-')[1])
                        else:
                            lport = int(tport.split('-')[0]) <= int(Port1) and int(Port2) <= int(tport.split('-')[1])

                else:
                    if '-' in tport:
                        lport = int(tport.split('-')[0]) <= int(Port) <= int(tport.split('-')[1])
                    else:
                        lport = int(tport) == int(Port)
                if lport:
                    break
        return lport

    #################################
    # Various Methods               #
    #################################

    def print_rule(self, color=False):
        """
        Print a rule
        :return: None
        """
        if self.DEBUG:
            print '[DEBUG][print_rule] Self rule: ', \
                'rulenumber:', self.rulenumber, ',', \
                'name:', self.name, ',',\
                'src:', self.source_address, ',',\
                'dst:', self.destination_address, ',',\
                'dport:', self.destination_port, ',',\
                'sport:', self.source_port, ',',\
                'proto:', self.protocol, ',',\
                'wildcard:', self.wildcard, ',',\
                'permit:', self.permit
        else:
            print 'Rule number:', self.rulenumber
            print 'Rule name:', self.name
            print 'Source Address:', self.source_address
            if self.source_name != '':
                print 'Source Name:', self.source_name
            print 'Destination Address:', self.destination_address
            if self.dest_name != '':
                print 'Destination Name:', self.dest_name
            print 'Destination Port:', self.destination_port
            print 'Source Port:', self.source_port
            print 'Protocol:', self.protocol
            print 'Wildcard:', self.wildcard
            if self.comment != '':
                print 'Comment:', self.comment
            if self.permit:
                if color:
                    print 'Action:', tools_color('B', 'green/black') + 'PERMIT' + tools_color()
                else:
                    print 'Action: PERMIT'
            else:
                if color:
                    print 'Action:', tools_color('B', 'red/black') + 'DENY' + tools_color()
                else:
                    print 'Action: DENY'

    def check_ip_acl(self, sIP, dIP, dPort, sPort, proto, show_deny_any, hide_allow_all, anyport, strict_search, is_0_any):
        """
        Check a flow in a rule
        :param sIP: Source IP
        :param dIP: Destination IP
        :param dPort: Destination Port
        :param sPort: Source Port
        :param proto: Protocol
        :param show_deny_any: Switch to SHOW a match in a DENY ALL ALL
        :param hide_allow_all: Switch to HIDE any PERMIT ALL ALL
        :param anyport: switch to match any port (usually for port ranges)
        :param strict_search: True/False (check explanation in link)
        :param is_0_any: FALSE when sIP/dIP is 0.0.0.0 but is the HOST 0.0.0.0/255.255.255.255 (or 0.0.0.0/0.0.0.0 with wildcards)
        :return: Integer (rule number matched)
        """
        def _any_in_source():
            return ('any' in self.source_address) or \
                   (self.wildcard and self.source_address == '0.0.0.0/255.255.255.255') or \
                   (not self.wildcard and self.source_address == '0.0.0.0/0.0.0.0')

        def _any_in_dest():
            return ('any' in self.destination_address) or \
                   (self.wildcard and self.destination_address == '0.0.0.0/255.255.255.255') or \
                   (not self.wildcard and self.destination_address == '0.0.0.0/0.0.0.0')

        def _check_ip(origin_ip, ip_to_check, wildcard):
            match = False
            for ip in origin_ip.split(','):
                if ':' in ip:
                    # IPv6
                    pass
                else:
                    netT = ip.split('/')[0]
                    filtT = ip.split('/')[1]

                    if '/' in ip_to_check:
                        if '.' not in ip_to_check.split('/')[1]:
                            ip_to_check = ip_to_check.split('/')[0] + '/' + cidr_to_mask(ip_to_check.split('/')[1])
                        if wildcard:
                            ip_to_check = ip_to_check.split('/')[0] + '/' + mask_to_wild(ip_to_check.split('/')[1])
                            match = self._checkNetWild(netT, filtT, ip_to_check)
                        else:
                            match = self._checkNetMask(netT, filtT, ip_to_check)
                    else:
                        if wildcard:
                            match = self._checkIPWild(netT, filtT, ip_to_check)
                        else:
                            match = self._checkIPMask(netT, filtT, ip_to_check)
                    if match:
                        break
            return match


        if self.DEBUG:
            print
            tools_debug(self.DEBUG, 'check_ip_acl',
                        'sIP:', sIP,
                        'dIP:', dIP,
                        'dPort:', dPort,
                        'sPort:', sPort,
                        'proto:', proto,
                        'show_deny_any:', show_deny_any,
                        'hide_allow_all:', hide_allow_all,
                        'anyport:', anyport,
                        'strict_search:', strict_search,
                        'is_0_any:', is_0_any)
            self.print_rule()
        match = False
        checked = False

        if not show_deny_any and not self.permit:
            if _any_in_source() and _any_in_dest():
                return 0

        if hide_allow_all and self.permit:
            if _any_in_source() and _any_in_dest():
                return 0

        if self.source_address == '' and self.destination_address == '':
            return 0

        if self.protocol == 'ip' or self.protocol == proto or (proto == 'ip' and not strict_search):
            # Link doesn't allow to check from the command line
            # Source IP = 0.0.0.0 and Destination IP = 0.0.0.0
            # so if both are 0.0.0.0 it means that it's being used as module
            # In this case, the only possible matches are also any any in source and destination
            if sIP == '0.0.0.0' and dIP == '0.0.0.0':
                if _any_in_source() and _any_in_dest():
                    # If source/dest are any, then check ports
                    match = True
                else:
                    return 0
            else:
                # Verifying that if strict_search = TRUE then when we have an ANY we are searching for 0.0.0.0
                if strict_search and is_0_any:
                    if sIP == '0.0.0.0' and not _any_in_source():
                        return 0
                    if dIP == '0.0.0.0' and not _any_in_dest():
                        return 0

                if _any_in_source() and _any_in_dest():
                    match = True
                    checked = True

                if not match and _any_in_source():
                    checked = True
                    if dIP == '0.0.0.0' and is_0_any:
                        match = True
                    else:
                        match = _check_ip(self.destination_address, dIP, self.wildcard)

                if not checked and _any_in_dest():
                    checked = True
                    if sIP == '0.0.0.0' and is_0_any:
                        match = True
                    else:
                        match = _check_ip(self.source_address, sIP, self.wildcard)

                if not checked:
                    match = _check_ip(self.source_address, sIP, self.wildcard) and  _check_ip(self.destination_address, dIP, self.wildcard)

        if match:
            if self.protocol == 'icmp' or self.protocol == 'ip':
                return self.rulenumber
            if self.protocol == 'vrrp' or self.protocol == '112':
                return self.rulenumber
            # If a dPort or sPort is specified in the command line, then it makes sense to check the ports when
            # the protocol is TCP/UDP
            if (dPort != '0' or sPort != '0') and (self.protocol != 'udp' and self.protocol != 'tcp'):
                return 0
            result = True
            for tport in dPort.split(','):
                result = result and self._checkPort(True, tport, anyport, strict_search)
            if result: # If still TRUE
                for tport in sPort.split(','):
                    result = result and self._checkPort(False, tport, anyport, strict_search)
            if result:
                return self.rulenumber
        return 0

    def has_non_contiguous(self):
        """
        Check if there is any wildcard non contiguous in the rule
        :return: TRUE/FALSE
        """
        if self.wildcard:
            if self.source_address == 'any':
                if self.destination_address == 'any':
                    return False
                else:
                    return not wild_is_contiguous(self.destination_address.split('/')[1])
            elif self.destination_address == 'any':
                    return not wild_is_contiguous(self.source_address.split('/')[1])

            return not (wild_is_contiguous(self.source_address.split('/')[1]) or
                        wild_is_contiguous(self.destination_address.split('/')[1]))
        return False

    def compare(self, rule_d):
        """
        Compare two rules
        :param rule_d: Rule to be compared
        :return: 0 -> If the rule is not equal
                 1 -> If the rule (syntactically) is the same
                 2 -> If even the name of the rule is the same
        """
        if self.DEBUG:
            tools_debug(self.DEBUG, 'rule.compare', 'entering')
        data_rule = rule_d.get_rule()
        result = 0
        if self.source_address == data_rule[1] and \
           self.destination_address == data_rule[2] and \
           self.destination_port == data_rule[3] and \
           self.source_port == data_rule[4] and \
           self.protocol == data_rule[5] and \
           self.permit == data_rule[6] and \
           self.wildcard == data_rule[7]:
            result = 1
            if self.name == data_rule[0]:
                result = 2
        if self.DEBUG:
            tools_debug(self.DEBUG, 'rule.compare', 'result', result)

        return result


class FWPolicy (object):
    """
    Policy class to store ACL and FW Policies.
    Self.rules will contain a list of FWRules with each rule

    Rules can be split in several ways:
        - splitting by non-continuos wildcards:
            This method will create several rules with contiguous wildcards instead of non-contiguous
            The name of the rule will be exactly the same than the original rule

        - splitting by IP:
            This method will create several rules with only one IP in source and destination.
            The name of the rules will be changed to:
                - <original rule name>{<original rule number>{<counter>{[<source_ip>,<destination_ip>]
    """
    DEBUG=False

    def __init__(self, name='', filename='', DEBUG=False):
        self.name = name
        self.filename = filename
        self.rules = ['<empty>'] # List of fwrules
        self.DEBUG = DEBUG

    #################################
    # GET Methods                   #
    #################################

    def get_rule_action(self, rulenumber):
        if len(self.rules) >= rulenumber:
            return self.rules[rulenumber-1].get_rule_action()

    def get_rules_number(self):
        i = 0
        if self.rules[0] != '<empty>':
            for rule in self.rules:
                i += 1
        return i

    def get_rule(self, rulenumber):
        if len(self.rules) >= rulenumber:
            return self.rules[rulenumber-1].get_rule()

    def get_rule_name(self, rulenumber):
        if len(self.rules) >= rulenumber:
            return self.rules[rulenumber-1].get_rule_name()

    def get_rules(self):
        return self.rules

    def get_policy_filename(self):
        return self.filename

    #################################
    # SET Methods                   #
    #################################

    def set_rule_dyn_data(self, rulenumber, attribute, value):
        if len(self.rules) >= rulenumber:
            self.rules[rulenumber-1].set_dyn_data(attribute, value)

    def set_name(self, name):
        self.name = name

    def set_empty_rule(self, rulenumber):
        self.rules[rulenumber-1].set_empty()

    def set_rule_name(self, rulenumber, name):
        self.rules[rulenumber - 1].set_name(name)

    def set_rule_comment(self, rulenumber, comment):
        self.rules[rulenumber - 1].set_comment(comment)

    def set_rule_action(self, rulenumber, accept):
        self.rules[rulenumber-1].set_action(accept)

    def set_all_rules(self, rules_list):
        if len(rules_list) > 0:
            self.rules = rules_list
        else:
            self.rules = ['<empty>']

    #################################
    # Various Methods               #
    #################################

    def new_rule(self, source_address, dest_address, dPort, sPort, protocol, ACCEPT, wildcard, source_name, dest_name):
        """
        Creates a new rule
        :param source_address:
        :param dest_address:
        :param dPort:
        :param sPort:
        :param protocol:
        :param ACCEPT:
        :param wildcard:
        :param source_name:
        :param dest_name:
        :return:
        """
        fwrule = FWRule()
        if self.DEBUG:
            fwrule.set_debug()
        fwrule.set_rule_data(sAddress=source_address, dAddress=dest_address, dPort=dPort, sPort=sPort, protocol=protocol, ACCEPT=ACCEPT, wildcard=wildcard, source_name=source_name, dest_name=dest_name)
        if self.rules[0] == '<empty>':
            self.rules = [fwrule]
        else:
            self.rules.append(fwrule)
        fwrule.set_rulenumber(len(self.rules))
        return len(self.rules)

    def new_empty_rule(self, wildcard):
        """
        Creates a new EMPTY rule
        :param wildcard: TRUE/FALSE if the rule has/hasn't a Wildcard
        :return:
        """
        fwrule = FWRule()
        if self.DEBUG:
            fwrule.set_debug()

        fwrule.set_rule_data('0.0.0.0/0.0.0.0', '0.0.0.0/0.0.0.0', '0', '0', 'ip', False, wildcard)
        if self.rules[0] == '<empty>':
            self.rules = [fwrule]
        else:
            self.rules.append(fwrule)
        fwrule.set_rulenumber(len(self.rules))
        return len(self.rules)

    def link(self, sIP, dIP, dPort, sPort, proto, rules_exclude=[], show_deny=False, hide_allow_all=True, showallmatches=False, ignore_dsmo=False, anyport=False, strict_search=False, is_0_any=True):
        """
        Check a flow against the policy

        :param sIP: Source IP
        :param dIP: Destination IP
        :param dPort: Destination Port
        :param sPort: Source Port
        :param proto: Protocol
        :param rules_exclude: Allow to exclude rules from being checked
        :param show_deny: Will show if a DENY is matched
        :param hide_allow_all: HIDE rules PERMIT ANY ANY
        :param showallmatches: will show all rules in the policy that match the flow (not just the first one)
        :param ignore_dsmo: Will ignore a match if the rule has a non-contiguous wildcard
        :param anyport: anyport matched will match the rule (usually with port ranges)
        :param strict_search: It makes a the search of the rules STRICT, so when we look for ANY in Source/Dest (0.0.0.0/0),
                              only ANY will match (we are not looking for any value but for the 0.0.0.0/0.0.0.0 value). Also
                              it applies to protocols: if we are looking for IP protocol, only IP protocol will match, but
                              if we are looking for TCP, TCP and IP will match.
        if Source IP or Destination IP is 0.0.0.0 and we want to match them with rules with ANY (or equivalent) in the rule
        :param is_0_any: FALSE when sIP/dIP is 0.0.0.0 but is the HOST 0.0.0.0/255.255.255.255 (or 0.0.0.0/0.0.0.0 with wildcards)
        :return: list of rules found
        """
        rulef = 0
        rules_found = []
        for rule in self.rules:
            if self.DEBUG:
                if self.rules[0] == '<empty>':
                    print '<empty>'
            if not self.rules[0] == '<empty>':
                rulef = rule.check_ip_acl(sIP, dIP, dPort, sPort, proto, show_deny, hide_allow_all, anyport, strict_search, is_0_any)
                if self.DEBUG:
                    tools_debug(self.DEBUG, 'link', 'Result check_ip_acl:', rulef)

            if rulef > 0:
                if rules_exclude and rulef in rules_exclude:
                    continue
                if rule.get_contiguous() > 0 and ignore_dsmo:
                    continue
                rules_found.append(rulef)
                if not showallmatches:
                    break
        return rules_found

    def split_non_contiguous_wild(self):
        """
        It will try to split a rule with a non contiguous wildcard into several networks
         It's not going to split any rule in more than <NONCONT_LIMIT> networks

        :return: None
        """
        end = False
        pos_list = -1
        non_c = False
        if type(self.rules[0]) != str:  # To avoid errors with "empty" policies
            while not end:
                pos_list += 1
                if pos_list >= len(self.rules):
                    break
                contig_num = self.rules[pos_list].get_contiguous()
                if 0 < contig_num <= NONCONT_LIMIT:
                    # This is a limit in the number of "new rules" that can be created

                    original_rule = self.rules[pos_list].get_rule()
                    original_rule_number = pos_list+1

                    if original_rule[1] != 'any' and original_rule[1] != '0.0.0.0/255.255.255.255':
                        if not wild_is_contiguous(original_rule[1].split('/')[1]):
                            netlistS = split_non_contiguous(original_rule[1].split('/')[0], original_rule[1].split('/')[1])
                            if len(netlistS) > 0:
                                non_c = True
                            else:
                                # It's possible that we can't split the source (because it will create more than 128)
                                # but still it's possible to split the destination
                                netlistS = [original_rule[1]]
                        else:
                            netlistS = [original_rule[1]]
                    else:
                        netlistS = ['0.0.0.0/255.255.255.255']

                    if original_rule[2] != 'any' and original_rule[2] != '0.0.0.0/255.255.255.255':
                        if not wild_is_contiguous(original_rule[2].split('/')[1]):
                            netlistD = split_non_contiguous(original_rule[2].split('/')[0], original_rule[2].split('/')[1])
                            if len(netlistD) > 0:
                                non_c = True
                            else:
                                netlistD = [original_rule[2]]
                        else:
                            netlistD = [original_rule[2]]
                    else:
                        netlistD = ['0.0.0.0/255.255.255.255']

                    # At this point we could have two different list with Source IPs and Dest IP, that together they
                    # can't reach NONCONT_LIMIT networks. We just combine then.
                    if non_c:
                        source_dest_list = []
                        for a in netlistS:
                            for b in netlistD:
                                source_dest_list.append([a,b])

                        inew_number = original_rule_number
                        for new_net in source_dest_list:
                            if source_dest_list.index(new_net) == 0:
                                self.rules[original_rule_number-1].set_source(new_net[0])
                                self.rules[original_rule_number-1].set_destination(new_net[1])
                            else:
                                inew_number += 1
                                # The first entry we already have it
                                newrule = FWRule()
                                newrule.set_rule_data(sAddress=new_net[0],
                                                      dAddress=new_net[1],
                                                      dPort=original_rule[3],
                                                      sPort=original_rule[4],
                                                      protocol=original_rule[5],
                                                      ACCEPT=original_rule[6],
                                                      wildcard=True,
                                                      name=original_rule[0],
                                                      rulenumber=inew_number)
                                if self.DEBUG:
                                    newrule.set_debug()
                                self.rules.insert(inew_number-1, newrule)
                        pos_list = inew_number-1 # Lists starts in 0!

                if self.get_rules_number() == pos_list or pos_list >= 50000:
                    # 50000 seems to be a good safe value to break the while in case of any issue. I would not expect to split in more than 50k rules
                    break
            self.renum_policy()

    def renum_policy(self):
        """
        Renumerate a policy
        :return: None
        """
        cont=0
        for rule in self.rules:
            if type(rule) == str:
                break
            cont += 1
            rule.set_rulenumber(cont)

    def check_if_any_non_contiguous(self):
        """
        Check if there is any non contiguous mask in the policy
        :return: TRUE/FALSE
        """
        if type(self.rules) != str:
            for rule in self.rules:
                if rule.has_non_contiguous():
                    return True
        return False

    def split_ips(self):
        """
        Some ACLs (like Juniper) allow to have multiple IPs in Source and Destination. This function split all these rules
        in rules with only one source and only one destination, adding some extra information in the name to identify them

        The name of the rules will be changed to:
            - <original rule name>{<original rule number>{<counter>{[<source_ip>,<destination_ip>]

        :return: True
        """
        if self.DEBUG:
            tools_debug(self.DEBUG, 'split_ips', 'Entering split_ips')
        cont_rules = 0
        for rule in self.rules:
            cont_rules += 1
            if self.DEBUG:
                if self.rules[0] == '<empty>':
                    print '<empty>'
                else:
                    rule.print_rule()
            if not self.rules[0] == '<empty>':
                rule_data = rule.get_rule()
                if rule_data[0].startswith('^'):  # Special rule, usually empty, we don't need to check it
                    continue
                if ',' not in rule_data[1] and ',' not in rule_data[2]:
                    continue
                if ',' in rule_data[1]:
                    ips_list = rule_data[1].split(',')
                else:
                    ips_list = [rule_data[1]]

                if ',' in rule_data[2]:
                    ipd_list = rule_data[2].split(',')
                else:
                    ipd_list = [rule_data[2]]
                rule_number = cont_rules
                num_split = 0
                for ips in ips_list:
                    for ipd in ipd_list:
                        num_split += 1
                        rule_name = rule_data[0] + '{' + str(cont_rules) + '{' + str(num_split) + '{' + str([ips,ipd])

                        if rule_number == cont_rules:
                            '''
                            We need to split the current rule into multiple rules, so instead of remove the current one
                            and add all the split, we change the current one with the data of the first "new rule"
                            '''
                            rule.set_source(ips)
                            rule.set_destination(ipd)
                            rule.set_name(rule_name)
                        else:
                            newrule = FWRule()
                            newrule.set_rule_data(sAddress=ips,
                                                  dAddress=ipd,
                                                  dPort=rule_data[3],
                                                  sPort=rule_data[4],
                                                  protocol=rule_data[5],
                                                  ACCEPT=rule_data[6],
                                                  wildcard=False,
                                                  name=rule_name,
                                                  rulenumber=rule_number)
                            if self.DEBUG:
                                newrule.set_debug()
                            self.rules.insert(rule_number - 1, newrule)
                        rule_number += 1

                self.renum_policy()

        return True

    def get_number_split_rules(self, rule_info):
        """
        Given a rule_name of a split rule by IP, will return the number of "children" matching that "child".
        Example:
        rule_info = term testt1{5{2{['10.0.0.0/255.255.255.0', '10.0.1.0/255.255.255.0']
        This rule, it's a compound one, with name: "term testt1" and number: "5", and this is the child '5{2'

        Will return the number of rules matching "term testt1{5"

        :param rule_info: Rule name of a child rule split by IP
        :return: Number of rules matching the info of the child
        """
        rule_data = rule_info.split('{')
        if len(rule_data) < 2:
            return -1
        if self.rules[0] == '<empty>':
            return -1
        rule_query = rule_data[0] + '{' + rule_data[1]
        i = 0
        for rule in self.rules:
            if rule_query in rule.get_rule()[0]:
                i += 1
        return i


    def remove_rule(self, rule_number):
        if self.DEBUG:
            tools_debug(self.DEBUG, 'find_rule', 'Entering remove_rule', rule_number)
        if self.rules[0] == '<empty>':
            return False
        for rule in self.rules:
            if rule.get_rule_number() == rule_number:
                self.rules.remove(rule)
                break
        if len(self.rules) == 0:
            self.rules = ['<empty>']

        return True

    def last_deny(self):
        """
        Check if the last rule is DENY ANY ANY
        :return: TRUE/FALSE
        """
        if self.DEBUG:
            tools_debug(self.DEBUG, 'last_deny', 'Entering')
        if self.rules[0] == '<empty>':
            return False
        last = self.rules[-1].get_rule()

        if not last[6]:  # DENY
            if last[7]:  # Wildcard
                return last[1] == '0.0.0.0/255.255.255.255' and last[2] == '0.0.0.0/255.255.255.255'
            else:
                return last[1] == '0.0.0.0/0.0.0.0' and last[2] == '0.0.0.0/0.0.0.0'
        return False

    def remove_shadowed_rules(self):
        """
        Check for a "basic" shadowed. It's only going to remove those rules that are fully shadowed.

        This method requires that the rules were split before
        :return: Number of removed rules (None in case of any error)
        """

        num_rules_removed = 0
        list_rules_removed = {}
        if self.DEBUG:
            tools_debug(self.DEBUG, 'remove_shadowed_rules', 'Entering"')
        if self.rules[0] == '<empty>':
            return list_rules_removed
        num_rule = len(self.rules)
        while num_rule > 0:
            rule = self.rules[num_rule-1].get_rule()
            # This method requires that the rules were split before
            if ',' in rule[1] or ',' in rule[2]:
                return None
            if rule[6]: # Only for Permit rules
                if rule[7]: # If it's a wildcard we need to change it
                    # Source
                    ip = rule[1].split('/')[0]
                    wild = rule[1].split('/')[1]
                    mask = mask_to_wild(wild) # This function is "bidirectional"
                    rule[1] = ip + '/' + mask
                    # Destination
                    ip = rule[2].split('/')[0]
                    wild = rule[2].split('/')[1]
                    mask = mask_to_wild(wild) # This function is "bidirectional"
                    rule[2] = ip + '/' + mask

                check = self.link(rule[1], rule[2], rule[3], rule[4], rule[5], rules_exclude=[num_rule], show_deny=True, hide_allow_all=False, strict_search=True, is_0_any=True, anyport=True)
                if len(check) > 0:
                    t_rule = self.rules[check[0]-1].get_rule()
                    if t_rule[6]:
                        if self.DEBUG:
                            tools_debug(self.DEBUG, 'remove_shadowed_rules', 'Removing rule', num_rule)
                        list_rules_removed[rule[0]] = self.rules[check[0]-1].get_rule()[0]
                        self.remove_rule(num_rule)
                        self.renum_policy()
                        num_rules_removed += 1
                    else:
                        if self.DEBUG:
                            tools_debug(self.DEBUG, 'remove_shadowed_rules', 'Matched with DENY. NOT removing', num_rule)
            num_rule -= 1

        return list_rules_removed


    #################################
    # Output Methods               #
    #################################


    def print_policy(self):
        """
        Print policy
        :return:
        """
        print 'Policy:', self.name
        for rule in self.rules:
            print
            if type(rule) == str:
                print rule
            else:
                rule.print_rule()

    def print_rule(self, rulenumber, color=False):
        """
        Print a specific rule
        :param rulenumber: Number of the rule to print
        :param color: Switch to print colors
        :return:
        """
        if len(self.rules) >= rulenumber:
            self.rules[rulenumber-1].print_rule(color=color)

'''
    def output_ncl_format(self):
        output_list = []
        if type(self.rules) != str:
            for rule in self.rules:
                rule.append(self.name)
                rule.append(self.source_address)
                rule.append(self.destination_address)
                rule.append(self.destination_port)
                rule.append(self.source_port)
                rule.append(self.protocol)
                rule.append(self.permit)
                rule.append(self.wildcard)
                
                rule_data = rule.get_rule()
                
                if rule_data[6]:
                    out = 'permit'
                else:
                    out = 'deny'
                    
                out += ' ' + rule_data[1].split('/')[0] + ' ' + rule_data[1].split('/')[1] + ' ' + \
                       rule_data[2].split('/')[0] + ' ' + rule_data[2].split('/')[1]
                output_list.append()
        return output_list
'''