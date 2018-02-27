# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import itertools

import sys
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

import linkdef


def DEBUG(debug_v, function, *args):
    if debug_v:
        print "[DEBUG][" + str(function) + "]", args


def cidr_to_mask(cidr):
    return '.'.join([str((0xffffffff << (32 - int(cidr)) >> i) & 0xff)
                     for i in [24, 16, 8, 0]])


def mask_to_wild(mask):
    return '.'.join([str(255 - int(i)) for i in mask.split('.')])


''' 
Not used, but let's keep it

def get_last_IP_wild(net, wild):
    # Return the last valid IP from a network with a wildcard
    netS = net.split('.')
    wildS = wild.split('.')
    iPos = 0
    resS = []
    for i in xrange(0, 4):
        resS.append([])
    for netOctect in netS:
        iPos += 1
        netB = format(int(netOctect), 'b').zfill(8)
        wildB = format(int(wildS[iPos - 1]), 'b').zfill(8)
        for x in xrange(8):
            resS[iPos - 1].append(str(int(netB[x]) | int(wildB[x])))
    res = ''
    for i in resS:
        res = res + '.' + str(int(''.join(i), 2))

    return res[1:]
'''


def calc_previous_IP(IP):
    # Return the previous IP to one given
    n = []
    first = True
    for octect in IP.split('.')[::-1]:
        if int(octect) == 0 and first:
             n.append('255')
        elif first:
            first = False
            n.append(str(int(octect) - 1))
        else:
            n.append(str(int(octect)))
    return '.'.join(n[::-1])


def wild_is_contiguous(wild):
    # Check if a wildcard is contiguous or not
    one_found = False
    wildS = wild.split('.')
    for octect in wildS:
        wildB = format(int(octect), 'b').zfill(8)
        for x in xrange(8):
            if wildB[x] == '1' and not one_found:
                one_found = True
            elif wildB[x] == '0' and one_found:
                return False
    return True


def split_non_contiguous(ip, wild):
    # It will create contiguous networks from the IP/wildcard (where wildcard is non contiguous)
    # Although technically it will work with contiguous wildcard, it will create in most of the
    # cases /32 networks, so it's not useful for this input.
    def _contiguous_octect(wild):
        # Check if the binary is a contiguous.
        cont = True
        first_bit = wild[0]
        if first_bit == '1' and wild.count('0') > 0:
            cont = False
        else:
            for i in xrange(7):
                if first_bit == '0':
                    if wild[i+1] == '0':
                        continue
                    else:
                        first_bit = '1'
                        continue
                elif first_bit == '1' and wildB[i+1] != '1':
                    cont = False
                    break
        return cont

    net_list = []
    num_networks = 0
    number_ones = 0

    # Number of networks is defined by numbers of 1
    # To find the mask length we need to perform a logic add between wild and network and
    # count the number of zeros starting from the right until first 1
    wildS = wild.split('.')
    ipS = ip.split('.')

    '''
     Counting number of networks and defining non contiguous octects:
     - We have the variable wild_list_contiguous_octects that is a list of the status of each octect. This state can be:
        - cont -> contiguous octect
        - non-cont -> non contiguous octect
        - full1 -> octect with 11111111
     We have to count the number of "1" per octects. If the octect is non contiguous then it's marked.
     If the octect is contiguous:
        - If it's '11111111' is marked
        - If not, we need to confirm that the all previous octects are '11111111'.
        
     Examples: 
     
     Standard non contiguous:
        0.0.0.2.255 :
            - We start with the 255 -> contiguous and full 1
            - 2 -> non contiguous
            - 0 and 0 -> contiguous
            
        Then the number of 1 in non-contiguous is one, so 2 ^ 1 = 2 networks
        
     Weird non contiguous mask:
        0.0.8.63 :
            - We start with 63 (01111111) -> contiguous, but NOT full
            - 8 -> Non contiguous
            - 0 and 0 -> contiguous
            
        Then the number of 1 in non-contiguous is one, so 2 ^ 1 = 2 networks

     More weird non contiguous mask:
        0.0.1.63 -> This a non-contiguous mask, but each of the octects are contiguous:
            - We start with 63 (01111111) -> contiguous, but NOT full
            - 1 -> contiguous BUT, the all the previous octects are not full1 so it's marked as NON contiguous
            - 0 and 0 -> contiguous
        
        Then the number of 1 in non-contiguous is one, so 2 ^ 1 = 2 networks
    
    '''

    iPos = 4
    wild_list_contiguous_octects = ['cont', 'cont', 'cont', 'cont']
    for octect in reversed(wildS):
        iPos -= 1
        wildB = format(int(octect), 'b').zfill(8)
        if _contiguous_octect(wildB):
            if wildB.count('1') == 8:
                wild_list_contiguous_octects[iPos] = 'full1'
            else:
                if iPos < 3:
                    for i in range(iPos, 3):
                        wildB_temp = format(int(wildS[i]), 'b').zfill(8)
                        if wild_list_contiguous_octects[i] != 'full1':
                            wild_list_contiguous_octects[iPos] = 'non-cont'
                            break
                else:
                    wild_list_contiguous_octects[iPos] = 'cont'

        else:
            wild_list_contiguous_octects[iPos] = 'non-cont'

        if wild_list_contiguous_octects[iPos] == 'non-cont':
            number_ones += wildB.count('1')
    num_networks = 2 ** number_ones

    '''
    # Calculating mask of networks.

    Once we identify the number of networks we have, we need to find which network mask is going to be used.
    
    Unfortunately is not clear this information in a non contiguous wild card. For example:
    
    10.0.0.0 0.0.2.0 -> Can be split into 10.0.0.0/24 and 10.0.2.0/24
    
    but also this one:
    
    10.0.0.0 0.0.2.255 -> Can be split into 10.0.0.0/24 and 10.0.2.0/24
    
    The first case will be only posible if the octect in the IP is 0.
          
    We defined a "logic switch" name weird_0_switch to indentify this behaviour. 
    
    To calculated the netmask, we need to start to check "1" starting from right to left. We take all the contiguous "1" and
    we create the netmask using 2 ^ number of ones.
    
    '''
    iPos = 4
    netmask = ''
    weird_0_switch = True
    for octect in reversed(wildS):
        iPos -= 1
        wildB = format(int(octect), 'b').zfill(8)
        ipB = format(int(ipS[iPos]), 'b').zfill(8)
        if wild_list_contiguous_octects[iPos] == 'cont' or wild_list_contiguous_octects[iPos] == 'full1':
            # It seems that a valid wildcard non contiguous is:
            # 8.64.4.0 -> that would match eight /24 networks
            # but this wildcard should be represented as:
            # 8.64.4.255 -> clearly now a /24 networks.
            # This change from 0 to 255 should only happen starting from the right to the left
            # and before we find any other value.
            # The switch: weird_0_switch is used to control this.
            if wildB == '00000000' and ipB == '00000000' and weird_0_switch:
                netmask = '255' + '.' + netmask
            else:
                weird_0_switch = False
                netmask = str(2 ** wildB.count('1') - 1) + '.' + netmask
        else:
            netmask = '0' + '.' + netmask
    netmask = netmask[:-1]

    # Binary list of all combinations that we would use to create the networks
    # This is how it works (with only one octect as example):
    #
    # network_addres: 00100000
    # wildcard:       00011000
    #
    # In bit position 4 and 5 any value is accepted so it will create a the following list:
    # (00,01,10,11)
    #
    # It will create the network changing the bit 4,5 (where there is a 1 in the wildcard) with the
    # values generates in the binary list

    # Creating binary list
    bin_list = ["".join(seq) for seq in itertools.product("01", repeat=number_ones)]

    ipS = ip.split('.')
    ipB = ''
    for octect in ipS:
        ipB = ipB + '.' + format(int(octect), 'b').zfill(8)
    ipB = ipB[1:]

    wildS = wild.split('.')
    wildB = ''
    for octect in wildS:
        wildB = wildB + '.' + format(int(octect), 'b').zfill(8)
    wildB = wildB[1:]

    for bin_combination in bin_list:
        new_net = []
        b = 0
        iPos = -1
        for octect in wildB.split('.'):
            iPos += 1
            for i in xrange(len(octect)):
                if octect[i] == '.':
                    continue
                elif octect[i] == '0':
                    new_net.append(ipB.split('.')[iPos][i])
                else:
                    if wild_list_contiguous_octects[iPos] == 'cont' or wild_list_contiguous_octects[iPos] == 'full1':
                        new_net.append(ipB.split('.')[iPos][i])
                    else:
                        new_net.append(bin_combination[b])
                        b += 1

        net_list.append(str(int(''.join(new_net[0:8]), 2)) + '.' +
                        str(int(''.join(new_net[8:16]), 2)) + '.' +
                        str(int(''.join(new_net[16:24]), 2)) + '.' +
                        str(int(''.join(new_net[24:32]), 2)) +
                        '/' + netmask)

    netlist_obj = []
    for net in net_list:
        if net.split('/')[1] == '0.0.0.0':
            net = net.split('/')[0] + '/' + '255.255.255.255'
        netlist_obj.append(netaddr.IPNetwork(net))
    merged_list = netaddr.cidr_merge(netlist_obj)

    inv_oct = []
    net_list = []
    for i in merged_list:
        inv_oct = []
        bits = i.netmask.bits()
        for octects in bits.split('.'):
            inv_oct.append(str(int(''.join('1' if x == '0' else '0' for x in octects), base=2)))
        wildcard = '.'.join(inv_oct)
        host = str(i.ip)
        net_list.append(host + '/' + wildcard)

    return net_list


def color(style='', color='default'):
    if color == 'default':
        return '\x1b[0m'

    fg = 30 + linkdef.colors.index(color.split('/')[0])
    bg = 40 + linkdef.colors.index(color.split('/')[1])

    return '\x1b[%sm' % (';'.join([str(linkdef.styles.index(style)), str(fg), str(bg)]))



