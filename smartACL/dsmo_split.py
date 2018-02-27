#!/usr/bin/env python


# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import sys
import argparse
import linkdef
import tools
import third_party.ipaddr as ipaddr

parser = argparse.ArgumentParser()
parser.add_argument('network', help='Network with DSMO mask in the format X.X.X.X/Y.Y.Y.Y')
parser.add_argument('--host', help='Display the split as HOST (/32)', action='store_true')
args = parser.parse_args()

dsmo_net = args.network

if len(dsmo_net.split('/')) != 2 or len(dsmo_net.split('.')) != 7:
    print 'ERROR: Format of network not valid. It should be in the format X.X.X.X/Y.Y.Y.Y'
    quit()

only_host = args.host

net_split = tools.split_non_contiguous(dsmo_net.split('/')[0], dsmo_net.split('/')[1])

for net in net_split:
    ip = net.split('/')[0]
    netmask = tools.mask_to_wild(net.split('/')[1])
    if only_host:
        if '/0.0.0.0' in net:
            # 0.0.0.0 in wildcard is host but in also means ANY is 'standard' way
            net = net.split('/')[0] + '/255.255.255.255'
        ip = ipaddr.IPv4Network(net)
        for host in list(ip):
            ip_host = str(host)
            print ip_host
    else:
        print ip + '/' + netmask
