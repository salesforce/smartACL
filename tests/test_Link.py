# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import unittest
import os
import sys
import glob

from smartACL import link


class smartTest(unittest.TestCase):
    def setUp(self):
        self.files_acl= './tests/test_data/test_acl_link.acl'
        self.files_ncl = './tests/test_data/test_acl_link.ncl'
        self.files_jcl = './tests/test_data/test_acl_link.jcl'
        self.files_all = './tests/test_data/test_acl_link*'

        self.input1 = ['8.8.8.8', '9.9.9.9']
        self.input2 = ['1.2.3.5', '10.0.0.1']

        self.results_acl_basic = {}
        self.results_ncl_basic = {}
        self.results_jcl_basic = {}
        self.results_all = {'./tests/test_data/test_acl_link.acl': [['permit tcp host 1.2.3.5 host 10.0.0.1 eq 80', '1.2.3.5/255.255.255.255', '10.0.0.1/255.255.255.255', '80', '0', 'tcp', True, False, '', '', ''], ['permit tcp host 1.2.3.5 gt 7000 any', '1.2.3.5/255.255.255.255', '0.0.0.0/0.0.0.0', '0', '7001-65535', 'tcp', True, False, '', '', '']],
                            './tests/test_data/test_acl_link.ncl': [['permit tcp host 1.2.3.5 gt 7000 any', '1.2.3.5/0.0.0.0', '0.0.0.0/255.255.255.255', '0', '7001-65535', 'tcp', True, True, '', '', ''], ['permit tcp host 1.2.3.5 lt 8000 any', '1.2.3.5/0.0.0.0', '0.0.0.0/255.255.255.255', '0', '0-7999', 'tcp', True, True, '', '', '']]}

    def test_Link_acl_basic(self):
        self.assertEqual(link.link(self.input1[0], self.input1[1], glob.glob(self.files_acl), {}), self.results_acl_basic)

    def test_Link_ncl_basic(self):
        self.assertEqual(link.link(self.input1[0], self.input1[1], glob.glob(self.files_ncl), {}), self.results_ncl_basic)

    def test_Link_jcl_basic(self):
        self.assertEqual(link.link(self.input1[0], self.input1[1], glob.glob(self.files_jcl), {}), self.results_jcl_basic)

    def test_Link_all(self):
        null = open(os.devnull, 'w')
        t_stdout = sys.stdout
        sys.stdout = null
        self.assertEqual(link.link(self.input2[0], self.input2[1], sorted(glob.glob(self.files_all)), {'dport':'80','proto':'tcp', 'showallmatches': True}), self.results_all)
        sys.stdout = t_stdout


unittest.main()