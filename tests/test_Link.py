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
        self.files_ftg = './tests/test_data/test_acl_link.ftg'
        self.files_all = './tests/test_data/test_acl_link*'


        self.input1 = ['8.8.8.8', '9.9.9.9']
        self.input2 = ['1.2.3.5', '10.0.0.1']
        self.input3 = ['10.0.0.1', '10.0.0.2']
        self.input4 = ['10.0.1.129', '10.0.1.1']
        self.input5 = ['11.0.0.1', '10.0.0.2']
        self.input6 = ['11.0.0.1', '10.0.0.3']

        self.results_acl_basic = {}
        self.results_ncl_basic = {}
        self.results_jcl_basic = {}
        self.results_all = {'./tests/test_data/test_acl_link.acl': [['permit tcp host 1.2.3.5 host 10.0.0.1 eq 80', '1.2.3.5/255.255.255.255', '10.0.0.1/255.255.255.255', '80', '0', 'tcp', True, False, '', '', False, False, ''], ['permit tcp host 1.2.3.5 gt 7000 any', '1.2.3.5/255.255.255.255', '0.0.0.0/0.0.0.0', '0', '7001-65535', 'tcp', True, False, '', '', False, False, '']],
                            './tests/test_data/test_acl_link.ncl': [['permit tcp host 1.2.3.5 gt 7000 any', '1.2.3.5/0.0.0.0', '0.0.0.0/255.255.255.255', '0', '7001-65535', 'tcp', True, True, '', '', False, False, ''], ['permit tcp host 1.2.3.5 lt 8000 any', '1.2.3.5/0.0.0.0', '0.0.0.0/255.255.255.255', '0', '0-7999', 'tcp', True, True, '', '', False, False, '']]}
        self.results_ftg_basic1 = {'./tests/test_data/test_acl_link.ftg': [['', '10.0.0.1/255.255.255.255', '10.0.0.2/255.255.255.255', '80,443', '', 'tcp', True, False, 'port1', 'any', False, False, '(Rule: 1) ']]}
        self.results_ignore_line = {'./tests/test_data/test_acl_link.acl': [['permit ip 10.0.0.0/8 any eq http', '10.0.0.0/255.0.0.0', '0.0.0.0/0.0.0.0', '0', '0', 'ip', True, False, '', '', False, False, ''], ['permit 10.0.0.1 11.0.0.1', '10.0.0.1/11.0.0.1', '0.0.0.0/0.0.0.0', '0', '0', 'ip', True, False, '', '', False, False, '']]}
        self.results_negated1 = {'./tests/test_data/test_acl_link.ftg': [['', '11.0.0.0/255.255.255.0', '10.0.0.0/255.255.255.0', '100-200', '50-80', 'tcp', True, False, 'any', 'any', False, False, '(Rule: 5) ']]}
        self.results_negated2 = {'./tests/test_data/test_acl_link.ftg': [['', '11.0.0.0/255.255.255.0', '10.0.0.2/255.255.255.255', '1-65535', '', 'tcp', True, False, 'any', 'any', False, True, '(Rule: 3) ']]}

        self.maxDiff = None

    def test_Link_acl_basic(self):
        self.assertEqual(link.link(self.input1[0], self.input1[1], glob.glob(self.files_acl), {}), self.results_acl_basic)

    def test_Link_ncl_basic(self):
        self.assertEqual(link.link(self.input1[0], self.input1[1], glob.glob(self.files_ncl), {}), self.results_ncl_basic)

    def test_Link_jcl_basic(self):
        self.assertEqual(link.link(self.input1[0], self.input1[1], glob.glob(self.files_jcl), {}), self.results_jcl_basic)

    def test_Link_ftg_basic(self):
        options = {'dport':'443','proto':'tcp'}
        self.assertEqual(link.link(self.input3[0], self.input3[1], glob.glob(self.files_ftg), options), self.results_ftg_basic1)

    def test_Link_all(self):
        null = open(os.devnull, 'w')
        t_stdout = sys.stdout
        sys.stdout = null
        options = {'dport':'80','proto':'tcp', 'showallmatches': True}
        self.assertEqual(link.link(self.input2[0], self.input2[1], sorted(glob.glob(self.files_all)), options), self.results_all)
        sys.stdout = t_stdout

    def test_Link_ignore_line(self):
        null = open(os.devnull, 'w')
        t_stdout = sys.stdout
        sys.stdout = null
        options = {'dport':'443','proto':'tcp', 'showallmatches': True, 'ignore-line': 'term testt6'}
        self.assertEqual(link.link(self.input4[0], self.input4[1], sorted(glob.glob(self.files_all)), options), self.results_ignore_line)
        sys.stdout = t_stdout

    def test_Link_negated1(self):
        null = open(os.devnull, 'w')
        t_stdout = sys.stdout
        sys.stdout = null
        options = {'dport':'101','proto':'tcp'}
        self.assertEqual(link.link(self.input5[0], self.input5[1], sorted(glob.glob(self.files_all)), options), self.results_negated1)
        sys.stdout = t_stdout

    def test_Link_negated2(self):
        null = open(os.devnull, 'w')
        t_stdout = sys.stdout
        sys.stdout = null
        options = {'dport':'101','proto':'tcp'}
        self.assertEqual(link.link(self.input6[0], self.input6[1], sorted(glob.glob(self.files_all)), options), self.results_negated2)
        sys.stdout = t_stdout


if __name__ == '__main__':
    unittest.main()