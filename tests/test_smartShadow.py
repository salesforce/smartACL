# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import unittest
import sys
import os

from smartACL import linkdef
from smartACL import link_cisco
from smartACL import link_juniper
from smartACL import smartACL


class smartTest(unittest.TestCase):
    def setUp(self):
        self.file1 = 'tests/test_data/test_acl_smartShadow1'
        self.file2 = 'tests/test_data/test_acl_smartShadow2'
        self.file3 = 'tests/test_data/test_acl_smartShadow3'
        self.file4 = 'tests/test_data/test_acl_smartShadow4'
        self.file5 = 'tests/test_data/test_acl_smartShadow5'
        self.file6 = 'tests/test_data/test_acl_smartShadow6'
        self.file7 = 'tests/test_data/test_acl_smartShadow7'
        self.file8 = 'tests/test_data/test_acl_smartShadow8'
        self.file9 = 'tests/test_data/test_acl_smartShadow9'
        self.file10 = 'tests/test_data/test_acl_smartShadow10'
        self.file11 = 'tests/test_data/test_acl_smartShadow11'


        self.results_f1 = [{'permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127': 'permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080': 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.127 eq 7080': 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080': 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080'}, {}]
        self.results_f2 = [{'permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127': 'permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080': 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080\npermit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.127 eq 7080\npermit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080'}, {}]
        self.results_f3 = [{}, {}]
        self.results_f4 = [{'deny tcp 10.0.0.0 0.255.255.255 10.0.0.0 0.0.255.255 eq 80': 'deny tcp 10.0.0.0 0.255.255.255 10.0.0.0 0.255.255.255 eq 80'}, {'deny tcp 10.0.0.0 0.255.255.255 10.0.0.0 0.0.255.255 eq 80': 'deny tcp 10.0.0.0 0.255.255.255 10.0.0.0 0.255.255.255 eq 80'}]
        self.results_f5 = [{}, {'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 80': 'deny tcp 10.0.0.0 0.255.255.255 10.0.0.0 0.255.255.255 eq 80'}]
        self.results_f6 = [{'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.127 eq 80': 'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 80'}, {}]
        self.results_f7 = [{'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.127 eq 80': 'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 80'}, {}]
        self.results_f8 = [{'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.127 eq 80': 'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 80'}, {'permit tcp host 10.0.0.10 host 10.10.10.10 eq 80': 'deny tcp 10.0.0.0 0.255.255.255 10.0.0.0 0.255.255.255 eq 80'}]
        self.results_f9 = [{'term testt5': 'term testt6', 'term testt2': 'term testt1'}, {'term testt6': 'term testt3'}]
        self.results_f10 = [{'term testt2a': "term testt1{1{1{['10.0.0.0/255.255.255.0', '10.0.1.0/255.255.255.0']", "term testt2b{8{1{['11.0.0.192/255.255.255.192', '10.0.1.0/255.255.255.0']": "term testt1{1{3{['11.0.0.0/255.255.255.0', '10.0.1.0/255.255.255.0']", "term testt6{17{1{['10.0.0.0/255.255.255.0', '10.0.1.0/255.255.255.192']": "term testt1{1{1{['10.0.0.0/255.255.255.0', '10.0.1.0/255.255.255.0']"}, {'term testt5': "term testt3{10{1{['10.0.0.0/255.0.0.0', '10.0.0.0/255.0.0.0']\nterm testt3{10{2{['10.0.0.0/255.0.0.0', '11.0.0.0/255.0.0.0']", "term testt6{17{1{['10.0.0.0/255.255.255.0', '10.0.1.0/255.255.255.192']": "term testt3{10{1{['10.0.0.0/255.0.0.0', '10.0.0.0/255.0.0.0']"}]
        self.results_f11 = [{'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.127 eq 80': 'permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 80'}, {'permit tcp 12.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 80': 'deny tcp any any eq 80', 'permit tcp host 10.0.0.10 host 10.10.10.10 eq 80': 'deny tcp any any eq 80'}]

        null = open(os.devnull, 'w')
        self.stdout = sys.stdout
        sys.stdout = null

    def test_smartShadow1(self):
        policy = linkdef.FWPolicy('', self.file1)
        link_cisco.acl_parser(self.file1, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f1)

    def test_smartShadow2(self):
        policy = linkdef.FWPolicy('', self.file2)
        link_cisco.acl_parser(self.file2, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f2)

    def test_smartShadow3(self):
        policy = linkdef.FWPolicy('', self.file3)
        link_cisco.acl_parser(self.file3, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f3)

    def test_smartShadow4(self):
        policy = linkdef.FWPolicy('', self.file4)
        link_cisco.acl_parser(self.file4, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f4)

    def test_smartShadow5(self):
        policy = linkdef.FWPolicy('', self.file5)
        link_cisco.acl_parser(self.file5, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f5)

    def test_smartShadow6(self):
        policy = linkdef.FWPolicy('', self.file6)
        link_cisco.acl_parser(self.file6, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f6)

    def test_smartShadow7(self):
        policy = linkdef.FWPolicy('', self.file7)
        link_cisco.acl_parser(self.file7, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f7)

    def test_smartShadow8(self):
        policy = linkdef.FWPolicy('', self.file8)
        link_cisco.acl_parser(self.file8, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f8)

    def test_smartShadow9(self):
        policy = linkdef.FWPolicy('', self.file9)
        link_juniper.jcl_parser(self.file9, policy)
        policy.split_ips()
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f9)

    def test_smartShadow10(self):
        policy = linkdef.FWPolicy('', self.file10)
        link_juniper.jcl_parser(self.file10, policy)
        policy.split_ips()
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f10)

    def test_smartShadow11(self):
        policy = linkdef.FWPolicy('', self.file11)
        link_cisco.acl_parser(self.file11, policy)
        self.assertEqual(smartACL.smartShadow2(policy), self.results_f11)

    def tearDown(self):
        sys.stdout = self.stdout


unittest.main()