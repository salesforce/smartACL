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
        self.filet1 = 'tests/test_data/test_acl_smartCompare1'
        self.filet2 = 'tests/test_data/test_acl_smartCompare2'
        self.filet2a = 'tests/test_data/test_acl_smartCompare2a'
        self.filet3 = 'tests/test_data/test_acl_smartCompare3'
        self.filet4 = 'tests/test_data/test_acl_smartCompare4'
        self.filet5 = 'tests/test_data/test_acl_smartCompare5'
        self.filet6 = 'tests/test_data/test_acl_smartCompare6'
        self.filet7 = 'tests/test_data/test_acl_smartCompare7'
        self.filet8 = 'tests/test_data/test_acl_smartCompare8'
        self.filet9 = 'tests/test_data/test_acl_smartCompare9'
        self.filet10 = 'tests/test_data/test_acl_smartCompare10'
        self.filet11 = 'tests/test_data/test_acl_smartCompare11'
        self.filet12 = 'tests/test_data/test_acl_smartCompare12'
        self.filet13 = 'tests/test_data/test_acl_smartCompare13'
        self.filet14 = 'tests/test_data/test_acl_smartCompare14'
        self.filet15 = 'tests/test_data/test_acl_smartCompare15'
        self.filet16 = 'tests/test_data/test_acl_smartCompare16'
        self.filet17 = 'tests/test_data/test_acl_smartCompare17'


        self.results_t1_t2 = ['permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.127 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080']
        self.results_t1_t2a = ['permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.127 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080']
        self.results_t2a_t2a = ['deny tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127 eq 22', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080']
        self.results_t3_t4 = ['permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7081']
        self.results_t5_t6 = ['permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.127 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080']
        self.results_t7_t8 = ['permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.192 0.0.0.63 eq 7080']
        self.results_t8_t7 = ['permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.254 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.1 0.0.0.254 eq 7080']
        self.results_t7_t7 = ['permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.63 eq 7080', 'permit tcp 10.231.69.128 0.0.0.127 10.0.0.192 0.0.0.63 eq 7080']
        '''
        The T9 - T9 comparison is an interesting case. T9 has two shadowed rules inside, so when we try to compare it with itself,
        the two shadowed rules are shown like NOT matched. That is completely TRUE. Although it could seem to be inconsistent,
        indeed these two lines will be never matched, so in this case, smartCompare is working fine.
        
        The same would apply to T10 - T10 and T9 - T10
        '''
        self.results_t9_t9 = ['term testt1', 'term testt2', 'term testt3', 'term testt4']
        self.results_t10_t10 =  ['term testt1', "term testt2{2{1{['10.0.0.192/255.255.255.192', '10.0.1.0/255.255.255.128']", "term testt2{2{2{['10.0.0.192/255.255.255.192', '10.0.1.128/255.255.255.192']", 'term testt3', 'term testt4']
        self.results_t9_t10 = ['term testt3', 'term testt4']
        self.results_t11_t12 = ['term testt2', 'term testt3', 'term testt5']
        self.results_t11_t12_is = ['term testt3', 'term testt5']
        self.results_t13_t13 = ['permit udp 0.0.0.0 0.0.0.0 eq 67 255.255.255.255 0.0.0.0 eq 68', 'permit udp any eq 68 255.255.255.255 0.0.0.0 eq 67', 'permit udp 192.168.1.0 0.0.0.63 eq 68 any eq 68', 'permit udp 192.168.1.192 0.0.0.63 eq 68 any eq 68']
        self.results_t14_t15 = ['permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127']
        self.results_t15_t14 = []
        self.results_t16_t17 = []
        self.results_t17_t16 = []


        null = open(os.devnull, 'w')
        self.stdout = sys.stdout
        sys.stdout = null
        self.longMessage = True

    def test_smartCompare_t1_t2(self):
        policy1 = linkdef.FWPolicy('', self.filet1, False)
        link_cisco.acl_parser(self.filet1, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet2, False)
        link_cisco.acl_parser(self.filet2, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t1_t2, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t1_t2, 'Ignoring Shadowed Rules')


    def test_smartCompare_t1_t2a(self):
        policy1 = linkdef.FWPolicy('', self.filet1, False)
        link_cisco.acl_parser(self.filet1, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet2a, False)
        link_cisco.acl_parser(self.filet2a, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t1_t2a, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t1_t2a, 'Ignoring Shadowed Rules')

    def test_smartCompare_t2a_t2a(self):
        policy1 = linkdef.FWPolicy('', self.filet2a, False)
        link_cisco.acl_parser(self.filet2a, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet2a, False)
        link_cisco.acl_parser(self.filet2a, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t2a_t2a, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t2a_t2a, 'Ignoring Shadowed Rules')

    def test_smartCompare_t3_t4(self):
        policy1 = linkdef.FWPolicy('', self.filet3, False)
        link_cisco.acl_parser(self.filet3, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet4, False)
        link_cisco.acl_parser(self.filet4, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t3_t4, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t3_t4, 'Ignoring Shadowed Rules')

    def test_smartCompare_t5_t6(self):
        policy1 = linkdef.FWPolicy('', self.filet5, False)
        link_cisco.acl_parser(self.filet5, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet6, False)
        link_cisco.acl_parser(self.filet6, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t5_t6, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t5_t6, 'Ignoring Shadowed Rules')

    def test_smartCompare_t7_t7(self):
        policy1 = linkdef.FWPolicy('', self.filet7, False)
        link_cisco.acl_parser(self.filet7, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet7, False)
        link_cisco.acl_parser(self.filet7, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t7_t7, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t7_t7, 'Ignoring Shadowed Rules')

    def test_smartCompare_t7_t8(self):
        policy1 = linkdef.FWPolicy('', self.filet7, False)
        link_cisco.acl_parser(self.filet7, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet8, False)
        link_cisco.acl_parser(self.filet8, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t7_t8, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t7_t8, 'Ignoring Shadowed Rules')

    def test_smartCompare_t8_t7(self):
        policy1 = linkdef.FWPolicy('', self.filet8, False)
        link_cisco.acl_parser(self.filet8, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet7, False)
        link_cisco.acl_parser(self.filet7, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t8_t7, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t8_t7, 'Ignoring Shadowed Rules')


    def test_smartCompare_t9_t9(self):
        policy1 = linkdef.FWPolicy('', self.filet9, False)
        link_juniper.jcl_parser(self.filet9, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet9, False)
        link_juniper.jcl_parser(self.filet9, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t9_t9, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        # Because the shadowed rule is removed, both list need to be sorted first.
        self.assertEqual(smartacl_result.sort(), self.results_t9_t9.sort(), 'Ignoring Shadowed Rules')

    def test_smartCompare_t10_t10(self):
        policy1 = linkdef.FWPolicy('', self.filet10, False)
        link_juniper.jcl_parser(self.filet10, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet10, False)
        link_juniper.jcl_parser(self.filet10, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t10_t10, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t10_t10, 'Ignoring Shadowed Rules')

    def test_smartCompare_t9_t10(self):
        policy1 = linkdef.FWPolicy('', self.filet9, False)
        link_juniper.jcl_parser(self.filet9, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet10, False)
        link_juniper.jcl_parser(self.filet10, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t9_t10, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t9_t10, 'Ignoring Shadowed Rules')

    def test_smartCompare_t11_t12(self):
        policy1 = linkdef.FWPolicy('', self.filet11, False)
        link_juniper.jcl_parser(self.filet11, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet12, False)
        link_juniper.jcl_parser(self.filet12, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t11_t12, 'Normal Test')

    '''
    This is a very special case that it's better to have it separated because the results are different with/without "ignoreshadow" option.
    Explanation (simplified):
        - ACL1: 
            - Rule1
            - Rule2 -> Shadowed by Rule1
        - ACL2:
            - Rule2
    
    With ignoreshadow FALSE:
        - The Rule1 is NOT in ACL2
        - The Rule2 is in ACL2
        - The output shows that Rule1 is missing
    
    With ignoreshadow TRUE:
        - The Rule2 is removed because it's shadowed by Rule1
        - The Rule1 is NOT in ACL2
        - The output shows Rule1 and Rule2 are missing (Rule1 logically, but also all shadowed rules like Rule2)
    
    '''
    def test_smartCompare_t11_t12_ignoreshadowed(self):
        policy1 = linkdef.FWPolicy('', self.filet11, False)
        link_juniper.jcl_parser(self.filet11, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet12, False)
        link_juniper.jcl_parser(self.filet12, policy2, False)
        policy1.split_ips()
        policy2.split_ips()
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t11_t12_is, 'Ignoring Shadowed Rules')

    def test_smartCompare_t13_t13(self):
        policy1 = linkdef.FWPolicy('', self.filet13, False)
        link_cisco.acl_parser(self.filet13, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet13, False)
        link_cisco.acl_parser(self.filet13, policy2, False)
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t13_t13, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t13_t13, 'Ignoring Shadowed Rules')

    def test_smartCompare_t14_t15(self):
        policy1 = linkdef.FWPolicy('', self.filet14, False)
        link_cisco.acl_parser(self.filet14, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet15, False)
        link_cisco.acl_parser(self.filet15, policy2, False)
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t14_t15, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t14_t15, 'Ignoring Shadowed Rules')

    def test_smartCompare_t15_t14(self):
        policy1 = linkdef.FWPolicy('', self.filet15, False)
        link_cisco.acl_parser(self.filet15, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet14, False)
        link_cisco.acl_parser(self.filet14, policy2, False)
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t15_t14, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t15_t14, 'Ignoring Shadowed Rules')

    def test_smartCompare_t16_t17(self):
        policy1 = linkdef.FWPolicy('', self.filet16, False)
        link_cisco.acl_parser(self.filet16, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet17, False)
        link_cisco.acl_parser(self.filet17, policy2, False)
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t16_t17, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t16_t17, 'Ignoring Shadowed Rules')

    def test_smartCompare_t17_t16(self):
        policy1 = linkdef.FWPolicy('', self.filet17, False)
        link_cisco.acl_parser(self.filet17, policy1, False)
        policy2 = linkdef.FWPolicy('', self.filet16, False)
        link_cisco.acl_parser(self.filet16, policy2, False)
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=False, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t17_t16, 'Normal Test')
        smartacl_result = smartACL.smartCompare2(policy1, policy2, verbose=False,only_different=False,outprint=False,ignore_lines='',ignoredeny=False, ignoreshadowed=True, DEBUG=False)
        self.assertEqual(smartacl_result, self.results_t17_t16, 'Ignoring Shadowed Rules')


    def tearDown(self):
        sys.stdout = self.stdout


unittest.main()