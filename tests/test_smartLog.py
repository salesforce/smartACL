# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

import unittest
import sys
import os

from smartACL import smartACL


class smartTest(unittest.TestCase):
    def setUp(self):
        self.filetacl_basic = 'tests/test_data/test_acl_basic.diff'
        self.filetacl_basic2 = 'tests/test_data/test_acl_basic2.diff'
        self.filetacl_basic4 = 'tests/test_data/test_acl_basic4.diff'
        self.filetacl_non = 'tests/test_data/test_acl_non.diff'
        self.filetacl_non_and_con = 'tests/test_data/test_acl_non_and_con.diff'
        self.filetacl_splitted = 'tests/test_data/test_acl_splitted.diff'

        self.results_filetacl_basic = [{'tests/test_data/test_acl_basic.diff': []}, [1, 0, 0, 1, 1, 0, 0, 0, [], 0]]
        self.results_filetacl_basic2 = [{'tests/test_data/test_acl_basic2.diff': []}, [2, 0, 0, 1, 0, 1, 0, 0, [], 0]]
        self.results_filetacl_basic4 = [{'tests/test_data/test_acl_basic4.diff': ['permit tcp 10.0.0.0 0.0.0.255 182.17.74.0 0.0.0.255 eq 80']}, [2, 0, 0, 2, 1, 0, 0, 0, [], 0]]
        self.results_filetacl_non = [{'tests/test_data/test_acl_non.diff': ['permit tcp 10.0.0.0 0.0.0.255 182.17.73.0 8.64.4.0 eq 80']}, [2, 0, 0, 1, 0, 0, 0, 0, [], 0]]
        self.results_filetacl_non_and_con = [{'tests/test_data/test_acl_non_and_con.diff': []}, [1, 0, 0, 2, 0, 2, 0, 0, [], 0]]
        self.results_filetacl_splitted = [{'tests/test_data/test_acl_splitted.diff': ['permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080']}, [2, 0, 0, 1, 0, 0, 0, 0, [], 0]]


        null = open(os.devnull, 'w')
        self.stdout = sys.stdout
        sys.stdout = null

    def test_smartLog_acl_basic(self):
        self.assertEqual(smartACL.smartLog(self.filetacl_basic), self.results_filetacl_basic)

    def test_smartLog_acl_basic2(self):
        self.assertEqual(smartACL.smartLog(self.filetacl_basic2), self.results_filetacl_basic2)

    def test_smartLog_acl_basic4(self):
        self.assertEqual(smartACL.smartLog(self.filetacl_basic4), self.results_filetacl_basic4)

    def test_smartLog_acl_non(self):
        self.assertEqual(smartACL.smartLog(self.filetacl_non), self.results_filetacl_non)

    def test_smartLog_acl_non_and_con(self):
        self.assertEqual(smartACL.smartLog(self.filetacl_non_and_con), self.results_filetacl_non_and_con)

    def test_smartLog_acl_splitted(self):
        self.assertEqual(smartACL.smartLog(self.filetacl_splitted), self.results_filetacl_splitted)

    def tearDown(self):
        sys.stdout = self.stdout


unittest.main()