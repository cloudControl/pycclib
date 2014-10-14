#!/usr/bin/env python
# -*- coding: utf-8 -*-


import unittest

from pycclib import cclib


class TestAnonymous(unittest.TestCase):
    def setUp(self):
        self.api = cclib.API()

    def test_list_addons(self):
        response = self.api.read_addons()
        self.assertFalse(response is None)
        self.assertTrue(len(response) > 0)

if __name__ == '__main__':
    unittest.main()
