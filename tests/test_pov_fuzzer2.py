#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
from mock import MagicMock
from nose.tools import *

from worker.workers.pov_fuzzer2_worker import PovFuzzer2Worker
from farnsworth_client.models import Job, ChallengeBinaryNode, Crash

class TestPovFuzzer2:
    def setup(self):
        crashing_test = MagicMock(Crash(),
                                  kind='arbitrary_read',
                                  blob=("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
                                        "%x%x%x%x%X%x%sAAAAAAAAAAAAAAAAAA"
                                        "AAAAAAAAAAAAAAAAAAAAAA"))
        self.cbn = MagicMock(ChallengeBinaryNode(),
                             exploits=[],
                             binary_path=os.path.join('../binaries-private/tests/i386/controlled_printf',
                                                      'controlled_printf_01'))
        self.job = MagicMock(Job(),
                             limit_cpu=1,
                             limit_memory=2,
                             cbn=self.cbn,
                             blob=crashing_test)
        self.work = PovFuzzer2Worker()

    def test_run(self):
        self.work.run(self.job)
        # for this binary we can create type-1 exploits, but not type-2s
        assert_equals(len(self.cbn.exploits), 1)
        assert_equals(self.cbn.exploits[0].pov_type, 2)
