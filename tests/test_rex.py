import os
from mock import MagicMock
from nose.tools import *

import worker
from farnsworth_client.models import Job, ChallengeBinaryNode, Test

class TestRexWorker:
    def setup(self):
        crashing_test = MagicMock(
            Test(),
            type = 'crash',
            blob = "1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n1\n1\n1\n"
        )
        self.cbn = MagicMock(
            ChallengeBinaryNode(),
            exploits = [],
            binary_path = os.path.join('../cbs/qualifier_event/ccf3d301', 'ccf3d301_01'),
        )
        self.job = MagicMock(
            Job(),
            limit_cpu = 1,
            limit_memory = 2,
            cbn = self.cbn,
            blob = crashing_test,
        )
        self.rw = worker.RexWorker()

    def test_ccf3d301_exploitation(self):
        self.rw.run(self.job)
        # for this binary we can create type-1 exploits, but not type-2s
        assert_equals(len(self.cbn.exploits), 1)
        assert_equals(self.cbn.exploits[0].pov_type, 1)
