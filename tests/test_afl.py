import os
from mock import MagicMock
from nose.tools import *

import farnsworth.test_support
from farnsworth.models import AFLJob, ChallengeBinaryNode
import worker

if os.environ.get('GITLAB_CI') is not None:
    cbs_path = "/home/angr/angr/cbs"
else:
    cbs_path = os.path.join(os.path.dirname(__file__), '../../cbs')

print cbs_path

class TestAFLWorker:
    def setup(self):
        farnsworth.test_support.truncate_tables()
        self.cbn = ChallengeBinaryNode.create(
            blob=open(os.path.join(cbs_path, 'qualifier_event/ccf3d301/ccf3d301_01'),'rb').read(),
            name='ccf3d301_01',
            cs_id='ccf3d301'
        )
        self.job = AFLJob.create(
            limit_cpu = 4,
            limit_memory = 1,
            limit_time = 10,
            cbn = self.cbn
        )
        self.aw = worker.AFLWorker()

    def test_it_finds_cases_and_assigns_them_to_cbn_tests(self):
        self.aw.run(self.job)

        cases = (self.aw._fuzzer.crashes() + self.aw._fuzzer.queue())
        assert_greater(len(cases), 0)
        # we check fuzzer results every 5s, so there could be less results in _seen
        assert_greater_equal(len(self.aw._seen), len(self.job.cbn.tests))
        assert_greater_equal(len(cases), len(self.job.cbn.tests))

        # check if fuzzer uploaded the stats
        pending_favs = int(self.aw._fuzzer.stats['fuzzer-master']['pending_favs'])
        assert_greater_equal(self.aw._cbn.fuzzer_stat.pending_favs, pending_favs)
