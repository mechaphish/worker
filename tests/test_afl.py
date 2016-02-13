import os
import timeout_decorator
import mock
from nose.tools import *

import worker
from farnsworth_client.models import Job, ChallengeBinaryNode

class TestAFLWorker:
    def setup(self):
        self.cbn = mock.create_autospec(
            ChallengeBinaryNode,
            tests = [],
            binary_path = os.path.join('../cbs/qualifier_event/ccf3d301', 'ccf3d301_01')
        )
        self.job = mock.create_autospec(
            Job,
            limit_cpu = 4,
            limit_memory = 1,
            cbn = self.cbn
        )
        self.aw = worker.AFLWorker()

    def test_it_finds_cases_and_assigns_them_to_cbn_tests(self):
        @timeout_decorator.timeout(10)
        def _timeout_run():
            self.aw.run(self.job)
        try:
            _timeout_run()
        except timeout_decorator.TimeoutError:
            pass

        cases = (self.aw._fuzzer.crashes() + self.aw._fuzzer.queue())
        assert_greater(cases, 0)
        assert_equals(len(self.aw._seen), len(self.job.cbn.tests))
        # we check fuzzer results every 5s, so there could be less results in _seen
        assert_greater_equal(len(cases), len(self.job.cbn.tests))
