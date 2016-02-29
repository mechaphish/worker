from ..worker import Worker
from farnsworth.models import Bitmap, Test
import fuzzer
import time

import logging
l = logging.getLogger('crs.worker.workers.afl_worker')
l.setLevel('DEBUG')

class AFLWorker(Worker):
    def __init__(self):
        self._seen = set()
        self._workdir = '/dev/shm/work'
        self._fuzzer = None
        self._job = None
        self._cbn = None

    def _check_testcase(self, t, test_type):
        if t in self._seen:
            return
        l.info("Got testcase (%s)!", test_type)
        self._job.produced_output = True
        self._cbn.bitmap = Bitmap(blob=self._fuzzer.bitmap())
        self._cbn.tests += [Test(job_id=self._job.id, type=test_type, blob=t)]
        self._cbn.save()
        self._seen.add(t)

    def _run(self, job):
        '''
        Runs AFL with the specified number of cores.
        '''

        self._job = job
        self._cbn = job.cbn

        # first, get the seeds we currently have, for the entire CB, not just for this binary
        self._seen.update(t.blob for t in self._cbn.tests_by_type('test'))

        self._fuzzer = fuzzer.Fuzzer(
            self._job.cbn.binary_path, self._workdir, self._job.limit_cpu, seeds=self._seen
        )
        l.info("Created fuzzer")
        self._fuzzer.start()
        time.sleep(10)
        assert self._fuzzer.alive
        l.info("Started fuzzer")

        while True:
            time.sleep(5)
            l.debug("Checking results...")

            for c in self._fuzzer.crashes():
                self._check_testcase(c, 'crash')
            for c in self._fuzzer.queue():
                self._check_testcase(c, 'test')

    def run(self, job):
        try:
            self._run(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
