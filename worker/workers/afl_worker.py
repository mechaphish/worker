from ..worker import Worker
from farnsworth.models import Test, Crash, Bitmap
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
        self._runtime = 0
        self._timeout = None
        self._last_bm = None

    def _update_bitmap(self):
        bm = self._fuzzer.bitmap()

        if self._last_bm == bm:
            return
        else:
            self._last_bm = bm

        try:
            dbm = self._cbn.bitmap.first()
            dbm.blob = bm
        except Bitmap.DoesNotExist: #pylint:disable=no-member
            dbm = Bitmap(blob=bm, cbn=self._cbn)
        dbm.save()

    def _check_test(self, t):
        if t in self._seen: return

        l.info("Got test of length (%s)!", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        Test.create(cbn=self._cbn, job=self._job, blob=t, drilled=False)

    def _check_crash(self, t):
        if t in self._seen: return

        l.info("Got crash of length (%s)!", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        #print repr(self._fuzzer.bitmap())
        Crash.create(cbn=self._cbn, job=self._job, blob=t, drilled=False)

    def _run(self, job):
        '''
        Runs AFL with the specified number of cores.
        '''

        self._job = job
        self._cbn = job.cbn
        self._timeout = job.limit_time

        # first, get the seeds we currently have, for the entire CB, not just for this binary
        self._seen.update(t.blob for t in self._cbn.tests)

        self._fuzzer = fuzzer.Fuzzer(
            self._cbn.path, self._workdir, self._job.limit_cpu, seeds=self._seen
        )
        l.info("Created fuzzer")
        self._fuzzer.start()
        for _ in range(10):
            if self._fuzzer.alive:
                break
            time.sleep(1)
        else:
            raise Exception("Fuzzer failed to start")

        l.info("Started fuzzer")

        while self._timeout is None or self._runtime < self._timeout:
            time.sleep(5)
            self._runtime += 5
            l.debug("Checking results...")

            for c in self._fuzzer.crashes():
                self._check_crash(c)
            for c in self._fuzzer.queue():
                self._check_test(c)
            self._seen.add(c)

    def run(self, job):
        try:
            self._run(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
