from ..worker import Worker
from farnsworth.models import Test, Crash, Bitmap, FuzzerStat
import datetime
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
        self._max_test_id = 0

    def _update_bitmap(self):
        bm = self._fuzzer.bitmap()

        if self._last_bm == bm:
            return
        else:
            self._last_bm = bm

        dbm = self._cbn.bitmap.first()
        if dbm is not None:
            dbm.blob = bm
        else: #except Bitmap.DoesNotExist: #pylint:disable=no-member
            dbm = Bitmap(blob=bm, cbn=self._cbn)
        dbm.save()

    def _check_test(self, t):
        if t in self._seen: return
        self._seen.add(t)

        l.info("Got test of length (%s)!", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        t = Test.create(cbn=self._cbn, job=self._job, blob=t, drilled=False)
        self._max_test_id = max(self._max_test_id, t.id) #pylint:disable=no-member

    def _check_crash(self, t):
        if t in self._seen: return
        self._seen.add(t)

        l.info("Got crash of length (%s)!", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        #print repr(self._fuzzer.bitmap())
        Crash.create(cbn=self._cbn, job=self._job, blob=t, drilled=False)

    def _sync_new_tests(self):
        new_tests = list(self._cbn.tests.filter(Test.id > self._max_test_id)) #pylint:disable=no-member
        if len(new_tests) > 0:
            blobs = [ str(t.blob) for t in new_tests ]
            self._max_test_id = max(self._max_test_id, *[t.id for t in new_tests ])
            self._seen.update(blobs)
            self._fuzzer.pollenate(blobs)
        return len(new_tests)

    def _run(self, job):
        '''
        Runs AFL with the specified number of cores.
        '''

        self._job = job
        self._cbn = job.cbn
        self._timeout = job.limit_time

        # first, get the seeds we currently have, for the entire CB, not just for this binary
        all_tests = list(self._cbn.tests)
        if len(all_tests) > 0:
            self._seen.update(str(t.blob) for t in all_tests)
            self._max_test_id = max(t.id for t in all_tests)

        l.info("Initializing fuzzer stats")
        fs = FuzzerStat.create(cbn=self._cbn)

        self._fuzzer = fuzzer.Fuzzer(
            self._cbn.path, self._workdir, self._job.limit_cpu, seeds=self._seen, create_dictionary=True
        )

        l.info("Created fuzzer")
        self._fuzzer.start()
        for _ in range(15):
            if self._fuzzer.alive:
                break
            time.sleep(1)
        else:
            raise Exception("Fuzzer failed to start")

        l.info("Started fuzzer")

        while self._timeout is None or self._runtime < self._timeout:
            time.sleep(5)
            self._runtime += 5

            l.debug("Updating fuzzer stats...")
            fs.pending_favs = int(self._fuzzer.stats['fuzzer-1']['pending_favs'])
            fs.pending_total = int(self._fuzzer.stats['fuzzer-1']['pending_total'])
            fs.paths_total = int(self._fuzzer.stats['fuzzer-1']['paths_total'])
            fs.paths_found = int(self._fuzzer.stats['fuzzer-1']['paths_found'])
            fs.last_path = datetime.datetime.fromtimestamp(int(self._fuzzer.stats['fuzzer-master']['last_path']))
            fs.save()

            l.debug("Checking results...")

            for c in self._fuzzer.crashes():
                self._check_crash(c)
            for c in self._fuzzer.queue():
                self._check_test(c)

            l.debug("Syncing new testcases...")
            n = self._sync_new_tests()
            l.debug("... synced %d new testcases!", n)

    def run(self, job):
        try:
            self._run(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
