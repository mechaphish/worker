from ..worker import Worker
from farnsworth.models import Test, Crash, Bitmap
import datetime
import fuzzer
import time

import logging
l = logging.getLogger('crs.worker.workers.were_rabbit_worker')
l.setLevel('DEBUG')

class WereRabbitWorker(Worker):
    """
    AFL's crash exploration mode. Affectionately named the 'Peruvian Were Rabbit' by lcamtuf.
    """
    def __init__(self):
        self._seen = set()
        self._workdir = '/dev/shm/crash_work'
        self._fuzzer = None
        self._job = None
        self._cbn = None
        self._runtime = 0
        self._timeout = None
        self._last_bm = None
        self._last_sync_time = datetime.datetime.now()

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

    def _check_crash(self, t):
        if t in self._seen: return
        self._seen.add(t)

        l.info("Got crash of length (%s)!", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        #print repr(self._fuzzer.bitmap())
        Crash.create(cbn=self._cbn, job=self._job, blob=t, drilled=False)

    def _sync_new_tests(self):
        prev_sync_time = self._last_sync_time
        self._last_sync_time = datetime.datetime.now()
        new_tests = list(Test.unsynced_testcases('driller', prev_sync_time)) #pylint:disable=no-member
        if len(new_tests) > 0:
            blobs = [ str(t.blob) for t in new_tests ]
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

        # first, get the crahes we have currently discovered, these will be used to seed the crash explorer
        l.info("Gathering all found crashes")
        all_crashes = list(self._cbn.crashes)
        if len(all_crashes) > 0:
            self._seen.update(str(c.blob) for c in all_crashes)
        else:
            raise Exception("No crashes found to explore (why was I scheduled?)")

        l.info("Starting up crash fuzzer")
        self._fuzzer = fuzzer.Fuzzer(
            self._cbn.path, self._workdir, self._job.limit_cpu, seeds=self._seen, create_dictionary=True, crash_mode=True
        )

        l.info("Created crash fuzzer")
        self._fuzzer.start()
        for _ in range(15):
            if self._fuzzer.alive:
                break
            time.sleep(1)
        else:
            raise Exception("Crash fuzzer failed to start")

        l.info("Started crash fuzzer")

        while self._timeout is None or self._runtime < self._timeout:
            time.sleep(5)
            self._runtime += 5

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
