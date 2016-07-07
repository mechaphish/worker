from ..worker import Worker
from farnsworth.models import Test, Job, Crash, Bitmap, FuzzerStat, ChallengeBinaryNode
import datetime
import fuzzer
import time
import rex

import logging
l = logging.getLogger('crs.worker.workers.afl_worker')
l.setLevel('DEBUG')

class AFLWorker(Worker):
    def __init__(self):
        self._workername = 'afl'
        self._seen = set()
        self._workdir = '/dev/shm/work'
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

        l.info("Got test of length %s", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        t = Test.create(cbn=self._cbn, job=self._job, blob=t, drilled=False)

    def _check_crash(self, t):
        if t in self._seen: return
        self._seen.add(t)

        l.info("Got crash of length %s", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        try:
            crash_kind = rex.Crash.quick_triage(self._cbn.path, t)
        except Exception as e: #pylint:disable=broad-except
            l.error("received a %s exception, shouldn't happen", str(e))
            crash_kind = None

        if crash_kind is None:
            l.error("encountered crash_kind of None, this shouldn't happen")
            l.error("binary: %s", self._cbn.path)
            l.error("crash: %s", t.encode('hex'))
            return

        Crash.create(cbn=self._cbn, job=self._job, blob=t, drilled=False, kind=crash_kind)

    def _sync_new_tests(self):
        prev_sync_time = self._last_sync_time
        self._last_sync_time = datetime.datetime.now()

        # any new tests which come from a different worker which apply to the same binary
        new_tests = list(
                Test.unsynced_testcases(prev_sync_time).\
                    join(Job).where(Job.worker != self._workername).\
                    join(ChallengeBinaryNode).where(ChallengeBinaryNode.id == self._cbn.id) #pylint:disable=no-member
                )

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

        # first, get the seeds we currently have, for the entire CB, not just for this binary
        all_tests = list(self._cbn.tests)
        if len(all_tests) > 0:
            self._seen.update(str(t.blob) for t in all_tests)

        l.info("Initializing fuzzer stats")
        fs = FuzzerStat.create(cbn=self._cbn)

        self._fuzzer = fuzzer.Fuzzer(
            self._cbn.path, self._workdir, self._job.limit_cpu, seeds=self._seen, create_dictionary=True
        )

        l.info("Created fuzzer for cbn %s", job.cbn.id)
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
            if n > 0:
                l.debug("... synced %d new testcases", n)

    def run(self, job):
        try:
            self._run(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
