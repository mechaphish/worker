from ..worker import Worker
import crscommon
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
        self._bitmap_id = None
        self._last_uploaded_bitmap = None
        self._job = None

    @property
    def bitmap_id(self):
        bm = self._fuzzer.bitmap()
        if bm != self._last_uploaded_bitmap:
            self._last_uploaded_bitmap = bm
            self._bitmap_id = crscommon.api.upload_bitmap(bm)
        return self._bitmap_id

    def _check_testcase(self, t, crashing):
        if t in self._seen:
            return

        l.info("Got testcase (crashing=%s)!", crashing)
        testcase = crscommon.Testcase(text=t)
        crscommon.api.submit_testcase(self._job.ct_id, self._job.binary.binary_id, testcase, bitmap_id=self.bitmap_id, crashing=crashing)
        self._seen.add(t)

    def _run(self, job):
        '''
        Runs AFL with the specified number of cores.
        '''

        self._job = job

        # first, get the seeds we currently have, for the entire CB, not just for this binary
        testcases = crscommon.api.get_testcases(job.ct_id)
        self._seen.update(t.text for t in testcases)

        self._fuzzer = fuzzer.Fuzzer(job.binary.path, self._workdir, job.cores, seeds=[t.text for t in testcases])
        l.info("Created fuzzer")

        self._fuzzer.start()
        time.sleep(10)
        assert self._fuzzer.alive
        l.info("Started fuzzer")

        while True:
            time.sleep(5)
            l.debug("Checking results...")

            for c in self._fuzzer.crashes():
                self._check_testcase(c, True)
            for c in self._fuzzer.queue():
                self._check_testcase(c, False)

    def run(self, job):
        try:
            self._run(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
