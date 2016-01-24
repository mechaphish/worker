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
        self._binary = None

    def _check_testcase(self, t, crashing):
        if t in self._seen:
            return

        l.info("Got testcase (crashing=%s)!", crashing)
        self._binary.bitmap = self._fuzzer.bitmap()
        self._binary.add_testcase(crscommon.api.Testcase(self._binary, text=t, crashing=crashing))
        self._seen.add(t)

    def _run(self, job):
        '''
        Runs AFL with the specified number of cores.
        '''

        self._binary = job.binary

        # first, get the seeds we currently have, for the entire CB, not just for this binary
        self._seen.update(t.text for t in self._binary.ct.testcases)

        self._fuzzer = fuzzer.Fuzzer(job.binary.path, self._workdir, job.cores, seeds=self._seen)
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